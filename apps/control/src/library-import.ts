import { nowIso, db, tx } from './db';
import { PolicyError, invalid, notFound } from './errors';
import type { Relationship } from './frameworks';
import * as ledger from './ledger';
import { singleOperatorMode, type Principal } from './rbac';

// Spreadsheet importer and mapping review (BP 9.1, 9.4). An organisation loads a framework from its own
// CSV or Excel file: a licensed copy of a paid standard (filling a locked "licence needed" entry), a
// framework whose terms stop Signet from shipping it, or its own internal policy. The browser reads the
// file and matches the columns; this module validates and stores the rows. Requirements are then linked
// to Signet Controls by people: one person proposes a link, a second confirms it, and only confirmed
// links count toward scores. Signet suggests links but never applies one by itself.

export interface SheetRow { external_id: string; title?: string; description?: string }
export interface SheetImportInput {
  framework_id?: string;
  name?: string;
  version?: string;
  category?: string;
  source_url?: string;
  licence_confirmation?: string;
  rows: SheetRow[];
  replace?: boolean;
}

const MAX_ROWS = 5000;
const CATEGORIES = ['ai_risk', 'ai_security', 'ai_law', 'security', 'privacy', 'resilience', 'threat', 'regional', 'other'];
const RELATIONSHIPS: Relationship[] = ['equivalent', 'subset_of', 'superset_of', 'intersects'];
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50);
const text = (v: unknown, max: number) => (typeof v === 'string' || typeof v === 'number' ? String(v).replace(/\s+/g, ' ').trim().slice(0, max) : '');

interface FrameworkRow { id: string; name: string; namespace: string; enabled: number }

export async function importSheet(input: SheetImportInput, p: Principal) {
  if (!Array.isArray(input?.rows) || !input.rows.length) throw invalid('rows must be a non-empty list');
  if (input.rows.length > MAX_ROWS) throw invalid(`at most ${MAX_ROWS} rows per import`);
  const rows = input.rows.map((r, i) => {
    const id = text(r?.external_id, 64);
    if (!id) throw invalid(`row ${i + 1}: the requirement ID is empty`);
    const title = text(r.title, 300);
    const description = text(r.description, 2000);
    return { id, summary: [title, description].filter(Boolean).join(': ') || id };
  });
  const dup = rows.map((r) => r.id).find((id, i, all) => all.indexOf(id) !== i);
  if (dup) throw invalid(`requirement ID ${dup} appears more than once`);
  const category = input.category ?? 'other';
  if (!CATEGORIES.includes(category)) throw invalid(`category must be one of ${CATEGORIES.join(', ')}`);

  const fwId = input.framework_id?.trim() || (input.name?.trim() ? `custom-${slug(input.name)}` : '');
  if (!fwId) throw invalid('give a framework name (or the id of a "licence needed" framework)');
  const existing = (await db.prepare('SELECT id, name, namespace, enabled FROM framework WHERE id = ?').get(fwId)) as FrameworkRow | undefined;
  if (existing && !['licence_required', 'customer', 'customer_licensed'].includes(existing.namespace)) {
    throw new PolicyError('BP-9.4', `${existing.name} is built in or imported from another source; import the spreadsheet as a new framework`, 409);
  }
  const licensed = existing?.namespace === 'licence_required' || existing?.namespace === 'customer_licensed';
  const confirmation = text(input.licence_confirmation, 300);
  if (licensed && !confirmation) throw invalid(`${existing!.name} is a licensed standard: record your licence (for example the order or licence number) in licence_confirmation`);
  if (!existing && !input.name?.trim()) throw invalid('a name is required for a new framework');

  return tx(async () => {
    if (!existing) {
      await db.prepare("INSERT INTO framework (id, name, version, licence, namespace, category, source_url, ships, enabled) VALUES (?, ?, ?, ?, 'customer', ?, ?, 'customer_copy', 0)")
        .run(fwId, text(input.name, 200), text(input.version, 60), confirmation ? `Customer copy: ${confirmation}` : 'Customer-provided content', category, text(input.source_url, 500) || null);
    } else if (licensed) {
      await db.prepare("UPDATE framework SET namespace = 'customer_licensed', ships = 'customer_copy', licence = ?, version = COALESCE(NULLIF(?, ''), version) WHERE id = ?").run(`Licensed copy: ${confirmation}`, text(input.version, 60), fwId);
    } else {
      await db.prepare('UPDATE framework SET name = COALESCE(NULLIF(?, \'\'), name), version = COALESCE(NULLIF(?, \'\'), version) WHERE id = ?').run(text(input.name, 200), text(input.version, 60), fwId);
    }
    const before = new Set(((await db.prepare("SELECT external_id FROM framework_requirement WHERE framework_id = ? AND source = 'sheet'").all(fwId)) as { external_id: string }[]).map((r) => r.external_id));
    for (const r of rows) {
      await db.prepare(
        `INSERT INTO framework_requirement (id, framework_id, external_id, summary, source, in_scope) VALUES (?, ?, ?, ?, 'sheet', 1)
         ON CONFLICT (id) DO UPDATE SET summary = EXCLUDED.summary, in_scope = 1`,
      ).run(`${fwId}:${r.id}`, fwId, r.id, r.summary);
    }
    let removed = 0;
    if (input.replace) {
      const keep = new Set(rows.map((r) => r.id));
      for (const old of [...before].filter((x) => !keep.has(x))) {
        await db.prepare('DELETE FROM control_mapping WHERE requirement_id = ?').run(`${fwId}:${old}`);
        await db.prepare('DELETE FROM framework_requirement WHERE id = ?').run(`${fwId}:${old}`);
        removed++;
      }
    }
    const created = rows.filter((r) => !before.has(r.id)).length;
    await ledger.append({ kind: 'admin', data: { event: 'library.sheet_import', framework_id: fwId, rows: rows.length, created, updated: rows.length - created, removed, licence_confirmation: confirmation || null, actor: p.id } });
    return { framework_id: fwId, rows: rows.length, created, updated: rows.length - created, removed, licensed };
  });
}

// --- Mapping review --------------------------------------------------------------------------------

async function requirement(id: string) {
  const r = (await db.prepare('SELECT id, framework_id, external_id, summary FROM framework_requirement WHERE id = ?').get(id)) as { id: string; framework_id: string; external_id: string; summary: string } | undefined;
  if (!r) throw notFound(`requirement ${id}`);
  return r;
}
async function control(id: string) {
  const c = (await db.prepare('SELECT id, objective, test, domain FROM control WHERE id = ?').get(id)) as { id: string; objective: string; test: string; domain: string } | undefined;
  if (!c) throw notFound(`control ${id}`);
  return c;
}
async function mapping(requirementId: string, controlId: string) {
  return (await db.prepare('SELECT origin, proposed_by, reviewed_by FROM control_mapping WHERE requirement_id = ? AND control_id = ?').get(requirementId, controlId)) as { origin: string; proposed_by: string | null; reviewed_by: string | null } | undefined;
}

/** Propose a link from a requirement to a Signet Control. It counts once a second person confirms it. */
export async function proposeMapping(input: { requirement_id: string; control_id: string; relationship?: Relationship; coverage_note?: string }, p: Principal) {
  const r = await requirement(input?.requirement_id);
  await control(input.control_id);
  const rel = input.relationship ?? 'subset_of';
  if (!RELATIONSHIPS.includes(rel)) throw invalid(`relationship must be one of ${RELATIONSHIPS.join(', ')}`);
  if (await mapping(r.id, input.control_id)) throw new PolicyError('BP-9.1', 'this requirement is already linked to that control', 409);
  // With a single administrator there is no second person; the link is confirmed and marked as such.
  const solo = singleOperatorMode();
  const at = nowIso();
  await tx(async () => {
    await db.prepare("INSERT INTO control_mapping (requirement_id, control_id, relationship, coverage_note, origin, proposed_by, proposed_at, reviewed_by, reviewed_at) VALUES (?, ?, ?, ?, 'customer', ?, ?, ?, ?)")
      .run(r.id, input.control_id, rel, text(input.coverage_note, 500) || null, p.id, at, solo ? p.id : null, solo ? at : null);
    await ledger.append({ kind: 'admin', data: { event: 'library.mapping_proposed', requirement_id: r.id, control_id: input.control_id, relationship: rel, waived_single_operator: solo || undefined, actor: p.id } });
  });
  return { requirement_id: r.id, control_id: input.control_id, relationship: rel, status: solo ? 'confirmed' : 'proposed' };
}

/** Confirm a proposed link. The person confirming must not be the person who proposed it. */
export async function confirmMapping(input: { requirement_id: string; control_id: string }, p: Principal) {
  const m = await mapping(input?.requirement_id, input?.control_id);
  if (!m) throw notFound('mapping');
  if (m.origin !== 'customer') throw new PolicyError('BP-9.1', 'built-in links are already reviewed', 409);
  if (m.reviewed_by) throw new PolicyError('BP-9.1', 'this link is already confirmed', 409);
  if (m.proposed_by === p.id) throw new PolicyError('BP-9.1', 'a second person must confirm a link you proposed', 403);
  await tx(async () => {
    await db.prepare('UPDATE control_mapping SET reviewed_by = ?, reviewed_at = ? WHERE requirement_id = ? AND control_id = ?').run(p.id, nowIso(), input.requirement_id, input.control_id);
    await ledger.append({ kind: 'admin', data: { event: 'library.mapping_confirmed', requirement_id: input.requirement_id, control_id: input.control_id, proposed_by: m.proposed_by, actor: p.id } });
  });
  return { requirement_id: input.requirement_id, control_id: input.control_id, status: 'confirmed' };
}

/** Remove a link the organisation added. Built-in links follow the Signet catalogue. */
export async function removeMapping(input: { requirement_id: string; control_id: string; reason?: string }, p: Principal) {
  const m = await mapping(input?.requirement_id, input?.control_id);
  if (!m) throw notFound('mapping');
  if (m.origin !== 'customer') throw new PolicyError('BP-9.1', 'built-in links cannot be removed; they follow the Signet catalogue', 409);
  if (!input.reason?.trim()) throw invalid('a reason is required');
  await tx(async () => {
    await db.prepare('DELETE FROM control_mapping WHERE requirement_id = ? AND control_id = ?').run(input.requirement_id, input.control_id);
    await ledger.append({ kind: 'admin', data: { event: 'library.mapping_removed', requirement_id: input.requirement_id, control_id: input.control_id, reason: input.reason, actor: p.id } });
  });
  return { removed: true };
}

// Suggestions: shared words between the requirement and each control, plus a small list of compliance
// terms that point at a control family. A hint for a person, never applied automatically.
const STOP = new Set(['with', 'that', 'this', 'from', 'have', 'their', 'there', 'which', 'shall', 'should', 'must', 'every', 'each', 'into', 'about', 'when', 'where', 'other', 'such', 'than', 'they', 'them', 'been', 'being', 'were', 'will', 'within', 'under', 'over', 'agent', 'agents', 'system', 'systems', 'information', 'organization', 'organisation', 'ensure', 'including', 'used', 'using']);
const HINTS: [RegExp, string[]][] = [
  [/\blog|record|audit trail|evidence/i, ['SGC-MON-001']],
  [/monitor|anomal|detect/i, ['SGC-MON-004']],
  [/inventor|asset|register/i, ['SGC-INV-001', 'SGC-INV-002']],
  [/access|privilege|authori[sz]/i, ['SGC-TOOL-004', 'SGC-IDN-001']],
  [/credential|secret|password|authenticat|identit/i, ['SGC-IDN-001', 'SGC-IDN-002']],
  [/personal|privacy|data protection|confidential|leak/i, ['SGC-DATA-001', 'SGC-DATA-002']],
  [/incident|breach/i, ['SGC-RESP-002', 'SGC-RESP-003']],
  [/supplier|vendor|third.party|outsourc|supply chain/i, ['SGC-MODEL-003', 'SGC-SUPPLY-001']],
  [/vulnerab|patch|software component/i, ['SGC-SUPPLY-001']],
  [/risk assess|impact assess/i, ['SGC-RISK-001', 'SGC-RISK-002']],
  [/human oversight|approv|review by|intervene/i, ['SGC-TOOL-006', 'SGC-HUMAN-001']],
  [/training|awareness|competen|literacy/i, ['SGC-HUMAN-002']],
  [/bias|fair|discriminat/i, ['SGC-FAIR-001']],
  [/transparen|inform users|disclos|notice/i, ['SGC-TRANS-001']],
  [/test|validat|verif/i, ['SGC-SEC-001']],
  [/polic|governance|leadership|management body|roles/i, ['SGC-GOV-001', 'SGC-GOV-002']],
  [/decommission|retire|dispos/i, ['SGC-LIFE-004']],
  [/cost|budget|resource/i, ['SGC-VALUE-002']],
];
const words = (s: string) => new Set(s.toLowerCase().match(/[a-z]{4,}/g)?.filter((w) => !STOP.has(w)) ?? []);

export async function suggestMappings(requirementId: string) {
  const r = await requirement(requirementId);
  const linked = new Set(((await db.prepare('SELECT control_id FROM control_mapping WHERE requirement_id = ?').all(r.id)) as { control_id: string }[]).map((x) => x.control_id));
  const controls = (await db.prepare('SELECT id, objective, test, domain FROM control').all()) as { id: string; objective: string; test: string; domain: string }[];
  const rw = words(r.summary);
  const hinted = new Set(HINTS.filter(([re]) => re.test(r.summary)).flatMap(([, ids]) => ids));
  return controls
    .filter((c) => !linked.has(c.id))
    .map((c) => {
      const cw = words(`${c.objective} ${c.test}`);
      const shared = [...rw].filter((w) => cw.has(w));
      const score = Math.min(1, shared.length / Math.max(3, Math.sqrt(rw.size * cw.size)) + (hinted.has(c.id) ? 0.5 : 0));
      return { control_id: c.id, objective: c.objective, score: Math.round(score * 100) / 100, why: [hinted.has(c.id) ? 'topic match' : '', shared.length ? `shared words: ${shared.slice(0, 5).join(', ')}` : ''].filter(Boolean).join('; ') };
    })
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);
}

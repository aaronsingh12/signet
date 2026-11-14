import { createHash } from 'node:crypto';
import { db, tx } from './db';
import { invalid } from './errors';
import { FRAMEWORKS, SP800_53_AI_SUBSET } from './frameworks';
import * as ledger from './ledger';
import type { Principal } from './rbac';

// OSCAL importer (BP 9.4). Loads an official OSCAL catalog (for example NIST SP 800-53 Rev. 5 from
// usnistgov/oscal-content) or profile (for example a FedRAMP baseline from GSA fedramp-automation).
// Every control is kept, but only the AI-relevant subset counts toward the compliance score unless the
// caller asks for "all"; this keeps scores about AI agents rather than about the whole enterprise.
// Built-in (Signet-written) rows are never overwritten by an import.

interface OscalPart { name?: string; prose?: string; parts?: OscalPart[] }
interface OscalControl { id: string; title?: string; parts?: OscalPart[]; controls?: OscalControl[] }
interface OscalGroup { id?: string; title?: string; controls?: OscalControl[]; groups?: OscalGroup[] }
interface OscalCatalog { metadata?: { title?: string; version?: string }; groups?: OscalGroup[]; controls?: OscalControl[] }
interface OscalProfile { metadata?: { title?: string; version?: string }; imports?: { href?: string; 'include-controls'?: { 'with-ids'?: string[] }[] }[] }

export interface OscalImportInput {
  document: { catalog?: OscalCatalog; profile?: OscalProfile };
  framework_id?: string;
  name?: string;
  licence?: string;
  subset?: 'ai' | 'all';
}

const MAX_CONTROLS = 5000;
const AI_SUBSET = new Map(SP800_53_AI_SUBSET.map(([id, , ...controls]) => [id, controls]));

/** "ac-2" → "AC-2", "ac-2.1" → "AC-2(1)" (the way NIST prints control and enhancement ids). */
export function displayId(oscalId: string): string {
  const [base, enh] = oscalId.toLowerCase().split('.');
  return `${base!.toUpperCase()}${enh ? `(${enh})` : ''}`;
}

const clean = (text: string) => text.replace(/\{\{\s*insert:[^}]*\}\}/g, '[value]').replace(/\s+/g, ' ').trim();
function statement(parts: OscalPart[] | undefined): string {
  const st = parts?.find((x) => x.name === 'statement');
  if (!st) return '';
  const all: string[] = [];
  const walk = (x: OscalPart) => {
    if (x.prose) all.push(x.prose);
    x.parts?.forEach(walk);
  };
  walk(st);
  return clean(all.join(' '));
}

function flatten(c: OscalCatalog): OscalControl[] {
  const out: OscalControl[] = [];
  const addControl = (x: OscalControl) => {
    out.push(x);
    x.controls?.forEach(addControl);
  };
  const addGroup = (g: OscalGroup) => {
    g.controls?.forEach(addControl);
    g.groups?.forEach(addGroup);
  };
  c.controls?.forEach(addControl);
  c.groups?.forEach(addGroup);
  return out;
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);

async function ensureFramework(id: string, name: string, version: string, licence: string) {
  const exists = await db.prepare('SELECT id FROM framework WHERE id = ?').get(id);
  if (exists) return;
  await db.prepare("INSERT INTO framework (id, name, version, licence, namespace, category, ships, enabled) VALUES (?, ?, ?, ?, 'oscal', 'security', 'full_text', 1)").run(id, name, version, licence);
}

async function upsertRequirement(fw: string, ext: string, summary: string, inScope: boolean) {
  await db.prepare(
    `INSERT INTO framework_requirement (id, framework_id, external_id, summary, source, in_scope) VALUES (?, ?, ?, ?, 'oscal', ?)
     ON CONFLICT (id) DO UPDATE SET
       summary = CASE WHEN framework_requirement.source = 'oscal' THEN EXCLUDED.summary ELSE framework_requirement.summary END,
       in_scope = CASE WHEN framework_requirement.source = 'oscal' THEN EXCLUDED.in_scope ELSE framework_requirement.in_scope END`,
  ).run(`${fw}:${ext}`, fw, ext, summary, inScope ? 1 : 0);
}

async function mapSubset(fw: string, ext: string) {
  for (const control of AI_SUBSET.get(ext) ?? []) {
    await db.prepare("INSERT INTO control_mapping (requirement_id, control_id, relationship, origin) VALUES (?, ?, 'subset_of', 'oscal') ON CONFLICT DO NOTHING").run(`${fw}:${ext}`, control);
  }
}

export async function importOscal(input: OscalImportInput, p: Principal) {
  const subset = input.subset ?? 'ai';
  if (!['ai', 'all'].includes(subset)) throw invalid('subset must be "ai" or "all"');
  const doc = input.document;
  if (!doc || typeof doc !== 'object' || (!doc.catalog && !doc.profile)) throw invalid('document must be an OSCAL JSON object with a "catalog" or a "profile"');

  if (doc.catalog) {
    const controls = flatten(doc.catalog);
    if (!controls.length) throw invalid('the catalog has no controls');
    if (controls.length > MAX_CONTROLS) throw invalid(`the catalog has ${controls.length} controls; the limit is ${MAX_CONTROLS}`);
    const title = doc.catalog.metadata?.title ?? input.name ?? 'Imported OSCAL catalog';
    const fw = input.framework_id ?? (/800-53/.test(title) ? 'nist-800-53' : slug(title));
    const builtIn = FRAMEWORKS.find((f) => f.id === fw);
    let inScope = 0;
    await tx(async () => {
      await ensureFramework(fw, input.name ?? title, doc.catalog!.metadata?.version ?? '', builtIn?.licence ?? input.licence ?? 'Imported by the customer; the customer confirms the licence');
      for (const c of controls) {
        if (typeof c.id !== 'string' || !c.id) throw invalid('every control needs an id');
        const ext = displayId(c.id);
        const scoped = subset === 'all' || AI_SUBSET.has(ext);
        if (scoped) inScope++;
        await upsertRequirement(fw, ext, clean([c.title, statement(c.parts)].filter(Boolean).join(': ')).slice(0, 600) || ext, scoped);
        if (fw === 'nist-800-53') await mapSubset(fw, ext);
      }
      await ledger.append({ kind: 'admin', data: { event: 'library.oscal_import', kind_of_document: 'catalog', framework_id: fw, title, controls: controls.length, in_scope: inScope, subset, actor: p.id } });
    });
    return { framework_id: fw, kind: 'catalog', controls: controls.length, in_scope: inScope };
  }

  const profile = doc.profile!;
  const ids = [...new Set((profile.imports ?? []).flatMap((i) => (i['include-controls'] ?? []).flatMap((x) => x['with-ids'] ?? [])))];
  if (!ids.length) throw invalid('the profile selects no controls (imports[].include-controls[].with-ids)');
  if (ids.length > MAX_CONTROLS) throw invalid(`the profile selects ${ids.length} controls; the limit is ${MAX_CONTROLS}`);
  const title = profile.metadata?.title ?? input.name ?? 'Imported OSCAL profile';
  const fedramp = /fedramp/i.test(title) ? (/li-?saas/i.test(title) ? 'fedramp-li-saas' : /moderate/i.test(title) ? 'fedramp-moderate' : /high/i.test(title) ? 'fedramp-high' : /low/i.test(title) ? 'fedramp-low' : null) : null;
  const fw = input.framework_id ?? fedramp ?? slug(title);
  const builtIn = FRAMEWORKS.find((f) => f.id === fw);
  const selected = new Set(ids.map(displayId));
  let inScope = 0;
  await tx(async () => {
    await ensureFramework(fw, input.name ?? title, profile.metadata?.version ?? '', builtIn?.licence ?? input.licence ?? 'Imported by the customer; the customer confirms the licence');
    for (const ext of selected) {
      const scoped = subset === 'all' || AI_SUBSET.has(ext);
      if (scoped) inScope++;
      const text = (await db.prepare("SELECT summary FROM framework_requirement WHERE id = ?").get(`nist-800-53:${ext}`)) as { summary: string } | undefined;
      await upsertRequirement(fw, ext, text?.summary ?? ext, scoped);
      await mapSubset(fw, ext);
    }
    // Controls this baseline no longer selects drop out of the score (imported rows only).
    const existing = (await db.prepare("SELECT id, external_id FROM framework_requirement WHERE framework_id = ? AND source = 'oscal'").all(fw)) as { id: string; external_id: string }[];
    for (const r of existing.filter((x) => !selected.has(x.external_id))) await db.prepare('UPDATE framework_requirement SET in_scope = 0 WHERE id = ?').run(r.id);
    // A built-in baseline row the official profile does not select is reported, not silently kept.
    await ledger.append({ kind: 'admin', data: { event: 'library.oscal_import', kind_of_document: 'profile', framework_id: fw, title, controls: selected.size, in_scope: inScope, subset, actor: p.id } });
  });
  const notInProfile = builtIn ? ((await db.prepare("SELECT external_id FROM framework_requirement WHERE framework_id = ? AND source = 'signet'").all(fw)) as { external_id: string }[]).map((r) => r.external_id).filter((x) => !selected.has(x)) : [];
  return { framework_id: fw, kind: 'profile', controls: selected.size, in_scope: inScope, built_in_not_in_profile: notInProfile };
}

// --- Official sources (BP 9.3: NIST SP 800-53 "imported via OSCAL importer, full text") ---------------
// Signet loads the official file itself instead of asking someone to download and upload it. Each
// source is fixed to one upstream commit and checked against its SHA-256 before anything is imported.
export const OFFICIAL_SOURCES = {
  'nist-800-53': {
    name: 'NIST SP 800-53 Rev. 5.2.0 catalog (OSCAL JSON)',
    url: 'https://raw.githubusercontent.com/usnistgov/oscal-content/5006f18c8047643eaa70e35dd0d20a58bcc41856/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json',
    sha256: '64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb',
    framework_id: 'nist-800-53',
  },
} as const;
export type OfficialSource = keyof typeof OFFICIAL_SOURCES;

export async function loadOfficial(source: string, p: Principal, opts: { url?: string; sha256?: string } = {}) {
  const s = OFFICIAL_SOURCES[source as OfficialSource];
  if (!s) throw invalid(`unknown official source; known: ${Object.keys(OFFICIAL_SOURCES).join(', ')}`);
  const url = opts.url ?? s.url;
  const r = await fetch(url, { signal: AbortSignal.timeout(120_000) });
  if (!r.ok) throw invalid(`could not download ${s.name}: HTTP ${r.status}`);
  const bytes = Buffer.from(await r.arrayBuffer());
  const got = createHash('sha256').update(bytes).digest('hex');
  const want = opts.sha256 ?? s.sha256;
  if (got !== want) throw invalid(`${s.name}: the downloaded file does not match the pinned SHA-256 (got ${got.slice(0, 12)}, expected ${want.slice(0, 12)}); nothing was imported`);
  const result = await importOscal({ document: JSON.parse(bytes.toString('utf8')), framework_id: s.framework_id }, p);
  await ledger.append({ kind: 'admin', data: { event: 'library.official_source_loaded', source, url, sha256: got, actor: p.id } });
  return { source, sha256: got, ...result };
}

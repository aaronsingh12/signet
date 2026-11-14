import { canonicalize, newId, sha256, signJws, toJwk, verifyJws } from '@signet/core';
import { COUNTED_MAPPING } from './controls';
import { db, nowIso } from './db';
import { invalid, notFound } from './errors';
import { keys } from './keys';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';

// Audit packs (BP 9.6): one-click, signed exports per framework, scoped to a date range and an agent set.
// Every pack has the requirements with their Signet Controls and current results, the AI inventory, an
// independence statement (BP 2), activity and enforcement in the period, the ledger roots that anchor the
// evidence, and a framework-specific section: EU AI Act Annex IV outline, NIST AI RMF profile and gaps,
// NIST 800-53 / FedRAMP implementation statements with an OSCAL SSP fragment, or the board pack.
// The pack is canonical JSON signed with the ledger key (JWS), so anyone can check it offline.

export const FORMAT = 'signet-audit-pack/1';
const DAY = 86_400_000;
export const BOARD = 'board';

export interface PackInput { framework_id: string; from?: string; to?: string; agents?: string[] }

const day = (s: string | undefined, fallback: Date) => {
  const v = s ?? fallback.toISOString().slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) throw invalid('from and to must be dates (YYYY-MM-DD)');
  return v;
};

async function inventory(agentIds: string[] | null) {
  const rows = (await db.prepare(
    `SELECT a.id, a.handle, a.name, a.purpose, a.tier, a.owner, a.sponsor, a.status, a.autonomy_level, a.kind, a.vendor, a.model_provider,
            (SELECT c.id FROM certificate c WHERE c.agent_id = a.id AND c.status = 'active' ORDER BY c.issued_at DESC LIMIT 1) AS cert_id,
            (SELECT c.valid_to FROM certificate c WHERE c.agent_id = a.id AND c.status = 'active' ORDER BY c.issued_at DESC LIMIT 1) AS cert_valid_to
       FROM agent a WHERE a.tenant_id = ? ORDER BY a.tier, a.handle`,
  ).all(tenant.id)) as Record<string, string | null>[];
  return agentIds ? rows.filter((r) => agentIds.includes(r.id!) || agentIds.includes(r.handle!)) : rows;
}

async function requirementsOf(frameworkId: string) {
  const reqs = (await db.prepare('SELECT id, external_id, summary FROM framework_requirement WHERE framework_id = ? AND in_scope = 1 ORDER BY external_id').all(frameworkId)) as { id: string; external_id: string; summary: string }[];
  const maps = (await db.prepare(
    `SELECT m.requirement_id, m.control_id, m.relationship, m.coverage_note, c.objective, c.test, c.test_type, COALESCE(r.status, 'not_tested') AS status, r.detail, r.evaluated_at
       FROM control_mapping m JOIN control c ON c.id = m.control_id LEFT JOIN control_result r ON r.control_id = m.control_id AND r.scope = 'tenant'
      WHERE ${COUNTED_MAPPING} AND m.requirement_id IN (SELECT id FROM framework_requirement WHERE framework_id = ?)`,
  ).all(frameworkId)) as { requirement_id: string; control_id: string; relationship: string; coverage_note: string | null; objective: string; test: string; test_type: string; status: string; detail: string | null; evaluated_at: string | null }[];
  return reqs.map((r) => {
    const controls = maps.filter((m) => m.requirement_id === r.id).map(({ requirement_id: _r, ...m }) => m);
    const st = controls.map((c) => c.status);
    const status = !st.length ? 'no_control' : st.every((s) => s === 'effective') ? 'effective' : st.some((s) => s === 'ineffective') ? 'ineffective' : st.every((s) => s === 'not_tested') ? 'not_tested' : 'partially_effective';
    return { id: r.external_id, summary: r.summary, status, controls };
  });
}

async function activity(from: string, to: string, agentIds: string[]) {
  const start = `${from}T00:00:00.000Z`;
  const end = new Date(Date.parse(`${to}T00:00:00.000Z`) + DAY).toISOString();
  const inAgents = agentIds.length ? `AND agent_id IN (${agentIds.map(() => '?').join(', ')})` : 'AND 1 = 0';
  const tx = (await db.prepare(
    `SELECT jsonb_extract_path_text(data::jsonb, 'policy_decision') AS decision, COUNT(*) AS n, SUM(COALESCE((data::jsonb ->> 'cost_usd')::numeric, 0)) AS usd
       FROM ledger_record WHERE kind = 'transaction' AND ts >= ? AND ts < ? ${inAgents}
        AND jsonb_extract_path_text(data::jsonb, 'action_type') IN ('llm_call', 'tool_call') GROUP BY 1`,
  ).all(start, end, ...agentIds)) as { decision: string | null; n: number; usd: number | null }[];
  const enforcement = (await db.prepare(`SELECT level, rule_id, agent_id, actor, reason, published_at FROM enforcement_event WHERE published_at >= ? AND published_at < ? ${inAgents} ORDER BY published_at`).all(start, end, ...agentIds)) as { level: string; rule_id: string | null; agent_id: string; actor: string; reason: string; published_at: string }[];
  const approvals = (await db.prepare(`SELECT type, status, COUNT(*) AS n FROM approval_request WHERE created_at >= ? AND created_at < ? ${inAgents} GROUP BY type, status`).all(start, end, ...agentIds)) as { type: string; status: string; n: number }[];
  return {
    transactions: Object.fromEntries(tx.map((t) => [t.decision ?? 'unknown', Number(t.n)])),
    spend_usd: Math.round(tx.reduce((a, t) => a + Number(t.usd ?? 0), 0) * 100) / 100,
    approvals: approvals.map((a) => ({ ...a, n: Number(a.n) })),
    enforcement: enforcement.map((e) => ({ ...e })),
  };
}

async function ledgerEvidence(from: string, to: string) {
  const roots = (await db.prepare(
    "SELECT r.day, r.count, r.merkle_root, r.jws, (SELECT a.ref FROM evidence_anchor a WHERE a.day = r.day AND a.kind = 's3') AS s3, (SELECT a.ref FROM evidence_anchor a WHERE a.day = r.day AND a.kind = 'tsa') AS tsa FROM daily_root r WHERE r.day BETWEEN ? AND ? ORDER BY r.day",
  ).all(from, to)) as { day: string; count: number; merkle_root: string; jws: string; s3: string | null; tsa: string | null }[];
  const head = (await db.prepare('SELECT seq, record_hash, ts FROM ledger_record ORDER BY seq DESC LIMIT 1').get()) as { seq: number; record_hash: string; ts: string } | undefined;
  return {
    daily_roots: roots.map((r) => ({ day: r.day, records: Number(r.count), merkle_root: r.merkle_root, jws: r.jws, s3_object_lock: r.s3 ? JSON.parse(r.s3) : null, rfc3161: r.tsa ? JSON.parse(r.tsa) : null })),
    ledger_head: head ? { seq: Number(head.seq), record_hash: head.record_hash, ts: head.ts } : null,
    how_to_verify: 'Each daily root is a JWS signed with the ledger key below; signet-verify checks a ledger export (.sep) against these roots offline.',
  };
}

function independence(agents: Record<string, string | null>[], exceptions: string[]) {
  const vendors = [...new Set(agents.map((a) => a.vendor || (a.kind === 'self_hosted' ? 'in-house (self-hosted)' : a.kind || 'unknown')))].sort();
  const own = agents.filter((a) => /techsnitch/i.test(a.vendor ?? '')).map((a) => a.handle);
  return {
    governed_vendors: vendors,
    statement: `Signet applies the same rulebook, lifecycle and controls to every agent in scope, whichever vendor or platform runs it (${vendors.length} source(s) listed).${own.length ? ` TechSnitch's own agents (${own.join(', ')}) are governed the same way, with no special path.` : ''}`,
    // Seals that carry an explicit exception to the standard rules (for example audit-only detector outages).
    exceptions,
  };
}

// --- framework-specific sections ----------------------------------------------------------------------
async function euAiAct(agents: Record<string, string | null>[], reqs: Awaited<ReturnType<typeof requirementsOf>>) {
  const out = [];
  for (const a of agents.filter((x) => x.tier === 'T1' || x.tier === 'T2')) {
    const lc = (await db.prepare("SELECT id, stage, status, data FROM lifecycle WHERE agent_id = ? ORDER BY started_at DESC LIMIT 1").get(a.id!)) as { id: string; stage: string; status: string; data: string } | undefined;
    const data = lc ? (JSON.parse(lc.data) as { intake?: Record<string, unknown>; manifest?: Record<string, unknown> }) : {};
    const assessments = lc ? ((await db.prepare('SELECT type, status FROM assessment WHERE lifecycle_id = ?').all(lc.id)) as { type: string; status: string }[]) : [];
    const test = lc ? ((await db.prepare("SELECT status, suites, created_at FROM test_run WHERE lifecycle_id = ? ORDER BY created_at DESC LIMIT 1").get(lc.id)) as { status: string; suites: string; created_at: string } | undefined) : undefined;
    const suites = test ? ((JSON.parse(test.suites).suites ?? []) as { suite: string; passed: boolean; required: boolean }[]) : [];
    out.push({
      agent: a.handle, tier: a.tier,
      annex_iv: {
        '1 general description': { purpose: a.purpose, owner: a.owner, provider: a.vendor ?? 'in-house', model_provider: a.model_provider, autonomy: a.autonomy_level },
        '2 development and design': { intake: data.intake ?? null, tools_in_seal: Object.keys((data.manifest as { actions?: Record<string, unknown> } | undefined)?.actions ?? {}) },
        '3 monitoring, functioning and control': { human_oversight: a.autonomy_level, certificate: a.cert_id, valid_to: a.cert_valid_to },
        '4 performance metrics': suites.map((s) => ({ suite: s.suite, passed: s.passed, required: s.required })),
        '5 risk management': assessments,
        '7 standards applied': 'Signet Controls as listed in this pack',
        '9 post-market monitoring': 'Every transaction is logged to the hash-chained ledger; DET-ANOM baselines, DET-GROUND samples and control evaluations run continuously',
      },
      lifecycle: lc ? { stage: lc.stage, status: lc.status } : null,
    });
  }
  const art = (id: string) => reqs.find((r) => r.id === id)?.status ?? 'not in pack';
  return { high_risk_agents: out, articles: { 'Art. 12 logging': art('Art. 12'), 'Art. 14 human oversight': art('Art. 14'), 'Art. 15 accuracy and robustness': art('Art. 15'), 'Art. 72 post-market monitoring': art('Art. 72') } };
}

function rmfProfile(reqs: Awaited<ReturnType<typeof requirementsOf>>) {
  const fns = ['GOVERN', 'MAP', 'MEASURE', 'MANAGE'];
  const profile = Object.fromEntries(fns.map((f) => {
    const rows = reqs.filter((r) => r.id.startsWith(f));
    const count = (s: string) => rows.filter((r) => r.status === s).length;
    return [f, { subcategories: rows.length, effective: count('effective'), partially_effective: count('partially_effective'), ineffective: count('ineffective'), not_tested: count('not_tested') }];
  }));
  const gaps = reqs.filter((r) => r.status !== 'effective').map((r) => ({ id: r.id, status: r.status, actions: r.controls.filter((c) => c.status !== 'effective').map((c) => `${c.control_id}: ${c.detail ?? c.test}`) }));
  return { profile, gaps };
}

function sp80053(frameworkId: string, reqs: Awaited<ReturnType<typeof requirementsOf>>) {
  const state = (s: string) => (s === 'effective' ? 'implemented' : s === 'partially_effective' ? 'partial' : 'planned');
  const component = sha256(`${tenant.id}:signet-component`).slice(0, 32).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
  const uuid = (s: string) => sha256(`${frameworkId}:${s}`).slice(0, 32).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
  const statements = reqs.map((r) => ({
    control: r.id, status: r.status,
    implementation: r.controls.length ? r.controls.map((c) => `${c.control_id} (${c.relationship}): ${c.objective}. Test: ${c.test}. Result: ${c.status}${c.detail ? ` (${c.detail})` : ''}.${c.coverage_note ? ` Note: ${c.coverage_note}.` : ''}`).join(' ') : 'No Signet Control; the organisation implements this control.',
  }));
  const oscal = {
    'system-security-plan': {
      uuid: uuid('ssp'),
      metadata: { title: `Signet AI agent governance: ${frameworkId} control implementation (fragment)`, 'last-modified': nowIso(), version: '1', 'oscal-version': '1.1.2' },
      'control-implementation': {
        description: 'Controls implemented by the Signet AI agent governance platform for the AI agents in scope. Fragment for merging into the system security plan.',
        'implemented-requirements': reqs.map((r) => ({
          uuid: uuid(r.id), 'control-id': r.id.toLowerCase().replace(/\((\d+)\)/g, '.$1'),
          'by-components': [{ 'component-uuid': component, uuid: uuid(`${r.id}:signet`), description: statements.find((s) => s.control === r.id)!.implementation, 'implementation-status': { state: state(r.status) } }],
        })),
      },
    },
  };
  return { implementation_statements: statements, oscal_ssp_fragment: oscal };
}

function board(agents: Record<string, string | null>[], act: Awaited<ReturnType<typeof activity>>, reqs: { status: string; controls: { control_id: string; status: string; detail: string | null }[] }[]) {
  const byTier = Object.fromEntries(['T1', 'T2', 'T3', 'T4'].map((t) => [t, agents.filter((a) => a.tier === t).length]));
  const failing = new Map<string, string>();
  for (const r of reqs) for (const c of r.controls) if (c.status === 'ineffective') failing.set(c.control_id, c.detail ?? '');
  return {
    inventory_by_tier: byTier,
    agents_without_active_seal: agents.filter((a) => !a.cert_id && a.status !== 'retired').map((a) => a.handle),
    incidents: act.enforcement.filter((e) => e.level === 'quarantined' || e.level === 'killed').length,
    kills: act.enforcement.filter((e) => e.level === 'killed'),
    open_gaps: [...failing].map(([control, detail]) => ({ control, detail })),
    spend_usd: act.spend_usd,
  };
}

async function exceptionsOf(agentIds: string[]) {
  const rows = (await db.prepare("SELECT a.handle, c.body FROM certificate c JOIN agent a ON a.id = c.agent_id WHERE c.status = 'active'").all()) as { handle: string; body: string }[];
  return rows.filter((r) => agentIds.length && JSON.parse(r.body).detector_unavailability === 'audit').map((r) => `${r.handle}: detector outages audited instead of held (seal exception)`);
}

export async function build(input: PackInput) {
  const to = day(input.to, new Date());
  const from = day(input.from, new Date(Date.now() - 90 * DAY));
  if (from > to) throw invalid('from must not be after to');
  const agents = await inventory(input.agents?.length ? input.agents : null);
  if (input.agents?.length && !agents.length) throw invalid('none of the agents given are in this tenant');
  const act = await activity(from, to, agents.map((a) => a.id!));
  let framework: Record<string, unknown>;
  let reqs: Awaited<ReturnType<typeof requirementsOf>> = [];
  let section: Record<string, unknown> = {};
  if (input.framework_id === BOARD) {
    framework = { id: BOARD, name: 'Board pack' };
    const all = (await db.prepare("SELECT id FROM framework WHERE enabled = 1 AND namespace <> 'licence_required'").all()) as { id: string }[];
    const allReqs = (await Promise.all(all.map((f) => requirementsOf(f.id)))).flat();
    section = { board: board(agents, act, allReqs) };
  } else {
    const f = (await db.prepare('SELECT id, name, version, licence, source_url, namespace, enabled FROM framework WHERE id = ?').get(input.framework_id)) as Record<string, unknown> | undefined;
    if (!f) throw notFound(`framework ${input.framework_id}`);
    if (f.namespace === 'licence_required') throw invalid(`${f.name} needs a licensed copy loaded before it can be exported`);
    framework = f;
    reqs = await requirementsOf(input.framework_id);
    if (input.framework_id === 'eu-ai-act') section = { eu_ai_act: await euAiAct(agents, reqs) };
    else if (input.framework_id === 'nist-ai-rmf') section = { nist_ai_rmf: rmfProfile(reqs) };
    else if (input.framework_id === 'nist-800-53' || input.framework_id.startsWith('fedramp-')) section = { sp800_53: sp80053(input.framework_id, reqs) };
  }
  const count = (s: string) => reqs.filter((r) => r.status === s).length;
  return {
    format: FORMAT,
    tenant: { id: tenant.id, name: tenant.name },
    framework,
    scope: { from, to, agents: input.agents?.length ? agents.map((a) => a.handle) : 'all agents' },
    generated_at: nowIso(),
    summary: reqs.length ? { requirements: reqs.length, effective: count('effective'), partially_effective: count('partially_effective'), ineffective: count('ineffective'), not_tested: count('not_tested'), no_control: count('no_control') } : undefined,
    independence: independence(agents, await exceptionsOf(agents.map((a) => a.id!))),
    inventory: agents,
    requirements: reqs,
    activity: act,
    ...section,
    evidence: await ledgerEvidence(from, to),
    keys: { ledger: toJwk(keys.ledger) },
  };
}

export async function generate(input: PackInput, p: Principal) {
  if (!input?.framework_id) throw invalid('framework_id is required (or "board")');
  const pack = await build(input);
  const digest = sha256(canonicalize(pack));
  const signature = signJws({ format: FORMAT, sha256: digest, framework: input.framework_id, from: pack.scope.from, to: pack.scope.to }, keys.ledger, 'signet-audit-pack');
  const id = newId('job').replace('job_', 'apk_');
  await db.prepare('INSERT INTO audit_pack (id, framework_id, scope, sha256, signature, content, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, input.framework_id, JSON.stringify(pack.scope), digest, signature, JSON.stringify(pack), p.id, pack.generated_at);
  await ledger.append({ kind: 'admin', data: { event: 'audit_pack.generated', pack_id: id, framework: input.framework_id, scope: pack.scope, sha256: digest, actor: p.id } });
  return { id, framework_id: input.framework_id, scope: pack.scope, sha256: digest, summary: pack.summary, created_at: pack.generated_at };
}

export async function list() {
  return ((await db.prepare('SELECT id, framework_id, scope, sha256, created_by, created_at FROM audit_pack ORDER BY created_at DESC LIMIT 50').all()) as { scope: string }[]).map((r) => ({ ...r, scope: JSON.parse(r.scope) }));
}

export async function get(id: string, p: Principal) {
  const r = (await db.prepare('SELECT content, signature FROM audit_pack WHERE id = ?').get(id)) as { content: string; signature: string } | undefined;
  if (!r) throw notFound(`audit pack ${id}`);
  await ledger.append({ kind: 'admin', data: { event: 'audit_pack.downloaded', pack_id: id, actor: p.id } });
  return { pack: JSON.parse(r.content), signature: r.signature };
}

/** Offline check: the signature is valid for the ledger key in the pack, and the pack hashes to the signed value. */
export function verify(file: { pack: Record<string, unknown> & { keys?: { ledger?: { kid?: string } } }; signature: string }, trusted = new Map([[keys.ledger.kid, keys.ledger.publicKey]])) {
  const payload = verifyJws<{ sha256: string; format: string }>(file.signature, trusted, 'signet-audit-pack').payload;
  const digest = sha256(canonicalize(file.pack));
  return { ok: payload.sha256 === digest && payload.format === FORMAT, sha256: digest, signed: payload.sha256 };
}

/** Requirements as CSV for spreadsheets (BP 14: every table exportable to CSV). */
export function requirementsCsv(pack: { requirements: { id: string; summary: string; status: string; controls: { control_id: string; relationship: string; status: string; coverage_note: string | null }[] }[] }) {
  const q = (s: string) => `"${s.replace(/"/g, '""')}"`;
  return ['requirement,summary,status,controls', ...pack.requirements.map((r) => [r.id, r.summary, r.status, r.controls.map((c) => `${c.control_id} (${c.relationship}, ${c.status})${c.coverage_note ? ` - ${c.coverage_note}` : ''}`).join('; ')].map(q).join(','))].join('\n');
}

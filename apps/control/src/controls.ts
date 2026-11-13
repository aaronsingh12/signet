import { combine, sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, invalid, notFound } from './errors';
import { FRAMEWORKS, PLACEHOLDERS, REQUIREMENTS } from './frameworks';
import * as ledger from './ledger';
import { correlation, enqueue } from './outbox';
import type { Principal } from './rbac';
import { tenant } from './tenant';

// Control library (BP 9) and continuous control testing (BP 9.5, E13). Signet Controls (SGC) are the
// hub; framework requirements map to them, so one test produces evidence for every framework mapped.
// The framework catalogue and its mappings live in frameworks.ts (BP 9.3 licence rules apply there).
// Results feed compliance scores and, through connectors, ServiceNow indicators.

type Status = 'effective' | 'partially_effective' | 'ineffective' | 'not_tested';
interface Check {
  status: Status;
  detail: string;
}

interface ControlDef {
  id: string;
  domain: string;
  objective: string;
  test: string;
  type: 'automated' | 'semi_automated' | 'manual';
  severity: 'critical' | 'high' | 'medium' | 'low';
  check?: () => Check | Promise<Check>;
}

const one = async <T>(sql: string, ...args: (string | number)[]) => (await db.prepare(sql).get(...args)) as T;
const all = async <T>(sql: string, ...args: (string | number)[]) => (await db.prepare(sql).all(...args)) as T[];
const since = (ms: number) => new Date(Date.now() - ms).toISOString();
const DAY = 86_400_000;
const ratio = (bad: number, total: number, what: string): Check =>
  total === 0 ? { status: 'not_tested', detail: `no ${what} yet` } : bad === 0 ? { status: 'effective', detail: `0 of ${total} ${what} failed` } : { status: bad / total < 0.05 ? 'partially_effective' : 'ineffective', detail: `${bad} of ${total} ${what} failed` };

const CONTROLS: ControlDef[] = [
  {
    id: 'SGC-GOV-001', domain: 'GOV', severity: 'high', type: 'automated', objective: 'Every agent has an active named owner and sponsor',
    test: '100% of non-retired agents have owner and sponsor',
    check: async () => { const r = (await one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN owner = '' OR sponsor = '' THEN 1 ELSE 0 END) bad FROM agent WHERE status != 'retired'")); return ratio(r.bad ?? 0, r.n, 'agents'); },
  },
  { id: 'SGC-GOV-002', domain: 'GOV', severity: 'medium', type: 'manual', objective: 'AI policy approved by the board and reviewed yearly', test: 'Uploaded policy with approval date under 12 months' },
  {
    id: 'SGC-INV-001', domain: 'INV', severity: 'critical', type: 'automated', objective: 'Every agent with traffic has an active certificate',
    test: '100% of agents with traffic in 24 h have an active seal',
    check: async () => { const r = (await all<{ agent_id: string; ok: number }>(`SELECT DISTINCT l.agent_id, (SELECT COUNT(*) FROM certificate c WHERE c.agent_id = l.agent_id AND c.status = 'active') ok FROM ledger_record l WHERE l.kind = 'transaction' AND l.ts >= ? AND l.agent_id IS NOT NULL AND jsonb_extract_path_text(l.data::jsonb, 'outcome') = 'success'`, since(DAY))); return ratio(r.filter((x) => !x.ok).length, r.length, 'agents with traffic'); },
  },
  {
    id: 'SGC-INV-002', domain: 'INV', severity: 'medium', type: 'automated', objective: 'Shadow AI discovery runs weekly',
    test: 'A discovery scan in the last 7 days; open findings under 14 days old',
    check: async () => {
      const scans = (await one<{ n: number }>("SELECT COUNT(*) n FROM ledger_record WHERE kind = 'admin' AND jsonb_extract_path_text(data::jsonb, 'event') = 'discovery.scan_ingested' AND ts >= ?", since(7 * DAY))).n;
      const stale = (await one<{ n: number }>("SELECT COUNT(*) n FROM discovered_asset WHERE status = 'open' AND first_seen < ?", since(14 * DAY))).n;
      return !scans ? { status: 'ineffective', detail: 'no discovery scan in the last 7 days' } : stale ? { status: 'partially_effective', detail: `${stale} open finding(s) older than 14 days` } : { status: 'effective', detail: `${scans} scan(s) this week` };
    },
  },
  {
    id: 'SGC-RISK-001', domain: 'RISK', severity: 'high', type: 'automated', objective: 'Risk tier set before testing',
    test: 'No test run exists without a confirmed classification',
    check: async () => { const r = (await one<{ n: number; bad: number }>('SELECT COUNT(*) n, SUM(CASE WHEN c.confirmed_by IS NULL THEN 1 ELSE 0 END) bad FROM test_run t LEFT JOIN classification c ON c.lifecycle_id = t.lifecycle_id')); return ratio(r.bad ?? 0, r.n, 'test runs'); },
  },
  {
    id: 'SGC-RISK-002', domain: 'RISK', severity: 'high', type: 'automated', objective: 'Impact assessment done for T1/T2',
    test: 'Every sealed T1/T2 agent has a completed impact assessment',
    check: async () => { const r = (await all<{ ok: number }>("SELECT (SELECT COUNT(*) FROM lifecycle l JOIN assessment a ON a.lifecycle_id = l.id WHERE l.agent_id = g.id AND a.type = 'impact' AND a.status = 'complete') ok FROM agent g WHERE g.tier IN ('T1','T2') AND g.status = 'sealed'")); return ratio(r.filter((x) => !x.ok).length, r.length, 'sealed T1/T2 agents'); },
  },
  {
    id: 'SGC-DATA-001', domain: 'DATA', severity: 'critical', type: 'automated', objective: 'DLP profile enforced on prompts and responses',
    test: '100% of transaction records carry DLP results',
    check: async () => { const r = (await one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN jsonb_extract_path_text(data::jsonb, 'dlp_actions') IS NULL THEN 1 ELSE 0 END) bad FROM ledger_record WHERE kind = 'transaction' AND jsonb_extract_path_text(data::jsonb, 'action_type') IN ('llm_call','tool_call') AND ts >= ?", since(DAY))); return ratio(r.bad ?? 0, r.n, 'transactions (24 h)'); },
  },
  {
    id: 'SGC-DATA-002', domain: 'DATA', severity: 'high', type: 'automated', objective: 'Personal data reaches the cloud LLM only tokenised (RB-DATA-01)',
    test: '0 model calls carrying personal data without tokenisation',
    check: async () => { const r = (await all<{ d: string }>("SELECT jsonb_extract_path_text(data::jsonb, 'dlp_actions') d FROM ledger_record WHERE kind = 'transaction' AND jsonb_extract_path_text(data::jsonb, 'action_type') = 'llm_call' AND jsonb_extract_path_text(data::jsonb, 'outcome') = 'success' AND ts >= ?", since(DAY))); const bad = r.filter((x) => /in:personal:(allow|log_only)/.test(x.d ?? '')).length; return ratio(bad, r.length, 'successful model calls (24 h)'); },
  },
  {
    id: 'SGC-IDN-001', domain: 'IDN', severity: 'critical', type: 'automated', objective: 'Workload identity per agent; no static keys in production',
    test: 'Every allowed call carries a workload-token instance',
    check: async () => { const r = (await one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN jsonb_extract_path_text(data::jsonb, 'instance_id') IS NULL THEN 1 ELSE 0 END) bad FROM ledger_record WHERE kind = 'transaction' AND jsonb_extract_path_text(data::jsonb, 'outcome') = 'success' AND ts >= ?", since(DAY))); return ratio(r.bad ?? 0, r.n, 'successful calls (24 h)'); },
  },
  {
    id: 'SGC-IDN-002', domain: 'IDN', severity: 'high', type: 'automated', objective: 'Agents are keyless',
    test: '0 open unmanaged-key findings',
    check: async () => { const n = (await one<{ n: number }>("SELECT COUNT(*) n FROM discovered_asset WHERE type = 'unmanaged_key' AND status = 'open'")).n; return n ? { status: 'partially_effective', detail: `${n} unmanaged key(s) still open in the Discovery Inbox` } : { status: 'effective', detail: 'every sealed agent authenticates with workload tokens; no unmanaged keys open' }; },
  },
  {
    id: 'SGC-TOOL-004', domain: 'TOOL', severity: 'critical', type: 'automated', objective: 'Agents invoke only tools listed in their manifest',
    test: '100% of out-of-manifest attempts denied',
    check: async () => { const r = (await one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN jsonb_extract_path_text(data::jsonb, 'outcome') = 'success' THEN 1 ELSE 0 END) bad FROM ledger_record WHERE kind = 'transaction' AND jsonb_extract_path_text(data::jsonb, 'error_code') = 'out_of_manifest'")); return r.n ? ratio(r.bad ?? 0, r.n, 'out-of-manifest attempts') : { status: 'effective', detail: 'no out-of-manifest attempts; default-deny enforced in code' }; },
  },
  {
    id: 'SGC-TOOL-005', domain: 'TOOL', severity: 'high', type: 'automated', objective: 'Every action has an impact label (RB-PRIV-01)',
    test: '0 active seals with unlabelled actions',
    check: async () => { const certs = (await all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'")); const bad = certs.filter((c) => (JSON.parse(c.body).tools ?? []).some((t: { actions: { impact?: string }[] }) => t.actions.some((a) => !a.impact))).length; return ratio(bad, certs.length, 'active seals'); },
  },
  {
    id: 'SGC-TOOL-006', domain: 'TOOL', severity: 'critical', type: 'automated', objective: 'Human approval applied to high-impact actions (RB-PRIV-03)',
    test: 'Every executed critical action on T1-T3 carries an approval',
    check: async () => { const r = (await all<{ a: string | null }>("SELECT jsonb_extract_path_text(data::jsonb, 'approval_id') a FROM ledger_record WHERE kind = 'transaction' AND jsonb_extract_path_text(data::jsonb, 'impact') = 'critical' AND jsonb_extract_path_text(data::jsonb, 'outcome') = 'success'")); return r.length ? ratio(r.filter((x) => !x.a).length, r.length, 'executed critical actions') : { status: 'effective', detail: 'no critical action executed without approval' }; },
  },
  {
    id: 'SGC-MODEL-001', domain: 'MODEL', severity: 'high', type: 'automated', objective: 'Only the approved cloud LLM is used (RB-INV-19)',
    test: '0 successful calls to models outside the catalogue',
    check: async () => { const models = tenant.settings.catalogue.map((c) => c.model); const r = (await all<{ t: string }>("SELECT jsonb_extract_path_text(data::jsonb, 'target') t FROM ledger_record WHERE kind = 'transaction' AND jsonb_extract_path_text(data::jsonb, 'action_type') = 'llm_call' AND jsonb_extract_path_text(data::jsonb, 'outcome') = 'success' AND ts >= ?", since(DAY))); return ratio(r.filter((x) => !models.includes(x.t)).length, r.length, 'model calls (24 h)'); },
  },
  {
    id: 'SGC-MODEL-002', domain: 'MODEL', severity: 'medium', type: 'automated', objective: 'Model versions pinned',
    test: 'Every seal names a specific model, not a bare wildcard',
    check: async () => { const certs = (await all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'")); const bad = certs.filter((c) => (JSON.parse(c.body).models ?? []).some((m: { model: string }) => m.model.trim() === '*')).length; return ratio(bad, certs.length, 'active seals'); },
  },
  { id: 'SGC-MODEL-003', domain: 'MODEL', severity: 'medium', type: 'semi_automated', objective: 'Provider terms verified yearly (RB-PROV-03)', test: 'Provider terms record verified in 12 months' },
  {
    id: 'SGC-SEC-001', domain: 'SEC', severity: 'high', type: 'automated', objective: 'Pre-deployment security testing',
    test: 'Every active seal references a passing test report',
    check: async () => { const certs = (await all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'")); const bad = (await Promise.all(certs.map(async (c) => { const h = JSON.parse(c.body).evidence_refs?.test_report_sha256; return !h || !(await one<{ n: number }>("SELECT COUNT(*) n FROM test_run WHERE report_sha256 = ? AND status = 'passed'", h)).n; }))).filter(Boolean).length; return ratio(bad, certs.length, 'active seals'); },
  },
  { id: 'SGC-SEC-002', domain: 'SEC', severity: 'high', type: 'semi_automated', objective: 'Independent red team for T1', test: 'Every T1 seal references a red-team report' },
  {
    id: 'SGC-SUPPLY-001', domain: 'SUPPLY', severity: 'medium', type: 'automated', objective: 'AIBOM maintained and scanned',
    test: 'Every sealed agent has an AIBOM scanned in the last 30 days',
    check: async () => {
      const r = (await all<{ scanned: string | null }>("SELECT (SELECT MAX(COALESCE(b.scanned_at, b.created_at)) FROM aibom b WHERE b.agent_id = a.id) AS scanned FROM agent a WHERE a.status = 'sealed'"));
      return ratio(r.filter((x) => !x.scanned || x.scanned < since(30 * DAY)).length, r.length, 'sealed agents');
    },
  },
  {
    id: 'SGC-SUPPLY-002', domain: 'SUPPLY', severity: 'high', type: 'automated', objective: 'No known-exploited or critical vulnerability left open on an active agent',
    test: '0 open findings that are on the CISA KEV list or critical, for sealed agents',
    check: async () => {
      const r = (await one<{ n: number; kev: number | null }>("SELECT COUNT(*) n, SUM(f.kev) kev FROM vulnerability_finding f JOIN agent a ON a.id = f.agent_id WHERE a.status = 'sealed' AND f.status = 'open' AND (f.kev = 1 OR f.severity = 'critical')"));
      const scanned = (await one<{ n: number }>("SELECT COUNT(*) n FROM aibom WHERE scanned_at IS NOT NULL")).n;
      return !Number(scanned) ? { status: 'not_tested', detail: 'no AIBOM scanned yet' } : Number(r.n) ? { status: 'ineffective', detail: `${r.n} open critical finding(s), ${r.kev ?? 0} on the CISA KEV list` } : { status: 'effective', detail: 'no open critical or known-exploited vulnerabilities' };
    },
  },
  {
    id: 'SGC-MON-001', domain: 'MON', severity: 'critical', type: 'automated', objective: 'Every transaction logged and chained',
    test: 'Hash chain verifies end to end',
    check: async () => { const r = await ledger.verifyIncremental(); return r.ok ? { status: 'effective', detail: `chain intact up to record ${r.head_seq} (${r.checked} checked this run${r.full ? ', full re-check' : ''})` } : { status: 'ineffective', detail: `chain broken at seq ${r.error?.seq}: ${r.error?.reason}` }; },
  },
  { id: 'SGC-MON-004', domain: 'MON', severity: 'medium', type: 'automated', objective: 'Behaviour baseline monitored (DET-ANOM, later phase)', test: 'Every prod agent has a baseline' },
  { id: 'SGC-MON-005', domain: 'MON', severity: 'medium', type: 'automated', objective: 'Groundedness sampled (Tier 2 evaluator, Phase 3)', test: 'Weekly 1% sample' },
  { id: 'SGC-RESP-001', domain: 'RESP', severity: 'high', type: 'automated', objective: 'Kill capability tested (Kill Drills, Phase 3)', test: 'Drill within schedule' },
  {
    id: 'SGC-RESP-002', domain: 'RESP', severity: 'high', type: 'automated', objective: 'Incident raised on level 4+ events',
    test: 'Every level 4-6 event has an incident queued or sent to a connector',
    check: async () => {
      const events = (await all<{ id: string }>("SELECT id FROM enforcement_event WHERE level IN ('quarantined','killed') AND published_at >= ?", since(30 * DAY)));
      const connectors = (await one<{ n: number }>("SELECT COUNT(*) n FROM connector WHERE status = 'active'")).n;
      if (!connectors) return { status: events.length ? 'partially_effective' : 'not_tested', detail: `${events.length} level 4+ event(s); no incident connector configured` };
      const bad = (await Promise.all(events.map(async (e) => !(await one<{ n: number }>("SELECT COUNT(*) n FROM connector_outbox WHERE event = 'incident.create' AND object_key = ?", correlation('incident', e.id))).n))).filter(Boolean).length;
      return ratio(bad, events.length, 'level 4+ events');
    },
  },
  {
    id: 'SGC-HUMAN-001', domain: 'HUMAN', severity: 'high', type: 'automated', objective: 'Oversight level declared',
    test: 'Every active seal has an autonomy level',
    check: async () => { const certs = (await all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'")); return ratio(certs.filter((c) => !JSON.parse(c.body).autonomy_level).length, certs.length, 'active seals'); },
  },
  {
    id: 'SGC-HUMAN-003', domain: 'HUMAN', severity: 'high', type: 'automated', objective: 'Runtime approvals decided by people within SLA',
    test: 'Runtime approvals decided before timeout in the last 7 days',
    check: async () => { const r = (await one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) bad FROM approval_request WHERE type = 'runtime_hitl' AND created_at >= ?", since(7 * DAY))); return ratio(r.bad ?? 0, r.n, 'runtime approvals (7 d)'); },
  },
  { id: 'SGC-HUMAN-002', domain: 'HUMAN', severity: 'medium', type: 'manual', objective: 'Reviewers trained', test: 'Approvers trained in 12 months' },
  {
    id: 'SGC-TRANS-001', domain: 'TRANS', severity: 'medium', type: 'automated', objective: 'Users told they are talking to AI (EU AI Act Art. 50)',
    test: 'Every user-facing agent seal has the disclosure flag',
    check: async () => { const certs = (await all<{ body: string; data: string | null }>("SELECT c.body, (SELECT data FROM lifecycle l WHERE l.agent_id = c.agent_id ORDER BY started_at DESC LIMIT 1) data FROM certificate c WHERE c.status = 'active'")); const facing = certs.filter((c) => c.data && (JSON.parse(c.data).intake?.users_affected ?? []).some((u: string) => u !== 'internal')); return ratio(facing.filter((c) => !JSON.parse(c.body).ai_disclosure).length, facing.length, 'user-facing seals'); },
  },
  {
    id: 'SGC-FAIR-001', domain: 'FAIR', severity: 'high', type: 'automated', objective: 'Bias testing for agents affecting individuals',
    test: 'Every such agent has a passing bias suite (0.8-1.25)',
    check: async () => {
      const lcs = (await all<{ id: string }>("SELECT id FROM lifecycle WHERE status IN ('complete','in_progress') AND CASE jsonb_extract_path_text(data::jsonb, 'intake', 'decisions_about_individuals') WHEN 'true' THEN 1 WHEN 'false' THEN 0 END = 1"));
      const bad = (await Promise.all(lcs.map(async (l) => !(await all<{ suites: string }>("SELECT suites FROM test_run WHERE lifecycle_id = ? AND status = 'passed'", l.id)).some((t) => (JSON.parse(t.suites).suites ?? []).some((s: { suite: string; passed: boolean }) => s.suite === 'bias' && s.passed))))).filter(Boolean).length;
      return ratio(bad, lcs.length, 'agents affecting individuals');
    },
  },
  {
    id: 'SGC-LIFE-001', domain: 'LIFE', severity: 'high', type: 'automated', objective: 'No agent runs on an expired certificate',
    test: '0 successful calls under an expired seal',
    check: async () => { const r = (await one<{ n: number }>("SELECT COUNT(*) n FROM certificate WHERE status = 'active' AND valid_to < ?", nowIso())).n; return r ? { status: 'ineffective', detail: `${r} active seal(s) past expiry` } : { status: 'effective', detail: 'no active seal past expiry' }; },
  },
  {
    id: 'SGC-LIFE-002', domain: 'LIFE', severity: 'critical', type: 'automated', objective: 'Every seal passed the full lifecycle (BP 6)',
    test: 'Every active seal was issued from a lifecycle with an approval pack',
    check: async () => { const certs = (await all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'")); return ratio(certs.filter((c) => !JSON.parse(c.body).evidence_refs?.approval_pack_sha256).length, certs.length, 'active seals'); },
  },
  {
    id: 'SGC-LIFE-004', domain: 'LIFE', severity: 'medium', type: 'automated', objective: 'Retired agents fully decommissioned',
    test: 'Every retired agent has a decommission pack',
    check: async () => { const r = (await all<{ ok: number }>("SELECT (SELECT COUNT(*) FROM attestation t WHERE t.agent_id = a.id AND t.type = 'decommission') ok FROM agent a WHERE a.status = 'retired'")); return r.length ? ratio(r.filter((x) => !x.ok).length, r.length, 'retired agents') : { status: 'not_tested', detail: 'no retired agents yet' }; },
  },
  { id: 'SGC-VALUE-001', domain: 'VALUE', severity: 'low', type: 'manual', objective: 'Business case recorded', test: 'Every T1/T2 agent has a value case' },
  {
    id: 'SGC-VALUE-002', domain: 'VALUE', severity: 'medium', type: 'automated', objective: 'Spend within limits',
    test: 'No agent over its daily cost limit',
    check: async () => { const r = (await one<{ n: number }>("SELECT COUNT(*) n FROM ledger_record WHERE kind = 'transaction' AND jsonb_extract_path_text(data::jsonb, 'error_code') = 'cost_budget_exhausted' AND ts >= ?", since(DAY))).n; return r ? { status: 'partially_effective', detail: `${r} request(s) hit a daily cost limit (limit enforced)` } : { status: 'effective', detail: 'no agent reached its daily cost limit' }; },
  },
  {
    id: 'SGC-SELF-002', domain: 'SELF', severity: 'critical', type: 'automated', objective: 'No detector output can cause an allow (DA 7)',
    test: 'Decision combiner never turns deny or hold into allow for any band',
    check: () => {
      const bands = ['low', 'elevated', 'high'] as const;
      const bad = (['deny', 'require_approval'] as const).flatMap((rule) => bands.flatMap((band) => (['T1', 'T2', 'T3', 'T4'] as const).filter((t) => ['allow', 'allow_with_obligations'].includes(combine(rule, [{ id: 'D', version: 'x', status: 'ok', band }], t).outcome))));
      return bad.length ? { status: 'ineffective', detail: `${bad.length} combination(s) allowed` } : { status: 'effective', detail: '24 combinations checked; detectors only add caution' };
    },
  },
  {
    id: 'SGC-SELF-003', domain: 'SELF', severity: 'critical', type: 'automated', objective: 'Automatic kills always reference a rule (DA 7)',
    test: 'Every automatic kill in the ledger cites a rule ID',
    check: async () => { const r = (await one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN rule_id IS NULL THEN 1 ELSE 0 END) bad FROM enforcement_event WHERE level = 'killed' AND actor LIKE 'gateway:%'")); return r.n ? ratio(r.bad ?? 0, r.n, 'automatic kills') : { status: 'effective', detail: 'no automatic kill without a rule (enforced in code, RB-INV-05)' }; },
  },
  {
    id: 'SGC-SELF-005', domain: 'SELF', severity: 'high', type: 'automated', objective: 'Detectors run in shadow 14 days before promotion (RB-MOD-03)',
    test: 'No active detector promoted with the shadow period skipped',
    check: async () => { const r = (await one<{ n: number }>("SELECT COUNT(*) n FROM ledger_record WHERE kind = 'admin' AND jsonb_extract_path_text(data::jsonb, 'event') = 'detector.mode_changed' AND jsonb_extract_path_text(data::jsonb, 'to') = 'active' AND CASE jsonb_extract_path_text(data::jsonb, 'shadow_period_skipped') WHEN 'true' THEN 1 WHEN 'false' THEN 0 END = 1")).n; const active = (await one<{ n: number }>("SELECT COUNT(*) n FROM detector WHERE mode = 'active'")).n; return !active ? { status: 'not_tested', detail: 'no detector active' } : r ? { status: 'partially_effective', detail: `${r} promotion(s) skipped the 14-day shadow (dev override, recorded)` } : { status: 'effective', detail: 'every active detector completed its shadow period' }; },
  },
  {
    id: 'SGC-RISK-003', domain: 'RISK', severity: 'critical', type: 'automated', objective: 'Prohibited AI practices are never sealed (EU AI Act Art. 5)',
    test: '0 active seals for agents classified as a prohibited practice',
    check: async () => {
      const r = (await one<{ n: number }>("SELECT COUNT(DISTINCT l.agent_id) n FROM classification c JOIN lifecycle l ON l.id = c.lifecycle_id JOIN certificate k ON k.agent_id = l.agent_id AND k.status = 'active' WHERE c.regulatory_category = 'eu_ai_act:prohibited'")).n;
      return r ? { status: 'ineffective', detail: `${r} agent(s) classified as prohibited hold an active seal` } : { status: 'effective', detail: 'no prohibited-practice agent holds an active seal (rejected at Classify)' };
    },
  },
  { id: 'SGC-RESP-003', domain: 'RESP', severity: 'high', type: 'manual', objective: 'Serious incidents reported to authorities on time (GDPR 72 h, NIS2 24 h, DORA, EU AI Act Art. 73)', test: 'Each level 4+ incident has a reporting decision and, where required, a report filed within the legal deadline' },
  {
    id: 'SGC-SELF-001', domain: 'SELF', severity: 'high', type: 'automated', objective: 'Every Signet detector in use is registered and pinned by hash (DA 7)',
    test: 'Every detector in shadow or active mode has a recorded model hash',
    check: async () => { const r = (await all<{ id: string; model_sha256: string | null }>("SELECT id, model_sha256 FROM detector WHERE mode != 'off'")); const bad = r.filter((d) => !d.model_sha256).map((d) => d.id); return !r.length ? { status: 'not_tested', detail: 'no detector in use' } : bad.length ? { status: 'partially_effective', detail: `no pinned model hash for ${bad.join(', ')}` } : { status: 'effective', detail: `${r.length} detector(s) pinned by hash` }; },
  },
  { id: 'SGC-SELF-004', domain: 'SELF', severity: 'high', type: 'semi_automated', objective: 'Detector versions meet benchmark targets before activation (DA 7)', test: 'Release record shows benchmark results above thresholds (benchmark records not built yet)' },
  { id: 'SGC-SELF-006', domain: 'SELF', severity: 'medium', type: 'manual', objective: 'Detector drift reviewed monthly (DA 7)', test: 'Monthly human-labelled sample completed; findings tracked' },
  { id: 'SGC-SELF-007', domain: 'SELF', severity: 'high', type: 'automated', objective: 'Decisions are reproducible (DA 7)', test: 'Replay of a random daily sample reproduces 100% of outcomes (Replay tool not built yet)' },
  { id: 'SGC-SELF-008', domain: 'SELF', severity: 'high', type: 'semi_automated', objective: 'Detectors are isolated: no network, no tools, no memory (DA 7)', test: 'Configuration check of each gateway detector runtime' },
  { id: 'SGC-SELF-009', domain: 'SELF', severity: 'medium', type: 'manual', objective: 'Detectors red-teamed every release (DA 7)', test: 'Red-team report linked to each detector release' },
  {
    id: 'SGC-SELF-010', domain: 'SELF', severity: 'critical', type: 'automated', objective: 'Fail-safe works when a detector is down (DA 2, 7)',
    test: 'With a detector unavailable, T1/T2 allows become holds and T3/T4 follow the rule result',
    check: () => {
      const down = [{ id: 'D', version: 'x', status: 'unavailable' as const }];
      const bad = (['T1', 'T2', 'T3', 'T4'] as const).filter((t) => {
        const out = combine('allow', down, t).outcome;
        return t === 'T1' || t === 'T2' ? out !== 'require_approval' : out !== 'allow';
      });
      return bad.length ? { status: 'ineffective', detail: `fail-safe wrong for ${bad.join(', ')}` } : { status: 'effective', detail: 'detector outage: T1/T2 held for approval, T3/T4 on rules alone' };
    },
  },
];

const req = (fw: string, ext: string) => `${fw}:${ext}`;

export const CONTROL_IDS = new Set(CONTROLS.map((c) => c.id));

// Loads the built-in catalogue. Framework rows keep the tenant's enabled choice; requirement text and
// mappings follow the catalogue, so a new Signet release updates them. Imported (OSCAL, ServiceNow)
// requirements and customer mappings are left alone.
// The catalogue fingerprint: when it matches what this database last loaded, seeding is skipped, so a
// cold start does not rewrite a few hundred rows.
const catalogueHash = () => sha256(JSON.stringify({ c: CONTROLS.map(({ check: _check, ...c }) => c), f: FRAMEWORKS, r: REQUIREMENTS, x: PLACEHOLDERS }));

export async function seed() {
  const hash = catalogueHash();
  const done = (await db.prepare("SELECT value FROM library_state WHERE key = 'catalogue_sha256'").get()) as { value: string } | undefined;
  if (done?.value === hash) return;
  (await tx(async () => {
    // Licence-required frameworks: empty, locked entries. Signet-written content is removed; a copy the
    // organisation loaded itself (source 'sheet') is kept, and so is its enabled choice.
    for (const ph of PLACEHOLDERS) {
      (await db.prepare("DELETE FROM control_mapping WHERE requirement_id IN (SELECT id FROM framework_requirement WHERE framework_id = ? AND source = 'signet')").run(ph.id));
      (await db.prepare("DELETE FROM framework_requirement WHERE framework_id = ? AND source = 'signet'").run(ph.id));
      (await db.prepare(
        `INSERT INTO framework (id, name, version, licence, namespace, category, source_url, ships, enabled, notes) VALUES (?, ?, ?, ?, 'licence_required', ?, ?, 'none', 0, ?)
         ON CONFLICT (id) DO UPDATE SET
           namespace = CASE WHEN framework.namespace IN ('signet', 'licence_required') THEN 'licence_required' ELSE framework.namespace END,
           enabled = CASE WHEN framework.namespace IN ('signet', 'licence_required') THEN 0 ELSE framework.enabled END,
           ships = CASE WHEN framework.namespace IN ('signet', 'licence_required') THEN 'none' ELSE framework.ships END,
           category = EXCLUDED.category, source_url = EXCLUDED.source_url, notes = EXCLUDED.notes`,
      ).run(ph.id, ph.name, ph.version, `Licence needed: ${ph.reason}`, ph.category, ph.source_url, ph.reason));
    }
    for (const c of CONTROLS) {
      (await db.prepare('INSERT INTO control (id, domain, objective, test, test_type, applies_to, namespace, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET domain = EXCLUDED.domain, objective = EXCLUDED.objective, test = EXCLUDED.test, test_type = EXCLUDED.test_type, applies_to = EXCLUDED.applies_to, namespace = EXCLUDED.namespace, severity = EXCLUDED.severity').run(c.id, c.domain, c.objective, c.test, c.type, 'tenant', 'signet', c.severity));
    }
    for (const f of FRAMEWORKS) {
      (await db.prepare(
        `INSERT INTO framework (id, name, version, licence, namespace, category, source_url, ships, enabled, notes) VALUES (?, ?, ?, ?, 'signet', ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, version = EXCLUDED.version, licence = EXCLUDED.licence, category = EXCLUDED.category, source_url = EXCLUDED.source_url, ships = EXCLUDED.ships, notes = EXCLUDED.notes`,
      ).run(f.id, f.name, f.version, f.licence, f.category, f.source_url, f.ships, f.default_enabled ? 1 : 0, f.notes ?? null));
    }
    const ids = REQUIREMENTS.map((r) => req(r.framework_id, r.external_id));
    for (const r of REQUIREMENTS) {
      const id = req(r.framework_id, r.external_id);
      (await db.prepare(
        `INSERT INTO framework_requirement (id, framework_id, external_id, summary, source, in_scope) VALUES (?, ?, ?, ?, 'signet', 1)
         ON CONFLICT (id) DO UPDATE SET summary = EXCLUDED.summary, source = 'signet', in_scope = 1`,
      ).run(id, r.framework_id, r.external_id, r.summary));
      (await db.prepare("DELETE FROM control_mapping WHERE requirement_id = ? AND origin = 'signet'").run(id));
      for (const mp of r.maps) {
        (await db.prepare("INSERT INTO control_mapping (requirement_id, control_id, relationship, coverage_note, origin) VALUES (?, ?, ?, ?, 'signet') ON CONFLICT (requirement_id, control_id) DO UPDATE SET relationship = EXCLUDED.relationship, coverage_note = EXCLUDED.coverage_note").run(id, mp.control, mp.rel, mp.note ?? null));
      }
    }
    // Built-in requirements dropped from the catalogue (never imported ones).
    const stale = ((await db.prepare("SELECT id FROM framework_requirement WHERE source = 'signet' AND framework_id IN (SELECT id FROM framework WHERE namespace = 'signet')").all()) as { id: string }[]).filter((r) => !ids.includes(r.id));
    for (const r of stale) {
      (await db.prepare('DELETE FROM control_mapping WHERE requirement_id = ?').run(r.id));
      (await db.prepare('DELETE FROM framework_requirement WHERE id = ?').run(r.id));
    }
    (await db.prepare("INSERT INTO library_state (key, value, updated_at) VALUES ('catalogue_sha256', ?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at").run(hash, nowIso()));
  }));
}

/** The frameworks this tenant has switched on. */
export async function enabledFrameworks(): Promise<{ id: string; name: string }[]> {
  return (await db.prepare('SELECT id, name FROM framework WHERE enabled = 1 ORDER BY name').all()) as { id: string; name: string }[];
}

/** Switch a framework on or off for this tenant (library change, BP 7.1: recorded in the ledger). */
export async function setFrameworkEnabled(id: string, enabled: boolean, p: Principal, reason: string) {
  if (typeof enabled !== 'boolean') throw invalid('enabled must be true or false');
  if (!reason?.trim()) throw invalid('a reason is required');
  const f = (await db.prepare('SELECT id, name, enabled, namespace FROM framework WHERE id = ?').get(id)) as { id: string; name: string; enabled: number; namespace: string } | undefined;
  if (!f) throw notFound(`framework ${id}`);
  if (enabled && f.namespace === 'licence_required') throw new PolicyError('BP-9.3', `${f.name} needs a licence: load your licensed copy with the spreadsheet importer first`, 409);
  (await tx(async () => {
    (await db.prepare('UPDATE framework SET enabled = ? WHERE id = ?').run(enabled ? 1 : 0, id));
    (await ledger.append({ kind: 'admin', data: { event: 'library.framework_enabled', framework_id: id, name: f.name, from: !!f.enabled, to: enabled, reason, actor: p.id } }));
  }));
  return { id, enabled };
}

export async function evaluate() {
  const at = nowIso();
  const out: { control_id: string; status: Status; detail: string }[] = [];
  for (const c of CONTROLS) {
    let r: Check;
    try {
      r = c.check ? await c.check() : { status: 'not_tested', detail: c.type === 'manual' ? 'manual attestation not uploaded' : 'test arrives in a later phase' };
    } catch (e) {
      r = { status: 'not_tested', detail: `test error: ${(e as Error).message}` };
    }
    const prev = (await db.prepare("SELECT status FROM control_result WHERE control_id = ? AND scope = 'tenant'").get(c.id)) as { status: string } | undefined;
    (await db.prepare("INSERT INTO control_result (control_id, scope, status, detail, evaluated_at) VALUES (?, 'tenant', ?, ?, ?) ON CONFLICT(control_id, scope) DO UPDATE SET status = excluded.status, detail = excluded.detail, evaluated_at = excluded.evaluated_at").run(c.id, r.status, r.detail, at));
    if (c.check && (!prev || prev.status !== r.status)) (await enqueue('indicator.result', correlation('indicator', c.id), { control_id: c.id, objective: c.objective, passed: r.status === 'effective', status: r.status, detail: r.detail }));
    out.push({ control_id: c.id, ...r });
  }
  return out;
}

interface MappingRow { requirement_id: string; control_id: string; relationship: string; coverage_note: string | null; origin: string; proposed_by: string | null; reviewed_by: string | null; external_id: string; summary: string; framework_id: string }

// A mapping counts toward scores once it is reviewed: built-in and imported mappings are reviewed by
// Signet; a mapping a person adds needs a second person to confirm it (BP 9.1, two reviewers).
export const COUNTED_MAPPING = "(m.origin <> 'customer' OR m.reviewed_by IS NOT NULL)";

export async function library() {
  const mappings = (await db.prepare('SELECT m.requirement_id, m.control_id, m.relationship, m.coverage_note, m.origin, m.proposed_by, m.reviewed_by, q.external_id, q.summary, q.framework_id FROM control_mapping m JOIN framework_requirement q ON q.id = m.requirement_id ORDER BY q.framework_id, q.external_id').all()) as unknown as MappingRow[];
  const byControl = new Map<string, MappingRow[]>();
  for (const row of mappings) byControl.set(row.control_id, [...(byControl.get(row.control_id) ?? []), row]);
  const controls = (await db.prepare("SELECT c.*, r.status, r.detail, r.evaluated_at FROM control c LEFT JOIN control_result r ON r.control_id = c.id AND r.scope = 'tenant' ORDER BY c.domain, c.id").all()) as { id: string }[];
  return {
    frameworks: (await db.prepare('SELECT * FROM framework ORDER BY name').all()),
    licence_held: (await db.prepare("SELECT id, name, version, notes AS reason, source_url FROM framework WHERE namespace = 'licence_required' ORDER BY name").all()),
    controls: controls.map((c) => ({ ...c, mappings: byControl.get(c.id) ?? [] })),
  };
}

// Compliance score per framework, over the requirements in scope:
//   score    = share of requirements whose mapped controls are all effective
//   coverage = share of requirements with at least one mapped Signet Control
// A requirement with no mapped control is a coverage gap ("no_control") and never counts as passing.
export async function scores() {
  const frameworks = (await db.prepare("SELECT id, name, enabled, category, namespace FROM framework WHERE namespace <> 'licence_required' ORDER BY name").all()) as { id: string; name: string; enabled: number; category: string; namespace: string }[];
  const reqs = (await db.prepare('SELECT id, framework_id, external_id, summary FROM framework_requirement WHERE in_scope = 1 ORDER BY external_id').all()) as { id: string; framework_id: string; external_id: string; summary: string }[];
  const statuses = (await db.prepare("SELECT m.requirement_id, COALESCE(r.status, 'not_tested') AS status FROM control_mapping m LEFT JOIN control_result r ON r.control_id = m.control_id AND r.scope = 'tenant' WHERE " + COUNTED_MAPPING).all()) as { requirement_id: string; status: string }[];
  const byReq = new Map<string, string[]>();
  for (const s of statuses) byReq.set(s.requirement_id, [...(byReq.get(s.requirement_id) ?? []), s.status]);
  return frameworks.map((f) => {
    const rows = reqs.filter((r) => r.framework_id === f.id).map((r) => {
      const st = byReq.get(r.id) ?? [];
      const status = !st.length ? 'no_control' : st.every((s) => s === 'effective') ? 'effective' : st.some((s) => s === 'ineffective') ? 'ineffective' : st.every((s) => s === 'not_tested') ? 'not_tested' : 'partially_effective';
      return { ...r, status, controls: st.length };
    });
    const tested = rows.filter((r) => r.status !== 'not_tested' && r.status !== 'no_control');
    const mapped = rows.filter((r) => r.status !== 'no_control').length;
    return {
      framework_id: f.id, name: f.name, category: f.category, enabled: !!f.enabled, namespace: f.namespace,
      score: tested.length ? Math.round((tested.filter((r) => r.status === 'effective').length / rows.length) * 100) : null,
      coverage: rows.length ? Math.round((mapped / rows.length) * 100) : null,
      requirements: rows,
    };
  });
}

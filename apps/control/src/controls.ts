import { combine, verifyChain } from '@signet/core';
import { db, nowIso, tx } from './db';
import * as ledger from './ledger';
import { correlation, enqueue } from './outbox';
import { tenant } from './tenant';

// Control library (BP 9) and continuous control testing (BP 9.5, E13). Signet Controls (SGC) are the
// hub; framework requirements map to them, so one test produces evidence for every framework mapped.
// Framework text that is copyrighted (ISO) ships as identifiers and Signet-written summaries only
// (BP 9.3). Results feed compliance scores and, through connectors, ServiceNow indicators.

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
  maps: string[]; // requirement ids (framework:external_id)
  check?: () => Check;
}

const one = <T>(sql: string, ...args: (string | number)[]) => db.prepare(sql).get(...args) as T;
const all = <T>(sql: string, ...args: (string | number)[]) => db.prepare(sql).all(...args) as T[];
const since = (ms: number) => new Date(Date.now() - ms).toISOString();
const DAY = 86_400_000;
const ratio = (bad: number, total: number, what: string): Check =>
  total === 0 ? { status: 'not_tested', detail: `no ${what} yet` } : bad === 0 ? { status: 'effective', detail: `0 of ${total} ${what} failed` } : { status: bad / total < 0.05 ? 'partially_effective' : 'ineffective', detail: `${bad} of ${total} ${what} failed` };

const FRAMEWORKS = [
  { id: 'nist-ai-rmf', name: 'NIST AI RMF 1.0', version: '1.0', licence: 'US government work, public domain' },
  { id: 'owasp-llm', name: 'OWASP Top 10 for LLM Applications', version: '2025', licence: 'CC BY-SA, with attribution' },
  { id: 'eu-ai-act', name: 'EU AI Act (Regulation (EU) 2024/1689)', version: '2024', licence: 'EU legal text, reuse with attribution' },
  { id: 'iso-42001', name: 'ISO/IEC 42001', version: '2023', licence: 'Copyrighted: identifiers and Signet summaries only' },
];

const REQUIREMENTS: [string, string, string][] = [
  ['nist-ai-rmf', 'GOVERN 1.1', 'Legal and regulatory requirements involving AI are understood and managed'],
  ['nist-ai-rmf', 'GOVERN 2.1', 'Roles, responsibilities and lines of communication for AI risk are documented'],
  ['nist-ai-rmf', 'MAP 1.1', 'Intended purpose and context of use are understood and documented'],
  ['nist-ai-rmf', 'MAP 4.1', 'Approaches for mapping AI technology and third-party risks are in place'],
  ['nist-ai-rmf', 'MEASURE 2.7', 'AI system security and resilience are evaluated and documented'],
  ['nist-ai-rmf', 'MEASURE 2.11', 'Fairness and bias are evaluated and results documented'],
  ['nist-ai-rmf', 'MANAGE 2.4', 'Mechanisms are in place to supersede, disengage or deactivate AI systems'],
  ['nist-ai-rmf', 'MANAGE 4.1', 'Post-deployment monitoring plans are implemented'],
  ['owasp-llm', 'LLM01', 'Prompt injection'],
  ['owasp-llm', 'LLM02', 'Sensitive information disclosure'],
  ['owasp-llm', 'LLM03', 'Supply chain'],
  ['owasp-llm', 'LLM06', 'Excessive agency'],
  ['owasp-llm', 'LLM10', 'Unbounded consumption'],
  ['eu-ai-act', 'Art. 9', 'Risk management system for high-risk AI'],
  ['eu-ai-act', 'Art. 12', 'Record-keeping: automatic logging of events'],
  ['eu-ai-act', 'Art. 13', 'Transparency and information to deployers'],
  ['eu-ai-act', 'Art. 14', 'Human oversight'],
  ['eu-ai-act', 'Art. 15', 'Accuracy, robustness and cybersecurity'],
  ['eu-ai-act', 'Art. 50', 'Transparency obligations: people told they interact with AI'],
  ['iso-42001', 'A.2.2', 'AI policy (Signet summary)'],
  ['iso-42001', 'A.3.2', 'AI roles and responsibilities (Signet summary)'],
  ['iso-42001', 'A.5.2', 'AI system impact assessment process (Signet summary)'],
  ['iso-42001', 'A.6.2.4', 'AI system verification and validation (Signet summary)'],
  ['iso-42001', 'A.6.2.6', 'AI system operation and monitoring (Signet summary)'],
  ['iso-42001', 'A.6.2.8', 'AI system recording of event logs (Signet summary)'],
  ['iso-42001', 'A.9.2', 'Processes for responsible use of AI systems (Signet summary)'],
];

const req = (fw: string, ext: string) => `${fw}:${ext}`;

const CONTROLS: ControlDef[] = [
  {
    id: 'SGC-GOV-001', domain: 'GOV', severity: 'high', type: 'automated', objective: 'Every agent has an active named owner and sponsor',
    test: '100% of non-retired agents have owner and sponsor', maps: [req('nist-ai-rmf', 'GOVERN 2.1'), req('iso-42001', 'A.3.2')],
    check: () => { const r = one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN owner = '' OR sponsor = '' THEN 1 ELSE 0 END) bad FROM agent WHERE status != 'retired'"); return ratio(r.bad ?? 0, r.n, 'agents'); },
  },
  { id: 'SGC-GOV-002', domain: 'GOV', severity: 'medium', type: 'manual', objective: 'AI policy approved by the board and reviewed yearly', test: 'Uploaded policy with approval date under 12 months', maps: [req('iso-42001', 'A.2.2'), req('nist-ai-rmf', 'GOVERN 1.1')] },
  {
    id: 'SGC-INV-001', domain: 'INV', severity: 'critical', type: 'automated', objective: 'Every agent with traffic has an active certificate',
    test: '100% of agents with traffic in 24 h have an active seal', maps: [req('nist-ai-rmf', 'MAP 1.1'), req('eu-ai-act', 'Art. 12'), req('iso-42001', 'A.6.2.6')],
    check: () => { const r = all<{ agent_id: string; ok: number }>(`SELECT DISTINCT l.agent_id, (SELECT COUNT(*) FROM certificate c WHERE c.agent_id = l.agent_id AND c.status = 'active') ok FROM ledger_record l WHERE l.kind = 'transaction' AND l.ts >= ? AND l.agent_id IS NOT NULL AND json_extract(l.data, '$.outcome') = 'success'`, since(DAY)); return ratio(r.filter((x) => !x.ok).length, r.length, 'agents with traffic'); },
  },
  {
    id: 'SGC-INV-002', domain: 'INV', severity: 'medium', type: 'automated', objective: 'Shadow AI discovery runs weekly',
    test: 'A discovery scan in the last 7 days; open findings under 14 days old', maps: [req('nist-ai-rmf', 'MAP 4.1')],
    check: () => {
      const scans = one<{ n: number }>("SELECT COUNT(*) n FROM ledger_record WHERE kind = 'admin' AND json_extract(data, '$.event') = 'discovery.scan_ingested' AND ts >= ?", since(7 * DAY)).n;
      const stale = one<{ n: number }>("SELECT COUNT(*) n FROM discovered_asset WHERE status = 'open' AND first_seen < ?", since(14 * DAY)).n;
      return !scans ? { status: 'ineffective', detail: 'no discovery scan in the last 7 days' } : stale ? { status: 'partially_effective', detail: `${stale} open finding(s) older than 14 days` } : { status: 'effective', detail: `${scans} scan(s) this week` };
    },
  },
  {
    id: 'SGC-RISK-001', domain: 'RISK', severity: 'high', type: 'automated', objective: 'Risk tier set before testing',
    test: 'No test run exists without a confirmed classification', maps: [req('eu-ai-act', 'Art. 9'), req('nist-ai-rmf', 'MAP 1.1')],
    check: () => { const r = one<{ n: number; bad: number }>('SELECT COUNT(*) n, SUM(CASE WHEN c.confirmed_by IS NULL THEN 1 ELSE 0 END) bad FROM test_run t LEFT JOIN classification c ON c.lifecycle_id = t.lifecycle_id'); return ratio(r.bad ?? 0, r.n, 'test runs'); },
  },
  {
    id: 'SGC-RISK-002', domain: 'RISK', severity: 'high', type: 'automated', objective: 'Impact assessment done for T1/T2',
    test: 'Every sealed T1/T2 agent has a completed impact assessment', maps: [req('iso-42001', 'A.5.2'), req('eu-ai-act', 'Art. 9')],
    check: () => { const r = all<{ ok: number }>("SELECT (SELECT COUNT(*) FROM lifecycle l JOIN assessment a ON a.lifecycle_id = l.id WHERE l.agent_id = g.id AND a.type = 'impact' AND a.status = 'complete') ok FROM agent g WHERE g.tier IN ('T1','T2') AND g.status = 'sealed'"); return ratio(r.filter((x) => !x.ok).length, r.length, 'sealed T1/T2 agents'); },
  },
  {
    id: 'SGC-DATA-001', domain: 'DATA', severity: 'critical', type: 'automated', objective: 'DLP profile enforced on prompts and responses',
    test: '100% of transaction records carry DLP results', maps: [req('owasp-llm', 'LLM02'), req('eu-ai-act', 'Art. 15')],
    check: () => { const r = one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN json_extract(data, '$.dlp_actions') IS NULL THEN 1 ELSE 0 END) bad FROM ledger_record WHERE kind = 'transaction' AND json_extract(data, '$.action_type') IN ('llm_call','tool_call') AND ts >= ?", since(DAY)); return ratio(r.bad ?? 0, r.n, 'transactions (24 h)'); },
  },
  {
    id: 'SGC-DATA-002', domain: 'DATA', severity: 'high', type: 'automated', objective: 'Personal data reaches the cloud LLM only tokenised (RB-DATA-01)',
    test: '0 model calls carrying personal data without tokenisation', maps: [req('owasp-llm', 'LLM02')],
    check: () => { const r = all<{ d: string }>("SELECT json_extract(data, '$.dlp_actions') d FROM ledger_record WHERE kind = 'transaction' AND json_extract(data, '$.action_type') = 'llm_call' AND json_extract(data, '$.outcome') = 'success' AND ts >= ?", since(DAY)); const bad = r.filter((x) => /in:personal:(allow|log_only)/.test(x.d ?? '')).length; return ratio(bad, r.length, 'successful model calls (24 h)'); },
  },
  {
    id: 'SGC-IDN-001', domain: 'IDN', severity: 'critical', type: 'automated', objective: 'Workload identity per agent; no static keys in production',
    test: 'Every allowed call carries a workload-token instance', maps: [req('owasp-llm', 'LLM06'), req('iso-42001', 'A.6.2.6')],
    check: () => { const r = one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN json_extract(data, '$.instance_id') IS NULL THEN 1 ELSE 0 END) bad FROM ledger_record WHERE kind = 'transaction' AND json_extract(data, '$.outcome') = 'success' AND ts >= ?", since(DAY)); return ratio(r.bad ?? 0, r.n, 'successful calls (24 h)'); },
  },
  {
    id: 'SGC-IDN-002', domain: 'IDN', severity: 'high', type: 'automated', objective: 'Agents are keyless',
    test: '0 open unmanaged-key findings', maps: [req('owasp-llm', 'LLM06')],
    check: () => { const n = one<{ n: number }>("SELECT COUNT(*) n FROM discovered_asset WHERE type = 'unmanaged_key' AND status = 'open'").n; return n ? { status: 'partially_effective', detail: `${n} unmanaged key(s) still open in the Discovery Inbox` } : { status: 'effective', detail: 'every sealed agent authenticates with workload tokens; no unmanaged keys open' }; },
  },
  {
    id: 'SGC-TOOL-004', domain: 'TOOL', severity: 'critical', type: 'automated', objective: 'Agents invoke only tools listed in their manifest',
    test: '100% of out-of-manifest attempts denied', maps: [req('owasp-llm', 'LLM06'), req('iso-42001', 'A.6.2.6'), req('eu-ai-act', 'Art. 15')],
    check: () => { const r = one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN json_extract(data, '$.outcome') = 'success' THEN 1 ELSE 0 END) bad FROM ledger_record WHERE kind = 'transaction' AND json_extract(data, '$.error_code') = 'out_of_manifest'"); return r.n ? ratio(r.bad ?? 0, r.n, 'out-of-manifest attempts') : { status: 'effective', detail: 'no out-of-manifest attempts; default-deny enforced in code' }; },
  },
  {
    id: 'SGC-TOOL-005', domain: 'TOOL', severity: 'high', type: 'automated', objective: 'Every action has an impact label (RB-PRIV-01)',
    test: '0 active seals with unlabelled actions', maps: [req('owasp-llm', 'LLM06')],
    check: () => { const certs = all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'"); const bad = certs.filter((c) => (JSON.parse(c.body).tools ?? []).some((t: { actions: { impact?: string }[] }) => t.actions.some((a) => !a.impact))).length; return ratio(bad, certs.length, 'active seals'); },
  },
  {
    id: 'SGC-TOOL-006', domain: 'TOOL', severity: 'critical', type: 'automated', objective: 'Human approval applied to high-impact actions (RB-PRIV-03)',
    test: 'Every executed critical action on T1-T3 carries an approval', maps: [req('eu-ai-act', 'Art. 14'), req('owasp-llm', 'LLM06')],
    check: () => { const r = all<{ a: string | null }>("SELECT json_extract(data, '$.approval_id') a FROM ledger_record WHERE kind = 'transaction' AND json_extract(data, '$.impact') = 'critical' AND json_extract(data, '$.outcome') = 'success'"); return r.length ? ratio(r.filter((x) => !x.a).length, r.length, 'executed critical actions') : { status: 'effective', detail: 'no critical action executed without approval' }; },
  },
  {
    id: 'SGC-MODEL-001', domain: 'MODEL', severity: 'high', type: 'automated', objective: 'Only the approved cloud LLM is used (RB-INV-19)',
    test: '0 successful calls to models outside the catalogue', maps: [req('nist-ai-rmf', 'MAP 4.1'), req('owasp-llm', 'LLM03')],
    check: () => { const models = tenant.settings.catalogue.map((c) => c.model); const r = all<{ t: string }>("SELECT json_extract(data, '$.target') t FROM ledger_record WHERE kind = 'transaction' AND json_extract(data, '$.action_type') = 'llm_call' AND json_extract(data, '$.outcome') = 'success' AND ts >= ?", since(DAY)); return ratio(r.filter((x) => !models.includes(x.t)).length, r.length, 'model calls (24 h)'); },
  },
  {
    id: 'SGC-MODEL-002', domain: 'MODEL', severity: 'medium', type: 'automated', objective: 'Model versions pinned',
    test: 'Every seal names a specific model, not a bare wildcard', maps: [req('owasp-llm', 'LLM03')],
    check: () => { const certs = all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'"); const bad = certs.filter((c) => (JSON.parse(c.body).models ?? []).some((m: { model: string }) => m.model.trim() === '*')).length; return ratio(bad, certs.length, 'active seals'); },
  },
  { id: 'SGC-MODEL-003', domain: 'MODEL', severity: 'medium', type: 'semi_automated', objective: 'Provider terms verified yearly (RB-PROV-03)', test: 'Provider terms record verified in 12 months', maps: [req('nist-ai-rmf', 'MAP 4.1')] },
  {
    id: 'SGC-SEC-001', domain: 'SEC', severity: 'high', type: 'automated', objective: 'Pre-deployment security testing',
    test: 'Every active seal references a passing test report', maps: [req('eu-ai-act', 'Art. 15'), req('nist-ai-rmf', 'MEASURE 2.7'), req('iso-42001', 'A.6.2.4'), req('owasp-llm', 'LLM01')],
    check: () => { const certs = all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'"); const bad = certs.filter((c) => { const h = JSON.parse(c.body).evidence_refs?.test_report_sha256; return !h || !one<{ n: number }>("SELECT COUNT(*) n FROM test_run WHERE report_sha256 = ? AND status = 'passed'", h).n; }).length; return ratio(bad, certs.length, 'active seals'); },
  },
  { id: 'SGC-SEC-002', domain: 'SEC', severity: 'high', type: 'semi_automated', objective: 'Independent red team for T1', test: 'Every T1 seal references a red-team report', maps: [req('eu-ai-act', 'Art. 15')] },
  { id: 'SGC-SUPPLY-001', domain: 'SUPPLY', severity: 'medium', type: 'automated', objective: 'AIBOM maintained (Phase 3, E16)', test: 'Every agent version has an AIBOM under 30 days old', maps: [req('owasp-llm', 'LLM03')] },
  {
    id: 'SGC-MON-001', domain: 'MON', severity: 'critical', type: 'automated', objective: 'Every transaction logged and chained',
    test: 'Hash chain verifies end to end', maps: [req('eu-ai-act', 'Art. 12'), req('iso-42001', 'A.6.2.8'), req('nist-ai-rmf', 'MANAGE 4.1')],
    check: () => { const r = verifyChain(ledger.all()); return r.ok ? { status: 'effective', detail: `${r.count} records, chain intact` } : { status: 'ineffective', detail: `chain broken at seq ${r.error?.seq}: ${r.error?.reason}` }; },
  },
  { id: 'SGC-MON-004', domain: 'MON', severity: 'medium', type: 'automated', objective: 'Behaviour baseline monitored (DET-ANOM, later phase)', test: 'Every prod agent has a baseline', maps: [req('nist-ai-rmf', 'MANAGE 4.1')] },
  { id: 'SGC-MON-005', domain: 'MON', severity: 'medium', type: 'automated', objective: 'Groundedness sampled (Tier 2 evaluator, Phase 3)', test: 'Weekly 1% sample', maps: [req('nist-ai-rmf', 'MEASURE 2.7')] },
  { id: 'SGC-RESP-001', domain: 'RESP', severity: 'high', type: 'automated', objective: 'Kill capability tested (Kill Drills, Phase 3)', test: 'Drill within schedule', maps: [req('nist-ai-rmf', 'MANAGE 2.4')] },
  {
    id: 'SGC-RESP-002', domain: 'RESP', severity: 'high', type: 'automated', objective: 'Incident raised on level 4+ events',
    test: 'Every level 4-6 event has an incident queued or sent to a connector', maps: [req('nist-ai-rmf', 'MANAGE 2.4')],
    check: () => {
      const events = all<{ id: string }>("SELECT id FROM enforcement_event WHERE level IN ('quarantined','killed') AND published_at >= ?", since(30 * DAY));
      const connectors = one<{ n: number }>("SELECT COUNT(*) n FROM connector WHERE status = 'active'").n;
      if (!connectors) return { status: events.length ? 'partially_effective' : 'not_tested', detail: `${events.length} level 4+ event(s); no incident connector configured` };
      const bad = events.filter((e) => !one<{ n: number }>("SELECT COUNT(*) n FROM connector_outbox WHERE event = 'incident.create' AND object_key = ?", correlation('incident', e.id)).n).length;
      return ratio(bad, events.length, 'level 4+ events');
    },
  },
  {
    id: 'SGC-HUMAN-001', domain: 'HUMAN', severity: 'high', type: 'automated', objective: 'Oversight level declared',
    test: 'Every active seal has an autonomy level', maps: [req('eu-ai-act', 'Art. 14'), req('iso-42001', 'A.9.2')],
    check: () => { const certs = all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'"); return ratio(certs.filter((c) => !JSON.parse(c.body).autonomy_level).length, certs.length, 'active seals'); },
  },
  {
    id: 'SGC-HUMAN-003', domain: 'HUMAN', severity: 'high', type: 'automated', objective: 'Runtime approvals decided by people within SLA',
    test: 'Runtime approvals decided before timeout in the last 7 days', maps: [req('eu-ai-act', 'Art. 14')],
    check: () => { const r = one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) bad FROM approval_request WHERE type = 'runtime_hitl' AND created_at >= ?", since(7 * DAY)); return ratio(r.bad ?? 0, r.n, 'runtime approvals (7 d)'); },
  },
  { id: 'SGC-HUMAN-002', domain: 'HUMAN', severity: 'medium', type: 'manual', objective: 'Reviewers trained', test: 'Approvers trained in 12 months', maps: [req('eu-ai-act', 'Art. 14')] },
  {
    id: 'SGC-TRANS-001', domain: 'TRANS', severity: 'medium', type: 'automated', objective: 'Users told they are talking to AI (EU AI Act Art. 50)',
    test: 'Every user-facing agent seal has the disclosure flag', maps: [req('eu-ai-act', 'Art. 50'), req('eu-ai-act', 'Art. 13')],
    check: () => { const certs = all<{ body: string; data: string | null }>("SELECT c.body, (SELECT data FROM lifecycle l WHERE l.agent_id = c.agent_id ORDER BY started_at DESC LIMIT 1) data FROM certificate c WHERE c.status = 'active'"); const facing = certs.filter((c) => c.data && (JSON.parse(c.data).intake?.users_affected ?? []).some((u: string) => u !== 'internal')); return ratio(facing.filter((c) => !JSON.parse(c.body).ai_disclosure).length, facing.length, 'user-facing seals'); },
  },
  {
    id: 'SGC-FAIR-001', domain: 'FAIR', severity: 'high', type: 'automated', objective: 'Bias testing for agents affecting individuals',
    test: 'Every such agent has a passing bias suite (0.8-1.25)', maps: [req('nist-ai-rmf', 'MEASURE 2.11'), req('eu-ai-act', 'Art. 9')],
    check: () => {
      const lcs = all<{ id: string }>("SELECT id FROM lifecycle WHERE status IN ('complete','in_progress') AND json_extract(data, '$.intake.decisions_about_individuals') = 1");
      const bad = lcs.filter((l) => !all<{ suites: string }>("SELECT suites FROM test_run WHERE lifecycle_id = ? AND status = 'passed'", l.id).some((t) => (JSON.parse(t.suites).suites ?? []).some((s: { suite: string; passed: boolean }) => s.suite === 'bias' && s.passed))).length;
      return ratio(bad, lcs.length, 'agents affecting individuals');
    },
  },
  {
    id: 'SGC-LIFE-001', domain: 'LIFE', severity: 'high', type: 'automated', objective: 'No agent runs on an expired certificate',
    test: '0 successful calls under an expired seal', maps: [req('iso-42001', 'A.6.2.6')],
    check: () => { const r = one<{ n: number }>("SELECT COUNT(*) n FROM certificate WHERE status = 'active' AND valid_to < ?", nowIso()).n; return r ? { status: 'ineffective', detail: `${r} active seal(s) past expiry` } : { status: 'effective', detail: 'no active seal past expiry' }; },
  },
  {
    id: 'SGC-LIFE-002', domain: 'LIFE', severity: 'critical', type: 'automated', objective: 'Every seal passed the full lifecycle (BP 6)',
    test: 'Every active seal was issued from a lifecycle with an approval pack', maps: [req('eu-ai-act', 'Art. 9'), req('iso-42001', 'A.6.2.4')],
    check: () => { const certs = all<{ body: string }>("SELECT body FROM certificate WHERE status = 'active'"); return ratio(certs.filter((c) => !JSON.parse(c.body).evidence_refs?.approval_pack_sha256).length, certs.length, 'active seals'); },
  },
  {
    id: 'SGC-LIFE-004', domain: 'LIFE', severity: 'medium', type: 'automated', objective: 'Retired agents fully decommissioned',
    test: 'Every retired agent has a decommission pack', maps: [req('nist-ai-rmf', 'MANAGE 2.4')],
    check: () => { const r = all<{ ok: number }>("SELECT (SELECT COUNT(*) FROM attestation t WHERE t.agent_id = a.id AND t.type = 'decommission') ok FROM agent a WHERE a.status = 'retired'"); return r.length ? ratio(r.filter((x) => !x.ok).length, r.length, 'retired agents') : { status: 'not_tested', detail: 'no retired agents yet' }; },
  },
  { id: 'SGC-VALUE-001', domain: 'VALUE', severity: 'low', type: 'manual', objective: 'Business case recorded', test: 'Every T1/T2 agent has a value case', maps: [req('nist-ai-rmf', 'MAP 1.1')] },
  {
    id: 'SGC-VALUE-002', domain: 'VALUE', severity: 'medium', type: 'automated', objective: 'Spend within limits',
    test: 'No agent over its daily cost limit', maps: [req('owasp-llm', 'LLM10')],
    check: () => { const r = one<{ n: number }>("SELECT COUNT(*) n FROM ledger_record WHERE kind = 'transaction' AND json_extract(data, '$.error_code') = 'cost_budget_exhausted' AND ts >= ?", since(DAY)).n; return r ? { status: 'partially_effective', detail: `${r} request(s) hit a daily cost limit (limit enforced)` } : { status: 'effective', detail: 'no agent reached its daily cost limit' }; },
  },
  {
    id: 'SGC-SELF-002', domain: 'SELF', severity: 'critical', type: 'automated', objective: 'No detector output can cause an allow (DA 7)',
    test: 'Decision combiner never turns deny or hold into allow for any band', maps: [req('nist-ai-rmf', 'MANAGE 4.1'), req('iso-42001', 'A.6.2.4')],
    check: () => {
      const bands = ['low', 'elevated', 'high'] as const;
      const bad = (['deny', 'require_approval'] as const).flatMap((rule) => bands.flatMap((band) => (['T1', 'T2', 'T3', 'T4'] as const).filter((t) => ['allow', 'allow_with_obligations'].includes(combine(rule, [{ id: 'D', version: 'x', status: 'ok', band }], t).outcome))));
      return bad.length ? { status: 'ineffective', detail: `${bad.length} combination(s) allowed` } : { status: 'effective', detail: '24 combinations checked; detectors only add caution' };
    },
  },
  {
    id: 'SGC-SELF-003', domain: 'SELF', severity: 'critical', type: 'automated', objective: 'Automatic kills always reference a rule (DA 7)',
    test: 'Every automatic kill in the ledger cites a rule ID', maps: [req('eu-ai-act', 'Art. 14')],
    check: () => { const r = one<{ n: number; bad: number }>("SELECT COUNT(*) n, SUM(CASE WHEN rule_id IS NULL THEN 1 ELSE 0 END) bad FROM enforcement_event WHERE level = 'killed' AND actor LIKE 'gateway:%'"); return r.n ? ratio(r.bad ?? 0, r.n, 'automatic kills') : { status: 'effective', detail: 'no automatic kill without a rule (enforced in code, RB-INV-05)' }; },
  },
  {
    id: 'SGC-SELF-005', domain: 'SELF', severity: 'high', type: 'automated', objective: 'Detectors run in shadow 14 days before promotion (RB-MOD-03)',
    test: 'No active detector promoted with the shadow period skipped', maps: [req('nist-ai-rmf', 'MEASURE 2.7')],
    check: () => { const r = one<{ n: number }>("SELECT COUNT(*) n FROM ledger_record WHERE kind = 'admin' AND json_extract(data, '$.event') = 'detector.mode_changed' AND json_extract(data, '$.to') = 'active' AND json_extract(data, '$.shadow_period_skipped') = 1").n; const active = one<{ n: number }>("SELECT COUNT(*) n FROM detector WHERE mode = 'active'").n; return !active ? { status: 'not_tested', detail: 'no detector active' } : r ? { status: 'partially_effective', detail: `${r} promotion(s) skipped the 14-day shadow (dev override, recorded)` } : { status: 'effective', detail: 'every active detector completed its shadow period' }; },
  },
];

export function seed() {
  tx(() => {
    for (const f of FRAMEWORKS) db.prepare('INSERT OR IGNORE INTO framework (id, name, version, licence, namespace) VALUES (?, ?, ?, ?, ?)').run(f.id, f.name, f.version, f.licence, 'signet');
    for (const [fw, ext, summary] of REQUIREMENTS) db.prepare('INSERT OR IGNORE INTO framework_requirement (id, framework_id, external_id, summary) VALUES (?, ?, ?, ?)').run(req(fw, ext), fw, ext, summary);
    for (const c of CONTROLS) {
      db.prepare('INSERT OR REPLACE INTO control (id, domain, objective, test, test_type, applies_to, namespace, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(c.id, c.domain, c.objective, c.test, c.type, 'tenant', 'signet', c.severity);
      for (const m of c.maps) db.prepare('INSERT OR IGNORE INTO control_mapping (requirement_id, control_id, relationship) VALUES (?, ?, ?)').run(m, c.id, 'intersects');
    }
  });
}

export function evaluate() {
  const at = nowIso();
  const out: { control_id: string; status: Status; detail: string }[] = [];
  for (const c of CONTROLS) {
    let r: Check;
    try {
      r = c.check ? c.check() : { status: 'not_tested', detail: c.type === 'manual' ? 'manual attestation not uploaded' : 'test arrives in a later phase' };
    } catch (e) {
      r = { status: 'not_tested', detail: `test error: ${(e as Error).message}` };
    }
    const prev = db.prepare("SELECT status FROM control_result WHERE control_id = ? AND scope = 'tenant'").get(c.id) as { status: string } | undefined;
    db.prepare("INSERT INTO control_result (control_id, scope, status, detail, evaluated_at) VALUES (?, 'tenant', ?, ?, ?) ON CONFLICT(control_id, scope) DO UPDATE SET status = excluded.status, detail = excluded.detail, evaluated_at = excluded.evaluated_at").run(c.id, r.status, r.detail, at);
    if (c.check && (!prev || prev.status !== r.status)) enqueue('indicator.result', correlation('indicator', c.id), { control_id: c.id, objective: c.objective, passed: r.status === 'effective', status: r.status, detail: r.detail });
    out.push({ control_id: c.id, ...r });
  }
  return out;
}

export function library() {
  return {
    frameworks: db.prepare('SELECT * FROM framework ORDER BY name').all(),
    controls: (db.prepare("SELECT c.*, r.status, r.detail, r.evaluated_at FROM control c LEFT JOIN control_result r ON r.control_id = c.id AND r.scope = 'tenant' ORDER BY c.domain, c.id").all() as { id: string }[]).map((c) => ({
      ...c,
      mappings: db.prepare('SELECT m.requirement_id, m.relationship, q.external_id, q.summary, q.framework_id FROM control_mapping m JOIN framework_requirement q ON q.id = m.requirement_id WHERE m.control_id = ?').all(c.id),
    })),
  };
}

// Compliance score per framework: mapped requirements whose controls are all effective.
export function scores() {
  return (db.prepare('SELECT * FROM framework ORDER BY name').all() as { id: string; name: string }[]).map((f) => {
    const reqs = db.prepare('SELECT id, external_id, summary FROM framework_requirement WHERE framework_id = ?').all(f.id) as { id: string; external_id: string; summary: string }[];
    const rows = reqs.map((r) => {
      const st = (db.prepare("SELECT r.status FROM control_mapping m LEFT JOIN control_result r ON r.control_id = m.control_id AND r.scope = 'tenant' WHERE m.requirement_id = ?").all(r.id) as { status: string | null }[]).map((x) => x.status ?? 'not_tested');
      const status = !st.length ? 'not_tested' : st.every((s) => s === 'effective') ? 'effective' : st.some((s) => s === 'ineffective') ? 'ineffective' : st.every((s) => s === 'not_tested') ? 'not_tested' : 'partially_effective';
      return { ...r, status, controls: st.length };
    });
    const tested = rows.filter((r) => r.status !== 'not_tested');
    return { framework_id: f.id, name: f.name, score: tested.length ? Math.round((tested.filter((r) => r.status === 'effective').length / rows.length) * 100) : null, requirements: rows };
  });
}

import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

// The lifecycle and approvals engine against a throwaway database (BP 6, 7).
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-wf-'));
process.env.SIGNET_TOOL_PRIVATE_DESTINATIONS = 'allow'; // the test tool address is on localhost
const { permissionsFor } = await import('../src/rbac');
const registry = await import('../src/registry');
const workflow = await import('../src/workflow');
const approvals = await import('../src/approvals');
const { putSecret } = await import('../src/secrets');
const { registerTool } = await import('../src/tools');
type Role = Parameters<typeof permissionsFor>[0][number];

const person = (id: string, roles: Role[], authAgeS = 10) => ({
  id, name: id, kind: 'human' as const, roles, permissions: permissionsFor(roles), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) - authAgeS,
});
const owner = person('priya@x.example', ['agent_owner']);
const builder = person('ananya@x.example', ['risk_officer']); // Risk, but on the build team
const security = person('jonas@x.example', ['security_officer']);
const risk = person('risk2@x.example', ['risk_officer']);

const manifest = {
  models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }],
  tools: [{ server: 'mcp://orders', data_scopes: ['personal'], actions: [{ name: 'issue_refund', impact: 'privileged', value_arg: 'amount', value_threshold_usd: 100, constraints: { amount: { min: 1, max: 5000 } } }] }],
  data_classes: { prompt: ['personal'], forbidden: ['payment_card'] },
  hitl: [{ action: 'mcp://orders.issue_refund', arg: 'amount', gt: 500, approver_group: 'ops-supervisors' }],
  limits: { rpm: 60, tokens_per_day: 100_000, usd_per_day: 10, tool_calls_per_session: 20 },
  environments: ['dev'],
} as never;

const admin = person('arjun@x.example', ['platform_admin']);
putSecret({ name: 'orders-key', kind: 'tool', value: 'test-tool-key-123' }, admin);
await registerTool({ alias: 'orders', kind: 'mcp', url: 'http://localhost:1/mcp', secret: 'orders-key' } as never, admin);

let n = 0;
function propose(intake: Record<string, unknown>) {
  const agent = registry.registerAgent({ handle: `wf-agent-${++n}`, name: 'WF agent', purpose: 'Answers order questions and refunds', sponsor: 'ravi@x.example', autonomy_level: 'L2', team: [{ user: builder.id, role: 'builder' }] }, owner);
  const lc = workflow.start(agent, intake as never, owner);
  workflow.setManifest(lc.id, manifest, owner);
  workflow.submitPropose(lc.id, owner);
  return { agent, lc: workflow.get(lc.id) };
}

test('classification: weighted score sets the tier; decisions about individuals floor at T2 (RB-INV-14)', () => {
  assert.equal(workflow.scoreToTier(4), 'T1');
  assert.equal(workflow.scoreToTier(3.65), 'T2');
  assert.equal(workflow.scoreToTier(2.9), 'T3');
  assert.equal(workflow.scoreToTier(1.9), 'T4');
  const cs = propose({ users_affected: ['customers'], data_touched: ['personal'], reversibility: 'partly', planned_tools: ['issue_refund (privileged)'] });
  assert.equal(workflow.classificationOf(cs.lc.id)!.tier, 'T2');
  const internal = propose({ users_affected: ['internal'], data_touched: [], reversibility: 'yes', planned_tools: ['lookup (read)'], decisions_about_individuals: true, individual_domains: ['credit'] });
  const cls = workflow.classificationOf(internal.lc.id)!;
  assert.equal(cls.tier, 'T2');
  assert.equal(cls.regulatory_category, 'eu_ai_act:high_risk');
});

test('T2 lifecycle: assessments gate, Risk confirms, matrix needs Owner + Security + Risk with SoD and step-up', () => {
  const { agent, lc } = propose({ users_affected: ['customers'], data_touched: ['personal'], reversibility: 'partly', planned_tools: ['issue_refund (privileged)'] });
  assert.throws(() => workflow.classify(lc.id, builder, { confirm: true }), (e: { rule?: string }) => e.rule === 'RB-INV-09'); // the build team does not confirm its own tier
  workflow.classify(lc.id, risk, { confirm: true });
  assert.throws(() => workflow.submitAssess(lc.id, owner), /exit gate/);
  for (const a of workflow.assessments(lc.id) as unknown as { type: string; content: { answers?: Record<string, unknown> } }[]) {
    const content = a.content;
    const filled = a.type === 'questionnaire' ? { ...content, answers: Object.fromEntries(Object.keys(content.answers ?? {}).map((k) => [k, { answer: 'yes' }])) } : { summary: 'done' };
    workflow.saveAssessment(lc.id, a.type, filled, true, owner);
  }
  workflow.submitAssess(lc.id, owner);
  const failed = workflow.runTests(lc.id, owner, { functional_score: 70 });
  assert.equal(failed.passed, false); // functional below 85 for T2 sends it back to Assess
  const gaps = workflow.gapsOf(lc.id) as { id: string; status: string }[];
  assert.ok(gaps.some((g) => g.status === 'open'));
  assert.throws(() => workflow.submitAssess(lc.id, owner), /high_gaps_mitigated_or_accepted/);
  for (const g of gaps.filter((x) => x.status === 'open')) workflow.updateGap(g.id, { status: 'mitigated', mitigation: 'retrained on refund FAQ' }, owner);
  workflow.submitAssess(lc.id, owner);
  const passed = workflow.runTests(lc.id, owner, { functional_score: 92 });
  assert.equal(passed.passed, true);

  const req = approvals.get(workflow.get(lc.id).data.approval_id!);
  assert.deepEqual(req.slots.map((s) => s.slot), ['owner', 'security', 'risk']);
  assert.throws(() => approvals.decide(req.id, owner, { decision: 'approve', slot: 'security' }), /no open approval slot/);
  assert.throws(() => approvals.decide(req.id, builder, { decision: 'approve' }), (e: { rule?: string }) => e.rule === 'RB-INV-09');
  assert.throws(() => approvals.decide(req.id, person('jonas@x.example', ['security_officer'], 900), { decision: 'approve' }), /fresh sign-in/);
  assert.throws(() => approvals.decide(req.id, security, { decision: 'approve_session' }), /runtime approvals only/);
  approvals.decide(req.id, owner, { decision: 'approve' });
  approvals.decide(req.id, security, { decision: 'approve' });
  assert.equal(approvals.get(req.id).status, 'pending');
  approvals.decide(req.id, risk, { decision: 'approve' });
  assert.equal(approvals.get(req.id).status, 'approved');

  const v = workflow.view(lc.id);
  assert.equal(v.lifecycle.stage, 'deploy');
  assert.equal(v.deploy!.mode, 'shadow');
  assert.equal(v.deploy!.canary, true);
  assert.ok(registry.activeCertificate(agent.id));
  assert.throws(() => workflow.advanceDeploy(lc.id, owner, { to: 'enforce' }), /canary before full enforcement/);
  assert.throws(() => workflow.advanceDeploy(lc.id, owner, { to: 'canary' }), /of 7 days/);
});

test('a rejection needs a reason; a send-back returns the lifecycle to Assess', () => {
  const { lc } = propose({ users_affected: ['customers'], data_touched: ['personal'], reversibility: 'partly', planned_tools: ['issue_refund (privileged)'] });
  workflow.classify(lc.id, risk, { confirm: true });
  for (const a of workflow.assessments(lc.id) as unknown as { type: string; content: { answers?: Record<string, unknown> } }[]) {
    const content = a.content;
    workflow.saveAssessment(lc.id, a.type, a.type === 'questionnaire' ? { ...content, answers: Object.fromEntries(Object.keys(content.answers ?? {}).map((k) => [k, { answer: 'yes' }])) } : { summary: 'done' }, true, owner);
  }
  workflow.submitAssess(lc.id, owner);
  workflow.runTests(lc.id, owner, { functional_score: 92 });
  const id = workflow.get(lc.id).data.approval_id!;
  assert.throws(() => approvals.decide(id, security, { decision: 'reject' }), /reason is required/);
  approvals.decide(id, security, { decision: 'send_back', comment: 'threat model misses tool abuse' });
  assert.equal(approvals.get(id).status, 'sent_back');
  assert.equal(workflow.get(lc.id).stage, 'assess');
});

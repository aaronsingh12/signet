import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { Principal } from '../src/rbac';

const directory = mkdtempSync(join(tmpdir(), 'signet-analytics-'));
process.env.SIGNET_DATA_DIR = directory;
process.env.SIGNET_DB = join(directory, 'analytics.db');

test('dashboard aggregates real ledger records per agent without counting detector scores or mixing outcomes', async () => {
  const { registerAgent, issueSeal } = await import('../src/registry');
  const { permissionsFor } = await import('../src/rbac');
  const { append } = await import('../src/ledger');
  const { agentAnalytics } = await import('../src/agent-analytics');
  const { parseAgentAnalytics } = await import('@signet/core');
  const owner: Principal = { id: 'owner@example.test', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const security: Principal = { ...owner, id: 'security@example.test', roles: ['security_officer'], permissions: permissionsFor(['security_officer']) };
  const agents = ['appointment', 'records', 'lab', 'care'].map((key) => registerAgent({ handle: `hospital-${key}`, name: key, purpose: 'Dashboard integration', sponsor: owner.id, tier: 'T1', autonomy_level: 'L0' }, owner));
  issueSeal(agents[0]!.id, { models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }], tools: [], limits: { rpm: 30, tokens_per_day: 1000, usd_per_day: 5 }, environments: ['dev'] }, security);
  const decisions = [
    { policy_decision: 'allow_with_obligations', outcome: 'success' },
    { policy_decision: 'deny', outcome: 'blocked' },
    { policy_decision: 'require_approval', outcome: 'blocked' },
    { policy_decision: 'allow', outcome: 'upstream_error' },
  ];
  for (const decision of decisions) append({ kind: 'transaction', agent_id: agents[0]!.id, data: { action_type: 'llm_call', tokens_in: 10, tokens_out: 5, cost_usd: 0.01, latency_ms_gateway: 10, latency_ms_upstream: 90, ...decision } });
  append({ kind: 'transaction', agent_id: agents[0]!.id, data: { action_type: 'detector_score', policy_decision: 'taint' } });
  append({ kind: 'transaction', agent_id: agents[1]!.id, data: { action_type: 'tool_call', policy_decision: 'allow', outcome: 'success' } });
  const snapshot = parseAgentAnalytics(agentAnalytics());
  assert.equal(snapshot.agents.length, 4);
  const appointment = snapshot.agents.find((agent) => agent.id === agents[0]!.id)!;
  assert.equal(appointment.requests, 4);
  assert.equal(appointment.allowed, 1);
  assert.equal(appointment.blocked, 1);
  assert.equal(appointment.review, 1);
  assert.equal(appointment.failed, 1);
  assert.equal(appointment.tokens, 60);
  assert.equal(appointment.cost_usd, 0.04);
  assert.equal(appointment.avg_latency_ms, 100);
  assert.equal(appointment.daily_budget_usd, 5);
  assert.equal(appointment.activity.length, 25);
  assert.equal(appointment.activity.reduce((sum, bucket) => sum + bucket.requests, 0), 4);
  const records = snapshot.agents.find((agent) => agent.id === agents[1]!.id)!;
  assert.equal(records.requests, 1);
  assert.equal(records.daily_budget_usd, null);
  const lab = snapshot.agents.find((agent) => agent.id === agents[2]!.id)!;
  assert.equal(lab.requests, 0);
  assert.equal(lab.last_activity, null);
  assert(lab.activity.every((bucket) => bucket.requests === 0));
  assert.throws(() => parseAgentAnalytics({ ...snapshot, agents: [{ ...appointment, requests: -1 }] }), /nonnegative/);
});

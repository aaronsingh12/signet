import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';

const directory = mkdtempSync(join(tmpdir(), 'signet-analytics-'));
process.env.SIGNET_DATA_DIR = directory;
process.env.SIGNET_DB_SCHEMA = 'test_'+Date.now().toString(36)+'_'+Math.random().toString(36).slice(2, 10);

after(dropTestDatabase);

test('dashboard aggregates real ledger records per agent without counting detector scores or mixing outcomes', async () => {
  const { registerAgent, issueSeal } = await import('../src/registry');
  const { permissionsFor } = await import('../src/rbac');
  const { append } = await import('../src/ledger');
  const { agentAnalytics } = await import('../src/agent-analytics');
  const { parseAgentAnalytics } = await import('@signet/core');
  const owner: Principal = { id: 'owner@example.test', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const security: Principal = { ...owner, id: 'security@example.test', roles: ['security_officer'], permissions: permissionsFor(['security_officer']) };
  const agents = (await Promise.all(['appointment', 'records', 'lab', 'care'].map(async (key) => (await registerAgent({ handle: `hospital-${key}`, name: key, purpose: 'Dashboard integration', sponsor: owner.id, tier: 'T1', autonomy_level: 'L0' }, owner)))));
  (await issueSeal(agents[0]!.id, { models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }], tools: [], limits: { rpm: 30, tokens_per_day: 1000, usd_per_day: 5 }, environments: ['dev'] }, security));
  const decisions = [
    { policy_decision: 'allow_with_obligations', outcome: 'success' },
    { policy_decision: 'deny', outcome: 'blocked' },
    { policy_decision: 'require_approval', outcome: 'blocked' },
    { policy_decision: 'allow', outcome: 'upstream_error' },
  ];
  for (const decision of decisions) (await append({ kind: 'transaction', agent_id: agents[0]!.id, data: { action_type: 'llm_call', tokens_in: 10, tokens_out: 5, cost_usd: 0.01, latency_ms_gateway: 10, latency_ms_upstream: 90, ...decision } }));
  (await append({ kind: 'transaction', agent_id: agents[0]!.id, data: { action_type: 'detector_score', policy_decision: 'taint' } }));
  (await append({ kind: 'transaction', agent_id: agents[1]!.id, data: { action_type: 'tool_call', policy_decision: 'allow', outcome: 'success' } }));
  const snapshot = parseAgentAnalytics((await agentAnalytics()));
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
  const { create } = await import('../src/external-connections');
  const { db } = await import('../src/db');
  const admin: Principal = { ...owner, roles: ['platform_admin'], permissions: permissionsFor(['platform_admin']) };
  const connection = await create(null, { credential: '', config: { name: 'Analytics REST provider', method: 'rest', auth: 'none', base_url: 'https://provider.example', header: '', client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 1000, sync_interval_seconds: 60, remote_management: false, endpoints: { test: { method: 'GET', path: '/status' } }, agents_mapping: null, executions_mapping: null, tracking_pointer: '', private_connector: null, execution_pagination: null } }, admin);
  const eventTime = new Date().toISOString();
  await db.prepare('INSERT INTO external_agent_mapping (connection_id, external_id, agent_id, last_seen_at) VALUES (?, ?, ?, ?)').run(connection.id, 'external-lab', agents[2]!.id, eventTime);
  for (const [externalId, metadata] of [
    ['success', { status: 'success', timestamp: eventTime, duration_ms: 6500 }],
    ['failure', { status: 'failed', timestamp: eventTime, duration_ms: null }],
    ['running', { status: 'running', timestamp: eventTime, duration_ms: null }],
    ['old', { status: 'success', timestamp: new Date(Date.now() - 90_000_000).toISOString() }],
    ['undated', { status: 'success', timestamp: null }],
  ] as const) {
    await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(connection_id, external_agent_id, kind, external_id) DO UPDATE SET observed_at = excluded.observed_at').run(connection.id, 'external-lab', externalId, 'execution', JSON.stringify(metadata), eventTime);
  }
  await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?)').run(connection.id, 'external-lab', 'tracking', 'tracking', JSON.stringify({ status: 'active', timestamp: eventTime }), eventTime);
  const synced = parseAgentAnalytics(await agentAnalytics());
  const external = synced.agents.find((agent) => agent.id === agents[2]!.id)!;
  assert.equal(external.requests, 0);
  assert.equal(external.cost_usd, 0);
  assert.equal(external.provider.executions, 3);
  assert.equal(external.provider.succeeded, 1);
  assert.equal(external.provider.failed, 1);
  assert.equal(external.provider.other, 1);
  assert.equal(external.provider.avg_duration_ms, 6500);
  assert.equal(external.provider.activity.reduce((sum, bucket) => sum + bucket.executions, 0), 3);
  assert.equal(external.provider.recent.length, 3);
  assert.equal(synced.agents.find((agent) => agent.id === agents[0]!.id)!.requests, 4);
  assert.equal(synced.agents.find((agent) => agent.id === agents[1]!.id)!.provider.executions, 0);
});

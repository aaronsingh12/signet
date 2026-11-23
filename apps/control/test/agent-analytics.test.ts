import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';

const directory = mkdtempSync(join(tmpdir(), 'signet-analytics-'));
process.env.SIGNET_DATA_DIR = directory;
process.env.MONGODB_DATABASE = 'test_'+Date.now().toString(36)+'_'+Math.random().toString(36).slice(2, 10);

after(dropTestDatabase);

test('dashboard aggregates real ledger records per agent without counting detector scores or mixing outcomes', async () => {
  const { registerAgent, issueSeal } = await import('../src/registry');
  const { permissionsFor } = await import('../src/rbac');
  const { append } = await import('../src/ledger');
  const { agentAnalytics, allTimeAgentAnalytics, todayAgentAnalytics } = await import('../src/agent-analytics');
  const { parseAgentAnalytics } = await import('@signet/core');
  const owner: Principal = { id: 'owner@example.test', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const security: Principal = { ...owner, id: 'security@example.test', roles: ['security_officer'], permissions: permissionsFor(['security_officer']) };
  const agents = (await Promise.all(['appointment', 'records', 'lab', 'care'].map(async (key) => (await registerAgent({ handle: `hospital-${key}`, name: key, purpose: 'Dashboard integration', sponsor: owner.id, tier: 'T1', autonomy_level: 'L0' }, owner)))));
  (await issueSeal(agents[0]!.id, { models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }], tools: [], limits: { rpm: 30, tokens_per_day: 1000, usd_per_day: 5 }, environments: ['dev'] }, security));
  const decisions = [
    { policy_decision: 'allow_with_obligations', outcome: 'success' },
    { policy_decision: 'deny', outcome: 'blocked' },
    { policy_decision: 'require_approval', outcome: 'pending' },
    { policy_decision: 'allow', outcome: 'upstream_error' },
  ];
  // A call held for approval that nobody approved in time was refused: it is a block, not a pending review.
  (await append({ kind: 'transaction', agent_id: agents[3]!.id, data: { action_type: 'tool_call', policy_decision: 'require_approval', outcome: 'blocked', error_code: 'approval_timeout' } }));
  for (const decision of decisions) (await append({ kind: 'transaction', agent_id: agents[0]!.id, data: { action_type: 'llm_call', tokens_in: 10, tokens_out: 5, cost_usd: 0.01, latency_ms_gateway: 10, latency_ms_upstream: 90, ...decision } }));
  (await append({ kind: 'transaction', agent_id: agents[0]!.id, data: { action_type: 'detector_score', policy_decision: 'taint' } }));
  (await append({ kind: 'transaction', agent_id: agents[1]!.id, data: { action_type: 'tool_call', policy_decision: 'allow', outcome: 'success' } }));
  for (const review of [
    { guardrail_review: { decision: 'clear', status: 'complete' } },
    { guardrail_review: { decision: 'flagged', status: 'complete' }, outcome: 'blocked', error_code: 'blocked_by_signet', request_id: 'req_01M83BLOCKTEST000000000001' },
    { guardrail_review: { decision: 'flagged', status: 'unavailable' }, outcome: 'blocked', error_code: 'blocked_by_signet' },
    { error_code: 'invalid_guardian_content' },
  ]) await append({ kind: 'transaction', agent_id: agents[0]!.id, data: { action_type: 'guardrail_check', ...review } });
  const snapshot = parseAgentAnalytics((await agentAnalytics()));
  assert.equal(snapshot.agents.length, 4);
  const appointment = snapshot.agents.find((agent) => agent.id === agents[0]!.id)!;
  assert.equal(appointment.requests, 4);
  assert.equal(appointment.processing.requests, 8);
  assert.equal(appointment.processing.allowed, 2);
  assert.equal(appointment.processing.blocked, 3);
  assert.equal(appointment.processing.review, 1);
  assert.equal(appointment.processing.failed, 2);
  assert.equal(appointment.processing.activity.reduce((sum, bucket) => sum + bucket.blocked, 0), 3);
  assert.equal(appointment.guardian.reviews, 3);
  assert.equal(appointment.guardian.flagged, 2);
  assert.equal(appointment.guardian.unavailable, 1);
  assert.equal(appointment.guardian.failed, 1);
  assert(appointment.guardian.last_review_at);
  assert.equal(appointment.allowed, 1);
  assert.equal(appointment.blocked, 1);
  assert.equal(appointment.review, 1);
  assert.equal(appointment.failed, 1);
  const care = snapshot.agents.find((agent) => agent.id === agents[3]!.id)!;
  assert.deepEqual([care.requests, care.blocked, care.review], [1, 1, 0]);
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
  assert.deepEqual(lab.guardian, { reviews: 0, flagged: 0, unavailable: 0, failed: 0, last_review_at: null, native_blocked: 0, native_signet: 0 });
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
  const { hashRecord, newId } = await import('@signet/core');
  const { tenant } = await import('../src/tenant');
  const { tx } = await import('../src/db');
  const historicAt = new Date(Date.now() - 3 * 86400000).toISOString();
  for (const data of [
    { action_type: 'llm_call', policy_decision: 'allow', outcome: 'success', tokens_in: 7, tokens_out: 0, cost_usd: 0.02 },
    { action_type: 'guardrail_check', guardrail_review: { decision: 'flagged', status: 'complete' }, safety_usage: { tokens_in: 3, tokens_out: 0, cost_usd: 0.03 } },
  ]) {
    await tx(async () => {
      await db.lock();
      const head = await db.prepare('SELECT seq, record_hash FROM ledger_record ORDER BY seq DESC LIMIT 1').get() as { seq: number; record_hash: string };
      const record = { record_id: newId('rec'), seq: head.seq + 1, tenant_id: tenant.id, kind: 'transaction' as const, ts: historicAt, agent_id: agents[0]!.id, cert_id: null, data, prev_hash: head.record_hash };
      await db.prepare('INSERT INTO ledger_record (seq, record_id, tenant_id, kind, ts, agent_id, cert_id, data, prev_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(record.seq, record.record_id, record.tenant_id, record.kind, record.ts, record.agent_id, record.cert_id, JSON.stringify(data), record.prev_hash, hashRecord(record));
    });
  }
  const history = parseAgentAnalytics(await allTimeAgentAnalytics());
  const historicAgent = history.agents.find(agent => agent.id === agents[0]!.id)!;
  assert.equal(historicAgent.requests, 5);
  assert.equal(historicAgent.processing.requests, 10);
  assert.equal(historicAgent.processing.blocked, 4);
  assert.equal(historicAgent.allowed, 2);
  assert.equal(historicAgent.guardian.flagged, 3);
  assert.equal(historicAgent.tokens, 70);
  assert(Math.abs(historicAgent.cost_usd - 0.09) < 1e-10);
  assert.equal(historicAgent.activity.reduce((sum, bucket) => sum + bucket.requests, 0), 5);
  assert(Date.parse(history.from) <= Date.parse(historicAt));
  assert.equal(history.agents.find(agent => agent.id === agents[2]!.id)!.provider.executions, 4);
  assert.equal(history.agents.find(agent => agent.id === agents[2]!.id)!.provider.activity.reduce((sum, bucket) => sum + bucket.executions, 0), 4);
  const recent = await agentAnalytics();
  assert.equal(recent.agents.find(agent => agent.id === agents[0]!.id)!.requests, 4);
  assert.equal(recent.agents.find(agent => agent.id === agents[2]!.id)!.provider.executions, 3);
  const { nativeGuardianBlocks, nativeGuardianBlocksBetween } = await import('../src/servicenow-guardian-events');
  await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?)').run(connection.id, 'external-lab', 'a'.repeat(32), 'guardian_block', JSON.stringify({ event_id: 'a'.repeat(32), execution_id: 'b'.repeat(32), at: historicAt, categories: ['blocked'], instance_url: 'https://provider.example', signet_request_id: null }), eventTime);
  assert.equal((await nativeGuardianBlocks(agents[2]!.id)).length, 0);
  assert.equal((await nativeGuardianBlocksBetween(agents[2]!.id, history.from, history.to)).length, 1);
  await db.prepare('INSERT INTO external_agent_mapping (connection_id, external_id, agent_id, last_seen_at) VALUES (?, ?, ?, ?)').run(connection.id, 'external-appointment', agents[0]!.id, eventTime);
  const confirmed = { event_id: 'd'.repeat(32), execution_id: 'c'.repeat(32), at: eventTime, categories: ['blocked'], instance_url: 'https://provider.example', signet_request_id: 'req_01M83BLOCKTEST000000000001' };
  await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?)').run(connection.id, 'external-appointment', confirmed.event_id, 'guardian_block', JSON.stringify(confirmed), eventTime);
  const combined = parseAgentAnalytics(await allTimeAgentAnalytics());
  assert.equal(combined.agents.find(agent => agent.id === agents[0]!.id)!.processing.blocked, 4, 'ServiceNow confirmation must not count the same Signet block twice');
  const nativeOnly = combined.agents.find(agent => agent.id === agents[2]!.id)!;
  assert.equal(nativeOnly.requests, 0, 'Native blocks must not become gateway calls');
  assert.equal(nativeOnly.processing.requests, 1);
  assert.equal(nativeOnly.processing.blocked, 1);
  assert.equal(nativeOnly.processing.activity.reduce((sum, bucket) => sum + bucket.blocked, 0), 1);
  for (const agent of combined.agents) {
    assert.equal(agent.processing.requests, agent.processing.allowed + agent.processing.blocked + agent.processing.review + agent.processing.failed);
    assert.equal(agent.processing.activity.reduce((sum, bucket) => sum + bucket.requests, 0), agent.processing.requests);
  }
  const midnight = new Date();
  midnight.setHours(0, 0, 0, 0);
  const today = parseAgentAnalytics(await todayAgentAnalytics(midnight.toISOString()));
  assert.equal(today.from, midnight.toISOString());
  assert.equal(today.agents.find(agent => agent.id === agents[0]!.id)!.processing.requests, 8);
  assert.equal(today.agents.find(agent => agent.id === agents[0]!.id)!.processing.blocked, 3);
  assert.equal(today.agents.find(agent => agent.id === agents[2]!.id)!.provider.executions, 3);
  assert.equal(today.agents.find(agent => agent.id === agents[2]!.id)!.processing.blocked, 0);
  await assert.rejects(todayAgentAnalytics('invalid-date'), /local midnight/);
  await assert.rejects(todayAgentAnalytics(historicAt), /local midnight/);
  await append({ kind: 'transaction', agent_id: agents[3]!.id, data: { action_type: 'guardrail_check', guardrail_review: { decision: 'clear', status: 'complete' }, safety_usage: { model: 'unpriced-model', calls: 1, tokens_in: 5, tokens_out: 1, cost_usd: 0, unpriced_calls: 1, missing_usage_calls: 1 } } });
  await append({ kind: 'transaction', agent_id: agents[3]!.id, data: { action_type: 'guardrail_check', guardrail_classifier: { chunk_count: 1 }, guardrail_review: { decision: 'clear', status: 'complete' } } });
  const unpriced = (await agentAnalytics()).agents.find(agent => agent.id === agents[3]!.id)!;
  assert.equal(unpriced.cost_usd, 0);
  assert.equal(unpriced.tokens, 6);
  // A call without provider token counts cannot be estimated, so it stays unpriced.
  assert.deepEqual(unpriced.cost_coverage, { estimated_calls: 0, estimated_usd: 0, unpriced_calls: 1, missing_usage_calls: 1, legacy_records: 1 });
});

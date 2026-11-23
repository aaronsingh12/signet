import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-gateway-costs-'));
process.env.MONGODB_DATABASE = 'test_costs_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
after(dropTestDatabase);

test('gateway cost settings include idle agents, separate models and preserve historical cost after repricing', async () => {
  const { registerAgent, issueSeal } = await import('../src/registry');
  const { permissionsFor } = await import('../src/rbac');
  const { append } = await import('../src/ledger');
  const { gatewayCosts } = await import('../src/gateway-costs');
  const { agentAnalytics } = await import('../src/agent-analytics');
  const { tenant, setModelPrice } = await import('../src/tenant');
  const owner: Principal = { id: 'cost-owner@example.test', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const security: Principal = { ...owner, id: 'security@example.test', roles: ['security_officer'], permissions: permissionsFor(['security_officer']) };
  const first = await registerAgent({ handle: 'cost-first', name: 'First', purpose: 'Gateway cost integration', sponsor: owner.id, tier: 'T1', autonomy_level: 'L0' }, owner);
  const idle = await registerAgent({ handle: 'cost-idle', name: 'Idle', purpose: 'Gateway cost integration', sponsor: owner.id, tier: 'T1', autonomy_level: 'L0' }, owner);
  const empty = await registerAgent({ handle: 'cost-empty', name: 'No activity', purpose: 'Gateway cost integration', sponsor: owner.id, tier: 'T1', autonomy_level: 'L0' }, owner);
  const model = tenant.settings.catalogue[0]!.model;
  await issueSeal(first.id, { models: [{ model, region: 'unverified' }], tools: [], limits: { rpm: 30, tokens_per_day: 10000, usd_per_day: 5 }, environments: ['dev'] }, security);
  await append({ kind: 'transaction', agent_id: first.id, data: { action_type: 'llm_call', target: model, tokens_in: 2000, tokens_out: 500, cost_usd: 0.7 } });
  await append({ kind: 'transaction', agent_id: first.id, data: { action_type: 'llm_call', target: 'second-model', tokens_in: 100, tokens_out: 50, cost_usd: 0.2 } });
  await append({ kind: 'transaction', agent_id: idle.id, data: { action_type: 'tool_call', target: 'mcp://read', cost_usd: 0 } });
  await append({ kind: 'transaction', agent_id: first.id, data: { action_type: 'guardrail_check', target: 'servicenow://guardian', tokens_in: 9999, cost_usd: 99 } });
  await append({ kind: 'transaction', agent_id: first.id, data: { action_type: 'guardrail_check', target: 'servicenow://guardian', safety_usage: { model, calls: 2, tokens_in: 4000, tokens_out: 1000, cost_usd: 0.6, unpriced_calls: 0, missing_usage_calls: 0 } } });
  await append({ kind: 'transaction', agent_id: first.id, data: { action_type: 'guardrail_check', target: 'servicenow://guardian', guardrail_classifier: { chunk_count: 1, completed_chunks: 1 } } });
  await append({ kind: 'transaction', agent_id: first.id, data: { action_type: 'detector_score', tokens_in: 9999, cost_usd: 99 } });
  await append({ kind: 'admin', agent_id: first.id, data: { action_type: 'llm_call', tokens_in: 9999, cost_usd: 99 } });
  await setModelPrice(model, { in: 0.00015, out: 0.0006 });
  const report = await gatewayCosts(1);
  const active = report.agents.find(agent => agent.id === first.id)!;
  assert.equal(report.agents.length, 3);
  assert.equal(active.daily_budget_usd, 5);
  assert.equal(active.model_calls, 2);
  assert.equal(active.tokens_in, 6100);
  assert.equal(active.tokens_out, 1550);
  assert.equal(active.safety_calls, 2);
  assert.equal(active.safety_cost_usd, 0.6);
  assert.equal(active.legacy_safety_records, 1);
  assert(Math.abs(active.cost_usd - 1.5) < 1e-10);
  assert.equal(active.models.length, 3);
  assert.equal(active.models.find(entry => entry.model === model && entry.source === 'agent_model')!.cost_usd, 0.7);
  const dashboard = (await agentAnalytics()).agents.find(agent => agent.id === first.id)!;
  assert.equal(dashboard.cost_usd, active.cost_usd);
  assert.equal(dashboard.tokens, active.tokens_in + active.tokens_out);
  assert.equal(dashboard.requests, 2, 'Safety reviews add cost without inflating gateway request counts');
  assert.equal(report.agents.find(agent => agent.id === idle.id)!.tool_calls, 1);
  assert.equal(report.agents.find(agent => agent.id === idle.id)!.daily_budget_usd, null);
  assert.equal(report.agents.find(agent => agent.id === empty.id)!.cost_usd, 0);
  assert.equal(report.agents.find(agent => agent.id === empty.id)!.model_calls, 0);
  assert.deepEqual(report.models.find(entry => entry.model === model)!.price_per_1k_usd, { in: 0.00015, out: 0.0006 });
  await setModelPrice(model, { in: 1, out: 2 });
  assert.equal((await gatewayCosts(1)).agents.find(agent => agent.id === first.id)!.cost_usd, active.cost_usd);
  assert.equal((await gatewayCosts(7)).agents.find(agent => agent.id === first.id)!.model_calls, 2);
  for (const days of [0, 91, 1.5, NaN]) await assert.rejects(gatewayCosts(days), /days must be an integer/);
});

test('safety calls recorded before any rate was set are shown at the current rate as an estimate; priced calls keep their rate', async () => {
  const { registerAgent } = await import('../src/registry');
  const { permissionsFor } = await import('../src/rbac');
  const { append } = await import('../src/ledger');
  const { gatewayCosts } = await import('../src/gateway-costs');
  const { agentAnalytics } = await import('../src/agent-analytics');
  const { setAgentModel, setModelPrice } = await import('../src/tenant');
  const owner: Principal = { id: 'estimate-owner@example.test', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const agent = await registerAgent({ handle: 'cost-estimate', name: 'Estimate', purpose: 'Unpriced safety estimate', sponsor: owner.id, tier: 'T1', autonomy_level: 'L0' }, owner);
  const model = 'estimate-judge';
  await setAgentModel(model, { base_url: 'https://judge.example.test/v1', secret_id: null }); // registered with no rate yet
  const usage = (calls: number, tokens_in: number, tokens_out: number, cost_usd: number, unpriced_calls: number, missing_usage_calls = 0) => ({ action_type: 'guardrail_check', target: 'servicenow://guardian', safety_usage: { model, calls, tokens_in, tokens_out, cost_usd, unpriced_calls, missing_usage_calls } });
  await append({ kind: 'transaction', agent_id: agent.id, data: usage(2, 10_000, 1_000, 0, 2) }); // ran with no rate
  await append({ kind: 'transaction', agent_id: agent.id, data: usage(1, 1_000, 100, 0.25, 0) }); // ran at a real rate
  await append({ kind: 'transaction', agent_id: agent.id, data: usage(1, 0, 0, 0, 1, 1) }); // no token counts: cannot be estimated
  const before = (await gatewayCosts(1)).agents.find(entry => entry.id === agent.id)!;
  assert.equal(before.estimated_safety_calls, 0, 'with no rate configured there is nothing to estimate');
  assert.equal(before.unpriced_safety_calls, 3);
  await setModelPrice(model, { in: 0.0001, out: 0.0005 });
  const report = (await gatewayCosts(1)).agents.find(entry => entry.id === agent.id)!;
  const estimate = (10_000 * 0.0001 + 1_000 * 0.0005) / 1000;
  assert.equal(report.estimated_safety_calls, 2);
  assert(Math.abs(report.estimated_safety_cost_usd - estimate) < 1e-12);
  assert(Math.abs(report.safety_cost_usd - (0.25 + estimate)) < 1e-12, 'the priced call keeps its recorded 0.25');
  assert(Math.abs(report.cost_usd - (0.25 + estimate)) < 1e-12);
  assert.equal(report.unpriced_safety_calls, 1);
  assert(Math.abs(report.models.find(entry => entry.model === model)!.estimated_cost_usd! - estimate) < 1e-12);
  const dashboard = (await agentAnalytics()).agents.find(entry => entry.id === agent.id)!;
  assert(Math.abs(dashboard.cost_usd - report.cost_usd) < 1e-12);
  assert.equal(dashboard.cost_coverage.estimated_calls, 2);
  assert.equal(dashboard.cost_coverage.unpriced_calls, 1);
});

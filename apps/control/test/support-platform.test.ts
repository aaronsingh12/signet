import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import type { ExternalConnectionConfig } from '@signet/core/types';
function supportLabConnectionConfig(): ExternalConnectionConfig {
  return {
    name: 'Customer Support AI Agent', method: 'rest', private_connector: null,
    base_url: 'https://customer-support-ai-agent-roan.vercel.app/api/v1', auth: 'api_key', header: 'x-api-key',
    client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 15000,
    sync_interval_seconds: 300, remote_management: false,
    endpoints: {
      test: { method: 'GET', path: '/agents' }, discover: { method: 'GET', path: '/agents' },
      track: { method: 'GET', path: '/agents/{id}/track' }, executions: { method: 'GET', path: '/agents/executions?agentId={id}' },
      run: { method: 'POST', path: '/agents/{id}/run' }, pause: { method: 'POST', path: '/agents/{id}/pause' },
      stop: { method: 'POST', path: '/agents/{id}/stop' }, activate: { method: 'POST', path: '/agents/{id}/activate' },
    },
    agents_mapping: { items: '', id: '/id', name: '/name', status: '/status', timestamp: '/createdAt' },
    executions_mapping: { items: '/data', id: '/id', name: '', status: '/status', timestamp: '/createdAt' },
    tracking_pointer: '/agent',
    execution_pagination: { total: '/total', offset: '/offset', limit: '/limit' },
  };
}


import { adaptRecords, nextExecutionOffset, parseConfig, pointer } from '../src/external-contract';

test('observed Support Lab schemas validate nested tracking and paginated execution metadata without retaining prompts', () => {
  const config = parseConfig(supportLabConnectionConfig());
  const agent = { id: 'agent-fixture', name: 'Support fixture', status: 'active', createdAt: '2026-11-03T00:00:00Z', permissions: [], model: 'fixture-model' };
  assert.equal(adaptRecords([agent], config.agents_mapping!)[0]!.id, agent.id);
  const tracked = pointer({ agent, telemetry: { totalExecutions: 1 }, auditTrail: [] }, config.tracking_pointer);
  assert.ok(tracked);
  assert.equal(adaptRecords([tracked], config.agents_mapping!)[0]!.status, 'active');
  const execution = { id: 'execution-fixture', agentId: agent.id, status: 'completed', createdAt: '2026-11-03T00:00:00Z', prompt: 'sensitive customer prompt', response: 'sensitive response', conversationId: 'private-customer-conversation' };
  const page = { total: 2, limit: 1, offset: 0, data: [execution] };
  const records = adaptRecords(page, config.executions_mapping!);
  assert.equal(records.length, 1);
  assert.equal(JSON.stringify(records).includes('sensitive'), false);
  assert.equal(JSON.stringify(records).includes('private-customer'), false);
  assert.equal(nextExecutionOffset(page, config.execution_pagination!, 0, records.length), 1);
  assert.equal(nextExecutionOffset({ total: 2, limit: 1, offset: 1, data: [execution] }, config.execution_pagination!, 1, 1), null);
  assert.throws(() => nextExecutionOffset({ total: 2, limit: 1, offset: 0, data: [] }, config.execution_pagination!, 0, 0), /incomplete/);
  assert.throws(() => nextExecutionOffset({ total: 1001, limit: 100, offset: 0 }, config.execution_pagination!, 0, 100), /narrow/);
  assert.throws(() => adaptRecords({ data: [{ ...execution, status: null }] }, config.executions_mapping!), /Mapped status/);
});

import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import type { Principal } from '../src/rbac';
import type { ExternalConnectionConfig } from '@signet/core/types';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-sn-agents-'));
process.env.MONGODB_DATABASE = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
after(dropTestDatabase);

test('ServiceNow agent linking reuses identities, maps read-only monitoring, reports actual coverage, and removes gateway secrets with its connection', async () => {
  const { createServiceNowSettings, removeServiceNowConnection } = await import('../src/servicenow-mcp-settings');
  const { linkServiceNowAgent, linkedServiceNowAgents } = await import('../src/servicenow-agents');
  const { create } = await import('../src/external-connections');
  const { agentAnalytics } = await import('../src/agent-analytics');
  const { prepareServiceNowGateway, serviceNowAccessToken } = await import('../src/servicenow-gateway');
  const { saveServiceNowAuthorization, serviceNowConnection } = await import('../src/servicenow-mcp');
  const { putSecret, revealForGateway } = await import('../src/secrets');
  const { db } = await import('../src/db');
  const { permissionsFor } = await import('../src/rbac');
  const actor: Principal = { id: 'sn-admin@example.test', name: 'Admin', kind: 'human', roles: ['tenant_admin', 'platform_admin', 'agent_owner'], permissions: permissionsFor(['tenant_admin', 'platform_admin', 'agent_owner']), groups: [], mfa: true, auth: 'session', auth_time: null };
  const settings = await createServiceNowSettings({ name: 'Monitoring', gateway_url: 'https://signet.example.test', instance_url: 'https://techsnitchpvtltddemo2.service-now.com', mcp_url: 'https://techsnitchpvtltddemo2.service-now.com/sncapps/mcp-server/mcp/test-monitoring', client_id: 'test-client', client_secret: 'test-client-secret' }, actor);
  const input = { external_id: '1234567890abcdef1234567890abcdef', name: 'ServiceNow integration agent', purpose: 'Monitor an existing ServiceNow agent without claiming gateway enforcement' };
  await assert.rejects(() => linkServiceNowAgent(settings.id, input, { ...actor, permissions: [] }), /agents.write/);
  const linked = await linkServiceNowAgent(settings.id, input, actor);
  assert.equal((await linkServiceNowAgent(settings.id, input, actor)).agent_id, linked.agent_id);
  const rows = await linkedServiceNowAgents(settings.id);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.monitoring, false);
  assert.equal(rows[0]!.gateway_enforcement, false);
  const snapshot = await agentAnalytics();
  assert.deepEqual(snapshot.agents.find(agent => agent.id === linked.agent_id)?.servicenow, { linked: true, monitoring: false, gateway_enforcement: false });
  const config: ExternalConnectionConfig = { name: 'Read-only ServiceNow execution source', method: 'rest', private_connector: null, base_url: 'https://techsnitchpvtltddemo2.service-now.com', auth: 'none', header: '', client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 1000, sync_interval_seconds: 60, remote_management: false, tracking_pointer: '', execution_pagination: null,
    endpoints: { test: { method: 'GET', path: '/api/test' }, executions: { method: 'GET', path: '/api/agents/{id}/executions' } }, agents_mapping: null, executions_mapping: { items: '/result', id: '/sys_id', name: '', status: '/state', timestamp: '/created_at' } };
  const source = await create(linked.agent_id, { config, credential: '' }, actor);
  const mapped = await db.prepare('SELECT external_id, agent_id FROM external_agent_mapping WHERE connection_id = ?').get(source.id) as { external_id: string; agent_id: string };
  assert.deepEqual(mapped, { external_id: input.external_id, agent_id: linked.agent_id });
  await assert.rejects(() => create(linked.agent_id, { config: { ...config, remote_management: true }, credential: '' }, actor), /read-only/);
  assert.equal((await linkedServiceNowAgents(settings.id))[0]!.monitoring, false);
  const tokens = await putSecret({ name: 'sn-agent-test-tokens', kind: 'platform', value: JSON.stringify({ access_token: 'test-provider-token', refresh_token: 'test-refresh-token' }) }, actor);
  await db.prepare('UPDATE servicenow_mcp_account SET token_secret_id = ?, expires_at = ?, tools_json = ? WHERE id = ?')
    .run(tokens.id, Date.now() + 600000, JSON.stringify([{ name: 'read_ci', title: 'Read CI', description: 'Read-only CI metadata' }]), settings.id);
  assert.equal(await serviceNowAccessToken(settings.id), 'test-provider-token');
  const route = await prepareServiceNowGateway(settings.id, 'sn-integration-tools', actor);
  assert.equal(route.url, 'https://signet.example.test/v1/mcp/sn-integration-tools');
  const savedRoute = await db.prepare('SELECT secret_id FROM servicenow_gateway_route WHERE connection_id = ?').get(settings.id) as { secret_id: string };
  assert.equal((await revealForGateway(savedRoute.secret_id)).value, 'test-provider-token');
  assert.equal((await linkedServiceNowAgents(settings.id))[0]!.gateway_enforcement, false);
  const discoveredAt = new Date().toISOString();
  await db.prepare('UPDATE servicenow_mcp_account SET expires_at = ?, discovered_at = ? WHERE id = ?')
    .run(Date.now() - 1000, discoveredAt, settings.id);
  assert.equal((await serviceNowConnection(settings.id)).authorized, false);
  const preserved = await db.prepare('SELECT tools_json, discovered_at FROM servicenow_mcp_account WHERE id = ?').get(settings.id);
  const agentBefore = await db.prepare('SELECT * FROM agent WHERE id = ?').get(linked.agent_id);
  const sourceBefore = await db.prepare('SELECT * FROM external_connection WHERE id = ?').get(source.id);
  const linksBefore = await linkedServiceNowAgents(settings.id);
  for (const accessToken of ['reauthorized-token', 'reauthorized-again-token']) {
    await saveServiceNowAuthorization(settings.id, JSON.stringify({ access_token: accessToken, refresh_token: 'renewed-refresh-token' }), Date.now() + 600000, actor);
    assert.equal((await serviceNowConnection(settings.id)).authorized, true);
    assert.equal(await serviceNowAccessToken(settings.id), accessToken);
    assert.equal((await revealForGateway(savedRoute.secret_id)).value, accessToken);
    assert.deepEqual(await db.prepare('SELECT tools_json, discovered_at FROM servicenow_mcp_account WHERE id = ?').get(settings.id), preserved);
    assert.deepEqual(await db.prepare('SELECT secret_id FROM servicenow_gateway_route WHERE connection_id = ?').get(settings.id), savedRoute);
    assert.deepEqual(await db.prepare('SELECT * FROM agent WHERE id = ?').get(linked.agent_id), agentBefore);
    assert.deepEqual(await db.prepare('SELECT * FROM external_connection WHERE id = ?').get(source.id), sourceBefore);
    assert.deepEqual(await linkedServiceNowAgents(settings.id), linksBefore);
  }
  await removeServiceNowConnection(settings.id);
  assert.equal(await db.prepare('SELECT alias FROM tool WHERE alias = ?').get(route.alias), undefined);
  assert.equal(await db.prepare('SELECT id FROM secret WHERE id = ?').get(savedRoute.secret_id), undefined);
  assert.equal(await db.prepare('SELECT agent_id FROM servicenow_agent_link WHERE connection_id = ?').get(settings.id), undefined);
  assert.equal(await db.prepare('SELECT id FROM external_connection WHERE id = ?').get(source.id), undefined);
  const afterRemoval = await agentAnalytics();
  assert.equal(afterRemoval.agents.find(agent => agent.id === linked.agent_id)?.servicenow?.linked, false);
  const replacement = await createServiceNowSettings({ name: 'Monitoring', gateway_url: settings.gateway_url, instance_url: settings.instance_url, mcp_url: settings.mcp_url, client_id: settings.client_id, client_secret: 'replacement-client-secret' }, actor);
  assert.equal((await linkServiceNowAgent(replacement.id, input, actor)).agent_id, linked.agent_id);
});

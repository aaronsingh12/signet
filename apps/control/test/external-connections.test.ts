import { strict as assert } from 'node:assert';
import dns from 'node:dns';
import http, { type RequestOptions, type IncomingMessage } from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import type { ExternalConnectionConfig } from '@signet/core/types';
import type { Principal } from '../src/rbac';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-external-'));
process.env.SIGNET_DB_SCHEMA = `test_external_${Date.now().toString(36)}`;
after(dropTestDatabase);

const config = (): ExternalConnectionConfig => ({ name: 'Mock documented platform', tracking_pointer: '', execution_pagination: null, method: 'rest', private_connector: null, base_url: 'https://platform.example/api/v1', auth: 'api_key', header: 'x-api-key', client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 1000, sync_interval_seconds: 60, remote_management: false, endpoints: { test: { method: 'GET', path: '/agents' }, discover: { method: 'GET', path: '/agents' }, executions: { method: 'GET', path: '/agents/executions?agentId={id}' }, pause: { method: 'POST', path: '/agents/{id}/pause' } }, agents_mapping: { items: '/agents', id: '/key', name: '/label', status: '', timestamp: '' }, executions_mapping: { items: '/history', id: '/executionId', name: '', status: '/state', timestamp: '/at' } });

test('outbound REST and OAuth use a mock HTTP service: secure storage, validation, lifecycle, sync, rotation and isolation', { timeout: 180000 }, async (context) => {
  const connections = await import('../src/external-connections');
  const { db } = await import('../src/db');
  const { tenant } = await import('../src/tenant');
  const { registerAgent, activeCertificate } = await import('../src/registry');
  const { permissionsFor } = await import('../src/rbac');
  const { parseConfig, adaptRecords, endpointUrl } = await import('../src/external-contract');
  const { requestJson } = await import('../src/external-http');
  const actor: Principal = { id: 'external-owner@example.test', name: 'Platform administrator and owner', kind: 'human', roles: ['platform_admin', 'agent_owner'], permissions: permissionsFor(['platform_admin', 'agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const viewer: Principal = { ...actor, roles: ['viewer'], permissions: permissionsFor(['viewer']) };
  const parent = await registerAgent({ handle: 'external-connection', name: 'External platform', purpose: 'Govern and monitor external agents', sponsor: actor.id, autonomy_level: 'L0', connection_method: 'rest' }, actor);
  let mode: 'normal' | 'empty' | 'malformed' | 'bad-auth' | 'unavailable' | 'redirect' | 'large' = 'normal';
  let tokens = 0;
  let actions = 0;
  const service = http.createServer((req, res) => {
    if (req.url === '/token') {
      tokens++;
      assert.equal(req.headers.authorization, `Basic ${Buffer.from('mock-client:mock-secret-value').toString('base64')}`);
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ access_token: 'mock-access-token', token_type: 'Bearer', expires_in: 3600 }));
      return;
    }
    if (mode === 'bad-auth') { res.writeHead(401).end('mock-secret-value'); return; }
    if (mode === 'unavailable') { res.writeHead(503).end(); return; }
    if (mode === 'redirect') { res.writeHead(302, { location: 'https://169.254.169.254/latest/meta-data' }).end(); return; }
    if (mode === 'large') { res.end('x'.repeat(1024 * 1024 + 1)); return; }
    assert.ok(req.headers['x-api-key'] === 'mock-secret-value' || req.headers.authorization === 'Bearer mock-access-token');
    if (req.url === '/api/v1/openapi.json') {
      res.end(JSON.stringify({ openapi: '3.1.0', paths: { '/api/v1/agents': { get: {} } }, components: { securitySchemes: { key: { type: 'apiKey', in: 'header', name: 'x-api-key' } } } })); return;
    }
    if (mode === 'malformed') { res.end('{malformed'); return; }
    if (req.method === 'POST') { actions++; res.end('{}'); return; }
    if (req.url?.startsWith('/api/v1/agents/executions')) {
      res.end(JSON.stringify({ history: [{ executionId: 'exec-1', state: 'completed', at: '2026-11-03T00:00:00Z', ignored: 'must not be retained' }] })); return;
    }
    res.end(JSON.stringify({ agents: mode === 'empty' ? [] : [{ key: 'agent-a', label: 'Support agent' }, { key: 'agent-b', label: 'Sales agent' }] }));
  });
  await new Promise<void>((resolve) => service.listen(0, '127.0.0.1', resolve));
  const address = service.address();
  assert.ok(address && typeof address === 'object');
  const port = address.port;
  // Only this test process redirects HTTPS transport into its local mock service. Production guards remain enabled.
  const originalLookup = dns.lookup;
  context.mock.method(dns, 'lookup', ((host: string, options: object, callback: (error: Error | null, addresses: { address: string; family: number }[]) => void) => host === 'platform.example' || host === 'other.example' ? callback(null, [{ address: '93.184.216.34', family: 4 }]) : Reflect.apply(originalLookup, dns, [host, options, callback])) as typeof dns.lookup);
  context.mock.method(https, 'request', ((url: URL, options: RequestOptions, callback: (response: IncomingMessage) => void) => http.request(`http://127.0.0.1:${port}${url.pathname}${url.search}`, { ...options, lookup: undefined }, callback)) as typeof https.request);
  syncBuiltinESMExports();
  context.after(async () => {
    context.mock.restoreAll(); syncBuiltinESMExports();
    service.closeAllConnections();
    await new Promise<void>((resolve, reject) => service.close((error) => error ? reject(error) : resolve()));
  });

  assert.throws(() => parseConfig({ ...config(), base_url: 'http://public.example' }), /HTTPS/);
  assert.throws(() => endpointUrl(config().base_url, '//metadata', null), /Endpoint path/);
  assert.throws(() => endpointUrl(config().base_url, '/%2e%2e/secrets', null), /traversal/);
  assert.equal(adaptRecords({ agents: [{ key: 1, label: 'Agent' }] }, config().agents_mapping!)[0]!.id, '1');
  assert.throws(() => adaptRecords({ agents: [{ key: -1 }] }, config().agents_mapping!), /Mapped id/);
  for (const host of ['169.254.169.254', '127.0.0.1', '10.0.0.1', '[::1]', '[::ffff:7f00:1]', '[::ffff:a9fe:a9fe]']) await assert.rejects(requestJson({ url: new URL(`https://${host}/`), method: 'GET', headers: {}, body: null, timeout: 1000 }), /address/);
  await assert.rejects(connections.create(parent.id, { config: config(), credential: 'mock-secret-value' }, viewer), /connectors.manage/);
  const automatic = await connections.connectRest(parent.id, { base_url: config().base_url, credential: 'mock-secret-value', connection_id: null }, actor);
  assert.equal(automatic.agents.length, 2);
  assert.equal(automatic.connection.agent_count, 0, 'Connecting previews agents without onboarding them');
  assert.equal(automatic.agents.every((agent) => agent.agent_id === null), true);
  assert.equal(JSON.stringify(automatic).includes('mock-secret-value'), false);
  const onboarded = await connections.onboardRestAgent(automatic.connection.id, 'agent-a', actor);
  assert.equal(await activeCertificate(onboarded.agent_id), null, 'Onboard must not approve agents');
  assert.equal((await connections.view(automatic.connection.id)).agent_count, 1, 'Only the selected agent is onboarded');
  assert.deepEqual(await connections.onboardRestAgent(automatic.connection.id, 'agent-a', actor), onboarded, 'Repeated onboarding reuses the existing identity');
  const preview = await connections.previewRestAgents(automatic.connection.id, actor);
  assert.equal(preview.agents.find((agent) => agent.id === 'agent-a')!.agent_id, onboarded.agent_id);
  assert.equal(preview.agents.find((agent) => agent.id === 'agent-b')!.agent_id, null);
  await assert.rejects(connections.onboardRestAgent(automatic.connection.id, 'missing-agent', actor), /not found/);
  await assert.rejects(connections.onboardRestAgent(automatic.connection.id, 'agent-b', viewer), /connectors.manage/);
  const refreshed = await connections.connectRest(parent.id, { base_url: config().base_url, credential: '', connection_id: automatic.connection.id }, actor);
  assert.equal(refreshed.connection.id, automatic.connection.id, 'Refresh retains the connection and saved API key');
  await connections.transition(automatic.connection.id, 'disconnected', actor);
  const connection = await connections.create(parent.id, { config: config(), credential: 'mock-secret-value' }, actor);
  assert.equal(JSON.stringify(connection).includes('mock-secret-value'), false);
  const stored = await db.prepare('SELECT sealed FROM secret WHERE id = (SELECT secret_id FROM external_connection WHERE id = ?)').get(connection.id);
  assert.equal(JSON.stringify(stored).includes('mock-secret-value'), false);
  assert.equal((await connections.testConnection(connection.id, actor)).health.authentication, 'valid');
  await assert.rejects(connections.inspectAgentList(connection.id, viewer), /connectors.manage/);
  const fields = await connections.inspectAgentList(connection.id, actor);
  assert.deepEqual(fields, { lists: [{ path: '/agents', count: 2, fields: ['/key', '/label'] }] });
  assert.equal(JSON.stringify(fields).includes('Support agent'), false, 'Inspection must not expose external record values');
  assert.equal((await connections.view(connection.id)).agent_count, 0, 'Inspection must not import or approve agents');
  mode = 'empty';
  assert.deepEqual(await connections.inspectAgentList(connection.id, actor), { lists: [{ path: '/agents', count: 0, fields: [] }] });
  assert.equal((await connections.discover(connection.id, actor)).health.discovered, 0);
  mode = 'normal';
  assert.equal((await connections.discover(connection.id, actor)).agent_count, 2);
  assert.equal((await connections.discover(connection.id, actor)).agent_count, 2);
  const mappings = await db.prepare('SELECT agent_id FROM external_agent_mapping WHERE connection_id = ?').all(connection.id) as { agent_id: string }[];
  assert.equal(await activeCertificate(mappings[0]!.agent_id), null);
  await connections.sync(connection.id, actor);
  await connections.sync(connection.id, actor);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM external_observation WHERE connection_id = ?').get(connection.id))!.n, 2);
  assert.equal(JSON.stringify(await db.prepare('SELECT metadata FROM external_observation WHERE connection_id = ?').all(connection.id)).includes('must not be retained'), false);
  await assert.rejects(connections.remoteAction(connection.id, mappings[0]!.agent_id, 'pause', { reason: 'test' }, viewer), /connectors.manage/);
  await connections.update(connection.id, { config: { ...config(), remote_management: true } }, actor);
  await assert.rejects(connections.remoteAction(connection.id, mappings[0]!.agent_id, 'pause', { reason: 'test' }, actor), /approved agent/);
  assert.equal(actions, 0, 'Unapproved agents must never send external control requests');
  const { registerTool } = await import('../src/tools');
  const { signSeal } = await import('../src/registry');
  await registerTool({ alias: 'mock-platform', kind: 'http', url: config().base_url, actions: { pause: { method: 'POST', path: '/agents/{id}/pause' } } }, actor);
  // Fixture represents a completed approval; lifecycle matrix behavior is covered by workflow integration tests.
  await db.prepare('UPDATE agent SET autonomy_level = ? WHERE id = ?').run('L3', mappings[0]!.agent_id);
  await signSeal(mappings[0]!.agent_id, { models: [], tools: [{ server: 'http://mock-platform', data_scopes: [], actions: [{ name: 'pause', impact: 'write' }] }], limits: { rpm: 10, tokens_per_day: 1000, usd_per_day: 1 }, environments: ['dev'] }, { approvers: [{ user: 'security@example.test', at: new Date().toISOString() }], evidence_refs: {}, regulatory_category: 'test-fixture', minor: false, actor: 'security@example.test' });
  await connections.remoteAction(connection.id, mappings[0]!.agent_id, 'pause', { reason: 'mock service only' }, actor);
  assert.equal(actions, 1);
  for (const next of ['bad-auth', 'malformed', 'redirect', 'large', 'unavailable'] as const) {
    mode = next;
    await assert.rejects(connections.testConnection(connection.id, actor));
    const state = await connections.view(connection.id);
    assert.ok(state.health.last_error);
    assert.equal(JSON.stringify(state).includes('mock-secret-value'), false);
  }
  mode = 'unavailable';
  await db.prepare('UPDATE external_connection SET next_sync_at = ? WHERE id = ?').run(0, connection.id);
  await connections.work();
  assert.equal((await connections.view(connection.id)).health.monitoring, false);
  mode = 'normal';
  await db.prepare('UPDATE external_connection SET next_sync_at = ? WHERE id = ?').run(0, connection.id);
  await connections.work();
  assert.equal((await connections.view(connection.id)).health.monitoring, true);
  assert.equal((await connections.view(connection.id)).health.gateway_enforcement, false);
  await assert.rejects(connections.update(connection.id, { config: { ...config(), base_url: 'https://other.example/api/v1' } }, actor), /resubmitting/);
  await connections.transition(connection.id, 'disconnected', actor);
  await assert.rejects(connections.testConnection(connection.id, actor), /disabled/);
  await connections.transition(connection.id, 'enabled', actor);
  await connections.testConnection(connection.id, actor);

  const oauthConfig = { ...config(), method: 'oauth', auth: 'oauth', client_id: 'mock-client', token_url: 'https://platform.example/token' };
  const oauth = await connections.create(parent.id, { config: oauthConfig, credential: 'mock-secret-value' }, actor);
  await connections.testConnection(oauth.id, actor);
  await connections.testConnection(oauth.id, actor);
  assert.equal(tokens, 1, 'Reuse a nonexpired OAuth token');
  const { revealForGateway, rotateSecret } = await import('../src/secrets');
  const secretId = (await db.prepare('SELECT secret_id FROM external_connection WHERE id = ?').get(oauth.id))!.secret_id as string;
  const sealed = JSON.parse((await revealForGateway(secretId)).value) as { expires_at: number };
  await rotateSecret(secretId, JSON.stringify({ ...sealed, expires_at: Date.now() - 1000 }), actor);
  await connections.testConnection(oauth.id, actor);
  assert.equal(tokens, 2, 'Expired client-credentials tokens are reacquired server-side');
  await connections.update(oauth.id, { config: oauthConfig, credential: 'mock-secret-value' }, actor);
  await connections.testConnection(oauth.id, actor);
  assert.equal(tokens, 3, 'Rotation invalidates cached access tokens');
  await db.prepare('INSERT INTO tenant (id, name, settings, created_at) VALUES (?, ?, ?, ?)').run('other-tenant', 'Other tenant', '{}', new Date().toISOString());
  await db.prepare('UPDATE external_connection SET tenant_id = ? WHERE id = ?').run('other-tenant', connection.id);
  await assert.rejects(connections.view(connection.id), /not found/);
  await assert.rejects(connections.testConnection(connection.id, actor), /not found/);
  await db.prepare('UPDATE external_connection SET tenant_id = ? WHERE id = ?').run(tenant.id, connection.id);
  await connections.transition(connection.id, 'revoked', actor);
  await assert.rejects(connections.transition(connection.id, 'enabled', actor), /cannot be reactivated/);
  assert.equal(JSON.stringify(await connections.list()).includes('mock-secret-value'), false);
});

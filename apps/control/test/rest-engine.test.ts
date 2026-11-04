import { strict as assert } from 'node:assert';
import { createHmac } from 'node:crypto';
import dns from 'node:dns';
import http, { type IncomingMessage, type RequestOptions } from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import type { ExternalConnectionConfig } from '@signet/core/types';
import type { Principal } from '../src/rbac';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-generic-rest-'));
process.env.SIGNET_DB_SCHEMA = `test_rest_${Date.now().toString(36)}`;
after(dropTestDatabase);

function config(auth: ExternalConnectionConfig['auth'], header: string, path: string): ExternalConnectionConfig {
  return { name: 'Generic REST integration', method: 'rest', private_connector: null, base_url: 'https://providers.example', auth, header, client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 1000, sync_interval_seconds: 60, remote_management: false, endpoints: { test: { method: 'GET', path, expected_status: [200] } }, agents_mapping: null, executions_mapping: null, tracking_pointer: '', execution_pagination: null };
}

test('generic REST connects Python, Node and nested provider contracts, gates mutations and verifies signed webhooks', { timeout: 240000 }, async (context) => {
  const engine = await import('../src/external-connections');
  const { db } = await import('../src/db');
  const { permissionsFor } = await import('../src/rbac');
  const { PolicyError } = await import('../src/errors');
  const { parseConfig, endpointUrl } = await import('../src/external-contract');
  const { requestJson } = await import('../src/external-http');
  const { suggestOpenApi } = await import('../src/external-openapi');
  const actor: Principal = { id: 'integration-owner@example.test', name: 'Integration owner', kind: 'human', roles: ['platform_admin', 'agent_owner'], permissions: permissionsFor(['platform_admin', 'agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const viewer: Principal = { ...actor, roles: ['viewer'], permissions: permissionsFor(['viewer']) };
  let nestedMode: 'valid' | 'partial' | 'missing' = 'valid';
  let retryCalls = 0;
  let writes = 0;
  const service = http.createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    const url = new URL(req.url!, 'http://test');
    const authorized = url.pathname === '/public' || req.headers['x-python-token'] === 'provider-secret-value' || req.headers.authorization === 'Bearer provider-secret-value' || req.headers.authorization === `Basic ${Buffer.from('user:provider-secret-value').toString('base64')}` || url.searchParams.get('access_key') === 'provider-secret-value' || (req.headers['x-client'] === 'client-secret' && req.headers['x-signature'] === 'signature-secret');
    if (!authorized) { res.writeHead(401).end(JSON.stringify({ secret: 'provider-secret-value' })); return; }
    if (url.pathname === '/retry') { if (++retryCalls === 1) { res.setHeader('retry-after', '0'); res.writeHead(429).end('{}'); return; } res.end('{"ok":true}'); return; }
    if (url.pathname === '/html') { res.setHeader('content-type', 'text/html'); res.end('<html>login</html>'); return; }
    if (url.pathname === '/broken') { res.end('{broken'); return; }
    if (url.pathname === '/redirect') { res.writeHead(302, { location: 'http://169.254.169.254/' }).end(); return; }
    if (url.pathname === '/slow') { setTimeout(() => res.end('{}'), 2000).unref(); return; }
    if (url.pathname === '/api/agents') { res.end(JSON.stringify({ agents: [{ agent_id: 'python-1', display_name: 'Python agent' }] })); return; }
    if (url.pathname === '/v2/bots') { res.end(JSON.stringify({ data: { items: [{ uuid: 'node-1', title: 'Node agent' }] } })); return; }
    if (url.pathname === '/catalog') {
      const rows = nestedMode === 'missing' ? [{ id: 'nested-1', name: 'Nested one' }] : [{ id: 'nested-1', name: 'Nested one' }, nestedMode === 'partial' ? { wrong_id: 'broken' } : { id: 'nested-2', name: 'Nested two' }];
      const offset = Number(url.searchParams.get('offset') ?? 0);
      res.end(JSON.stringify({ data: { agents: rows.slice(offset, offset + 1) }, paging: { total: rows.length, offset, limit: 1 } })); return;
    }
    if (url.pathname === '/v2/bots/node-1/execute' && req.method === 'POST') {
      writes++;
      let body = ''; for await (const part of req) body += part.toString();
      const data = JSON.parse(body) as { target: string; instruction: string };
      assert.equal(data.target, 'node-1');
      assert.equal(url.searchParams.get('bot'), 'node-1');
      assert.ok(req.headers['idempotency-key']);
      res.end(JSON.stringify({ status: 'running', echoed_key: 'provider-secret-value', access_token: 'must-not-leak', instruction: data.instruction })); return;
    }
    if (['/status', '/api/health', '/public'].includes(url.pathname)) { res.end('{"ok":true}'); return; }
    res.writeHead(404).end('{}');
  });
  await new Promise<void>((resolve) => service.listen(0, '127.0.0.1', resolve));
  const address = service.address(); assert.ok(address && typeof address === 'object');
  const originalLookup = dns.lookup;
  context.mock.method(dns, 'lookup', ((host: string, options: object, callback: (error: Error | null, addresses: { address: string; family: number }[]) => void) => host === 'providers.example' ? callback(null, [{ address: '93.184.216.34', family: 4 }]) : Reflect.apply(originalLookup, dns, [host, options, callback])) as typeof dns.lookup);
  context.mock.method(https, 'request', ((url: URL, options: RequestOptions, callback: (response: IncomingMessage) => void) => http.request(`http://127.0.0.1:${address.port}${url.pathname}${url.search}`, { ...options, lookup: undefined, agent: false }, callback)) as typeof https.request);
  syncBuiltinESMExports();
  context.after(async () => { context.mock.restoreAll(); syncBuiltinESMExports(); service.closeAllConnections(); await new Promise<void>((resolve) => service.close(() => resolve())); });

  assert.throws(() => parseConfig({ ...config('api_key_query', 'access_key', '/status') }), /explicit/);
  assert.throws(() => parseConfig({ ...config('api_key', 'Host', '/status') }), /reserved/);
  assert.throws(() => endpointUrl(config('none', '', '/public').base_url, '/v2/{agent_id}#evil', 'a'), /unsupported/);
  assert.equal(endpointUrl('https://providers.example', '/bots/{agent_id}', 'a/b').pathname, '/bots/a%2Fb');
  await assert.rejects(requestJson({ url: new URL('https://providers.example:444/status'), method: 'GET', headers: {}, body: null, timeout: 1000 }), /443/);
  await assert.rejects(requestJson({ url: new URL('https://providers.example/status'), method: 'GET', headers: { authorization: 'bad\r\nheader' }, body: null, timeout: 1000 }), /invalid characters/);
  assert.throws(() => parseConfig({ ...config('none', '', '/public'), endpoints: { test: { method: 'GET', path: '/public', response_schema: { type: 'object', patternProperties: { '(a+)+': {} } } } } }), /not supported/);
  assert.equal(suggestOpenApi({ openapi: '3.0.3', paths: { '/different/{botId}/execute': { post: { operationId: 'customExecute' } } } }).operations[0]!.endpoint.path, '/different/{botId}/execute');

  const cases: { config: ExternalConnectionConfig; credential: string }[] = [
    { config: config('none', '', '/public'), credential: '' },
    { config: { ...config('basic', '', '/status'), username: 'user' }, credential: 'provider-secret-value' },
    { config: { ...config('api_key_query', 'access_key', '/status'), query_key_acknowledged: true }, credential: 'provider-secret-value' },
    { config: { ...config('custom_headers', '', '/status'), secret_headers: ['x-client', 'x-signature'] }, credential: JSON.stringify({ 'x-client': 'client-secret', 'x-signature': 'signature-secret' }) },
  ];
  for (const item of cases) {
    const connection = await engine.create(null, item, actor);
    const tested = await engine.testConnection(connection.id, actor);
    assert.equal(tested.health.endpoint_verified, true);
    assert.ok(tested.health.last_tested_at);
    assert.equal(tested.health.authentication, item.config.auth === 'none' ? 'not_required' : 'valid');
    assert.equal(JSON.stringify(tested).includes('provider-secret-value'), false);
    await assert.rejects(engine.deleteConnection(connection.id, viewer), /connectors.manage/);
    await engine.deleteConnection(connection.id, actor);
    await assert.rejects(engine.view(connection.id), /not found/);
  }
  const python = await engine.create(null, { config: { ...config('api_key', 'x-python-token', '/api/health'), endpoints: { test: { method: 'GET', path: '/api/health', response_schema: { type: 'object', required: ['ok'], properties: { ok: { type: 'boolean' } } } }, discover: { method: 'GET', path: '/api/agents' } }, agents_mapping: { items: '/agents', id: '/agent_id', name: '/display_name', status: '', timestamp: '' } }, credential: 'provider-secret-value' }, actor);
  await engine.testConnection(python.id, actor);
  assert.equal((await engine.discover(python.id, actor)).agent_count, 1);
  assert.equal((await engine.discover(python.id, actor)).agent_count, 1);
  const { getAgent, registerAgent, validateSeal } = await import('../src/registry');
  const workflow = await import('../src/workflow');
  const discovered = (await engine.inventory(python.id)).items[0]!;
  const discoveredAgent = await getAgent(discovered.agent_id);
  const observationManifest = { models: [], tools: [], limits: { rpm: 10, tokens_per_day: 100, usd_per_day: 1 }, environments: ['dev'] };
  const lifecycle = await workflow.currentLifecycle(discoveredAgent.id);
  assert.ok(lifecycle);
  const savedManifest = await workflow.setManifest(lifecycle.id, observationManifest, actor);
  assert.deepEqual(savedManifest.lifecycle.data.manifest?.models, []);
  assert.equal(savedManifest.agent.kind, 'third_party');
  await assert.rejects(validateSeal(discoveredAgent, { ...observationManifest, models: [{ model: 'vendor-model', region: 'unverified' }] }), /list no models/);
  const unmapped = await registerAgent({ handle: 'unmapped-vendor', name: 'Unmapped vendor', purpose: 'Validate existing vendor tool requirements', sponsor: actor.id, autonomy_level: 'L0', kind: 'third_party', vendor: 'Example' }, actor);
  await assert.rejects(validateSeal(unmapped, observationManifest), /mapped REST platform connection or at least one company tool/);
  await engine.update(python.id, { config: python.config, credential: 'invalid-secret-value' }, actor);
  await assert.rejects(engine.testConnection(python.id, actor), (error: Error) => error instanceof PolicyError && error.rule === 'EXTERNAL_AUTH' && !error.message.includes('provider-secret-value'));
  assert.equal((await engine.view(python.id)).health.authentication, 'invalid');
  await engine.update(python.id, { config: python.config, credential: 'provider-secret-value' }, actor);
  for (const [path, rule] of [['/html', 'EXTERNAL_CONTENT'], ['/broken', 'EXTERNAL_SCHEMA'], ['/missing', 'EXTERNAL_NOT_FOUND'], ['/redirect', 'EXTERNAL_REDIRECT'], ['/slow', 'EXTERNAL_TIMEOUT']] as const) {
    await engine.update(python.id, { config: { ...python.config, endpoints: { test: { method: 'GET', path } } } }, actor);
    await assert.rejects(engine.testConnection(python.id, actor), (error: Error) => error instanceof PolicyError && error.rule === rule);
    assert.equal((await engine.view(python.id)).health.endpoint_verified, false);
  }
  await engine.update(python.id, { config: { ...python.config, endpoints: { test: { method: 'GET', path: '/retry' } } } }, actor);
  await engine.testConnection(python.id, actor);
  assert.equal(retryCalls, 2);

  const nodeConfig: ExternalConnectionConfig = { ...config('bearer', '', '/status'), remote_management: true, endpoints: { test: { method: 'GET', path: '/status' }, discover: { method: 'GET', path: '/v2/bots' }, run: { method: 'POST', path: '/v2/bots/{botId}/execute', variables: { botId: 'id' }, query: { bot: '{agent_id}' }, request_body: { target: '{id}', instruction: '{instruction}' }, expected_status: [200], idempotency_header: 'idempotency-key' } }, agents_mapping: { items: '/data/items', id: '/uuid', name: '/title', status: '', timestamp: '' } };
  const node = await engine.create(null, { config: nodeConfig, credential: 'provider-secret-value' }, actor);
  await engine.testConnection(node.id, actor);
  await engine.discover(node.id, actor);
  const nodeAgent = (await db.prepare('SELECT agent_id FROM external_agent_mapping WHERE connection_id = ?').get(node.id))!.agent_id as string;
  const action = { payload: { instruction: 'Start' }, confirmation: `run:${nodeAgent}`, idempotency_key: 'integration-key-001' };
  await assert.rejects(engine.remoteAction(node.id, nodeAgent, 'run', {}, actor), /confirmation/);
  await assert.rejects(engine.remoteAction(node.id, nodeAgent, 'run', action, actor), /approved agent/);
  assert.equal(writes, 0);
  const { registerTool } = await import('../src/tools');
  const { signSeal } = await import('../src/registry');
  await registerTool({ alias: 'generic-node', kind: 'http', url: nodeConfig.base_url, actions: { run: { method: 'POST', path: '/v2/bots/{botId}/execute' } } }, actor);
  await signSeal(nodeAgent, { models: [], tools: [{ server: 'http://generic-node', actions: [{ name: 'run', impact: 'read' }] }], limits: { rpm: 10, tokens_per_day: 10, usd_per_day: 1 }, environments: ['dev'] }, { approvers: [{ user: 'reviewer@example.test', at: new Date().toISOString() }], evidence_refs: {}, regulatory_category: 'minimal', minor: false, actor: actor.id });
  const response = await engine.remoteAction(node.id, nodeAgent, 'run', action, actor);
  assert.equal(writes, 1);
  assert.equal(JSON.stringify(response).includes('provider-secret-value'), false);
  assert.equal(JSON.stringify(response).includes('must-not-leak'), false);

  const nestedConfig: ExternalConnectionConfig = { ...config('api_key', 'x-python-token', '/status'), endpoints: { test: { method: 'GET', path: '/status' }, discover: { method: 'GET', path: '/catalog' }, track: { method: 'GET', path: '/catalog' } }, agents_mapping: { items: '/data/agents', id: '/id', name: '/name', status: '', timestamp: '' }, discovery_pagination: { total: '/paging/total', offset: '/paging/offset', limit: '/paging/limit' }, executions_mapping: { items: '/executions', id: '/id', name: '', status: '/status', timestamp: '/at', fields: { duration_ms: '/ms' } } };
  const nested = await engine.create(null, { config: nestedConfig, credential: 'provider-secret-value' }, actor);
  assert.equal((await engine.discover(nested.id, actor)).agent_count, 2);
  nestedMode = 'partial';
  await engine.discover(nested.id, actor);
  assert.equal((await engine.history(nested.id, actor)).items.some((run) => run.outcome === 'partial'), true);
  assert.equal((await db.prepare("SELECT presence FROM external_agent_mapping WHERE connection_id = ? AND external_id = 'nested-2'").get(nested.id))!.presence, 'present');
  nestedMode = 'missing';
  await engine.discover(nested.id, actor);
  assert.equal((await db.prepare("SELECT presence FROM external_agent_mapping WHERE connection_id = ? AND external_id = 'nested-2'").get(nested.id))!.presence, 'missing');
  assert.equal((await engine.view(nested.id)).agent_count, 2);
  await engine.setMonitoring(nested.id, false, actor);
  assert.equal((await engine.view(nested.id)).config.monitoring_enabled, false);
  const signingSecret = 'webhook-secret-that-is-at-least-32-characters';
  await engine.configureWebhook(nested.id, { enabled: true, secret: signingSecret, agent_pointer: '/agent', kind: 'execution' }, actor);
  const raw = Buffer.from(JSON.stringify({ agent: 'nested-1', executions: [{ id: 'execution-1', status: 'completed', at: new Date().toISOString(), ms: 12, private_prompt: 'not retained' }] }));
  const timestamp = String(Math.floor(Date.now() / 1000));
  const eventId = 'event-0000001';
  const signature = 'sha256=' + createHmac('sha256', signingSecret).update(`${timestamp}.${eventId}.`).update(raw).digest('hex');
  await assert.rejects(engine.receiveWebhook(nested.id, raw, timestamp, eventId, 'sha256=' + '0'.repeat(64)), /signature/);
  assert.equal((await engine.receiveWebhook(nested.id, raw, timestamp, eventId, signature)).records, 1);
  await assert.rejects(engine.receiveWebhook(nested.id, raw, timestamp, eventId, signature), /already been processed/);
  assert.equal(JSON.stringify(await db.prepare('SELECT metadata FROM external_observation WHERE connection_id = ?').all(nested.id)).includes('not retained'), false);
  await engine.configureWebhook(nested.id, { enabled: false }, actor);
  await assert.rejects(engine.receiveWebhook(nested.id, raw, timestamp, 'event-0000002', signature), /not been enabled/);
  await assert.rejects(engine.history(nested.id, viewer), /ledger.read/);
});

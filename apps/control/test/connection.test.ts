import { strict as assert } from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';

const directory = mkdtempSync(join(tmpdir(), 'signet-connect-'));
process.env.SIGNET_DATA_DIR = directory;
process.env.SIGNET_DB_SCHEMA = 'test_'+Date.now().toString(36)+'_'+Math.random().toString(36).slice(2, 10);
process.env.SIGNET_TOOL_PRIVATE_DESTINATIONS = 'allow';

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return address.port;
}

async function unusedPort(): Promise<number> {
  const server = createServer();
  const port = await listen(server);
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => { child.once('exit', () => resolve()); child.kill(); });
}

async function until(check: () => Promise<boolean>, description: string): Promise<void> {
  for (let attempt = 0; attempt < 450; attempt++) {
    if (await check()) return;
    await setTimeout(100);
  }
  throw new Error(`Timed out waiting for ${description}`);
}

after(dropTestDatabase);

test('OAuth and bootstrap identities reach a private API through a real outbound runner; policy and revocation deny access', { timeout: 180_000 }, async (context) => {
  let logs = '';
  try {
  const { permissionsFor } = await import('../src/rbac');
  const { db } = await import('../src/db');
  const { registerAgent, issueSeal } = await import('../src/registry');
  const { createClient, createBootstrap } = await import('../src/identity');
  const edge = await import('../src/edge');
  const { registerTool } = await import('../src/tools');
  const { parseTools } = await import('../../edge/src/config');
  const owner: Principal = { id: 'owner@example.test', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const security: Principal = { ...owner, id: 'security@example.test', roles: ['security_officer'], permissions: permissionsFor(['security_officer']) };
  let calls = 0;
  let privateToken = 'local-only-test-token';
  let slowStarted = false;
  let slowClosed = false;
  const privateApi = createServer((request, response) => {
    calls++;
    assert.equal(request.headers.authorization, `Bearer ${privateToken}`);
    if (request.url === '/records/slow') {
      slowStarted = true;
      response.once('close', () => { slowClosed = true; });
      return;
    }
    assert.equal(request.url, '/records/42');
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ id: '42', source: 'private-api' }));
  });
  const privatePort = await listen(privateApi);
  const children: ChildProcess[] = [];
  context.after(async () => {
    await Promise.all(children.map(stop));
    privateApi.closeAllConnections();
    await new Promise<void>((resolve, reject) => privateApi.close((error) => error ? reject(error) : resolve()));
  });
  const runner = (await edge.createRunner('Test private network', owner));
  const toolsFile = join(directory, 'edge-tools.json');
  const definition = { alias: 'private-records', url: `http://127.0.0.1:${privatePort}`, actions: { read: { method: 'GET', path: '/records/{id}' }, test: { method: 'GET', path: '/records/42' } }, token_env: 'SIGNET_TEST_PRIVATE_TOKEN' };
  writeFileSync(toolsFile, JSON.stringify([definition]));
  assert.throws(() => parseTools([{ ...definition, actions: { read: { method: 'GET', path: '/../metadata' } } }]), /invalid method or path/);
  await registerTool({ ...definition, kind: 'http', runner_id: runner.id }, owner);
  const agent = (await registerAgent({ handle: 'private-connector', name: 'Private connector', purpose: 'Read approved private records', sponsor: owner.id, tier: 'T3', autonomy_level: 'L3', connection_method: 'hybrid' }, owner));
  await assert.rejects(async () => (await createClient(agent.id, owner, 'before approval', 'dev')), /no active seal/);
  (await issueSeal(agent.id, { models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }], tools: [{ server: 'http://private-records', data_scopes: [], actions: [{ name: 'read', impact: 'read' }, { name: 'test', impact: 'read' }] }], limits: { rpm: 100, tokens_per_day: 1000, usd_per_day: 1 }, environments: ['dev'] }, security));
  await assert.rejects(async () => (await createClient(agent.id, owner, 'wrong environment', 'production')), /does not cover/);
  const client = (await createClient(agent.id, owner, 'REST connection', 'dev'));
  const bootstrap = (await createBootstrap(agent.id, owner, 'dev'));
  const controlPort = await unusedPort();
  const gatewayPort = await unusedPort();
  const controlUrl = `http://127.0.0.1:${controlPort}`;
  const gatewayUrl = `http://127.0.0.1:${gatewayPort}`;
  const env: NodeJS.ProcessEnv = { ...process.env, SIGNET_CONTROL_PORT: String(controlPort), SIGNET_GATEWAY_PORT: String(gatewayPort), SIGNET_CONTROL_URL: controlUrl + '/', SIGNET_NODE_ID: 'connect-test', SIGNET_AUTH_MODE: 'local', SIGNET_ADMIN_ID: 'connect-admin', SIGNET_ADMIN_PASSWORD: 'isolated-test-password', SIGNET_PUBLIC_URL: controlUrl, SIGNET_LLM_BASE_URL: 'http://127.0.0.1:1/v1', SIGNET_ENV: 'dev', SIGNET_EDGE_RUNNER_ID: runner.id, SIGNET_EDGE_RUNNER_SECRET: runner.runner_secret, SIGNET_EDGE_TOOLS_FILE: toolsFile, SIGNET_TEST_PRIVATE_TOKEN: 'local-only-test-token' };
  const start = (entry: string): ChildProcess => {
    const child = spawn(process.execPath, ['--import', 'tsx', resolve(entry)], { env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    child.stdout?.on('data', (chunk: Buffer) => { logs = (logs + chunk.toString()).slice(-12_000); });
    child.stderr?.on('data', (chunk: Buffer) => { logs = (logs + chunk.toString()).slice(-12_000); });
    children.push(child);
    return child;
  };
  const healthy = async (url: string): Promise<boolean> => {
    try { return (await fetch(`${url}/healthz`, { signal: AbortSignal.timeout(1000) })).ok; }
    catch (error) { if (error instanceof TypeError || (error instanceof Error && error.name === 'TimeoutError')) return false; throw error; }
  };
  const control = start('apps/control/src/index.ts');
  await until(async () => { assert.equal(control.exitCode, null, logs); return (await healthy(controlUrl)); }, 'control plane');
  const gateway = start('apps/gateway/src/index.ts');
  await until(async () => { assert.equal(gateway.exitCode, null, logs); return (await healthy(gatewayUrl)); }, 'gateway');
  const worker = start('apps/edge/src/index.ts');
  await until(async () => { assert.equal(worker.exitCode, null, logs); return (await edge.listRunners())[0]?.status === 'online'; }, 'runner enrollment');
  const login = await fetch(`${controlUrl}/api/v1/auth/local-login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'connect-admin', password: 'isolated-test-password' }) });
  assert.equal(login.status, 200, await login.text());
  const cookie = login.headers.get('set-cookie')!.split(';')[0]!;
  const settings = await fetch(`${controlUrl}/api/v1/connect/settings`, { method: 'PUT', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ control_url: controlUrl, gateway_url: gatewayUrl }) });
  assert.equal(settings.status, 200, await settings.clone().text());
  const info = await (await fetch(`${controlUrl}/api/v1/connect/info`, { headers: { cookie } })).json() as { control_url: string; gateway_url: string; gateway_url_source: string };
  assert.equal(info.control_url, controlUrl);
  assert.equal(info.gateway_url, gatewayUrl);
  assert.equal(info.gateway_url_source, 'database');
  const { connectionAddresses } = await import('../src/connection-settings');
  assert.equal((await connectionAddresses()).gateway_url, gatewayUrl, 'a separate control instance reads the saved addresses without restarting');
  assert.equal((await fetch(`${controlUrl}/api/v1/connect/settings`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ control_url: controlUrl, gateway_url: gatewayUrl }) })).status, 401);
  assert.equal((await fetch(`${controlUrl}/api/v1/connect/settings`, { method: 'PUT', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ control_url: 'https://user:password@example.com', gateway_url: gatewayUrl }) })).status, 400);
  const exchange = await fetch(`${controlUrl}/api/v1/identity/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}` }, body: 'grant_type=client_credentials' });
  assert.equal(exchange.status, 200);
  const identity = await exchange.json() as { access_token: string; expires_in: number };
  assert.equal(identity.expires_in, 1800);
  const call = (token: string, action: string): Promise<Response> => fetch(`${gatewayUrl}/v1/tools/http/private-records/${action}`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ id: '42' }) });
  const result = await call(identity.access_token, 'read');
  assert.equal(result.status, 200, await result.clone().text());
  assert.deepEqual(await result.json(), { id: '42', source: 'private-api' });
  assert.equal(calls, 1);
  const savedCredential = await fetch(`${controlUrl}/api/v1/edge-runners/${runner.id}/tools/private-records/credential`, { method: 'PUT', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ credential: privateToken }) });
  assert.equal(savedCredential.status, 200, await savedCredential.clone().text());
  const isolatedRunner = await edge.createRunner('Unrelated runner', owner);
  assert.equal((await fetch(`${controlUrl}/api/v1/edge/runners/${isolatedRunner.id}/tools/private-records/credential`, { headers: { authorization: `Bearer ${isolatedRunner.runner_secret}` } })).status, 403, 'runner credentials cannot open another runner\'s tools');
  const pairedFile = join(directory, 'signet-runner.json');
  writeFileSync(pairedFile, JSON.stringify({ version: 1, control_url: controlUrl, runner_id: runner.id, runner_secret: runner.runner_secret, private_destinations: 'allow', tools: [{ alias: definition.alias, url: definition.url, actions: definition.actions, credential_source: 'broker' }] }));
  await stop(worker);
  const pairedWorker = spawn(process.execPath, ['--import', 'tsx', resolve('apps/edge/src/index.ts'), '--config', pairedFile], { env: { ...env, SIGNET_EDGE_RUNNER_ID: '', SIGNET_EDGE_RUNNER_SECRET: '', SIGNET_EDGE_TOOLS_FILE: '', SIGNET_TEST_PRIVATE_TOKEN: '' }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  children.push(pairedWorker);
  pairedWorker.stderr?.on('data', (chunk: Buffer) => { logs = (logs + chunk.toString()).slice(-12_000); });
  await until(async () => { assert.equal(pairedWorker.exitCode, null, logs); return (await edge.listRunners()).some((item) => item.id === runner.id && item.status === 'online'); }, 'file-configured runner');
  const fromFile = await call(identity.access_token, 'read');
  assert.equal(fromFile.status, 200, await fromFile.clone().text());
  privateToken = 'rotated-private-api-token';
  const rotated = await fetch(`${controlUrl}/api/v1/edge-runners/${runner.id}/tools/private-records/credential`, { method: 'PUT', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ credential: privateToken }) });
  assert.equal(rotated.status, 200, await rotated.clone().text());
  assert.equal((await call(identity.access_token, 'read')).status, 200, 'the paired runner uses a rotated database credential without restarting or changing environment variables');
  const meta = await (await fetch(`${controlUrl}/api/v1/tools`, { headers: { cookie } })).text();
  assert.ok(!meta.includes(privateToken), 'ordinary tool metadata never exposes plaintext credentials');
  const denied = await call(identity.access_token, 'not-approved');
  assert.equal(denied.status, 403);
  assert.equal(calls, 3, 'unapproved actions must never reach the private service');
  const bootstrapExchange = (): Promise<Response> => fetch(`${controlUrl}/api/v1/identity/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bootstrap_credential: bootstrap.bootstrap_credential }) });
  const first = await bootstrapExchange();
  assert.equal(first.status, 200);
  const workload = await first.json() as { token: string; claims: { ins: string } };
  assert.equal((await bootstrapExchange()).status, 401);
  const refresh = await fetch(`${controlUrl}/api/v1/identity/token/refresh`, { method: 'POST', headers: { authorization: `Bearer ${workload.token}` } });
  assert.equal(refresh.status, 200);
  const pending = fetch(`${gatewayUrl}/v1/tools/http/private-records/read`, { method: 'POST', headers: { authorization: `Bearer ${workload.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ id: 'slow' }) });
  await until(async () => slowStarted, 'in-flight private connector operation');
  const instanceRevoke = await fetch(`${controlUrl}/api/v1/instances/${workload.claims.ins}/revoke`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'Cancel an in-flight connector operation' }) });
  assert.equal(instanceRevoke.status, 200, await instanceRevoke.text());
  assert.notEqual((await pending).status, 200);
  await until(async () => slowClosed, 'private operation cancellation');
  const unrelated = await call(identity.access_token, 'read');
  assert.equal(unrelated.status, 200, await unrelated.text());
  // No-code connection (A1, A2): the app only knows a base URL and an API key. The deployment
  // credential works as that key, in the Authorization header or an api-key header, and the model
  // list shows only the tenant's cloud LLM.
  const { createDeploymentCredential } = await import('../src/deployment-identity');
  const deployment = await createDeploymentCredential(agent.id, owner, 'dev');
  const models = await fetch(`${gatewayUrl}/v1/models`, { headers: { authorization: `Bearer ${deployment.deployment_credential}` } });
  assert.equal(models.status, 200);
  assert.deepEqual(((await models.json()) as { data: { id: string }[] }).data.map((m) => m.id), ['gpt-oss:120b-cloud']);
  const viaKey = await call(deployment.deployment_credential, 'read');
  assert.equal(viaKey.status, 200, await viaKey.clone().text());
  const viaHeader = await fetch(`${gatewayUrl}/v1/tools/http/private-records/read`, { method: 'POST', headers: { 'api-key': deployment.deployment_credential, 'content-type': 'application/json' }, body: JSON.stringify({ id: '42' }) });
  assert.equal(viaHeader.status, 200, await viaHeader.clone().text());
  const sidecarFile = join(directory, 'signet-agent.json');
  writeFileSync(sidecarFile, JSON.stringify({ version: 1, control_url: controlUrl, gateway_url: gatewayUrl, identity: { kind: 'gateway', credential: deployment.deployment_credential }, token_cache: null }));
  const sidecarPort = await unusedPort();
  const sidecar = spawn(process.execPath, ['--import', 'tsx', resolve('apps/sidecar/src/index.ts'), '--config', sidecarFile], { env: { ...env, SIGNET_GATEWAY_URL: '', SIGNET_CONTROL_URL: '', SIGNET_SIDECAR_PORT: String(sidecarPort), SIGNET_SIDECAR_BIND: '127.0.0.1' }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  children.push(sidecar);
  sidecar.stderr?.on('data', (chunk: Buffer) => { logs = (logs + chunk.toString()).slice(-12_000); });
  await until(async () => {
    assert.equal(sidecar.exitCode, null, logs);
    try { return (await fetch(`http://127.0.0.1:${sidecarPort}/signet/status`, { signal: AbortSignal.timeout(1000) })).ok; }
    catch (error) { if (error instanceof TypeError || (error instanceof Error && error.name === 'TimeoutError')) return false; throw error; }
  }, 'sidecar with a UI connection file');
  const sidecarCall = await fetch(`http://127.0.0.1:${sidecarPort}/v1/tools/http/private-records/read`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: '42' }) });
  assert.equal(sidecarCall.status, 200, await sidecarCall.clone().text());
  assert.deepEqual(await sidecarCall.json(), { id: '42', source: 'private-api' }, 'a connection file carries the gateway identity through the real sidecar without environment credentials');
  const forged = await call(`sdc_${'x'.repeat(43)}`, 'read');
  assert.equal(forged.status, 401);
  assert.equal(((await forged.json()) as { error: { code: string } }).error.code, 'invalid_api_key');
  assert.equal(pairedWorker.exitCode, null, 'revoking one agent instance must not stop the runner');
  const external = await import('../src/external-connections');
  const manager: Principal = { ...owner, roles: ['platform_admin', 'agent_owner'], permissions: permissionsFor(['platform_admin', 'agent_owner']) };
  const connection = await external.create(agent.id, { credential: client.client_secret, config: { name: 'Managed private connector', tracking_pointer: '', execution_pagination: null, method: 'hybrid', private_connector: { runner_id: runner.id, tool_alias: 'private-records', environment: 'dev' }, base_url: definition.url, auth: 'connector', header: '', client_id: client.client_id, token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 30000, sync_interval_seconds: 300, remote_management: false, endpoints: { test: definition.actions.test }, agents_mapping: null, executions_mapping: null } }, manager);
  const tested = await external.testConnection(connection.id, manager);
  assert.equal(tested.health.gateway_enforcement, true);
  assert.equal(tested.coverage, 'gateway_tools');
  await external.transition(connection.id, 'disconnected', manager);
  await assert.rejects(external.testConnection(connection.id, manager), /disabled/);
  await external.transition(connection.id, 'enabled', manager);
  const revoke = await fetch(`${controlUrl}/api/v1/clients/${client.client_id}/revoke`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'Integration revocation check' }) });
  assert.equal(revoke.status, 200, await revoke.text());
  await until(async () => (await call(identity.access_token, 'read')).status === 401, 'gateway token revocation');
  const runnerRevoke = await fetch(`${controlUrl}/api/v1/edge-runners/${runner.id}/revoke`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(runnerRevoke.status, 200, await runnerRevoke.text());
  await assert.rejects(async () => (await edge.authenticateRunner(runner.id, `Bearer ${runner.runner_secret}`)), /invalid or revoked/);
  await assert.rejects(external.testConnection(connection.id, manager), /revoked/);
  assert.equal((await external.view(connection.id)).health.gateway_enforcement, false);
  const retained = (await db.prepare("SELECT COUNT(*) AS n FROM edge_job WHERE args_json <> '{}' OR result_json IS NOT NULL").get()) as { n: number };
  assert.equal(retained.n, 0, 'completed connector payloads must be cleared');
  // Exercise the same authenticated routes used by the REST configuration controls against the real control server.
  const restConfig = { name: 'UI REST contract', method: 'rest', private_connector: null, base_url: 'https://unreachable-provider.invalid', auth: 'none', header: '', client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 1000, sync_interval_seconds: 60, remote_management: false, endpoints: { test: { method: 'GET', path: '/status' } }, agents_mapping: null, executions_mapping: null, tracking_pointer: '', execution_pagination: null };
  const savedRest = await fetch(`${controlUrl}/api/v1/connections`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ agent_id: null, config: restConfig, credential: '' }) });
  assert.equal(savedRest.status, 201, await savedRest.clone().text());
  const rest = await savedRest.json() as { id: string; configuration_status: string; health: { endpoint_verified: boolean } };
  assert.equal(rest.configuration_status, 'configured');
  assert.equal(rest.health.endpoint_verified, false);
  const failedRestTest = await fetch(`${controlUrl}/api/v1/connections/${rest.id}/test`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: '{}' });
  assert.notEqual(failedRestTest.status, 200, 'A saved configuration must not pretend an unreachable provider is connected');
  assert.equal(((await failedRestTest.json()) as { rule: string }).rule, 'EXTERNAL_DNS');
  const restHistory = await fetch(`${controlUrl}/api/v1/connections/${rest.id}/history`, { headers: { cookie } });
  assert.equal(restHistory.status, 200);
  assert.equal(((await restHistory.json()) as { items: { outcome: string }[] }).items[0]!.outcome, 'failed');
  assert.equal((await fetch(`${controlUrl}/api/v1/connections/${rest.id}`, { method: 'DELETE', headers: { cookie, 'content-type': 'application/json' } })).status, 200);
  assert.equal((await fetch(`${controlUrl}/api/v1/connections/${rest.id}`, { headers: { cookie } })).status, 404);
  assert.equal((await fetch(`${controlUrl}/api/v1/connections`)).status, 401);
  } catch (error) {
    context.diagnostic(logs.replaceAll(process.env.DATABASE_URL ?? 'not-configured', '[database URL redacted]'));
    throw error;
  }
});

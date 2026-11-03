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

test('OAuth and bootstrap identities reach a private API through a real outbound runner; policy and revocation deny access', { timeout: 120_000 }, async (context) => {
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
  let slowStarted = false;
  let slowClosed = false;
  const privateApi = createServer((request, response) => {
    calls++;
    assert.equal(request.headers.authorization, 'Bearer local-only-test-token');
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
  const definition = { alias: 'private-records', url: `http://127.0.0.1:${privatePort}`, actions: { read: { method: 'GET', path: '/records/{id}' } }, token_env: 'SIGNET_TEST_PRIVATE_TOKEN' };
  writeFileSync(toolsFile, JSON.stringify([definition]));
  assert.throws(() => parseTools([{ ...definition, actions: { read: { method: 'GET', path: '/../metadata' } } }]), /invalid method or path/);
  await registerTool({ ...definition, kind: 'http', runner_id: runner.id }, owner);
  const agent = (await registerAgent({ handle: 'private-connector', name: 'Private connector', purpose: 'Read approved private records', sponsor: owner.id, tier: 'T3', autonomy_level: 'L3', connection_method: 'hybrid' }, owner));
  await assert.rejects(async () => (await createClient(agent.id, owner, 'before approval', 'dev')), /no active seal/);
  (await issueSeal(agent.id, { models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }], tools: [{ server: 'http://private-records', data_scopes: [], actions: [{ name: 'read', impact: 'read' }] }], limits: { rpm: 100, tokens_per_day: 1000, usd_per_day: 1 }, environments: ['dev'] }, security));
  await assert.rejects(async () => (await createClient(agent.id, owner, 'wrong environment', 'production')), /does not cover/);
  const client = (await createClient(agent.id, owner, 'REST connection', 'dev'));
  const bootstrap = (await createBootstrap(agent.id, owner, 'dev'));
  const controlPort = await unusedPort();
  const gatewayPort = await unusedPort();
  const controlUrl = `http://127.0.0.1:${controlPort}`;
  const gatewayUrl = `http://127.0.0.1:${gatewayPort}`;
  let logs = '';
  const env: NodeJS.ProcessEnv = { ...process.env, SIGNET_CONTROL_PORT: String(controlPort), SIGNET_GATEWAY_PORT: String(gatewayPort), SIGNET_CONTROL_URL: controlUrl, SIGNET_NODE_ID: 'connect-test', SIGNET_AUTH_MODE: 'local', SIGNET_ADMIN_ID: 'connect-admin', SIGNET_ADMIN_PASSWORD: 'isolated-test-password', SIGNET_PUBLIC_URL: controlUrl, SIGNET_LLM_BASE_URL: 'http://127.0.0.1:1/v1', SIGNET_ENV: 'dev', SIGNET_EDGE_RUNNER_ID: runner.id, SIGNET_EDGE_RUNNER_SECRET: runner.runner_secret, SIGNET_EDGE_TOOLS_FILE: toolsFile, SIGNET_TEST_PRIVATE_TOKEN: 'local-only-test-token' };
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
  const exchange = await fetch(`${controlUrl}/api/v1/identity/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')}` }, body: 'grant_type=client_credentials' });
  assert.equal(exchange.status, 200);
  const identity = await exchange.json() as { access_token: string; expires_in: number };
  assert.equal(identity.expires_in, 1800);
  const call = (token: string, action: string): Promise<Response> => fetch(`${gatewayUrl}/v1/tools/http/private-records/${action}`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ id: '42' }) });
  const result = await call(identity.access_token, 'read');
  assert.equal(result.status, 200, await result.clone().text());
  assert.deepEqual(await result.json(), { id: '42', source: 'private-api' });
  assert.equal(calls, 1);
  const denied = await call(identity.access_token, 'not-approved');
  assert.equal(denied.status, 403);
  assert.equal(calls, 1, 'unapproved actions must never reach the private service');
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
  assert.equal(worker.exitCode, null, 'revoking one agent instance must not stop the runner');
  const revoke = await fetch(`${controlUrl}/api/v1/clients/${client.client_id}/revoke`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'Integration revocation check' }) });
  assert.equal(revoke.status, 200, await revoke.text());
  await until(async () => (await call(identity.access_token, 'read')).status === 401, 'gateway token revocation');
  const runnerRevoke = await fetch(`${controlUrl}/api/v1/edge-runners/${runner.id}/revoke`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(runnerRevoke.status, 200, await runnerRevoke.text());
  await assert.rejects(async () => (await edge.authenticateRunner(runner.id, `Bearer ${runner.runner_secret}`)), /invalid or revoked/);
  const retained = (await db.prepare("SELECT COUNT(*) AS n FROM edge_job WHERE args_json <> '{}' OR result_json IS NOT NULL").get()) as { n: number };
  assert.equal(retained.n, 0, 'completed connector payloads must be cleared');
});

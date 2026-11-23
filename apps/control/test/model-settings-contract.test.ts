import { strict as assert } from 'node:assert';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { after, test } from 'node:test';
import type { ModelConnection, PolicyBundle } from '@signet/core';
import type { Principal } from '../src/rbac';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-model-contract-'));
process.env.MONGODB_DATABASE = 'test_model_contract_' + Date.now().toString(36);
after(dropTestDatabase);

async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert(address && typeof address === 'object');
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return address.port;
}

/** A local HTTP contract fixture checks routing and storage, not the quality of a real classifier. */
test('provider HTTP contract preserves old routes, encrypts credentials and publishes saved settings without environment overrides', async context => {
  const key = 'local-contract-credential-12345';
  const calls: { model: string; authorization: string | undefined }[] = [];
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk: Buffer) => { raw += chunk.toString(); });
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/v1/models') return void res.end(JSON.stringify({ data: [{ id: 'previous-model' }, { id: 'selected-model' }] }));
      const input = JSON.parse(raw) as { model: string; messages: { role: string; content: string }[] };
      calls.push({ model: input.model, authorization: req.headers.authorization });
      if (input.model === 'missing-model') { res.statusCode = 404; res.end(JSON.stringify({ error: 'model is not installed' })); return; }
      const content = input.model === 'always-allow-model' ? 'allow' : input.messages[0]?.role === 'system' ? input.messages[1]?.content.includes('crowded train station') ? 'violence' : 'allow' : 'OK';
      res.end(JSON.stringify({ model: input.model, choices: [{ message: { role: 'assistant', content } }], usage: { prompt_tokens: 12, completion_tokens: 1 } }));
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  const address = server.address();
  assert(address && typeof address === 'object');
  const base = `http://127.0.0.1:${address.port}/v1`;
  process.env.SIGNET_LLM_BASE_URL = base;
  process.env.SIGNET_LLM_MODEL = 'previous-model';
  process.env.SIGNET_LLM_UPSTREAM_MODEL = 'previous-model';
  process.env.SIGNET_LLM_API_KEY = key;
  const { decodeJwt, modelHeaders, modelRequestBody } = await import('@signet/core');
  const modelSettings = await import('../src/model-settings');
  const { db } = await import('../src/db');
  const { buildBundle } = await import('../src/enforcement');
  const { reloadSettings } = await import('../src/tenant');
  const { askTenantModel } = await import('../src/tenant-model');
  const { testModelConnection } = await import('../src/model-connection');
  const { permissionsFor } = await import('../src/rbac');
  const actor: Principal = { id: 'model-contract-admin', name: 'Admin', kind: 'human', roles: ['tenant_admin'], permissions: permissionsFor(['tenant_admin']), groups: [], mfa: true, auth: 'session', auth_time: null };
  const draft = { provider: 'ollama_local' as const, base_url: base, model: 'selected-model', api_key: key };
  assert.deepEqual((await modelSettings.listModelOptions(draft)).models, ['previous-model', 'selected-model']);
  const saved = await modelSettings.saveModelSettings(draft, actor);
  assert.equal(saved.source, 'saved');
  assert.equal(saved.has_api_key, true);
  assert(!JSON.stringify(saved).includes(key));
  const active = await modelSettings.runtimeModelConnection();
  const stored = await db.prepare('SELECT sealed FROM secret WHERE id = ?').get(active.secret_id);
  assert.equal(typeof stored?.sealed, 'string');
  assert(!String(stored?.sealed).includes(key));
  const previous = (await reloadSettings()).catalogue.find(entry => entry.model === 'previous-model');
  assert.equal(previous?.upstream?.base_url, base);
  assert(previous?.upstream?.secret_id);
  delete process.env.SIGNET_LLM_BASE_URL;
  delete process.env.SIGNET_LLM_MODEL;
  delete process.env.SIGNET_LLM_API_KEY;
  assert.equal(await modelSettings.runtimeModelKey(active), key);
  assert.equal((await askTenantModel([{ role: 'user', content: 'Reply OK' }], 32))?.text, 'OK');
  assert.equal((await testModelConnection('selected-model', actor.id)).model, 'selected-model');
  const bundle = decodeJwt<PolicyBundle>(await buildBundle()).payload;
  assert.equal(bundle.model_connection?.model, 'selected-model');
  assert.equal(bundle.model_connection_saved, true);
  assert(!JSON.stringify(bundle).includes(key));
  assert(calls.every(call => call.authorization === `Bearer ${key}`));
  await assert.rejects(modelSettings.saveModelSettings({ ...draft, model: 'missing-model', api_key: '' }, actor), /HTTP 404.*model is not installed/s);
  await assert.rejects(modelSettings.saveModelSettings({ ...draft, model: 'always-allow-model', api_key: '' }, actor), /harmful-content classification check/);
  await assert.rejects(modelSettings.saveModelSettings({ ...draft, provider: 'openai', base_url: 'https://api.openai.com/v1', api_key: '' }, actor), /Enter the API key/);
  assert.equal((await modelSettings.modelSettings()).model, 'selected-model');
  const claude: ModelConnection = { provider: 'claude', base_url: 'https://api.anthropic.com/v1', model: 'claude-test', secret_id: null };
  assert.equal(modelHeaders(claude, key)['x-api-key'], key);
  const claudeBody = JSON.parse(modelRequestBody(claude, { model: 'claude-haiku-5-5', temperature: 0, top_p: 1, top_k: 10, max_tokens: 1024, messages: [] })) as { temperature?: number; top_p?: number; top_k?: number; max_tokens: number };
  assert.equal(claudeBody.temperature, undefined);
  assert.equal(claudeBody.top_p, undefined);
  assert.equal(claudeBody.top_k, undefined);
  assert.equal(claudeBody.max_tokens, 1024);
  const openai: ModelConnection = { ...claude, provider: 'openai', base_url: 'https://api.openai.com/v1', model: 'gpt-5' };
  const adapted = JSON.parse(modelRequestBody(openai, { model: 'gpt-5', max_tokens: 1024, temperature: 0, messages: [] })) as { max_tokens?: number; max_completion_tokens: number; temperature?: number };
  assert.equal(adapted.max_completion_tokens, 1024);
  assert.equal(adapted.max_tokens, undefined);
  assert.equal(adapted.temperature, undefined);
  // Claude 5 models reject non-default sampling values with HTTP 400; Signet never sends them to Claude.
  const toClaude = JSON.parse(modelRequestBody({ ...claude, model: 'claude-haiku-5-5' }, { model: 'claude-haiku-5-5', max_tokens: 1024, temperature: 0, top_p: 0.9, top_k: 5, messages: [] })) as Record<string, unknown>;
  assert.deepEqual(toClaude, { model: 'claude-haiku-5-5', max_tokens: 1024, messages: [], stream: false });

  const { registerAgent, issueSeal } = await import('../src/registry');
  const { createClient, exchangeClientCredentials } = await import('../src/identity');
  const owner: Principal = { ...actor, roles: ['tenant_admin', 'platform_admin', 'agent_owner'], permissions: permissionsFor(['tenant_admin', 'platform_admin', 'agent_owner']) };
  const security: Principal = { ...owner, id: 'model-security', roles: ['security_officer'], permissions: permissionsFor(['security_officer']) };
  const agent = await registerAgent({ handle: 'configured-model', name: 'Configured model', purpose: 'Verify model settings reach actual Guardian gateway requests', sponsor: owner.id, tier: 'T3', autonomy_level: 'L0' }, owner);
  await issueSeal(agent.id, { models: [{ model: 'selected-model', region: 'unverified' }], tools: [], limits: { rpm: 100, tokens_per_day: 100000, usd_per_day: 10 }, environments: ['dev'] }, security);
  const client = await createClient(agent.id, owner, 'Configured model Guardian', 'dev');
  const token = await exchangeClientCredentials(client.client_id, client.client_secret);
  const controlPort = await availablePort();
  const gatewayPort = await availablePort();
  const control = `http://127.0.0.1:${controlPort}`;
  const gateway = `http://127.0.0.1:${gatewayPort}`;
  const children: ChildProcess[] = [];
  let logs = '';
  context.after(async () => {
    await Promise.all(children.map(async child => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      await new Promise<void>(resolve => { child.once('exit', resolve); child.kill(); });
    }));
  });
  const env: NodeJS.ProcessEnv = { ...process.env, SIGNET_CONTROL_PORT: String(controlPort), SIGNET_GATEWAY_PORT: String(gatewayPort), SIGNET_CONTROL_URL: control,
    SIGNET_NODE_ID: 'model-contract', SIGNET_ENV: 'dev', SIGNET_AUTH_MODE: 'local', SIGNET_ADMIN_ID: 'model-admin', SIGNET_ADMIN_PASSWORD: 'isolated-model-contract-password', SIGNET_PUBLIC_URL: control,
    SIGNET_DET_RUNTIME: 'off', SIGNET_LLM_BASE_URL: 'http://127.0.0.1:1/v1', SIGNET_LLM_MODEL: 'wrong-environment-model', SIGNET_LLM_API_KEY: 'wrong-environment-key' };
  const start = async (entry: string, origin: string): Promise<void> => {
    const child = spawn(process.execPath, ['--max-semi-space-size=1', '--max-old-space-size=256', '--import', 'tsx', resolve(entry)], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    child.stdout?.on('data', (chunk: Buffer) => { logs = (logs + chunk.toString()).slice(-10000); });
    child.stderr?.on('data', (chunk: Buffer) => { logs = (logs + chunk.toString()).slice(-10000); });
    for (let attempt = 0; attempt < 180; attempt++) {
      assert.equal(child.exitCode, null, logs);
      try { if ((await fetch(origin + '/healthz', { signal: AbortSignal.timeout(1000) })).ok) return; }
      catch (error) { if (!(error instanceof TypeError) && !(error instanceof Error && error.name === 'TimeoutError')) throw error; }
      await setTimeout(250);
    }
    throw new Error(`Model settings integration service did not start: ${origin}\n${logs}`);
  };
  await start('apps/control/src/index.ts', control);
  await start('apps/gateway/src/index.ts', gateway);
  const review = async (): Promise<{ review: { status: string; decision: string } }> => {
    const response = await fetch(gateway + '/v1/guardrails/servicenow', { method: 'POST', headers: { authorization: 'Bearer ' + token.token, 'content-type': 'application/json' }, body: JSON.stringify({ content: 'Please summarize a routine incident without modifying records.' }) });
    assert.equal(response.status, 200, logs);
    return response.json() as Promise<{ review: { status: string; decision: string } }>;
  };
  assert.equal((await review()).review.status, 'complete', logs);
  assert.equal(calls.at(-1)?.model, 'selected-model', 'Gateway must ignore incorrect environment settings and use the saved model');
  const login = await fetch(control + '/api/v1/auth/local-login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: env.SIGNET_ADMIN_ID, password: env.SIGNET_ADMIN_PASSWORD }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie')?.split(';')[0];
  assert(cookie);
  const updated = await fetch(control + '/api/v1/model-settings', { method: 'PUT', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ ...draft, model: 'previous-model', api_key: '' }) });
  assert.equal(updated.status, 200, await updated.text());
  let refreshed = false;
  for (let attempt = 0; attempt < 20; attempt++) {
    await setTimeout(300);
    assert.equal((await review()).review.status, 'complete');
    if (calls.at(-1)?.model === 'previous-model') { refreshed = true; break; }
  }
  assert(refreshed, 'Settings saved through the actual API must reach Guardian without restarting the gateway');
});

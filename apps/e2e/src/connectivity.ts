import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT, TOKEN_AUDIENCE, loadSigningKey, newId, signJws, spiffeId, tokenIssuer, type StoredKey } from '@signet/core';
import { CONTROL, GW_A1, GW_A2, MODEL, TOOLS_URL, api, check, deployAgent, ensureTools, gw, mcp, onboard, outcome, type Json } from './api';

// Agent connectivity, scenarios 1-7: a real Python agent with the SDK, refused identities, MCP and HTTP
// tools, kill, a third-party (vendor) agent with client credentials, and bypass detection. Runs on the
// isolated stack from the harness, against the real identity provider and the configured cloud LLM.

const say = (s: string) => console.log(`   ${s}`);
let n = 0;
const head = (s: string) => console.log(`\n\x1b[1m${++n}. ${s}\x1b[0m`);

const MANIFEST = {
  models: [{ model: MODEL, region: 'unverified', max_tokens: 400 }],
  tools: [
    { server: 'mcp://orders', data_scopes: ['personal'], actions: [{ name: 'lookup_order', impact: 'read', constraints: { order_id: { pattern: '^A-[0-9]{4}$' } } }] },
    { server: 'http://crm', data_scopes: ['personal'], actions: [{ name: 'get_customer', impact: 'read' }] },
  ],
  data_classes: { prompt: ['personal'], forbidden: ['payment_card'] },
  limits: { rpm: 120, tokens_per_day: 200_000, usd_per_day: 20, tool_calls_per_session: 40 },
  environments: ['dev'],
};
const INTERNAL_INTAKE = { users_affected: ['internal'], data_touched: ['personal'], reversibility: 'yes', planned_tools: ['orders lookup (read)', 'crm lookup (read)'], business_value: 'e2e' };

// Runs the Python agent with the SDK from sdk/python, in a clean environment plus what we pass.
function python(script: string, extraEnv: Record<string, string>) {
  const uv = process.env.UV ?? 'uv';
  const r = spawnSync(uv, ['run', '--no-project', '--quiet', '--with', 'httpx', '--with', 'openai', '--with-editable', join(REPO_ROOT, 'sdk/python'), 'python', script], {
    env: { PATH: process.env.PATH ?? '', SYSTEMROOT: process.env.SYSTEMROOT ?? '', USERPROFILE: process.env.USERPROFILE ?? '', LOCALAPPDATA: process.env.LOCALAPPDATA ?? '', APPDATA: process.env.APPDATA ?? '', TEMP: process.env.TEMP ?? '', HOME: process.env.HOME ?? '', ...extraEnv },
    encoding: 'utf8',
    timeout: 240_000,
  });
  if (r.error) throw new Error(`cannot run uv (${r.error.message}); install uv or set UV to its path`);
  if (r.status !== 0) throw new Error(`python agent failed (${r.status}):\n${r.stderr}\n${r.stdout}`);
  return JSON.parse(r.stdout.trim().split('\n').pop()!) as Json;
}

// A token signed with the test stack's own token key, for cases that cannot be produced through the
// API in reasonable time (an expired token) or should never be issued (wrong audience, no seal).
function forge(claims: Partial<Json>) {
  const stored = JSON.parse(readFileSync(join(process.env.SIGNET_DATA_DIR!, 'keys.json'), 'utf8')) as Record<string, StoredKey>;
  const key = loadSigningKey(stored.token!);
  const now = Math.floor(Date.now() / 1000);
  return signJws({ iat: now, exp: now + 600, jti: newId('jti'), ...claims }, key, 'JWT');
}

const sdkEnv = (bootstrap: string) => ({
  SIGNET_GATEWAY_URL: GW_A1,
  SIGNET_CONTROL_URL: CONTROL,
  SIGNET_BOOTSTRAP_CREDENTIAL: bootstrap,
  SIGNET_EGRESS_CHECK: '0', // a direct connection test is environment-specific; scenario 7 covers detection via env
  SIGNET_RUNTIME: 'e2e-runner',
  SIGNET_FRAMEWORK: 'python-sdk',
  E2E_MODEL: MODEL,
});

async function ledgerFor(agentId: string) {
  const r = await api('security', 'GET', `/ledger/records?agent=${agentId}&limit=200`);
  return r.json.items as Json[];
}

async function connection(agentId: string) {
  return (await api('security', 'GET', `/agents/${agentId}/connection`)).json;
}

export async function run() {
  await ensureTools();
  const stamp = Date.now().toString(36);

  head('Scenario 1: a self-hosted Python agent registers, is approved, and connects with the SDK');
  const { agentId, tier } = await onboard({
    handle: `py-agent-${stamp}`, name: 'Python agent', purpose: 'Answers internal order questions', intake: INTERNAL_INTAKE, manifest: MANIFEST,
    registration: { kind: 'self_hosted', runtime: 'docker', framework: 'custom-python', model_provider: 'openai-compatible' },
  }, say);
  let st = await connection(agentId);
  say(`${tier} sealed · connection ${st.state}: ${st.reason}`);
  check(st.state === 'credentials_not_provisioned', 'approved without credentials is not "connected"');
  const boot = await api('automation', 'POST', `/agents/${agentId}/bootstrap`, { environment: 'dev' });
  check(boot.status === 201, `bootstrap issued (${boot.status} ${JSON.stringify(boot.json)})`);
  st = await connection(agentId);
  check(st.state === 'not_connected', `bootstrap issued but unused is "not_connected", got ${st.state}`);
  say(`bootstrap issued · connection ${st.state}`);
  const py = python(join(REPO_ROOT, 'apps/e2e/python/agent_check.py'), { ...sdkEnv(boot.json.bootstrap_credential), E2E_TOOLS: '1' });
  say(`python identity ${py.identity.agent_id} instance ${py.identity.instance} · aud ${py.identity.aud}`);
  check(py.identity.agent_id === agentId && py.identity.aud === TOKEN_AUDIENCE, 'the token names this agent and the gateway audience');
  say(`model answered: ${String(py.model.content).trim().slice(0, 60)} (model ${py.model.model})`);
  check(String(py.model.content ?? '').trim().length > 0, 'the cloud LLM answered through the gateway');
  const records = await ledgerFor(agentId);
  const llm = records.find((r) => r.data.action_type === 'llm_call' && r.data.outcome === 'success');
  check(llm, 'a successful llm_call record is in the ledger');
  check(llm.data.latency_ms_upstream > 0 && llm.data.tokens_out > 0, 'the record shows a real upstream call (latency and tokens)');
  say(`ledger ${llm.record_id}: upstream ${llm.data.latency_ms_upstream} ms, ${llm.data.tokens_in}→${llm.data.tokens_out} tokens, auth ${llm.data.auth_kind}`);
  // C4: the stack scores every answer (SIGNET_EVAL_SAMPLE_RATE=1); the judge is the same cloud LLM.
  let evaluation: Json | undefined;
  for (let i = 0; i < 90 && !evaluation; i++) {
    evaluation = (await ledgerFor(agentId)).find((r) => r.data.action_type === 'evaluation' && r.data.request_id === llm.data.request_id);
    if (!evaluation) await new Promise((r) => setTimeout(r, 1000));
  }
  check(evaluation, 'the answer was scored by the judge and the scores are in the ledger');
  const sc = evaluation.data.scores as Json;
  check([sc.helpfulness, sc.safety, sc.on_policy].every((v) => typeof v === 'number' && v >= 1 && v <= 5), `judge scores are 1-5: ${JSON.stringify(sc)}`);
  say(`quality scored by ${evaluation.data.judge_model}: helpful ${sc.helpfulness} · safe ${sc.safety} · on-policy ${sc.on_policy} · flags ${JSON.stringify(evaluation.data.flags)}`);
  st = await connection(agentId);
  check(st.state === 'connected', `after real gateway traffic the agent is "connected", got ${st.state}`);
  check(st.diagnostics.length === 1 && st.diagnostics[0].bypass_risk === false, 'clean runtime: no bypass risk reported');
  say(`connection ${st.state}: ${st.reason}`);

  head('Scenario 3: MCP tool call through the gateway reaches the real MCP server');
  check(JSON.stringify(py.mcp_tools) === JSON.stringify(['lookup_order']), `tools/list is filtered to the seal, got ${py.mcp_tools}`);
  check(py.mcp_call?.structuredContent?.status === 'delivered', 'lookup_order executed downstream (credential injected by the gateway)');
  check(py.out_of_manifest?.decision === 'deny' && py.out_of_manifest?.code === 'out_of_manifest', 'delete_customer (not in the seal) is denied');
  const toolRecs = (await ledgerFor(agentId)).filter((r) => r.data.action_type === 'tool_call');
  check(toolRecs.some((r) => r.data.target === 'mcp://orders.lookup_order' && r.data.outcome === 'success'), 'MCP call recorded');
  check(toolRecs.some((r) => r.data.target === 'mcp://orders.delete_customer' && r.data.outcome === 'blocked'), 'refused MCP call recorded');
  say(`tools/list → ${py.mcp_tools}; lookup_order → ${py.mcp_call.structuredContent.status}; delete_customer → ${py.out_of_manifest.decision}`);

  head('Scenario 4: HTTP tool: permitted call, call outside the seal, SSRF and path traversal');
  check(py.http_tool?.tier === 'gold', 'get_customer executed downstream');
  const token = (await deployAgent(agentId)).token as string;
  const notInSeal = await gw(GW_A1, '/v1/tools/http/crm/add_note', token, { customer_id: 'C-1', text: 'x' });
  check(outcome(notInSeal) === 'deny', `add_note (registered tool, not in the seal) is denied, got ${outcome(notInSeal)}`);
  const traversal = await gw(GW_A1, '/v1/tools/http/crm/get_customer', token, { id: '..' });
  check(traversal.status !== 200, 'a ".." path parameter does not reach another path');
  const ssrf = await api('platform', 'POST', '/tools', { alias: `meta-${stamp}`, kind: 'http', url: 'http://169.254.169.254/latest', actions: { x: { method: 'GET', path: '/meta-data' } } });
  check(ssrf.status === 422 && ssrf.json.rule === 'SSRF', `a cloud metadata address is refused at registration, got ${ssrf.status}`);
  say(`get_customer → ${py.http_tool.tier}; add_note → ${outcome(notInSeal)}; ".." → ${traversal.status}; metadata URL → ${ssrf.status} ${ssrf.json.rule}`);

  head('Scenario 2: refused identities: invalid, wrong audience, expired, revoked, unapproved agent');
  const chat = { model: MODEL, messages: [{ role: 'user', content: 'hi' }], max_tokens: 20 };
  const bad = await gw(GW_A1, '/v1/chat/completions', 'not-a-token', chat);
  check(bad.status === 401 && bad.json.error?.code === 'invalid_token', 'garbage token refused');
  const claims = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()) as Json;
  const wrongAud = await gw(GW_A1, '/v1/chat/completions', forge({ ...claims, aud: 'someone-else', jti: newId('jti') }), chat);
  check(wrongAud.status === 401 && wrongAud.json.error?.code === 'invalid_token', 'token for another audience refused');
  const now = Math.floor(Date.now() / 1000);
  const expired = await gw(GW_A1, '/v1/chat/completions', forge({ ...claims, iat: now - 3600, exp: now - 60, jti: newId('jti') }), chat);
  check(expired.status === 401 && expired.json.error?.code === 'token_expired', 'expired token refused');
  const refreshExpired = await fetch(`${CONTROL}/api/v1/identity/token/refresh`, { method: 'POST', headers: { authorization: `Bearer ${forge({ ...claims, iat: now - 3600, exp: now - 60, jti: newId('jti') })}` } });
  check(refreshExpired.status === 401, 'an expired token cannot be refreshed');
  const inst = (await api('security', 'GET', `/agents/${agentId}/connection`)).json.identity.instances.find((i: Json) => i.id === claims.ins);
  const rev = await api('security', 'POST', `/instances/${inst.id}/revoke`, { reason: 'e2e: revocation check' });
  check(rev.status === 200 && rev.json.tokens_revoked >= 1, `instance revoked: ${rev.status} ${JSON.stringify(rev.json)}`);
  await new Promise((r) => setTimeout(r, 600)); // revocation list reaches both nodes
  for (const base of [GW_A1, GW_A2]) {
    const revoked = await gw(base, '/v1/chat/completions', token, chat);
    check(revoked.status === 401 && revoked.json.error?.code === 'token_revoked', `revoked token refused on ${base}`);
  }
  const refreshRevoked = await fetch(`${CONTROL}/api/v1/identity/token/refresh`, { method: 'POST', headers: { authorization: `Bearer ${token}` } });
  check(refreshRevoked.status === 401, 'a revoked instance cannot refresh');
  const unapproved = await api('owner', 'POST', '/agents', { handle: `unapproved-${stamp}`, name: 'Unapproved', purpose: 'Never approved agent', sponsor: 'ravi.kapoor@northwind.example', autonomy_level: 'L2', intake: INTERNAL_INTAKE });
  const noBoot = await api('automation', 'POST', `/agents/${unapproved.json.id}/bootstrap`, { environment: 'dev' });
  check(noBoot.status === 403, `an unapproved agent gets no bootstrap credential, got ${noBoot.status}`);
  const tenant = claims.tenant as string;
  const forgedUnapproved = forge({ iss: tokenIssuer(tenant), aud: TOKEN_AUDIENCE, sub: spiffeId(tenant, unapproved.json.id, 'v1.0'), agent_id: unapproved.json.id, ver: 'v1.0', cert_id: 'crt_none', ins: 'ins_none', tier: 'T3', tenant, kind: 'bootstrap' });
  const unapprovedCall = await gw(GW_A1, '/v1/chat/completions', forgedUnapproved, chat);
  check(unapprovedCall.status === 403 && unapprovedCall.json.error?.code === 'no_active_seal', 'a validly signed token for an unsealed agent is refused');
  st = await connection(agentId);
  say(`invalid → 401 · wrong aud → 401 · expired → 401 (refresh 401) · revoked → 401 on both nodes · unapproved → bootstrap 403, call ${unapprovedCall.status}`);
  say(`connection now ${st.state}: ${st.reason}`);
  check(st.state === 'connection_error', `after refused calls the agent shows a connection error, got ${st.state}`);

  head('Scenario 5: kill: model and tool calls refused on every node, no new identity');
  const t2 = (await deployAgent(agentId)).token as string;
  const okBefore = await mcp(GW_A1, 'orders', t2, 'tools/call', { name: 'lookup_order', arguments: { order_id: 'A-1182' } });
  check(outcome(okBefore) === 'allow', 'redeployed instance works before the kill');
  const kill = await api('security', 'POST', `/agents/${agentId}/ladder`, { action: 'kill', reason: 'e2e kill check', confirm_handle: `py-agent-${stamp}` });
  check(kill.status === 200 || kill.status === 201, `kill applied (${kill.status} ${JSON.stringify(kill.json).slice(0, 200)})`);
  await new Promise((r) => setTimeout(r, 600));
  for (const base of [GW_A1, GW_A2]) {
    const m = await gw(base, '/v1/chat/completions', t2, chat);
    const t = await mcp(base, 'orders', t2, 'tools/call', { name: 'lookup_order', arguments: { order_id: 'A-1182' } });
    check(m.status >= 400 && outcome(t) !== 'allow', `model and tool calls refused on ${base}`);
  }
  const reboot = await api('automation', 'POST', `/agents/${agentId}/bootstrap`, { environment: 'dev' });
  check(reboot.status === 403, 'a killed agent gets no new bootstrap credential');
  st = await connection(agentId);
  check(st.state === 'revoked', `killed agent shows "revoked", got ${st.state}`);
  say(`model and tool calls refused on both nodes · bootstrap ${reboot.status} · connection ${st.state}`);

  head('Scenario 6: a third-party (vendor-hosted) agent: tools only, OAuth client credentials');
  const vendorManifest = { ...MANIFEST, models: [] };
  const tp = await onboard({
    handle: `copilot-orders-${stamp}`, name: 'Copilot order helper', purpose: 'Vendor-hosted assistant that looks up orders', intake: INTERNAL_INTAKE, manifest: vendorManifest,
    registration: { kind: 'third_party', vendor: 'Microsoft Copilot Studio', runtime: 'vendor', vendor_details: { contract: 'MSA-2026-114', data_residency: 'EU' } },
    hooks: {
      drafted: async (lc) => {
        const withModel = await api('owner', 'PUT', `/lifecycles/${lc}/manifest`, MANIFEST);
        check(withModel.status === 422, `a model grant for a vendor agent is refused (${withModel.status})`);
        say(`manifest with a model → ${withModel.status}: ${withModel.json.detail}`);
      },
    },
  }, say);
  const tpBoot = await api('automation', 'POST', `/agents/${tp.agentId}/bootstrap`, { environment: 'dev' });
  check(tpBoot.status === 409, 'third-party agents get no bootstrap credential');
  st = await connection(tp.agentId);
  check(st.state === 'credentials_not_provisioned' && st.coverage.model_calls === 'not_intercepted', 'vendor agent: no credentials yet; model calls reported as not intercepted');
  const client = await api('platform', 'POST', `/agents/${tp.agentId}/clients`, { label: 'Copilot Studio connector' });
  check(client.status === 201 && client.json.client_secret, 'client credentials created');
  // The vendor platform's OAuth request: form-encoded with HTTP Basic client authentication.
  const form = await fetch(`${CONTROL}/api/v1/identity/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${client.json.client_id}:${client.json.client_secret}`).toString('base64')}` },
    body: 'grant_type=client_credentials',
  });
  const tok = (await form.json()) as Json;
  check(form.status === 200 && tok.access_token, `OAuth client credentials exchange (${form.status})`);
  const vendorCall = await gw(GW_A1, '/v1/tools/http/crm/get_customer', tok.access_token, { id: 'C-7781' });
  check(outcome(vendorCall) === 'allow', 'vendor agent called a protected company tool through the gateway');
  const vendorModel = await gw(GW_A1, '/v1/chat/completions', tok.access_token, chat);
  check(vendorModel.status >= 400, 'vendor agent cannot use the Signet model route (it has no model grant)');
  const vrec = (await ledgerFor(tp.agentId)).find((r) => r.data.target === 'http://crm.get_customer');
  check(vrec?.data.auth_kind === 'client_credentials' && vrec.agent_id === tp.agentId, 'tool call attributed to the vendor agent and its client');
  st = await connection(tp.agentId);
  check(st.state === 'connected', `vendor agent connected after a governed tool call, got ${st.state}`);
  const wrongSecret = await fetch(`${CONTROL}/api/v1/identity/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'client_credentials', client_id: client.json.client_id, client_secret: 'wrong' }) });
  check(wrongSecret.status === 401, 'wrong client secret refused');
  await api('platform', 'POST', `/clients/${client.json.client_id}/revoke`, { reason: 'e2e: vendor offboarded' });
  await new Promise((r) => setTimeout(r, 600));
  const afterRevoke = await gw(GW_A1, '/v1/tools/http/crm/get_customer', tok.access_token, { id: 'C-7781' });
  check(afterRevoke.status === 401, 'revoked vendor client: its token is refused');
  const reExchange = await fetch(`${CONTROL}/api/v1/identity/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'client_credentials', client_id: client.json.client_id, client_secret: client.json.client_secret }) });
  check(reExchange.status === 401, 'revoked vendor client cannot get a new token');
  say(`bootstrap ${tpBoot.status} · OAuth ${form.status} · tool ${outcome(vendorCall)} · model ${vendorModel.status} · auth_kind ${vrec!.data.auth_kind} · after revoke ${afterRevoke.status}/${reExchange.status}`);

  head('Scenario 7: bypass detection: provider credentials in the runtime, direct AI traffic in network logs');
  const b = await onboard({ handle: `leaky-agent-${stamp}`, name: 'Leaky agent', purpose: 'Agent whose runtime still holds a provider key', intake: INTERNAL_INTAKE, manifest: MANIFEST, registration: { kind: 'framework', framework: 'langchain', runtime: 'runpod' } }, say);
  const boot2 = await api('automation', 'POST', `/agents/${b.agentId}/bootstrap`, { environment: 'dev' });
  const leaky = python(join(REPO_ROOT, 'apps/e2e/python/agent_check.py'), { ...sdkEnv(boot2.json.bootstrap_credential), OPENAI_API_KEY: 'sk-e2e-placeholder-not-a-real-key', OPENAI_BASE_URL: 'https://api.openai.com/v1' });
  check(String(leaky.model.content ?? '').length > 0, 'the agent still works through Signet');
  st = await connection(b.agentId);
  const diag = st.diagnostics[0];
  check(diag?.bypass_risk === true, 'the SDK reported a bypass risk');
  const names = (diag.report.env_findings as Json[]).map((f) => f.name).sort();
  check(JSON.stringify(names) === JSON.stringify(['OPENAI_API_KEY', 'OPENAI_BASE_URL']), `names reported: ${names}`);
  check(!JSON.stringify(diag.report).includes('sk-e2e-placeholder'), 'the key value never left the agent');
  const findings = (await api('platform', 'GET', '/discovered-assets')).json.items as Json[];
  const f = findings.find((x) => x.type === 'bypass_risk' && x.agent_id === b.agentId);
  check(f && JSON.parse(f.evidence).detected_not_enforced === true, 'a Discovery finding marks it as detected, not enforced');
  say(`diagnostics: ${names.join(', ')} → finding ${f.id} (${f.summary.slice(0, 80)}…)`);
  const logs = await api('platform', 'POST', '/discovery/logs', {
    source: 'network-logs',
    gateway_hosts: ['signet-gw-egress'],
    records: [
      { ts: new Date().toISOString(), src: 'build-runner-7', host: 'api.openai.com' },
      { ts: new Date().toISOString(), src: 'build-runner-7', url: 'https://api.openai.com/v1/chat/completions' },
      { ts: new Date().toISOString(), src: 'signet-gw-egress', host: 'ollama.com' },
      { ts: new Date().toISOString(), src: 'laptop-114', user: 'sam@northwind.example', host: 'chatgpt.com' },
      { ts: new Date().toISOString(), src: 'build-runner-7', host: 'github.com' },
    ],
  });
  check(logs.status === 201 && logs.json.ai_matches === 3 && logs.json.new === 2, `log ingestion: ${JSON.stringify(logs.json)}`);
  const srcs = (await api('platform', 'GET', '/discovery/sources')).json.items as Json[];
  check(srcs.find((x) => x.id === 'network-logs')?.connected === true && srcs.find((x) => x.id === 'saas-audit')?.connected === false, 'source status reflects what actually delivered data');
  say(`network logs: ${logs.json.received} records, ${logs.json.ai_matches} AI matches (gateway egress skipped), ${logs.json.new} findings; SaaS audit source still not connected`);

  head('No-code agent through the sidecar: the framework keeps its own (fake) API key, Signet ignores it');
  const nc = await onboard({ handle: `n8n-flow-${stamp}`, name: 'n8n flow', purpose: 'No-code workflow that summarises orders', intake: INTERNAL_INTAKE, manifest: MANIFEST, registration: { kind: 'no_code', framework: 'n8n', runtime: 'docker' } }, say);
  const boot3 = await api('automation', 'POST', `/agents/${nc.agentId}/bootstrap`, { environment: 'dev' });
  const port = 8390;
  const sidecar = spawn(process.execPath, ['--import', 'tsx', join(REPO_ROOT, 'apps/sidecar/src/index.ts')], {
    cwd: join(REPO_ROOT, 'apps/sidecar'),
    env: { ...process.env, SIGNET_GATEWAY_URL: GW_A2, SIGNET_CONTROL_URL: CONTROL, SIGNET_BOOTSTRAP_CREDENTIAL: boot3.json.bootstrap_credential, SIGNET_SIDECAR_PORT: String(port) },
    stdio: 'ignore',
  });
  try {
    let status: Json = {};
    for (let i = 0; i < 60 && !status.identity; i++) {
      await new Promise((r) => setTimeout(r, 250));
      status = (await fetch(`http://127.0.0.1:${port}/signet/status`).then((r) => r.json()).catch(() => ({}))) as Json;
    }
    check(status.identity?.agent_id === nc.agentId, `sidecar holds the agent's identity (${JSON.stringify(status)})`);
    const viaSidecar = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer sk-whatever-n8n-insists-on' },
      body: JSON.stringify({ model: MODEL, messages: [{ role: 'user', content: 'Reply with exactly one word: sidecar' }], max_tokens: 200 }),
    });
    const sbody = (await viaSidecar.json()) as Json;
    check(viaSidecar.status === 200 && String(sbody.choices?.[0]?.message?.content ?? '').length > 0, `model call through the sidecar (${viaSidecar.status} ${JSON.stringify(sbody).slice(0, 200)})`);
    const viaMcp = await fetch(`http://127.0.0.1:${port}/v1/mcp/orders`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'lookup_order', arguments: { order_id: 'A-1182' } } }) });
    const mbody = (await viaMcp.json()) as Json;
    check(mbody.result?.structuredContent?.status === 'delivered', 'MCP call through the sidecar');
    st = await connection(nc.agentId);
    check(st.state === 'connected', `no-code agent connected via the sidecar, got ${st.state}`);
    say(`sidecar identity ${status.identity.instance} · model ${viaSidecar.status} "${String(sbody.choices[0].message.content).trim().slice(0, 30)}" · MCP ${mbody.result.structuredContent.status} · connection ${st.state}`);
  } finally {
    sidecar.kill();
  }

  void TOOLS_URL;
}

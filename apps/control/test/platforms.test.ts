import { strict as assert } from 'node:assert';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';
import type { CreateInput } from '../src/platforms';

// Platform connectors against one local stand-in for the platform APIs Signet calls (Vercel, AWS STS,
// Bedrock Agents and Lambda, Azure login and Resource Manager, Google token, Vertex AI and Cloud Run).
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-plat-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);

const VERCEL_TOKEN = 'vercel-test-token-1234567890';
const calls: { method: string; host: string; path: string; body: unknown; auth: string | undefined }[] = [];
const lambdaEnv: Record<string, string> = { OPENAI_API_KEY: 'sk-provider-value', DATABASE_URL: 'postgres://keep-me' };
const appSettings: Record<string, string> = { AZURE_OPENAI_API_KEY: 'azure-provider-value', WEBSITE_NODE_DEFAULT_VERSION: '~20' };
const SUB = '/subscriptions/sub1';
const SITE = `${SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/hospital-api`;

const readBody = (req: IncomingMessage) => new Promise<string>((resolve) => { let s = ''; req.on('data', (c) => (s += c)); req.on('end', () => resolve(s)); });
const fake = createServer(async (req, res) => {
  const [, host, ...rest] = req.url!.split('/');
  const url = new URL(`https://${host}/${rest.join('/')}`);
  const raw = await readBody(req);
  let body: unknown = raw;
  try { body = raw ? JSON.parse(raw) : null; } catch { /* form or empty */ }
  calls.push({ method: req.method!, host: host!, path: url.pathname, body, auth: req.headers.authorization });
  const json = (status: number, v: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(v));
  const p = url.pathname;
  if (host === 'api.vercel.com') {
    if (req.headers.authorization !== `Bearer ${VERCEL_TOKEN}`) return json(403, { error: { message: 'Not authorized' } });
    if (p === '/v2/user') return json(200, { user: { username: 'hospital-team' } });
    if (p === '/v9/projects') return json(200, { projects: [{ id: 'prj_hosp', name: 'signethost', framework: 'vite', targets: { production: { url: 'signethost.vercel.app' } } }, { id: 'prj_blog', name: 'blog', framework: 'nextjs' }] });
    if (p === '/v9/projects/prj_hosp/env') return json(200, { envs: [{ id: 'e1', key: 'GROQ_API_KEY' }, { id: 'e2', key: 'OPENAI_BASE_URL' }, { id: 'e3', key: 'DATABASE_URL' }, { id: 'e4', key: 'OPENAI_MODEL' }] });
    if (p === '/v9/projects/prj_blog/env') return json(200, { envs: [{ id: 'b1', key: 'NEXT_PUBLIC_SITE' }] });
    if (p === '/v10/projects/prj_hosp/env') return json(201, {});
    if (p.startsWith('/v9/projects/prj_hosp/env/') && req.method === 'DELETE') return json(200, {});
    if (p === '/v6/deployments') return json(200, { deployments: [{ uid: 'dpl_prev' }] });
    if (p === '/v13/deployments' && req.method === 'POST') return json(200, { id: 'dpl_new' });
    if (p === '/v13/deployments/dpl_new') return json(200, { readyState: 'READY' });
  }
  if (host!.endsWith('amazonaws.com')) {
    assert.match(String(req.headers.authorization), /^AWS4-HMAC-SHA256 Credential=AKIATEST\//);
    if (host === 'sts.amazonaws.com') return res.writeHead(200, { 'content-type': 'text/xml' }).end('<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::111122223333:user/signet</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>');
    if (host === 'bedrock-agent.us-east-1.amazonaws.com' && p === '/agents/') return json(200, { agentSummaries: [{ agentId: 'AG1', agentName: 'claims-bot', agentStatus: 'PREPARED' }] });
    if (host === 'lambda.us-east-1.amazonaws.com') {
      if (p === '/2015-03-31/functions/') return json(200, { Functions: [{ FunctionName: 'triage-fn', Runtime: 'python3.12', Environment: { Variables: lambdaEnv } }] });
      if (p === '/2015-03-31/functions/triage-fn/configuration' && req.method === 'GET') return json(200, { Environment: { Variables: lambdaEnv }, LastUpdateStatus: 'Successful' });
      if (p === '/2015-03-31/functions/triage-fn/configuration' && req.method === 'PUT') return json(200, {});
    }
  }
  if (host === 'login.microsoftonline.com') return json(200, { access_token: 'azure-token' });
  if (host === 'management.azure.com') {
    assert.equal(req.headers.authorization, 'Bearer azure-token');
    if (p === SUB) return json(200, { displayName: 'Hospital prod' });
    if (p === `${SUB}/resources`) return json(200, { value: [
      { id: `${SUB}/x/openai1`, name: 'hospital-openai', type: 'Microsoft.CognitiveServices/accounts', kind: 'OpenAI', location: 'eastus' },
      { id: `${SUB}/x/hub1`, name: 'care-foundry', type: 'Microsoft.MachineLearningServices/workspaces', kind: 'Project', location: 'eastus' },
      { id: SITE, name: 'hospital-api', type: 'Microsoft.Web/sites', kind: 'app,linux', location: 'eastus' },
    ] });
    if (p === `${SITE}/config/appsettings/list`) return json(200, { properties: appSettings });
    if (p === `${SITE}/config/appsettings` && req.method === 'PUT') return json(200, {});
    if (p === `${SITE}/restart`) return json(200, {});
    if (p === SITE) return json(200, { properties: { state: 'Running' } });
  }
  if (host === 'oauth2.googleapis.com') {
    assert.equal(String((raw.match(/assertion=([^&]+)/)?.[1] ?? '')).split('.').length, 3, 'a signed JWT assertion');
    return json(200, { access_token: 'gcp-token' });
  }
  if (host === 'cloudresourcemanager.googleapis.com') return json(200, { name: 'Hospital AI' });
  if (host === 'us-central1-aiplatform.googleapis.com') return json(200, { reasoningEngines: [{ name: 'projects/p1/locations/us-central1/reasoningEngines/123', displayName: 'support-agent' }] });
  if (host === 'run.googleapis.com') {
    const svc = { name: 'projects/p1/locations/us-central1/services/chat-api', uri: 'https://chat-api.run.app', template: { containers: [{ image: 'gcr.io/p1/chat', env: [{ name: 'GEMINI_API_KEY', value: 'g-provider-value' }, { name: 'PORT', value: '8080' }] }] } };
    if (p.endsWith('/services')) return json(200, { services: [svc] });
    if (p === '/v2/projects/p1/locations/us-central1/services/chat-api' && req.method === 'GET') return json(200, svc);
    if (p === '/v2/projects/p1/locations/us-central1/services/chat-api' && req.method === 'PATCH') return json(200, { name: 'projects/p1/locations/us-central1/operations/op1' });
    if (p === '/v2/projects/p1/locations/us-central1/operations/op1') return json(200, { done: true });
  }
  if (host === 'monitoring.us-east-1.amazonaws.com') {
    assert.equal(req.headers['x-amz-target'], 'GraniteServiceVersion20100801.GetMetricData');
    return json(200, { MetricDataResults: [
      { Id: 'i', Label: 'anthropic.claude-v2 InputTokenCount', Timestamps: [1793577600], Values: [5000] },
      { Id: 'o', Label: 'anthropic.claude-v2 OutputTokenCount', Timestamps: [1793577600], Values: [800] },
      { Id: 'n', Label: 'anthropic.claude-v2 Invocations', Timestamps: [1793577600], Values: [40] },
    ] });
  }
  if (host === 'management.azure.com' && p.endsWith('/providers/Microsoft.Insights/metrics')) return json(200, { value: [
    { name: { value: 'ProcessedPromptTokens' }, timeseries: [{ data: [{ timeStamp: '2026-11-02T00:00:00Z', total: 900 }] }] },
    { name: { value: 'GeneratedTokens' }, timeseries: [{ data: [{ timeStamp: '2026-11-02T00:00:00Z', total: 100 }] }] },
    { name: { value: 'AzureOpenAIRequests' }, timeseries: [{ data: [{ timeStamp: '2026-11-02T00:00:00Z', total: 12 }] }] },
  ] });
  if (host === 'monitoring.googleapis.com') {
    const metric = url.searchParams.get('filter') ?? '';
    if (metric.includes('token_count')) return json(200, { timeSeries: [
      { metric: { labels: { type: 'input' } }, resource: { labels: { model_user_id: 'gemini-2.0-flash' } }, points: [{ interval: { startTime: '2026-11-02T00:00:00Z' }, value: { int64Value: '3000' } }] },
      { metric: { labels: { type: 'output' } }, resource: { labels: { model_user_id: 'gemini-2.0-flash' } }, points: [{ interval: { startTime: '2026-11-02T00:00:00Z' }, value: { int64Value: '700' } }] },
    ] });
    return json(200, { timeSeries: [{ resource: { labels: { model_user_id: 'gemini-2.0-flash' } }, points: [{ interval: { startTime: '2026-11-02T00:00:00Z' }, value: { int64Value: '25' } }] }] });
  }
  if (host === 'hospital.crm.dynamics.com') {
    if (p === '/api/data/v9.2/WhoAmI') return json(200, { OrganizationId: 'org-1' });
    if (p === '/api/data/v9.2/bots') return json(200, { value: [{ botid: 'b1', name: 'Patient FAQ copilot', statecode: 0 }] });
  }
  if (host === 'api.openai.com') {
    assert.equal(req.headers.authorization, 'Bearer sk-admin-openai-test-123');
    if (p === '/v1/organization/projects') return json(200, { data: [{ id: 'proj_1', name: 'Marketing' }] });
    if (p === '/v1/organization/projects/proj_1/api_keys' && req.method === 'GET') return json(200, { data: [{ id: 'key_1', name: 'campaign-bot', last_used_at: 1793600000, owner: { user: { email: 'sam@hospital.test' } } }] });
    if (p === '/v1/organization/projects/proj_1/api_keys/key_1' && req.method === 'DELETE') return json(200, { deleted: true });
    if (p === '/v1/organization/usage/completions') return json(200, { data: [{ start_time: 1793577600, results: [{ project_id: 'proj_1', api_key_id: 'key_1', input_tokens: 1200, output_tokens: 300, num_model_requests: 7 }] }] });
  }
  if (host === 'api.anthropic.com') {
    assert.equal(req.headers['x-api-key'], 'sk-ant-admin-test-123');
    if (p === '/v1/organizations/workspaces') return json(200, { data: [] });
    if (p === '/v1/organizations/usage_report/messages') return json(200, { data: [{ starting_at: '2026-11-02T00:00:00Z', results: [{ api_key_id: 'apikey_1', uncached_input_tokens: 400, cache_read_input_tokens: 100, output_tokens: 50 }] }] });
    if (p === '/v1/organizations/api_keys') return json(200, { data: [{ id: 'apikey_1', name: 'research-notebook', status: 'active', workspace_id: null }] });
    if (p === '/v1/organizations/api_keys/apikey_1' && req.method === 'POST') return json(200, { status: 'inactive' });
  }
  if (host === 'api.vercel.com' && p === '/v1/projects/prj_hosp/pause') return json(200, {});
  if (host === 'lambda.us-east-1.amazonaws.com' && p === '/2017-10-31/functions/triage-fn/concurrency') return json(200, { ReservedConcurrentExecutions: 0 });
  json(404, { error: { message: `unexpected ${req.method} ${host}${p}` } });
});
await new Promise<void>((r) => fake.listen(0, '127.0.0.1', r));
process.env.SIGNET_PLATFORM_API_OVERRIDE = `http://127.0.0.1:${(fake.address() as { port: number }).port}`;

after(async () => {
  fake.close();
  await dropTestDatabase();
});

const { permissionsFor } = await import('../src/rbac');
const platforms = await import('../src/platforms');
const { registerAgent, issueSeal, getAgent } = await import('../src/registry');
const discovery = await import('../src/discovery');
const { db } = await import('../src/db');
const { exchangeDeploymentCredential } = await import('../src/deployment-identity');
const admin: Principal = { id: 'admin', name: 'admin', kind: 'human', roles: ['platform_admin', 'agent_owner'], permissions: permissionsFor(['platform_admin', 'agent_owner']), groups: [], mfa: true, auth: 'session', auth_time: null };
const security: Principal = { ...admin, id: 'sec@example.test', roles: ['security_officer'], permissions: permissionsFor(['security_officer']) };
let n = 0;
async function sealedAgent() {
  const agent = await registerAgent({ handle: `hosp-agent-${++n}`, name: 'Hospital agent', purpose: 'Hospital assistant for patients', sponsor: 'ravi@example.test', tier: 'T3', autonomy_level: 'L2' }, admin);
  await issueSeal(agent.id, { models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }], tools: [], limits: { rpm: 60, tokens_per_day: 1000, usd_per_day: 1 }, environments: ['dev'] }, security);
  return agent;
}

test('Vercel: finds AI projects, then connects one to Signet without a code change', async () => {
  const { saveConnectionAddresses } = await import('../src/connection-settings');
  await saveConnectionAddresses({ control_url: 'https://control.signet.example.test', gateway_url: 'https://signet.example.test' }, admin);
  await assert.rejects(platforms.create({ platform: 'vercel', token: 'wrong-token-1234567890' }, admin), /403|Not authorized/);
  const conn = await platforms.create({ platform: 'vercel', token: VERCEL_TOKEN }, admin);
  assert.equal(conn.status, 'connected');
  const secretId = ((await db.prepare('SELECT secret_id FROM platform_connection WHERE id = ?').get(conn.id)) as { secret_id: string }).secret_id;
  const secretsModule = await import('../src/secrets');
  await assert.rejects(secretsModule.revealForGateway(secretId), /not found/, 'gateways can never read a platform credential');

  const ws = await platforms.workloads(conn.id);
  assert.deepEqual(ws.find((w) => w.name === 'signethost')!.ai_signals.map((s) => s.name).sort(), ['GROQ_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_MODEL']);
  assert.equal(ws.find((w) => w.name === 'blog')!.ai_signals.length, 0);
  assert.deepEqual(await platforms.scan(conn.id, admin), { workloads: 2, ai_workloads: 1, new_findings: 1 });
  assert.ok(((await discovery.list()) as { summary: string }[]).some((f) => f.summary.includes('signethost') && f.summary.includes('Groq')));

  const unsealed = await registerAgent({ handle: 'not-yet', name: 'Not yet', purpose: 'Waiting for approval', sponsor: 'ravi@example.test', tier: 'T3', autonomy_level: 'L2' }, admin);
  const input = { base_url_var: 'OPENAI_BASE_URL', key_var: 'OPENAI_API_KEY', model_var: 'OPENAI_MODEL', remove_vars: ['GROQ_API_KEY'] };
  await assert.rejects(platforms.link(conn.id, 'prj_hosp', { ...input, agent_id: unsealed.id }, admin), /no seal yet/);
  const agent = await sealedAgent();
  calls.length = 0;
  const link = await platforms.link(conn.id, 'prj_hosp', { ...input, agent_id: agent.id }, admin) as { state: string };
  assert.equal(link.state, 'redeploying');
  const set = calls.find((c) => c.path === '/v10/projects/prj_hosp/env')!.body as { key: string; value: string; type: string }[];
  assert.deepEqual(set.map((v) => v.key), ['OPENAI_BASE_URL', 'OPENAI_API_KEY', 'OPENAI_MODEL']);
  assert.equal(set[0]!.value, 'https://signet.example.test/v1');
  assert.equal(set[2]!.value, 'gpt-oss:120b-cloud');
  assert.ok(set.every((v) => v.type === 'encrypted'));
  assert.ok(calls.some((c) => c.method === 'DELETE' && c.path.endsWith('/env/e1')), 'the old Groq key is removed');
  assert.ok(!calls.some((c) => c.method === 'DELETE' && c.path.endsWith('/env/e3')), 'unrelated variables stay');
  assert.equal(((await platforms.linkStatus(conn.id, 'prj_hosp')) as { state: string }).state, 'connected_pending_traffic');
  assert.equal((await exchangeDeploymentCredential(set[1]!.value)).claims.agent_id, agent.id, 'the key put on Vercel works for this agent only');
});

test('AWS: Bedrock agents are discovered and registered as third-party; a Lambda function is connected', async () => {
  const conn = await platforms.create({ platform: 'aws', access_key_id: 'AKIATEST', secret_access_key: 'secret-test-key-123456', regions: 'us-east-1' }, admin);
  assert.match(String(conn.status_detail), /arn:aws:iam::111122223333:user\/signet/);
  const ws = await platforms.workloads(conn.id);
  const bedrock = ws.find((w) => w.kind === 'bedrock_agent')!;
  assert.equal(bedrock.name, 'claims-bot');
  assert.equal(bedrock.linkable, false);
  assert.equal(bedrock.ai_signals[0]!.kind, 'platform');
  const fn = ws.find((w) => w.kind === 'lambda')!;
  assert.deepEqual(fn.env_names, ['DATABASE_URL', 'OPENAI_API_KEY']);
  const reg = await platforms.register(conn.id, bedrock.id, admin);
  const registered = await getAgent(reg.agent_id);
  assert.equal(registered.kind, 'third_party');
  assert.equal(registered.vendor, 'Amazon Bedrock agent');
  await assert.rejects(platforms.link(conn.id, bedrock.id, { agent_id: reg.agent_id, base_url_var: 'X', key_var: 'Y' }, admin), /cannot be changed by Signet/);

  const agent = await sealedAgent();
  calls.length = 0;
  const link = await platforms.link(conn.id, fn.id, { agent_id: agent.id, base_url_var: 'OPENAI_BASE_URL', key_var: 'OPENAI_API_KEY' }, admin) as { state: string };
  const put = calls.find((c) => c.method === 'PUT' && c.path.endsWith('/configuration'))!.body as { Environment: { Variables: Record<string, string> } };
  assert.equal(put.Environment.Variables.DATABASE_URL, 'postgres://keep-me', 'other variables are written back unchanged');
  assert.equal(put.Environment.Variables.OPENAI_BASE_URL, 'https://signet.example.test/v1');
  assert.match(put.Environment.Variables.OPENAI_API_KEY!, /^sdc_/, 'the provider key is replaced by a Signet credential');
  assert.equal(link.state, 'redeploying');
  assert.equal(((await platforms.linkStatus(conn.id, fn.id)) as { state: string }).state, 'connected_pending_traffic');
});

test('Azure: OpenAI and AI Foundry resources are discovered; an App Service app is connected', async () => {
  const conn = await platforms.create({ platform: 'azure', tenant_id: 't1', client_id: 'c1', client_secret: 'azure-secret-123', subscription_id: 'sub1' }, admin);
  const ws = await platforms.workloads(conn.id);
  assert.deepEqual(ws.map((w) => w.kind).sort(), ['ai_account', 'ai_foundry', 'app_service']);
  assert.equal(ws.find((w) => w.kind === 'ai_account')!.platform_ai, 'Azure OpenAI');
  const app = ws.find((w) => w.kind === 'app_service')!;
  assert.deepEqual(app.ai_signals.map((s) => s.name), ['AZURE_OPENAI_API_KEY']);
  const scan = await platforms.scan(conn.id, admin);
  assert.equal(scan.ai_workloads, 3);
  const agent = await sealedAgent();
  calls.length = 0;
  await platforms.link(conn.id, app.id, { agent_id: agent.id, base_url_var: 'OPENAI_BASE_URL', key_var: 'OPENAI_API_KEY', remove_vars: ['AZURE_OPENAI_API_KEY'] }, admin);
  const put = calls.find((c) => c.method === 'PUT' && c.path.endsWith('/config/appsettings'))!.body as { properties: Record<string, string> };
  assert.equal(put.properties.WEBSITE_NODE_DEFAULT_VERSION, '~20');
  assert.equal(put.properties.AZURE_OPENAI_API_KEY, undefined, 'the Azure OpenAI key is removed');
  assert.match(put.properties.OPENAI_API_KEY!, /^sdc_/);
  assert.ok(calls.some((c) => c.path.endsWith('/restart')), 'the app is restarted');
  assert.equal(((await platforms.linkStatus(conn.id, app.id)) as { state: string }).state, 'connected_pending_traffic');
});

test('Google Cloud: Vertex AI agents and Cloud Run services are discovered with a service account', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = JSON.stringify({ client_email: 'signet@p1.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }), project_id: 'p1' });
  const conn = await platforms.create({ platform: 'gcp', service_account_json: key, regions: 'us-central1' }, admin);
  assert.match(String(conn.status_detail), /Hospital AI/);
  const ws = await platforms.workloads(conn.id);
  assert.equal(ws.find((w) => w.kind === 'vertex_agent')!.name, 'support-agent');
  const run = ws.find((w) => w.kind === 'cloud_run')!;
  assert.deepEqual(run.ai_signals.map((s) => s.name), ['GEMINI_API_KEY']);
  const agent = await sealedAgent();
  calls.length = 0;
  const link = await platforms.link(conn.id, run.id, { agent_id: agent.id, base_url_var: 'OPENAI_BASE_URL', key_var: 'OPENAI_API_KEY', remove_vars: ['GEMINI_API_KEY'] }, admin) as { state: string };
  assert.equal(link.state, 'redeploying');
  const patch = calls.find((c) => c.method === 'PATCH')!.body as { template: { containers: { image: string; env: { name: string; value: string }[] }[] } };
  const env = patch.template.containers[0]!.env;
  assert.equal(patch.template.containers[0]!.image, 'gcr.io/p1/chat', 'the rest of the template is kept');
  assert.deepEqual(env.map((e) => e.name).sort(), ['OPENAI_API_KEY', 'OPENAI_BASE_URL', 'PORT']);
  assert.match(env.find((e) => e.name === 'OPENAI_API_KEY')!.value, /^sdc_/);
  assert.equal(((await platforms.linkStatus(conn.id, run.id)) as { state: string }).state, 'connected_pending_traffic');
  assert.deepEqual(await platforms.syncUsage(conn.id, 7), { rows: 1, supported: true });
});

test('Copilot Studio, OpenAI and Anthropic: agents and direct API keys are discovered; usage outside Signet is pulled', async () => {
  const copilot = await platforms.create({ platform: 'copilot', tenant_id: 't1', client_id: 'c1', client_secret: 'copilot-secret-1', environment_url: 'https://hospital.crm.dynamics.com' }, admin);
  assert.equal((await platforms.workloads(copilot.id))[0]!.platform_ai, 'Microsoft Copilot Studio agent');
  const openai = await platforms.create({ platform: 'openai', admin_key: 'sk-admin-openai-test-123' }, admin);
  const key = (await platforms.workloads(openai.id))[0]!;
  assert.equal(key.kind, 'api_key');
  assert.equal(key.framework, 'sam@hospital.test', 'the key owner is shown');
  assert.deepEqual(await platforms.syncUsage(openai.id, 7), { rows: 1, supported: true });
  const outside = (await platforms.usageSummary(30)) as { workload_id: string; input_tokens: number; requests: number }[];
  const own = outside.find((u) => u.workload_id === 'openai:proj_1:key_1')!;
  assert.deepEqual([Number(own.input_tokens), Number(own.requests)], [1200, 7]);
  const anthropic = await platforms.create({ platform: 'anthropic', admin_key: 'sk-ant-admin-test-123' }, admin);
  assert.equal((await platforms.workloads(anthropic.id))[0]!.name, 'research-notebook');
  calls.length = 0;
  await platforms.stop(anthropic.id, 'anthropic:apikey_1', 'shadow AI found in the research team', 'admin');
  assert.deepEqual(calls.find((c) => c.path === '/v1/organizations/api_keys/apikey_1')!.body, { status: 'inactive' });
  await assert.rejects(platforms.stop(openai.id, key.id, '', 'admin'), /reason is required/);
  const { costs } = await import('../src/costs');
  const report = await costs(30);
  assert.ok(report.outside_signet.some((u) => (u as { workload_id: string }).workload_id === 'openai:proj_1:key_1'));
});

test('kill stops linked workloads on their platform (Vercel paused, Lambda concurrency 0)', async () => {
  const enforcement = await import('../src/enforcement');
  enforcement.setKillListener(platforms.stopLinkedWorkloads);
  const linked = (await db.prepare("SELECT agent_id, workload_id FROM platform_link WHERE state <> 'registered' ORDER BY workload_id").all()) as { agent_id: string; workload_id: string }[];
  const vercelAgent = linked.find((l) => l.workload_id === 'prj_hosp')!.agent_id;
  calls.length = 0;
  await platforms.stopLinkedWorkloads(vercelAgent, 'leaked data', 'admin');
  assert.ok(calls.some((c) => c.path === '/v1/projects/prj_hosp/pause' && c.method === 'POST'), 'the Vercel project is paused');
  const lambdaAgent = linked.find((l) => l.workload_id.startsWith('lambda:'))!.agent_id;
  calls.length = 0;
  await enforcement.applyLadder({ agentId: lambdaAgent }, 'kill', { actor: 'admin', reason: 'test kill' } as never);
  for (let i = 0; i < 50 && !calls.some((c) => c.path.endsWith('/concurrency')); i++) await new Promise((r) => setTimeout(r, 50));
  assert.deepEqual(calls.find((c) => c.path.endsWith('/concurrency'))!.body, { ReservedConcurrentExecutions: 0 }, 'a kill in Signet stops the Lambda function');
  const state = ((await db.prepare('SELECT state FROM platform_link WHERE agent_id = ?').get(lambdaAgent)) as { state: string }).state;
  assert.equal(state, 'stopped');
});

test('usage outside Signet from AWS CloudWatch and Azure Monitor; scheduled sweep covers every platform', async () => {
  const conns = await platforms.list();
  const aws = conns.find((c) => c.platform === 'aws')!;
  const azure = conns.find((c) => c.platform === 'azure')!;
  assert.deepEqual(await platforms.syncUsage(aws.id, 7), { rows: 1, supported: true });
  assert.deepEqual(await platforms.syncUsage(azure.id, 7), { rows: 1, supported: true });
  const rows = (await platforms.usageSummary(30)) as { workload_id: string; input_tokens: number; output_tokens: number; requests: number }[];
  const bedrock = rows.find((r) => r.workload_id === 'bedrock-model:us-east-1:anthropic.claude-v2')!;
  assert.deepEqual([Number(bedrock.input_tokens), Number(bedrock.output_tokens), Number(bedrock.requests)], [5000, 800, 40]);
  const openaiAccount = rows.find((r) => r.workload_id.endsWith('/x/openai1'))!;
  assert.deepEqual([Number(openaiAccount.input_tokens), Number(openaiAccount.output_tokens), Number(openaiAccount.requests)], [900, 100, 12]);
  const vertex = rows.find((r) => r.workload_id === 'vertex-model:gemini-2.0-flash')!;
  assert.deepEqual([Number(vertex.input_tokens), Number(vertex.output_tokens), Number(vertex.requests)], [3000, 700, 25]);
  await platforms.sweepUsage();
  assert.ok(((await platforms.list()).every((c) => c.status === 'connected')), 'the sweep ran on every connection without errors');
});

test('all seven platform sources attach to the safety proposal without creating another agent or enabling runtime access', async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const inputs: CreateInput[] = [
    { platform: 'vercel', token: VERCEL_TOKEN },
    { platform: 'aws', access_key_id: 'AKIATEST', secret_access_key: 'aws-test-secret', regions: 'us-east-1' },
    { platform: 'azure', tenant_id: 't1', client_id: 'c1', client_secret: 'azure-secret', subscription_id: 'sub1' },
    { platform: 'gcp', service_account_json: JSON.stringify({ client_email: 'signet@p1.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }), project_id: 'p1' }), regions: 'us-central1' },
    { platform: 'copilot', tenant_id: 't1', client_id: 'c1', client_secret: 'copilot-secret-1', environment_url: 'https://hospital.crm.dynamics.com' },
    { platform: 'openai', admin_key: 'sk-admin-openai-test-123' },
    { platform: 'anthropic', admin_key: 'sk-ant-admin-test-123' },
  ];
  for (const input of inputs) {
    const connection = await platforms.create(input, admin);
    const source = (await platforms.workloads(connection.id))[0]!;
    const vendorHosted = source.platform_ai !== null && source.kind !== 'api_key';
    const proposal = await registerAgent({ handle: `source-intake-${input.platform}`, name: source.name, purpose: 'Platform agent completing its guided safety intake', sponsor: admin.id, autonomy_level: 'L1', kind: vendorHosted ? 'third_party' : 'self_hosted', vendor: vendorHosted ? source.platform_ai! : undefined }, admin);
    const before = await db.prepare('SELECT COUNT(*) AS count FROM agent').get();
    assert.deepEqual(await platforms.attachAgent(connection.id, source.id, proposal.id, admin), { agent_id: proposal.id });
    assert.deepEqual(await platforms.attachAgent(connection.id, source.id, proposal.id, admin), { agent_id: proposal.id }, 'retrying the same proposal is idempotent');
    assert.deepEqual(await db.prepare('SELECT COUNT(*) AS count FROM agent').get(), before, 'source attachment never registers a duplicate');
    assert.equal((await platforms.workloads(connection.id)).find((item) => item.id === source.id)!.registered_agent_id, proposal.id);
    const link = await db.prepare('SELECT state, credential_id FROM platform_link WHERE connection_id = ? AND workload_id = ?').get(connection.id, source.id);
    assert.deepEqual(link, { state: 'registered', credential_id: null });
    const other = await registerAgent({ handle: `other-intake-${input.platform}`, name: 'Other agent', purpose: 'Another proposal must not take over a selected source', sponsor: admin.id, autonomy_level: 'L1', kind: vendorHosted ? 'third_party' : 'self_hosted', vendor: vendorHosted ? source.platform_ai! : undefined }, admin);
    await assert.rejects(platforms.attachAgent(connection.id, source.id, other.id, admin), /already attached/);
    await assert.rejects(platforms.attachAgent(connection.id, 'missing-source', proposal.id, admin), /not found/);
  }
});

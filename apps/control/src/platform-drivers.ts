import { createSign } from 'node:crypto';
import { request, signAws, type AwsCredentials } from '@signet/core';
import { PolicyError, invalid } from './errors';

// One driver per hosting platform. A driver lists workloads (with the NAMES of their environment
// variables, never values kept), and, where the platform allows it, changes a workload's settings and
// restarts it so its AI calls go through Signet. Credentials arrive as the decrypted secret string.

export type PlatformKind = 'vercel' | 'aws' | 'azure' | 'gcp' | 'copilot' | 'openai' | 'anthropic';

export interface RawWorkload {
  id: string;
  name: string;
  kind: string; // vercel_project, lambda, bedrock_agent, app_service, ai_account, ai_foundry, vertex_agent, cloud_run
  framework: string | null;
  url: string | null;
  region: string | null;
  env_names: string[];
  // The workload is itself an AI agent or model service on the platform (Bedrock agent, Azure OpenAI).
  platform_ai: string | null;
  // Settings can be changed by Signet (no-code connect).
  linkable: boolean;
}

export interface Driver {
  validate(secret: string, scope: Record<string, string>): Promise<string>;
  workloads(secret: string, scope: Record<string, string>): Promise<RawWorkload[]>;
  setVars?(secret: string, scope: Record<string, string>, w: RawWorkload, vars: { key: string; value: string }[], remove: string[]): Promise<string[]>;
  restart?(secret: string, scope: Record<string, string>, w: RawWorkload): Promise<string | null>; // a deployment/operation id to follow
  restartState?(secret: string, scope: Record<string, string>, w: RawWorkload, id: string): Promise<'pending' | 'ready' | 'failed'>;
  // Stop the workload on the platform (Phase C2): what a kill means where Signet's gateway is not in the path.
  stop?(secret: string, scope: Record<string, string>, w: RawWorkload): Promise<string>;
  // Daily usage the platform reports (Phase C1): AI use that does not pass through Signet.
  usage?(secret: string, scope: Record<string, string>, days: number): Promise<UsageRow[]>;
}

export interface UsageRow { workload_id: string; day: string; requests: number; input_tokens: number; output_tokens: number; cost_usd: number | null }

// Tests point every platform host at one local stand-in: https://api.vercel.com/x → <override>/api.vercel.com/x.
function target(url: URL): URL {
  const o = process.env.SIGNET_PLATFORM_API_OVERRIDE;
  return o ? new URL(`${o.replace(/\/+$/, '')}/${url.host}${url.pathname}${url.search}`) : url;
}

async function call<T>(platform: string, url: URL, init: { method?: string; headers?: Record<string, string>; body?: string }): Promise<T> {
  let r;
  try {
    const headers = { ...(init.headers ?? {}) };
    delete headers.host;
    r = await request(target(url), { method: init.method ?? 'GET', headers, body: init.body, timeoutMs: 25_000, maxBytes: 16 * 1024 * 1024 });
  } catch (e) {
    throw new PolicyError('PLATFORM_UNREACHABLE', `${platform} API unreachable: ${(e as Error).message}`, 502);
  }
  const text = r.text();
  if (!r.ok) {
    // AWS answers errors in XML: show its <Message>, not the document.
    let msg = text.trimStart().startsWith('<') ? (text.match(/<Message>([^<]+)<\/Message>/)?.[1] ?? text.match(/<Code>([^<]+)<\/Code>/)?.[1] ?? 'error') : text.slice(0, 300);
    try {
      const j = JSON.parse(text) as { error?: { message?: string } | string; message?: string; Message?: string; error_description?: string };
      msg = (typeof j.error === 'object' ? j.error?.message : j.error_description ?? j.error) ?? j.message ?? j.Message ?? msg;
    } catch { /* not JSON */ }
    const auth = r.status === 401 || r.status === 403;
    throw new PolicyError(auth ? 'PLATFORM_AUTH' : 'PLATFORM_API', `${platform} ${init.method ?? 'GET'} ${url.pathname} failed (${r.status}): ${msg}`, auth ? 422 : 502);
  }
  return (text ? (text.trimStart().startsWith('<') ? (text as unknown) : JSON.parse(text)) : {}) as T;
}

// --- Vercel --------------------------------------------------------------------------------------

const vercelUrl = (path: string, scope: Record<string, string>) => {
  const u = new URL('https://api.vercel.com' + path);
  if (scope.team_id) u.searchParams.set('teamId', scope.team_id);
  return u;
};

const vercel: Driver = {
  async validate(token, scope) {
    const u = await call<{ user?: { username?: string; email?: string } }>('Vercel', vercelUrl('/v2/user', {}), { headers: { authorization: `Bearer ${token}` } });
    if (scope.team_id) await call('Vercel', vercelUrl(`/v2/teams/${encodeURIComponent(scope.team_id)}`, {}), { headers: { authorization: `Bearer ${token}` } });
    return `signed in as ${u.user?.username ?? u.user?.email ?? 'unknown'}`;
  },
  async workloads(token, scope) {
    const h = { authorization: `Bearer ${token}` };
    const out = await call<{ projects: { id: string; name: string; framework?: string | null; targets?: { production?: { url?: string } } }[] }>('Vercel', vercelUrl('/v9/projects?limit=100', scope), { headers: h });
    const res: RawWorkload[] = [];
    for (const p of out.projects ?? []) {
      const env = await call<{ envs: { key: string }[] }>('Vercel', vercelUrl(`/v9/projects/${encodeURIComponent(p.id)}/env`, scope), { headers: h });
      res.push({ id: p.id, name: p.name, kind: 'vercel_project', framework: p.framework ?? null, url: p.targets?.production?.url ? `https://${p.targets.production.url}` : null, region: null, env_names: [...new Set((env.envs ?? []).map((e) => e.key))].sort(), platform_ai: null, linkable: true });
    }
    return res;
  },
  async setVars(token, scope, w, vars, remove) {
    const h = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    await call('Vercel', vercelUrl(`/v10/projects/${encodeURIComponent(w.id)}/env?upsert=true`, scope), { method: 'POST', headers: h, body: JSON.stringify(vars.map((v) => ({ ...v, type: 'encrypted', target: ['production', 'preview'] }))) });
    const removed: string[] = [];
    if (remove.length) {
      const env = await call<{ envs: { id: string; key: string }[] }>('Vercel', vercelUrl(`/v9/projects/${encodeURIComponent(w.id)}/env`, scope), { headers: h });
      for (const e of env.envs ?? []) {
        if (!remove.includes(e.key)) continue;
        await call('Vercel', vercelUrl(`/v9/projects/${encodeURIComponent(w.id)}/env/${encodeURIComponent(e.id)}`, scope), { method: 'DELETE', headers: h });
        removed.push(e.key);
      }
    }
    return removed;
  },
  async restart(token, scope, w) {
    const h = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const latest = await call<{ deployments: { uid: string }[] }>('Vercel', vercelUrl(`/v6/deployments?projectId=${encodeURIComponent(w.id)}&target=production&limit=1`, scope), { headers: h });
    const prev = latest.deployments?.[0]?.uid;
    if (!prev) return null;
    const dep = await call<{ id: string }>('Vercel', vercelUrl('/v13/deployments?forceNew=1', scope), { method: 'POST', headers: h, body: JSON.stringify({ name: w.name, deploymentId: prev, target: 'production' }) });
    return dep.id;
  },
  async stop(token, scope, w) {
    await call('Vercel', vercelUrl(`/v1/projects/${encodeURIComponent(w.id)}/pause`, scope), { method: 'POST', headers: { authorization: `Bearer ${token}` } });
    return 'project paused: Vercel serves no deployment of it until it is resumed';
  },
  async restartState(token, scope, _w, id) {
    const d = await call<{ readyState?: string }>('Vercel', vercelUrl(`/v13/deployments/${encodeURIComponent(id)}`, scope), { headers: { authorization: `Bearer ${token}` } });
    return d.readyState === 'READY' ? 'ready' : d.readyState === 'ERROR' || d.readyState === 'CANCELED' ? 'failed' : 'pending';
  },
};

// --- AWS (Bedrock Agents, Lambda) ----------------------------------------------------------------

interface AwsSecret extends AwsCredentials { regions?: string[] }

function awsSecret(secret: string): AwsSecret {
  const s = JSON.parse(secret) as AwsSecret;
  if (!s.access_key_id || !s.secret_access_key) throw invalid('AWS credentials need access_key_id and secret_access_key');
  return s;
}
const awsRegions = (s: AwsSecret, scope: Record<string, string>) => (scope.regions ?? s.regions?.join(',') ?? 'us-east-1').split(',').map((r) => r.trim()).filter(Boolean);

async function aws<T>(s: AwsSecret, region: string, service: string, method: string, url: URL, body?: unknown, extra: Record<string, string> = {}): Promise<T> {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const headers = signAws({ method, url, region, service, credentials: s, body: payload, headers: payload ? { 'content-type': 'application/json', ...extra } : extra });
  return call<T>('AWS', url, { method, headers, body: payload });
}

const lambdaUrl = (region: string, path: string) => new URL(`https://lambda.${region}.amazonaws.com/2015-03-31/functions${path}`);

const awsDriver: Driver = {
  async validate(secret) {
    const s = awsSecret(secret);
    const url = new URL('https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15');
    const xml = await aws<string>(s, 'us-east-1', 'sts', 'GET', url);
    const arn = String(xml).match(/<Arn>([^<]+)<\/Arn>/)?.[1];
    if (!arn) throw new PolicyError('PLATFORM_AUTH', 'AWS did not confirm the identity of these credentials', 422);
    return `signed in as ${arn}`;
  },
  async workloads(secret, scope) {
    const s = awsSecret(secret);
    const out: RawWorkload[] = [];
    for (const region of awsRegions(s, scope)) {
      const agents = await aws<{ agentSummaries?: { agentId: string; agentName: string; agentStatus?: string; description?: string }[] }>(s, region, 'bedrock', 'POST', new URL(`https://bedrock-agent.${region}.amazonaws.com/agents/`), { maxResults: 100 });
      for (const a of agents.agentSummaries ?? []) {
        out.push({ id: `bedrock:${region}:${a.agentId}`, name: a.agentName, kind: 'bedrock_agent', framework: a.agentStatus ?? null, url: null, region, env_names: [], platform_ai: 'Amazon Bedrock agent', linkable: false });
      }
      const fns = await aws<{ Functions?: { FunctionName: string; Runtime?: string; Environment?: { Variables?: Record<string, string> } }[] }>(s, region, 'lambda', 'GET', lambdaUrl(region, '/?MaxItems=50'));
      for (const f of fns.Functions ?? []) {
        out.push({ id: `lambda:${region}:${f.FunctionName}`, name: f.FunctionName, kind: 'lambda', framework: f.Runtime ?? null, url: null, region, env_names: Object.keys(f.Environment?.Variables ?? {}).sort(), platform_ai: null, linkable: true });
      }
    }
    return out;
  },
  // Lambda keeps all variables in one map: read it, change only ours, write it back. Values are held in
  // memory for this call only.
  async setVars(secret, _scope, w, vars, remove) {
    const s = awsSecret(secret);
    const [, region, name] = w.id.split(':') as [string, string, string];
    const path = `/${encodeURIComponent(name)}/configuration`;
    const cfg = await aws<{ Environment?: { Variables?: Record<string, string> } }>(s, region, 'lambda', 'GET', lambdaUrl(region, path));
    const merged = { ...(cfg.Environment?.Variables ?? {}) };
    const removed = remove.filter((k) => k in merged);
    for (const k of removed) delete merged[k];
    for (const v of vars) merged[v.key] = v.value;
    await aws(s, region, 'lambda', 'PUT', lambdaUrl(region, path), { Environment: { Variables: merged } });
    return removed;
  },
  async restart(_secret, _scope, w) {
    return w.id; // a configuration change applies to new invocations; follow LastUpdateStatus
  },
  // Bedrock usage per model and day from CloudWatch (namespace AWS/Bedrock), in every scanned region.
  async usage(secret, scope, days) {
    const s = awsSecret(secret);
    const end = Math.floor(Date.now() / 86_400_000) * 86_400 + 86_400;
    const start = end - days * 86_400;
    const search = (m: string) => `SEARCH('{AWS/Bedrock,ModelId} MetricName="${m}"', 'Sum', 86400)`;
    const rows = new Map<string, UsageRow>();
    for (const region of awsRegions(s, scope)) {
      const out = await aws<{ MetricDataResults?: { Id: string; Label?: string; Timestamps?: number[]; Values?: number[] }[] }>(s, region, 'monitoring', 'POST', new URL(`https://monitoring.${region}.amazonaws.com/`), {
        StartTime: start, EndTime: end,
        MetricDataQueries: [{ Id: 'i', Expression: search('InputTokenCount'), ReturnData: true }, { Id: 'o', Expression: search('OutputTokenCount'), ReturnData: true }, { Id: 'n', Expression: search('Invocations'), ReturnData: true }],
      }, { 'content-type': 'application/x-amz-json-1.0', 'x-amz-target': 'GraniteServiceVersion20100801.GetMetricData' });
      for (const m of out.MetricDataResults ?? []) {
        const model = (m.Label ?? 'unknown').replace(/\s+(InputTokenCount|OutputTokenCount|Invocations)$/, '');
        (m.Timestamps ?? []).forEach((t, i) => {
          const day = new Date(t * 1000).toISOString().slice(0, 10);
          const key = `${region}:${model}|${day}`;
          const row = rows.get(key) ?? { workload_id: `bedrock-model:${region}:${model}`, day, requests: 0, input_tokens: 0, output_tokens: 0, cost_usd: null };
          const v = Math.round(m.Values?.[i] ?? 0);
          if (m.Id === 'i') row.input_tokens += v; else if (m.Id === 'o') row.output_tokens += v; else row.requests += v;
          rows.set(key, row);
        });
      }
    }
    return [...rows.values()];
  },
  async stop(secret, _scope, w) {
    if (w.kind !== 'lambda') throw new PolicyError('VALIDATION', 'only Lambda functions can be stopped from Signet; disable a Bedrock agent in the AWS console', 409);
    const s = awsSecret(secret);
    const [, region, name] = w.id.split(':') as [string, string, string];
    await aws(s, region, 'lambda', 'PUT', new URL(`https://lambda.${region}.amazonaws.com/2017-10-31/functions/${encodeURIComponent(name)}/concurrency`), { ReservedConcurrentExecutions: 0 });
    return 'reserved concurrency set to 0: the function accepts no new invocations';
  },
  async restartState(secret, _scope, w) {
    const s = awsSecret(secret);
    const [, region, name] = w.id.split(':') as [string, string, string];
    const cfg = await aws<{ LastUpdateStatus?: string }>(s, region, 'lambda', 'GET', lambdaUrl(region, `/${encodeURIComponent(name)}/configuration`));
    return cfg.LastUpdateStatus === 'Successful' ? 'ready' : cfg.LastUpdateStatus === 'Failed' ? 'failed' : 'pending';
  },
};

// --- Azure (Azure OpenAI / AI Services, AI Foundry, App Service) ----------------------------------

interface AzureSecret { tenant_id: string; client_id: string; client_secret: string; subscription_id: string }

function azureSecret(secret: string): AzureSecret {
  const s = JSON.parse(secret) as AzureSecret;
  for (const k of ['tenant_id', 'client_id', 'client_secret', 'subscription_id'] as const) if (!s[k]) throw invalid(`Azure credentials need ${k}`);
  return s;
}

async function azureToken(s: AzureSecret): Promise<string> {
  const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: s.client_id, client_secret: s.client_secret, scope: 'https://management.azure.com/.default' }).toString();
  const t = await call<{ access_token?: string }>('Azure', new URL(`https://login.microsoftonline.com/${encodeURIComponent(s.tenant_id)}/oauth2/v2.0/token`), { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  if (!t.access_token) throw new PolicyError('PLATFORM_AUTH', 'Azure returned no access token', 422);
  return t.access_token;
}
const arm = (path: string) => new URL(`https://management.azure.com${path}`);

const azureDriver: Driver = {
  async validate(secret) {
    const s = azureSecret(secret);
    const token = await azureToken(s);
    const sub = await call<{ displayName?: string }>('Azure', arm(`/subscriptions/${encodeURIComponent(s.subscription_id)}?api-version=2022-12-01`), { headers: { authorization: `Bearer ${token}` } });
    return `subscription ${sub.displayName ?? s.subscription_id}`;
  },
  async workloads(secret) {
    const s = azureSecret(secret);
    const token = await azureToken(s);
    const h = { authorization: `Bearer ${token}` };
    const filter = "resourceType eq 'Microsoft.CognitiveServices/accounts' or resourceType eq 'Microsoft.MachineLearningServices/workspaces' or resourceType eq 'Microsoft.Web/sites'";
    const list = await call<{ value?: { id: string; name: string; type: string; kind?: string; location?: string }[] }>('Azure', arm(`/subscriptions/${encodeURIComponent(s.subscription_id)}/resources?api-version=2021-04-01&$filter=${encodeURIComponent(filter)}`), { headers: h });
    const out: RawWorkload[] = [];
    for (const r of list.value ?? []) {
      const type = r.type.toLowerCase();
      if (type === 'microsoft.cognitiveservices/accounts') {
        out.push({ id: r.id, name: r.name, kind: 'ai_account', framework: r.kind ?? null, url: null, region: r.location ?? null, env_names: [], platform_ai: r.kind === 'OpenAI' ? 'Azure OpenAI' : `Azure AI Services (${r.kind ?? 'account'})`, linkable: false });
      } else if (type === 'microsoft.machinelearningservices/workspaces') {
        out.push({ id: r.id, name: r.name, kind: 'ai_foundry', framework: r.kind ?? null, url: null, region: r.location ?? null, env_names: [], platform_ai: `Azure AI Foundry ${(r.kind ?? 'workspace').toLowerCase()}`, linkable: false });
      } else {
        const settings = await call<{ properties?: Record<string, string> }>('Azure', arm(`${r.id}/config/appsettings/list?api-version=2023-01-01`), { method: 'POST', headers: h });
        out.push({ id: r.id, name: r.name, kind: 'app_service', framework: r.kind ?? null, url: `https://${r.name}.azurewebsites.net`, region: r.location ?? null, env_names: Object.keys(settings.properties ?? {}).sort(), platform_ai: null, linkable: true });
      }
    }
    return out;
  },
  async setVars(secret, _scope, w, vars, remove) {
    const s = azureSecret(secret);
    const token = await azureToken(s);
    const h = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const cur = await call<{ properties?: Record<string, string> }>('Azure', arm(`${w.id}/config/appsettings/list?api-version=2023-01-01`), { method: 'POST', headers: h });
    const merged = { ...(cur.properties ?? {}) };
    const removed = remove.filter((k) => k in merged);
    for (const k of removed) delete merged[k];
    for (const v of vars) merged[v.key] = v.value;
    await call('Azure', arm(`${w.id}/config/appsettings?api-version=2023-01-01`), { method: 'PUT', headers: h, body: JSON.stringify({ properties: merged }) });
    return removed;
  },
  async restart(secret, _scope, w) {
    const s = azureSecret(secret);
    const token = await azureToken(s);
    await call('Azure', arm(`${w.id}/restart?api-version=2023-01-01`), { method: 'POST', headers: { authorization: `Bearer ${token}` } });
    return w.id;
  },
  // Azure OpenAI / AI Services usage per account and day from Azure Monitor.
  async usage(secret, scope, days) {
    const s = azureSecret(secret);
    const token = await azureToken(s);
    const accounts = (await azureDriver.workloads(secret, scope)).filter((w) => w.kind === 'ai_account');
    const end = new Date();
    const start = new Date(end.getTime() - days * 86_400_000);
    const rows = new Map<string, UsageRow>();
    for (const a of accounts) {
      const m = await call<{ value?: { name?: { value?: string }; timeseries?: { data?: { timeStamp: string; total?: number }[] }[] }[] }>('Azure', arm(`${a.id}/providers/Microsoft.Insights/metrics?api-version=2023-10-01&metricnames=ProcessedPromptTokens,GeneratedTokens,AzureOpenAIRequests&timespan=${start.toISOString()}/${end.toISOString()}&interval=P1D&aggregation=Total`), { headers: { authorization: `Bearer ${token}` } });
      for (const metric of m.value ?? []) for (const ts of metric.timeseries ?? []) for (const d of ts.data ?? []) {
        const day = d.timeStamp.slice(0, 10);
        const key = `${a.id}|${day}`;
        const row = rows.get(key) ?? { workload_id: a.id, day, requests: 0, input_tokens: 0, output_tokens: 0, cost_usd: null };
        const v = Math.round(d.total ?? 0);
        if (metric.name?.value === 'ProcessedPromptTokens') row.input_tokens += v; else if (metric.name?.value === 'GeneratedTokens') row.output_tokens += v; else row.requests += v;
        rows.set(key, row);
      }
    }
    return [...rows.values()];
  },
  async stop(secret, _scope, w) {
    if (w.kind !== 'app_service') throw new PolicyError('VALIDATION', 'only App Service apps can be stopped from Signet', 409);
    const s = azureSecret(secret);
    const token = await azureToken(s);
    await call('Azure', arm(`${w.id}/stop?api-version=2023-01-01`), { method: 'POST', headers: { authorization: `Bearer ${token}` } });
    return 'app stopped';
  },
  async restartState(secret, _scope, w) {
    const s = azureSecret(secret);
    const token = await azureToken(s);
    const site = await call<{ properties?: { state?: string } }>('Azure', arm(`${w.id}?api-version=2023-01-01`), { headers: { authorization: `Bearer ${token}` } });
    return site.properties?.state === 'Running' ? 'ready' : 'pending';
  },
};

// --- Google Cloud (Vertex AI Agent Engine, Cloud Run) -----------------------------------------------

interface GcpSecret { client_email: string; private_key: string; project_id: string; regions?: string[] }

function gcpSecret(secret: string): GcpSecret {
  const s = JSON.parse(secret) as GcpSecret;
  for (const k of ['client_email', 'private_key', 'project_id'] as const) if (!s[k]) throw invalid(`a Google service account key needs ${k}`);
  return s;
}

async function gcpToken(s: GcpSecret): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ iss: s.client_email, scope: 'https://www.googleapis.com/auth/cloud-platform', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 })}`;
  const sig = createSign('RSA-SHA256').update(unsigned).sign(s.private_key).toString('base64url');
  const body = new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${sig}` }).toString();
  const t = await call<{ access_token?: string }>('Google Cloud', new URL('https://oauth2.googleapis.com/token'), { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  if (!t.access_token) throw new PolicyError('PLATFORM_AUTH', 'Google returned no access token', 422);
  return t.access_token;
}
const gcpRegions = (s: GcpSecret, scope: Record<string, string>) => (scope.regions ?? s.regions?.join(',') ?? 'us-central1').split(',').map((r) => r.trim()).filter(Boolean);

const gcpDriver: Driver = {
  async validate(secret) {
    const s = gcpSecret(secret);
    const token = await gcpToken(s);
    const p = await call<{ name?: string }>('Google Cloud', new URL(`https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(s.project_id)}`), { headers: { authorization: `Bearer ${token}` } });
    return `project ${p.name ?? s.project_id} as ${s.client_email}`;
  },
  async workloads(secret, scope) {
    const s = gcpSecret(secret);
    const token = await gcpToken(s);
    const h = { authorization: `Bearer ${token}` };
    const out: RawWorkload[] = [];
    for (const region of gcpRegions(s, scope)) {
      const engines = await call<{ reasoningEngines?: { name: string; displayName?: string }[] }>('Google Cloud', new URL(`https://${region}-aiplatform.googleapis.com/v1/projects/${encodeURIComponent(s.project_id)}/locations/${region}/reasoningEngines`), { headers: h });
      for (const e of engines.reasoningEngines ?? []) out.push({ id: e.name, name: e.displayName ?? e.name.split('/').pop()!, kind: 'vertex_agent', framework: null, url: null, region, env_names: [], platform_ai: 'Vertex AI Agent Engine', linkable: false });
      const run = await call<{ services?: { name: string; uri?: string; template?: { containers?: { env?: { name: string }[] }[] } }[] }>('Google Cloud', new URL(`https://run.googleapis.com/v2/projects/${encodeURIComponent(s.project_id)}/locations/${region}/services`), { headers: h });
      for (const svc of run.services ?? []) {
        const names = (svc.template?.containers ?? []).flatMap((c) => (c.env ?? []).map((e) => e.name));
        out.push({ id: svc.name, name: svc.name.split('/').pop()!, kind: 'cloud_run', framework: null, url: svc.uri ?? null, region, env_names: [...new Set(names)].sort(), platform_ai: null, linkable: true });
      }
    }
    return out;
  },
  // Vertex AI usage per model and day from Cloud Monitoring.
  async usage(secret, _scope, days) {
    const s = gcpSecret(secret);
    const token = await gcpToken(s);
    const end = new Date();
    const start = new Date(end.getTime() - days * 86_400_000);
    const rows = new Map<string, UsageRow>();
    type Series = { metric?: { labels?: Record<string, string> }; resource?: { labels?: Record<string, string> }; points?: { interval: { startTime: string }; value: { int64Value?: string; doubleValue?: number } }[] };
    const series = async (metric: string) => {
      const q = new URLSearchParams({ filter: `metric.type="${metric}"`, 'interval.startTime': start.toISOString(), 'interval.endTime': end.toISOString(), 'aggregation.alignmentPeriod': '86400s', 'aggregation.perSeriesAligner': 'ALIGN_SUM' });
      return (await call<{ timeSeries?: Series[] }>('Google Cloud', new URL(`https://monitoring.googleapis.com/v3/projects/${encodeURIComponent(s.project_id)}/timeSeries?${q}`), { headers: { authorization: `Bearer ${token}` } })).timeSeries ?? [];
    };
    const num = (v: { int64Value?: string; doubleValue?: number }) => Math.round(Number(v.int64Value ?? v.doubleValue ?? 0));
    const add = (model: string, day: string, f: (row: UsageRow) => void) => {
      const key = `${model}|${day}`;
      const row = rows.get(key) ?? { workload_id: `vertex-model:${model}`, day, requests: 0, input_tokens: 0, output_tokens: 0, cost_usd: null };
      f(row);
      rows.set(key, row);
    };
    for (const t of await series('aiplatform.googleapis.com/publisher/online_serving/token_count')) {
      const model = t.resource?.labels?.model_user_id ?? 'unknown';
      for (const pt of t.points ?? []) add(model, pt.interval.startTime.slice(0, 10), (row) => { if (t.metric?.labels?.type === 'output') row.output_tokens += num(pt.value); else row.input_tokens += num(pt.value); });
    }
    for (const t of await series('aiplatform.googleapis.com/publisher/online_serving/model_invocation_count')) {
      const model = t.resource?.labels?.model_user_id ?? 'unknown';
      for (const pt of t.points ?? []) add(model, pt.interval.startTime.slice(0, 10), (row) => { row.requests += num(pt.value); });
    }
    return [...rows.values()];
  },
  // Cloud Run: the service template is replaced as a whole, so read it, change only our variables in every
  // container, and write it back; Cloud Run then rolls out a new revision (a long-running operation).
  async setVars(secret, _scope, w, vars, remove) {
    if (w.kind !== 'cloud_run') throw new PolicyError('VALIDATION', 'only Cloud Run services can be connected', 409);
    const s = gcpSecret(secret);
    const token = await gcpToken(s);
    const h = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const svc = await call<{ template?: { containers?: { env?: { name: string; value?: string; valueSource?: unknown }[] }[] } & Record<string, unknown> }>('Google Cloud', new URL(`https://run.googleapis.com/v2/${w.id}`), { headers: h });
    const removed = new Set<string>();
    const containers = (svc.template?.containers ?? []).map((c) => {
      const env = (c.env ?? []).filter((e) => {
        if (remove.includes(e.name)) { removed.add(e.name); return false; }
        return !vars.some((v) => v.key === e.name);
      });
      return { ...c, env: [...env, ...vars.map((v) => ({ name: v.key, value: v.value }))] };
    });
    const op = await call<{ name?: string }>('Google Cloud', new URL(`https://run.googleapis.com/v2/${w.id}?updateMask=template.containers`), { method: 'PATCH', headers: h, body: JSON.stringify({ template: { ...svc.template, containers } }) });
    gcpOperations.set(w.id, op.name ?? '');
    return [...removed];
  },
  async restart(_secret, _scope, w) {
    return gcpOperations.get(w.id) || null; // the PATCH above already started the new revision
  },
  async restartState(secret, _scope, _w, id) {
    const s = gcpSecret(secret);
    const token = await gcpToken(s);
    const op = await call<{ done?: boolean; error?: { message?: string } }>('Google Cloud', new URL(`https://run.googleapis.com/v2/${id}`), { headers: { authorization: `Bearer ${token}` } });
    return op.done ? (op.error ? 'failed' : 'ready') : 'pending';
  },
};
const gcpOperations = new Map<string, string>();

// --- Microsoft Copilot Studio (agents are rows of the Dataverse "bot" table) -----------------------

interface CopilotSecret { tenant_id: string; client_id: string; client_secret: string; environment_url: string }

function copilotSecret(secret: string): CopilotSecret {
  const s = JSON.parse(secret) as CopilotSecret;
  for (const k of ['tenant_id', 'client_id', 'client_secret', 'environment_url'] as const) if (!s[k]) throw invalid(`Copilot Studio needs ${k}`);
  return s;
}

async function dataverse<T>(s: CopilotSecret, path: string): Promise<T> {
  const env = new URL(s.environment_url);
  const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: s.client_id, client_secret: s.client_secret, scope: `${env.origin}/.default` }).toString();
  const t = await call<{ access_token?: string }>('Microsoft', new URL(`https://login.microsoftonline.com/${encodeURIComponent(s.tenant_id)}/oauth2/v2.0/token`), { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  if (!t.access_token) throw new PolicyError('PLATFORM_AUTH', 'Microsoft returned no access token', 422);
  return call<T>('Copilot Studio', new URL(`${env.origin}/api/data/v9.2${path}`), { headers: { authorization: `Bearer ${t.access_token}`, accept: 'application/json', 'OData-Version': '4.0' } });
}

const copilotDriver: Driver = {
  async validate(secret) {
    const s = copilotSecret(secret);
    const who = await dataverse<{ OrganizationId?: string }>(s, '/WhoAmI');
    return `Dataverse environment ${new URL(s.environment_url).host} (org ${who.OrganizationId ?? 'unknown'})`;
  },
  async workloads(secret) {
    const s = copilotSecret(secret);
    const bots = await dataverse<{ value?: { botid: string; name: string; statecode?: number; schemaname?: string }[] }>(s, '/bots?$select=botid,name,statecode,schemaname');
    return (bots.value ?? []).map((b) => ({ id: `copilot:${b.botid}`, name: b.name, kind: 'copilot_agent', framework: b.statecode === 0 ? 'active' : 'inactive', url: null, region: null, env_names: [], platform_ai: 'Microsoft Copilot Studio agent', linkable: false }));
  },
};

// --- OpenAI and Anthropic organisations (projects and API keys: who uses the APIs directly) ---------

const openaiDriver: Driver = {
  async validate(adminKey) {
    const p = await call<{ data?: unknown[] }>('OpenAI', new URL('https://api.openai.com/v1/organization/projects?limit=1'), { headers: { authorization: `Bearer ${adminKey}` } });
    return `organization admin key (${Array.isArray(p.data) ? 'projects readable' : 'connected'})`;
  },
  async workloads(adminKey) {
    const h = { authorization: `Bearer ${adminKey}` };
    const projects = await call<{ data?: { id: string; name: string; status?: string }[] }>('OpenAI', new URL('https://api.openai.com/v1/organization/projects?limit=100'), { headers: h });
    const out: RawWorkload[] = [];
    for (const p of projects.data ?? []) {
      const keys = await call<{ data?: { id: string; name?: string; last_used_at?: number | null; owner?: { user?: { email?: string } } }[] }>('OpenAI', new URL(`https://api.openai.com/v1/organization/projects/${encodeURIComponent(p.id)}/api_keys?limit=100`), { headers: h });
      for (const k of keys.data ?? []) {
        out.push({ id: `openai:${p.id}:${k.id}`, name: `${p.name} / ${k.name ?? k.id}`, kind: 'api_key', framework: k.owner?.user?.email ?? null, url: null, region: k.last_used_at ? `last used ${new Date(k.last_used_at * 1000).toISOString().slice(0, 10)}` : 'never used', env_names: [], platform_ai: 'OpenAI API key (direct, not through Signet)', linkable: false });
      }
    }
    return out;
  },
};

(openaiDriver as Driver).stop = async (adminKey, _scope, w) => {
  const [, project, key] = w.id.split(':') as [string, string, string];
  await call('OpenAI', new URL(`https://api.openai.com/v1/organization/projects/${encodeURIComponent(project)}/api_keys/${encodeURIComponent(key)}`), { method: 'DELETE', headers: { authorization: `Bearer ${adminKey}` } });
  return 'API key deleted';
};

(openaiDriver as Driver).usage = async (adminKey, _scope, days) => {
  const h = { authorization: `Bearer ${adminKey}` };
  const start = Math.floor(Date.now() / 1000) - days * 86_400;
  const usage = await call<{ data?: { start_time: number; results?: { project_id?: string; api_key_id?: string; input_tokens?: number; output_tokens?: number; num_model_requests?: number }[] }[] }>('OpenAI', new URL(`https://api.openai.com/v1/organization/usage/completions?start_time=${start}&bucket_width=1d&group_by=project_id&group_by=api_key_id&limit=${days}`), { headers: h });
  const rows: UsageRow[] = [];
  for (const b of usage.data ?? []) for (const x of b.results ?? []) {
    if (!x.project_id || !x.api_key_id) continue;
    rows.push({ workload_id: `openai:${x.project_id}:${x.api_key_id}`, day: new Date(b.start_time * 1000).toISOString().slice(0, 10), requests: x.num_model_requests ?? 0, input_tokens: x.input_tokens ?? 0, output_tokens: x.output_tokens ?? 0, cost_usd: null });
  }
  return rows;
};

const anthropicHeaders = (key: string) => ({ 'x-api-key': key, 'anthropic-version': '2023-06-01' });
const anthropicDriver: Driver = {
  async validate(adminKey) {
    await call('Anthropic', new URL('https://api.anthropic.com/v1/organizations/workspaces?limit=1'), { headers: anthropicHeaders(adminKey) });
    return 'organization admin key';
  },
  async workloads(adminKey) {
    const keys = await call<{ data?: { id: string; name?: string; status?: string; workspace_id?: string | null; created_by?: { id?: string } }[] }>('Anthropic', new URL('https://api.anthropic.com/v1/organizations/api_keys?limit=100'), { headers: anthropicHeaders(adminKey) });
    return (keys.data ?? []).map((k) => ({ id: `anthropic:${k.id}`, name: k.name ?? k.id, kind: 'api_key', framework: k.status ?? null, url: null, region: k.workspace_id ?? 'default workspace', env_names: [], platform_ai: 'Anthropic API key (direct, not through Signet)', linkable: false }));
  },
};

anthropicDriver.stop = async (adminKey, _scope, w) => {
  await call('Anthropic', new URL(`https://api.anthropic.com/v1/organizations/api_keys/${encodeURIComponent(w.id.slice('anthropic:'.length))}`), { method: 'POST', headers: { ...anthropicHeaders(adminKey), 'content-type': 'application/json' }, body: JSON.stringify({ status: 'inactive' }) });
  return 'API key set inactive';
};

anthropicDriver.usage = async (adminKey, _scope, days) => {
  const start = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10) + 'T00:00:00Z';
  const usage = await call<{ data?: { starting_at: string; results?: { api_key_id?: string | null; uncached_input_tokens?: number; cache_read_input_tokens?: number; output_tokens?: number }[] }[] }>('Anthropic', new URL(`https://api.anthropic.com/v1/organizations/usage_report/messages?starting_at=${encodeURIComponent(start)}&bucket_width=1d&group_by[]=api_key_id&limit=${days}`), { headers: anthropicHeaders(adminKey) });
  const rows: UsageRow[] = [];
  for (const b of usage.data ?? []) for (const x of b.results ?? []) {
    if (!x.api_key_id) continue;
    rows.push({ workload_id: `anthropic:${x.api_key_id}`, day: b.starting_at.slice(0, 10), requests: 0, input_tokens: (x.uncached_input_tokens ?? 0) + (x.cache_read_input_tokens ?? 0), output_tokens: x.output_tokens ?? 0, cost_usd: null });
  }
  return rows;
};

export const DRIVERS: Record<PlatformKind, Driver> = { vercel, aws: awsDriver, azure: azureDriver, gcp: gcpDriver, copilot: copilotDriver, openai: openaiDriver, anthropic: anthropicDriver };
export const PLATFORM_LABEL: Record<PlatformKind, string> = { vercel: 'Vercel', aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', copilot: 'Copilot Studio', openai: 'OpenAI', anthropic: 'Anthropic' };

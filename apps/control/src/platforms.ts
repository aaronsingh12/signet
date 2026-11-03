import { newId, sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { createDeploymentCredential } from './deployment-identity';
import * as discovery from './discovery';
import { PolicyError, invalid, notFound } from './errors';
import * as ledger from './ledger';
import { DRIVERS, PLATFORM_LABEL, type PlatformKind, type RawWorkload } from './platform-drivers';
import type { Principal } from './rbac';
import { activeCertificate, getAgent, registerAgent } from './registry';
import { putSecret, revealPlatformCredential } from './secrets';
import { tenant } from './tenant';
import * as workflow from './workflow';

// Platform connectors (Phases A3 and B): an admin connects a hosting platform once. Signet lists its
// workloads, flags the ones that use an AI provider or are AI agents themselves, registers them as
// agents in one click, and — where the platform lets Signet change settings — connects one to Signet
// without a code change: LLM base URL to the gateway, a Signet deployment credential as the API key,
// old provider keys removed, restart. Every step is ledgered. Values of other variables are never kept.

export interface Workload extends RawWorkload {
  ai_signals: { name: string; provider: string; kind: 'key' | 'base_url' | 'model' | 'platform' }[];
  linked_agent_id: string | null;
  link_state: string | null;
  registered_agent_id: string | null;
}

// Variables that point an app at a model provider. Names only.
const AI_VARS: { re: RegExp; provider: string; kind: 'key' | 'base_url' | 'model' }[] = [
  { re: /^OPENAI_API_KEY$/, provider: 'OpenAI-compatible', kind: 'key' },
  { re: /^(OPENAI_BASE_URL|OPENAI_API_BASE|OPENAI_API_BASE_URL)$/, provider: 'OpenAI-compatible', kind: 'base_url' },
  { re: /^GROQ_API_KEY$/, provider: 'Groq', kind: 'key' },
  { re: /^GROQ_BASE_URL$/, provider: 'Groq', kind: 'base_url' },
  { re: /^ANTHROPIC_API_KEY$/, provider: 'Anthropic', kind: 'key' },
  { re: /^(GOOGLE_API_KEY|GEMINI_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY)$/, provider: 'Google', kind: 'key' },
  { re: /^AZURE_OPENAI_API_KEY$/, provider: 'Azure OpenAI', kind: 'key' },
  { re: /^AZURE_OPENAI_ENDPOINT$/, provider: 'Azure OpenAI', kind: 'base_url' },
  { re: /^OLLAMA_API_KEY$/, provider: 'Ollama', kind: 'key' },
  { re: /^(OLLAMA_HOST|OLLAMA_BASE_URL|OLLAMA_URL)$/, provider: 'Ollama', kind: 'base_url' },
  { re: /^(MISTRAL_API_KEY|COHERE_API_KEY|TOGETHER_API_KEY|OPENROUTER_API_KEY|DEEPSEEK_API_KEY|XAI_API_KEY|PERPLEXITY_API_KEY|HF_TOKEN)$/, provider: 'other provider', kind: 'key' },
  { re: /^(LLM_BASE_URL|AI_BASE_URL|MODEL_BASE_URL|LLM_API_URL)$/, provider: 'custom', kind: 'base_url' },
  { re: /^(LLM_API_KEY|AI_API_KEY|MODEL_API_KEY)$/, provider: 'custom', kind: 'key' },
  { re: /^(OPENAI_MODEL|LLM_MODEL|AI_MODEL|MODEL_NAME|GROQ_MODEL|OLLAMA_MODEL)$/, provider: 'model setting', kind: 'model' },
];

export function aiSignals(w: Pick<RawWorkload, 'env_names' | 'platform_ai'>): Workload['ai_signals'] {
  const vars = w.env_names.flatMap((name) => {
    const m = AI_VARS.find((v) => v.re.test(name));
    return m ? [{ name, provider: m.provider, kind: m.kind }] : [];
  });
  return w.platform_ai ? [{ name: w.platform_ai, provider: w.platform_ai, kind: 'platform' as const }, ...vars] : vars;
}

// --- connections ---------------------------------------------------------------------------------

interface ConnectionRow { id: string; platform: PlatformKind; label: string; secret_id: string; scope: string; status: string; revoked_at: string | null }

async function connection(id: string) {
  const row = (await db.prepare('SELECT * FROM platform_connection WHERE tenant_id = ? AND id = ?').get(tenant.id, id)) as ConnectionRow | undefined;
  if (!row || row.revoked_at) throw notFound(`platform connection ${id}`);
  return { ...row, secret: await revealPlatformCredential(row.secret_id), scopeObj: JSON.parse(row.scope) as Record<string, string>, driver: DRIVERS[row.platform] };
}

export interface ConnectionView { id: string; platform: PlatformKind; label: string; scope: Record<string, string>; status: string; status_detail: string | null; created_at: string; last_scan_at: string | null; last_scan_count: number }

export async function list(): Promise<ConnectionView[]> {
  const rows = (await db.prepare('SELECT id, platform, label, scope, status, status_detail, created_at, last_scan_at, last_scan_count FROM platform_connection WHERE tenant_id = ? AND revoked_at IS NULL ORDER BY created_at DESC').all(tenant.id)) as unknown as (Omit<ConnectionView, 'scope'> & { scope: string })[];
  return rows.map((r) => ({ ...r, scope: JSON.parse(r.scope) as Record<string, string> }));
}

export interface CreateInput {
  platform?: string;
  label?: string;
  token?: string; team_id?: string; // Vercel
  access_key_id?: string; secret_access_key?: string; regions?: string; // AWS (regions also for Google)
  tenant_id?: string; client_id?: string; client_secret?: string; subscription_id?: string; // Azure
  service_account_json?: string; // Google Cloud
  environment_url?: string; // Copilot Studio (Dataverse), with the Azure fields
  admin_key?: string; // OpenAI or Anthropic organisation admin key
}

function credentialOf(input: CreateInput): { secret: string; scope: Record<string, string> } {
  const regions = input.regions?.split(',').map((r) => r.trim()).filter((r) => /^[a-z0-9-]{3,30}$/.test(r)).join(',');
  switch (input.platform) {
    case 'vercel':
      if ((input.token ?? '').trim().length < 16) throw invalid('a Vercel access token is required (Vercel → Account settings → Tokens)');
      return { secret: input.token!.trim(), scope: input.team_id?.trim() ? { team_id: input.team_id.trim() } : {} };
    case 'aws':
      if (!input.access_key_id?.trim() || !input.secret_access_key?.trim()) throw invalid('AWS needs an access key ID and secret access key (an IAM user or role with read access, plus lambda:UpdateFunctionConfiguration to connect functions)');
      return { secret: JSON.stringify({ access_key_id: input.access_key_id.trim(), secret_access_key: input.secret_access_key.trim() }), scope: { regions: regions || 'us-east-1' } };
    case 'azure':
      for (const k of ['tenant_id', 'client_id', 'client_secret', 'subscription_id'] as const) if (!input[k]?.trim()) throw invalid(`Azure needs ${k.replace('_', ' ')} (an app registration with Reader on the subscription, plus Website Contributor to connect App Service apps)`);
      return { secret: JSON.stringify({ tenant_id: input.tenant_id!.trim(), client_id: input.client_id!.trim(), client_secret: input.client_secret!.trim(), subscription_id: input.subscription_id!.trim() }), scope: {} };
    case 'gcp': {
      let sa: { client_email?: string; private_key?: string; project_id?: string };
      try { sa = JSON.parse(input.service_account_json ?? ''); } catch { throw invalid('paste the Google service account key as JSON'); }
      if (!sa.client_email || !sa.private_key || !sa.project_id) throw invalid('the service account key needs client_email, private_key and project_id');
      return { secret: JSON.stringify({ client_email: sa.client_email, private_key: sa.private_key, project_id: sa.project_id }), scope: { regions: regions || 'us-central1' } };
    }
    case 'copilot':
      for (const k of ['tenant_id', 'client_id', 'client_secret', 'environment_url'] as const) if (!input[k]?.trim()) throw invalid(`Copilot Studio needs ${k.replace('_', ' ')} (an app registration added as an application user with read access to the Dataverse environment)`);
      return { secret: JSON.stringify({ tenant_id: input.tenant_id!.trim(), client_id: input.client_id!.trim(), client_secret: input.client_secret!.trim(), environment_url: input.environment_url!.trim() }), scope: {} };
    case 'openai':
    case 'anthropic':
      if ((input.admin_key ?? '').trim().length < 16) throw invalid(`an ${input.platform === 'openai' ? 'OpenAI' : 'Anthropic'} organization admin key is required`);
      return { secret: input.admin_key!.trim(), scope: {} };
    default:
      throw invalid('platform must be vercel, aws, azure, gcp, copilot, openai or anthropic');
  }
}

export async function create(input: CreateInput, p: Principal) {
  const platform = input.platform as PlatformKind;
  const { secret, scope } = credentialOf(input);
  const detail = await DRIVERS[platform].validate(secret, scope); // prove the credential before storing it
  const id = newId('plc');
  const label = input.label?.trim() || `${PLATFORM_LABEL[platform]} (${detail.replace(/^(signed in as|subscription|project) /, '').slice(0, 60)})`;
  const stored = await putSecret({ name: `platform-${platform}-${id.slice(-10).toLowerCase()}`, kind: 'platform', value: secret }, p);
  await tx(async () => {
    await db.prepare('INSERT INTO platform_connection (id, tenant_id, platform, label, secret_id, scope, status, status_detail, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, tenant.id, platform, label, stored.id, JSON.stringify(scope), 'connected', detail, p.id, nowIso());
    await ledger.append({ kind: 'admin', data: { event: 'platform.connected', connection_id: id, platform, label, scope, actor: p.id } });
  });
  return (await list()).find((c) => c.id === id)!;
}

export async function remove(id: string, p: Principal) {
  await connection(id);
  await tx(async () => {
    await db.prepare('UPDATE platform_connection SET revoked_at = ?, status = ? WHERE id = ?').run(nowIso(), 'disconnected', id);
    await ledger.append({ kind: 'admin', data: { event: 'platform.disconnected', connection_id: id, actor: p.id } });
  });
  return { disconnected: true };
}

// --- discovery -----------------------------------------------------------------------------------

async function rawWorkloads(id: string) {
  const c = await connection(id);
  return { c, raw: await c.driver.workloads(c.secret, c.scopeObj) };
}

export async function workloads(id: string): Promise<Workload[]> {
  const { raw } = await rawWorkloads(id);
  const links = (await db.prepare('SELECT workload_id, agent_id, state FROM platform_link WHERE connection_id = ?').all(id)) as { workload_id: string; agent_id: string; state: string }[];
  const regs = (await db.prepare("SELECT workload_id, agent_id FROM platform_link WHERE connection_id = ? AND state = 'registered'").all(id)) as { workload_id: string; agent_id: string }[];
  return raw.map((w) => {
    const l = links.find((x) => x.workload_id === w.id && x.state !== 'registered');
    return { ...w, ai_signals: aiSignals(w), linked_agent_id: l?.agent_id ?? null, link_state: l?.state ?? null, registered_agent_id: regs.find((r) => r.workload_id === w.id)?.agent_id ?? l?.agent_id ?? null };
  });
}

// Every workload that uses an AI provider, or is an AI agent on the platform, and is not yet in Signet
// becomes a Discovery Inbox finding.
export async function scan(id: string, p: Principal) {
  const c = await connection(id);
  const all = await workloads(id);
  const ai = all.filter((w) => w.ai_signals.length && !w.registered_agent_id);
  if (ai.length) {
    await discovery.ingest(`${c.platform}:${c.label}`, ai.map((w) => ({
      type: 'unregistered_agent' as const,
      summary: w.platform_ai
        ? `${w.platform_ai} "${w.name}" on ${PLATFORM_LABEL[c.platform]}${w.region ? ` (${w.region})` : ''} is not registered in Signet`
        : `${PLATFORM_LABEL[c.platform]} ${w.kind.replace('_', ' ')} ${w.name} uses ${[...new Set(w.ai_signals.map((s) => s.provider))].join(', ')} (${w.ai_signals.map((s) => s.name).join(', ')}) and is not connected to Signet`,
      location: `${PLATFORM_LABEL[c.platform]} ${w.kind.replace('_', ' ')} ${w.name}${w.url ? ` (${w.url})` : ''}`,
      fingerprint: sha256(`${c.platform}|${w.id}`).slice(0, 16),
    })), p);
  }
  await db.prepare('UPDATE platform_connection SET last_scan_at = ?, last_scan_count = ? WHERE id = ?').run(nowIso(), all.length, id);
  return { workloads: all.length, ai_workloads: all.filter((w) => w.ai_signals.length).length, new_findings: ai.length };
}

// One click from a discovered workload to a proposed agent (lifecycle starts at Propose; nothing is
// approved automatically). AI agents run by the platform itself are registered as third-party agents.
export async function register(connectionId: string, workloadId: string, p: Principal) {
  const c = await connection(connectionId);
  const w = (await workloads(connectionId)).find((x) => x.id === workloadId);
  if (!w) throw notFound(`workload ${workloadId}`);
  if (w.registered_agent_id) throw new PolicyError('VALIDATION', 'this workload is already registered as an agent', 409);
  const base = w.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50) || 'agent';
  const handle = `${base}-${sha256(w.id).slice(0, 6)}`;
  const vendorRun = !!w.platform_ai;
  const agent = await registerAgent({
    handle, name: w.name, sponsor: p.id, autonomy_level: 'L2',
    purpose: `Discovered on ${PLATFORM_LABEL[c.platform]} (${w.kind.replace('_', ' ')}${w.region ? `, ${w.region}` : ''}); describe its purpose before submitting`,
    kind: vendorRun ? 'third_party' : 'self_hosted',
    runtime: c.platform === 'vercel' ? 'vercel' : w.kind,
    framework: w.framework ?? undefined,
    vendor: vendorRun ? w.platform_ai! : undefined,
    model_provider: w.ai_signals.find((s) => s.kind !== 'model')?.provider,
  } as never, p);
  const lc = await workflow.start(agent, { planned_tools: [], users_affected: [], data_touched: [] } as never, p);
  const now = nowIso();
  await db.prepare('INSERT INTO platform_link (id, tenant_id, connection_id, workload_id, workload_name, agent_id, settings, state, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (connection_id, workload_id) DO NOTHING')
    .run(newId('pll'), tenant.id, connectionId, w.id, w.name, agent.id, '{}', 'registered', p.id, now, now);
  await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'platform.workload_registered', platform: c.platform, connection_id: connectionId, workload: w.name, workload_kind: w.kind, actor: p.id } });
  return { agent_id: agent.id, handle: agent.handle, lifecycle_id: lc.id };
}

// --- connect a workload to Signet (no code change) -----------------------------------------------

export interface LinkInput {
  agent_id: string;
  base_url_var: string;
  key_var: string;
  model_var?: string;
  remove_vars?: string[];
  environment?: string;
  redeploy?: boolean;
}

const VAR = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

function gatewayBase(): string {
  const url = process.env.SIGNET_GATEWAY_PUBLIC_URL;
  if (!url) throw new PolicyError('CONFIG', 'SIGNET_GATEWAY_PUBLIC_URL is not set: Signet does not know the public gateway address to give the app', 503);
  return url.replace(/\/+$/, '').replace(/\/v1$/, '') + '/v1';
}

export async function link(connectionId: string, workloadId: string, input: LinkInput, p: Principal) {
  const { c, raw } = await rawWorkloads(connectionId);
  const w = raw.find((x) => x.id === workloadId);
  if (!w) throw notFound(`workload ${workloadId}`);
  if (!w.linkable || !c.driver.setVars) throw new PolicyError('VALIDATION', `${PLATFORM_LABEL[c.platform]} ${w.kind.replace('_', ' ')} settings cannot be changed by Signet: ${w.platform_ai ? 'its model runs inside the platform; govern its tools instead' : 'connect it with the SDK or sidecar'}`, 409);
  for (const [k, v] of [['base_url_var', input.base_url_var], ['key_var', input.key_var], ...(input.model_var ? [['model_var', input.model_var]] : [])] as [string, string][]) {
    if (!VAR.test(v ?? '')) throw invalid(`${k} must be an environment variable name like OPENAI_API_KEY`);
  }
  const removeVars = (input.remove_vars ?? []).filter((v) => VAR.test(v) && ![input.key_var, input.base_url_var, input.model_var].includes(v));
  const agent = await getAgent(input.agent_id);
  const cert = (await activeCertificate(agent.id))?.certificate;
  if (!cert) throw new PolicyError('RB-INV-01', `agent ${agent.handle} has no seal yet: take it through approval before connecting`, 409);
  const environment = input.environment ?? cert.environments[0] ?? 'dev';
  const model = cert.models[0]?.model;
  if (!model) throw new PolicyError('VALIDATION', 'the agent\'s seal has no model grant (third-party agents cannot route their model through Signet)', 409);
  const base = gatewayBase();

  const now = nowIso();
  await db.prepare('INSERT INTO platform_link (id, tenant_id, connection_id, workload_id, workload_name, agent_id, settings, state, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (connection_id, workload_id) DO UPDATE SET agent_id = excluded.agent_id, settings = excluded.settings, state = excluded.state, detail = NULL, updated_at = excluded.updated_at')
    .run(newId('pll'), tenant.id, connectionId, w.id, w.name, agent.id, JSON.stringify({ ...input, remove_vars: removeVars }), 'configuring', p.id, now, now);
  const setState = async (state: string, detail: string | null, extra: { credential_id?: string; deployment_id?: string } = {}) => {
    await db.prepare('UPDATE platform_link SET state = ?, detail = ?, credential_id = COALESCE(?, credential_id), deployment_id = COALESCE(?, deployment_id), updated_at = ? WHERE connection_id = ? AND workload_id = ?')
      .run(state, detail, extra.credential_id ?? null, extra.deployment_id ?? null, nowIso(), connectionId, w.id);
  };
  try {
    const cred = await createDeploymentCredential(agent.id, p, environment);
    const vars = [
      { key: input.base_url_var, value: base },
      { key: input.key_var, value: cred.deployment_credential },
      ...(input.model_var ? [{ key: input.model_var, value: model }] : []),
    ];
    const removed = await c.driver.setVars(c.secret, c.scopeObj, w, vars, removeVars);
    await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'platform.workload_connected', platform: c.platform, connection_id: connectionId, workload: w.name, workload_kind: w.kind, credential_id: cred.id, set_vars: vars.map((v) => v.key), removed_vars: removed, gateway: base, actor: p.id } });
    let opId: string | null = null;
    if (input.redeploy !== false && c.driver.restart) {
      opId = await c.driver.restart(c.secret, c.scopeObj, w);
      if (opId) await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'platform.restart_started', platform: c.platform, workload: w.name, operation: opId, actor: p.id } });
    }
    await setState(opId ? 'redeploying' : 'configured', opId ? 'restart started; the app calls Signet once it is ready' : 'settings saved; redeploy or restart the workload to apply them', { credential_id: cred.id, deployment_id: opId ?? undefined });
  } catch (e) {
    await setState('failed', (e as Error).message);
    throw e;
  }
  return linkView(connectionId, w.id);
}

async function linkView(connectionId: string, workloadId: string) {
  return (await db.prepare('SELECT id, workload_id, workload_name, agent_id, credential_id, state, detail, deployment_id, updated_at FROM platform_link WHERE connection_id = ? AND workload_id = ?').get(connectionId, workloadId)) as Record<string, unknown>;
}

export async function linkStatus(connectionId: string, workloadId: string) {
  const l = (await linkView(connectionId, workloadId)) as { deployment_id: string | null; state: string } | undefined;
  if (!l) throw notFound(`link for ${workloadId}`);
  if (l.deployment_id && l.state === 'redeploying') {
    const { c, raw } = await rawWorkloads(connectionId);
    const w = raw.find((x) => x.id === workloadId);
    if (w && c.driver.restartState) {
      const s = await c.driver.restartState(c.secret, c.scopeObj, w, l.deployment_id);
      const state = s === 'ready' ? 'connected_pending_traffic' : s === 'failed' ? 'failed' : 'redeploying';
      const detail = s === 'ready' ? 'restarted; the agent shows Connected after its first call reaches the gateway' : s === 'failed' ? 'the restart failed on the platform' : 'restart in progress';
      await db.prepare('UPDATE platform_link SET state = ?, detail = ?, updated_at = ? WHERE connection_id = ? AND workload_id = ?').run(state, detail, nowIso(), connectionId, workloadId);
    }
  }
  return linkView(connectionId, workloadId);
}

export async function links() {
  return db.prepare('SELECT l.id, l.connection_id, l.workload_id, l.workload_name, l.agent_id, a.handle, l.state, l.detail, l.updated_at FROM platform_link l JOIN agent a ON a.id = l.agent_id WHERE l.tenant_id = ? ORDER BY l.updated_at DESC').all(tenant.id);
}

// --- stop on the platform (Phase C2) --------------------------------------------------------------

export async function stop(connectionId: string, workloadId: string, reason: string, actor: string) {
  if (!reason?.trim()) throw invalid('a reason is required to stop a workload');
  const { c, raw } = await rawWorkloads(connectionId);
  const w = raw.find((x) => x.id === workloadId);
  if (!w) throw notFound(`workload ${workloadId}`);
  if (!c.driver.stop) throw new PolicyError('VALIDATION', `${PLATFORM_LABEL[c.platform]} workloads cannot be stopped from Signet`, 409);
  const result = await c.driver.stop(c.secret, c.scopeObj, w);
  const linked = (await db.prepare('SELECT agent_id FROM platform_link WHERE connection_id = ? AND workload_id = ?').get(connectionId, workloadId)) as { agent_id: string } | undefined;
  await db.prepare("UPDATE platform_link SET state = 'stopped', detail = ?, updated_at = ? WHERE connection_id = ? AND workload_id = ?").run(`stopped on ${PLATFORM_LABEL[c.platform]}: ${result}`, nowIso(), connectionId, workloadId);
  await ledger.append({ kind: 'admin', agent_id: linked?.agent_id ?? null, data: { event: 'platform.workload_stopped', platform: c.platform, connection_id: connectionId, workload: w.name, workload_kind: w.kind, result, reason, actor } });
  return { stopped: true, result };
}

// Called after an agent-wide kill: every workload linked to that agent is stopped on its platform too.
export async function stopLinkedWorkloads(agentId: string, reason: string, actor: string) {
  const linked = (await db.prepare("SELECT connection_id, workload_id FROM platform_link WHERE agent_id = ? AND state <> 'stopped'").all(agentId)) as { connection_id: string; workload_id: string }[];
  for (const l of linked) {
    try {
      await stop(l.connection_id, l.workload_id, `agent killed: ${reason}`, actor);
    } catch (e) {
      // Record the failure; the kill itself (tokens revoked on every gateway) already stands.
      await ledger.append({ kind: 'admin', agent_id: agentId, data: { event: 'platform.workload_stop_failed', connection_id: l.connection_id, workload_id: l.workload_id, error: (e as Error).message } });
    }
  }
}

// --- usage outside Signet (Phase C1) -------------------------------------------------------------

export async function syncUsage(connectionId: string, days = 30) {
  const c = await connection(connectionId);
  if (!c.driver.usage) return { rows: 0, supported: false };
  const rows = await c.driver.usage(c.secret, c.scopeObj, Math.min(Math.max(days, 1), 31));
  await tx(async () => {
    for (const r of rows) {
      await db.prepare('INSERT INTO platform_usage (connection_id, workload_id, day, requests, input_tokens, output_tokens, cost_usd) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (connection_id, workload_id, day) DO UPDATE SET requests = excluded.requests, input_tokens = excluded.input_tokens, output_tokens = excluded.output_tokens, cost_usd = excluded.cost_usd')
        .run(connectionId, r.workload_id, r.day, r.requests, r.input_tokens, r.output_tokens, r.cost_usd);
    }
  });
  return { rows: rows.length, supported: true };
}

export async function usageSummary(days = 30) {
  const since = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
  return db.prepare('SELECT u.connection_id, c.platform, c.label, u.workload_id, SUM(u.requests) AS requests, SUM(u.input_tokens) AS input_tokens, SUM(u.output_tokens) AS output_tokens, MAX(u.day) AS last_day FROM platform_usage u JOIN platform_connection c ON c.id = u.connection_id WHERE c.tenant_id = ? AND u.day >= ? GROUP BY u.connection_id, c.platform, c.label, u.workload_id ORDER BY SUM(u.input_tokens) + SUM(u.output_tokens) DESC').all(tenant.id, since);
}

// Scheduled (every 6 h): refresh the last 3 days of usage for every connection that reports it. A failing
// platform is recorded on its connection and does not stop the others.
export async function sweepUsage() {
  const rows = (await db.prepare('SELECT id, platform FROM platform_connection WHERE tenant_id = ? AND revoked_at IS NULL').all(tenant.id)) as { id: string; platform: PlatformKind }[];
  for (const r of rows) {
    if (!DRIVERS[r.platform].usage) continue;
    try {
      await syncUsage(r.id, 3);
      await db.prepare("UPDATE platform_connection SET status = 'connected' WHERE id = ? AND status = 'error'").run(r.id);
    } catch (e) {
      await db.prepare("UPDATE platform_connection SET status = 'error', status_detail = ? WHERE id = ?").run(`usage sync failed: ${(e as Error).message}`.slice(0, 500), r.id);
    }
  }
}

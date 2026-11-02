import { devUserToken, automationToken, env, request } from '@signet/core';

// Clients for the e2e suites: the control API as named people (real Keycloak sign-ins), and the gateway
// as an agent. URLs come from the harness, which runs an isolated stack.

export const CONTROL = env('SIGNET_CONTROL_URL', 'http://localhost:4100');
export const GW_A1 = env('SIGNET_GATEWAY_URL', 'http://localhost:8100');
export const GW_A2 = env('SIGNET_GATEWAY2_URL', 'http://localhost:8101');
export const MODEL = env('SIGNET_LLM_MODEL', 'gpt-oss:120b-cloud');
export const TOOLS_URL = env('SIGNET_FIXTURES_URL', 'http://localhost:7910');

export type Json = Record<string, any>;

export const PEOPLE = {
  owner: 'priya.menon',
  security: 'jonas.weber',
  risk: 'ananya.rao',
  platform: 'arjun.mehta',
} as const;

const cache = new Map<string, string>();
export async function tokenFor(who: keyof typeof PEOPLE | 'automation') {
  if (!cache.has(who)) cache.set(who, who === 'automation' ? await automationToken() : await devUserToken(PEOPLE[who]));
  return cache.get(who)!;
}

export async function api(who: keyof typeof PEOPLE | 'automation', method: string, path: string, body?: unknown): Promise<{ status: number; json: Json }> {
  const r = await fetch(`${CONTROL}/api/v1${path}`, {
    method,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${await tokenFor(who)}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  return { status: r.status, json: text ? (JSON.parse(text) as Json) : {} };
}

export interface GwResult {
  status: number;
  json: Json;
  ms: number;
  decision: string | null;
  record: string | null;
  gatewayMs: number | null;
}

export async function gw(base: string, path: string, token: string, body: unknown, extra: Record<string, string> = {}): Promise<GwResult> {
  const t0 = performance.now();
  const r = await request(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, ...extra }, body: JSON.stringify(body) });
  const text = r.text();
  return {
    status: r.status,
    json: text ? (JSON.parse(text) as Json) : {},
    ms: Math.round(performance.now() - t0),
    decision: r.headers['x-signet-decision'] ?? null,
    record: r.headers['x-signet-record-id'] ?? null,
    gatewayMs: Number(r.headers['x-signet-gateway-ms']) || null,
  };
}

let rpcId = 0;
export const mcp = (base: string, alias: string, token: string, method: string, params: unknown = {}, session = 'demo-session', extra: Record<string, string> = {}) =>
  gw(base, `/v1/mcp/${alias}`, token, { jsonrpc: '2.0', id: ++rpcId, method, params }, { 'x-signet-session': session, ...extra });

// The fixture tools' credential: stored in the broker by the platform admin; the fixtures check it.
export const fixtureToolKey = () => process.env.SIGNET_FIXTURE_TOOL_KEY!;

export async function deployAgent(agentId: string) {
  const boot = await api('automation', 'POST', `/agents/${agentId}/bootstrap`, { environment: 'dev' });
  if (boot.status !== 201) throw new Error(`bootstrap failed: ${JSON.stringify(boot.json)}`);
  const r = await fetch(`${CONTROL}/api/v1/identity/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bootstrap_credential: boot.json.bootstrap_credential }) });
  return (await r.json()) as Json;
}

const must = (r: { status: number; json: Json }, what: string) => {
  if (r.status >= 300) throw new Error(`${what} failed (${r.status}): ${r.json.rule ?? ''} ${r.json.detail ?? JSON.stringify(r.json)}`);
  return r.json;
};

export interface OnboardInput {
  handle: string;
  name: string;
  purpose: string;
  team?: { user: string; role: 'builder' | 'operator' }[];
  intake: Json;
  manifest: Json;
  evidence?: { functional_score?: number; bias_ratio?: number };
  autonomy_level?: string;
  deployTo?: 'shadow' | 'enforce'; // where the rollout is left (default enforce)
  registration?: Json; // kind, runtime, framework, model_provider, vendor, vendor_details
  // Called with the lifecycle once the manifest is drafted, and with the approval before anyone signs.
  hooks?: { drafted?: (lifecycleId: string) => Promise<void>; approval?: (approvalId: string) => Promise<void> };
}

// Walks an agent through the 8-stage lifecycle as the right people (BP 6): the owner proposes, drafts
// the manifest, completes assessments and runs tests; the owner (T3/T4) or Risk (T1/T2) confirms the
// classification; the approval matrix signs; the deploy moves shadow -> (canary) -> enforce. Shadow
// periods are cut short with the recorded dev override.
export async function onboard(input: OnboardInput, log: (s: string) => void = () => {}) {
  const reg = must(await api('owner', 'POST', '/agents', { handle: input.handle, name: input.name, purpose: input.purpose, sponsor: 'ravi.kapoor@northwind.example', autonomy_level: input.autonomy_level ?? 'L2', team: input.team ?? [], intake: input.intake, ...(input.registration ?? {}) }), 'propose');
  const lc = reg.lifecycle_id as string;
  must(await api('owner', 'PUT', `/lifecycles/${lc}/manifest`, input.manifest), 'manifest');
  await input.hooks?.drafted?.(lc);
  must(await api('owner', 'POST', `/lifecycles/${lc}/stages/propose/submit`), 'submit propose');
  let view = must(await api('owner', 'GET', `/lifecycles/${lc}`), 'view');
  const tier = view.classification.tier as string;
  log(`classified ${tier} (score ${view.classification.score}, ${view.classification.regulatory_category})`);
  must(await api(tier === 'T1' || tier === 'T2' ? 'risk' : 'owner', 'POST', `/lifecycles/${lc}/classification`, { confirm: true }), 'confirm classification');
  view = must(await api('owner', 'GET', `/lifecycles/${lc}`), 'view');
  for (const a of view.assessments as Json[]) {
    const content = a.type === 'questionnaire'
      ? { ...a.content, answers: Object.fromEntries(Object.keys(a.content.answers).map((k) => [k, { answer: 'yes', note: 'confirmed by owner' }])) }
      : { summary: `${a.type.replace('_', ' ')} completed for ${input.handle}`, findings: 'no open findings', owner_signoff: 'priya.menon@northwind.example' };
    must(await api('owner', 'PUT', `/lifecycles/${lc}/assessments/${a.type}`, { content, complete: true }), `assessment ${a.type}`);
  }
  must(await api('owner', 'POST', `/lifecycles/${lc}/stages/assess/submit`), 'submit assess');
  const test = must(await api('owner', 'POST', `/lifecycles/${lc}/test-runs`, input.evidence ?? { functional_score: 92 }), 'tests');
  log(`baseline tests ${test.passed ? 'passed' : 'FAILED'} · report ${String(test.report_sha256).slice(0, 12)}…`);
  if (!test.passed) throw new Error(`tests failed: ${JSON.stringify(test.suites.filter((s: Json) => s.required && !s.passed))}`);
  view = must(await api('owner', 'GET', `/lifecycles/${lc}`), 'view');
  if (view.approval) {
    await input.hooks?.approval?.(view.approval.id);
    await approveAll(view.approval.id);
  }
  view = must(await api('owner', 'GET', `/lifecycles/${lc}`), 'view');
  if (input.deployTo === 'shadow') return { agentId: reg.id as string, lifecycleId: lc, tier };
  if (view.lifecycle.data.deploy?.canary) must(await api('owner', 'POST', `/lifecycles/${lc}/deploy`, { to: 'canary', dev_override: true, reason: 'demo: shadow period cut short', acknowledge_would_blocks: true }), 'canary');
  must(await api('owner', 'POST', `/lifecycles/${lc}/deploy`, { to: 'enforce', dev_override: true, reason: 'demo: deploy period cut short', acknowledge_would_blocks: true }), 'enforce');
  return { agentId: reg.id as string, lifecycleId: lc, tier };
}

// Fills every open slot of an approval with the dev account that may hold it.
export async function approveAll(approvalId: string, comment = 'approved in demo') {
  const r = must(await api('owner', 'GET', `/approvals/${approvalId}`), 'approval');
  for (const slot of r.slots as Json[]) {
    const who = slot.owner_only || slot.owner_allowed ? 'owner' : slot.roles.includes('security_officer') ? 'security' : slot.roles.includes('risk_officer') ? 'risk' : null;
    if (!who) throw new Error(`no dev account for slot ${slot.slot}`);
    must(await api(who, 'POST', `/approvals/${approvalId}/decisions`, { decision: 'approve', slot: slot.slot, comment }), `approve ${slot.slot}`);
  }
}

// The fixture tools, registered as a platform admin would. Already registered (409) is fine.
export async function ensureTools() {
  const ok = (r: { status: number; json: Json }, what: string) => {
    if (r.status >= 300 && r.status !== 409) throw new Error(`${what} failed (${r.status}): ${r.json.rule ?? ''} ${r.json.detail ?? JSON.stringify(r.json)}`);
  };
  ok(await api('platform', 'POST', '/secrets', { name: 'orders-api-key', kind: 'tool', value: fixtureToolKey() }), 'secret');
  ok(await api('platform', 'POST', '/tools', { alias: 'orders', kind: 'mcp', url: `${TOOLS_URL}/mcp`, secret: 'orders-api-key' }), 'tool orders');
  ok(await api('platform', 'POST', '/tools', {
    alias: 'crm', kind: 'http', url: `${TOOLS_URL}/crm`, secret: 'orders-api-key',
    actions: { get_customer: { method: 'GET', path: '/customers/{id}' }, add_note: { method: 'POST', path: '/notes' } },
  }), 'tool crm');
}

// What the gateway decided: the error's decision, or the x-signet-decision header on success.
export function outcome(r: GwResult): string {
  const rpc = r.json.jsonrpc ? r.json : null;
  const err = rpc?.error?.data ?? r.json.error;
  if (r.status === 200 && !err) return r.decision ?? 'allow';
  return String(err?.decision ?? r.status);
}

export function check(cond: unknown, what: string): asserts cond {
  if (!cond) throw new Error(`check failed: ${what}`);
}

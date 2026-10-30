import { devSecret, devUserToken, automationToken, env, request } from '@signet/core';

// Small clients for demo scripts: the control API as named people, and the gateway as an agent.

export const CONTROL = env('SIGNET_CONTROL_URL', 'http://localhost:4100');
export const GW_A1 = env('SIGNET_GATEWAY_URL', 'http://localhost:8100');
export const GW_A2 = env('SIGNET_GATEWAY2_URL', 'http://localhost:8101');
export const MODEL = env('SIGNET_LLM_MODEL', 'gpt-oss:120b-cloud');
export const TOOLS_URL = env('SIGNET_MOCK_TOOLS_URL', 'http://localhost:7100');

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
export const mcp = (base: string, alias: string, token: string, method: string, params: unknown = {}, session = 'demo-session') =>
  gw(base, `/v1/mcp/${alias}`, token, { jsonrpc: '2.0', id: ++rpcId, method, params }, { 'x-signet-session': session });

// The demo tool credential: stored in the broker by the platform admin; the mock tools check it.
export const demoToolKey = () => devSecret('SIGNET_DEMO_TOOL_KEY');

export async function deployAgent(agentId: string) {
  const boot = await api('automation', 'POST', `/agents/${agentId}/bootstrap`, { environment: 'dev' });
  if (boot.status !== 201) throw new Error(`bootstrap failed: ${JSON.stringify(boot.json)}`);
  const r = await fetch(`${CONTROL}/api/v1/identity/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ bootstrap_credential: boot.json.bootstrap_credential }) });
  return (await r.json()) as Json;
}

export async function ensureTools() {
  await api('platform', 'POST', '/secrets', { name: 'orders-api-key', kind: 'tool', value: demoToolKey() });
  await api('platform', 'POST', '/tools', { alias: 'orders', kind: 'mcp', url: `${TOOLS_URL}/mcp`, secret: 'orders-api-key' });
  await api('platform', 'POST', '/tools', {
    alias: 'crm', kind: 'http', url: `${TOOLS_URL}/crm`, secret: 'orders-api-key',
    actions: { get_customer: { method: 'GET', path: '/customers/{id}' }, add_note: { method: 'POST', path: '/notes' } },
  });
}

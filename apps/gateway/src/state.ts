import { hostname } from 'node:os';
import type { KeyObject } from 'node:crypto';
import {
  canonicalize, devSecret, env, fromJwk, request, scopeKey, sha256, verifyJws,
  type CertificateBody, type CompiledPolicy, type DetectorConfig, type PolicyBundle, type PublicJwk, type ScopeState, type ToolAlias,
} from '@signet/core';

// Gateway-side cache of the signed policy bundle (BP 3, 5.2). Gateways are stateless apart from this
// cache: they enforce from memory and keep enforcing on the last bundle if the control plane is down.

export const CONTROL_URL = env('SIGNET_CONTROL_URL', 'http://localhost:4100');
const INTERNAL_TOKEN = devSecret('SIGNET_INTERNAL_TOKEN');
export const PORT = Number(env('SIGNET_GATEWAY_PORT', '8100'));
export const NODE_ID = env('SIGNET_NODE_ID', `gw-${hostname().toLowerCase()}-${PORT}`);
const POLL_MS = 5_000; // BP 5.4 fallback poll
const SECRET_TTL_MS = 60_000;

let caKeys: Map<string, KeyObject> = new Map();
export let tokenKeys: Map<string, KeyObject> = new Map();
export let bundle: PolicyBundle | null = null;
export const certs = new Map<string, CertificateBody>();
export const policies = new Map<string, CompiledPolicy>();
export const tools = new Map<string, ToolAlias>();
export const detectors = new Map<string, DetectorConfig>();
let scopes = new Map<string, ScopeState>();
let revoked = new Set<string>();

// In-flight upstream calls, cut on quarantine or kill (BP 5.4).
interface Inflight {
  agentId: string;
  version: string;
  instanceId: string;
  ctrl: AbortController;
}
const inflight = new Set<Inflight>();

export function track(agentId: string, version: string, instanceId: string, ctrl: AbortController) {
  const entry = { agentId, version, instanceId, ctrl };
  inflight.add(entry);
  return () => inflight.delete(entry);
}

const liveState = (s: ScopeState | undefined) => (s && (s.level === 'killed' || s.level === 'quarantined' || !s.until_ms || s.until_ms > Date.now()) ? s : undefined);

export interface Effective {
  blocked: 'killed' | 'quarantined' | null;
  stepUp: boolean;
  throttleFactor: number;
}

// The strictest state across the agent, its version and this instance.
export function effective(agentId: string, version: string, instanceId: string): Effective {
  const states = [scopeKey.agent(agentId), scopeKey.version(agentId, version), scopeKey.instance(instanceId)].map((k) => liveState(scopes.get(k))).filter(Boolean) as ScopeState[];
  return {
    blocked: states.some((s) => s.level === 'killed') ? 'killed' : states.some((s) => s.level === 'quarantined') ? 'quarantined' : null,
    stepUp: states.some((s) => s.level === 'step_up'),
    throttleFactor: Math.min(1, ...states.filter((s) => s.level === 'throttled').map((s) => s.factor ?? 0.5)),
  };
}

export const isRevoked = (jti: string) => revoked.has(jti);
export const bundleExpired = () => !bundle || Date.parse(bundle.expires_at) < Date.now();

export function applyScope(key: string, state: ScopeState) {
  if (scopes.get(key)?.level === 'killed') return; // never lifted (RB-INV-08)
  if (state.level === 'active') scopes.delete(key);
  else scopes.set(key, state);
  if (state.level === 'killed' || state.level === 'quarantined') {
    for (const f of inflight) {
      const hit = key === scopeKey.agent(f.agentId) || key === scopeKey.version(f.agentId, f.version) || key === scopeKey.instance(f.instanceId);
      if (hit) f.ctrl.abort(new Error(`agent ${state.level}`));
    }
  }
}

export async function internal<T>(path: string, init?: { method?: string; body?: string }): Promise<T> {
  const r = await request(`${CONTROL_URL}${path}`, {
    method: init?.method ?? 'GET',
    body: init?.body,
    headers: { 'content-type': 'application/json', 'x-signet-internal': INTERNAL_TOKEN },
    timeoutMs: 5_000,
  });
  const body = r.json<T & { detail?: string }>();
  if (!r.ok) throw new Error(`control plane ${path}: ${r.status} ${body.detail ?? ''}`);
  return body;
}

export async function refresh() {
  const { bundle: jws } = await internal<{ bundle: string }>('/internal/bundle');
  const next = verifyJws<PolicyBundle>(jws, caKeys, 'signet-bundle').payload;
  if (bundle && next.version < bundle.version) return;
  const verifiedCerts = new Map<string, CertificateBody>();
  const verifiedPolicies = new Map<string, CompiledPolicy>();
  for (const c of next.certificates) {
    const body = verifyJws<CertificateBody>(c, caKeys, 'signet-seal').payload; // each seal checked again
    const policy = next.policies[body.cert_id];
    // The compiled policy must be exactly the one the seal was signed over.
    if (!policy || sha256(canonicalize(policy)) !== body.policy_sha256) {
      console.error(`[gateway] policy for ${body.cert_id} does not match its seal; seal ignored`);
      continue;
    }
    verifiedCerts.set(body.cert_id, body);
    verifiedPolicies.set(body.cert_id, policy);
  }
  certs.clear();
  policies.clear();
  for (const [k, v] of verifiedCerts) certs.set(k, v);
  for (const [k, v] of verifiedPolicies) policies.set(k, v);
  const killed = [...scopes].filter(([, s]) => s.level === 'killed');
  scopes = new Map(Object.entries(next.enforcement));
  for (const [k, s] of killed) scopes.set(k, s);
  for (const [k, s] of Object.entries(next.enforcement)) applyScope(k, s);
  tools.clear();
  for (const t of next.tools) tools.set(t.alias, t);
  detectors.clear();
  for (const d of next.detectors) detectors.set(d.id, d);
  revoked = new Set(next.revoked_jti);
  bundle = next;
}

// Brokered credentials (BP 5.2 step 11), cached briefly in memory, never logged.
const secretCache = new Map<string, { value: string; at: number }>();
export async function secret(id: string): Promise<string> {
  const c = secretCache.get(id);
  if (c && Date.now() - c.at < SECRET_TTL_MS) return c.value;
  const s = await internal<{ value: string }>(`/internal/secrets/${encodeURIComponent(id)}`);
  secretCache.set(id, { value: s.value, at: Date.now() });
  return s.value;
}

async function subscribe() {
  for (;;) {
    try {
      const r = await fetch(`${CONTROL_URL}/internal/events?node=${encodeURIComponent(NODE_ID)}`, { headers: { 'x-signet-internal': INTERNAL_TOKEN } });
      if (!r.ok || !r.body) throw new Error(`events ${r.status}`);
      const decoder = new TextDecoder();
      let buf = '';
      for await (const chunk of r.body as unknown as AsyncIterable<Uint8Array>) {
        buf += decoder.decode(chunk, { stream: true });
        let i: number;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const frame = buf.slice(0, i);
          buf = buf.slice(i + 2);
          const type = frame.match(/^event: (.+)$/m)?.[1];
          const data = frame.match(/^data: (.+)$/m)?.[1];
          if (!type || !data) continue;
          const ev = JSON.parse(data) as Record<string, unknown>;
          if (type === 'enforcement') {
            applyScope(String(ev.scope_key), ev.state as ScopeState); // apply first, then confirm
            internal('/internal/acks', { method: 'POST', body: JSON.stringify({ event_id: ev.event_id, node_id: NODE_ID }) }).catch(() => {});
            refresh().catch(() => {});
          } else if (type === 'secret') {
            secretCache.delete(String(ev.secret_id));
          } else {
            refresh().catch(() => {});
          }
        }
      }
    } catch {
      // control plane unreachable: keep enforcing on the cached bundle and retry
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
}

const heartbeat = () =>
  internal('/internal/heartbeat', { method: 'POST', body: JSON.stringify({ node_id: NODE_ID, url: `http://localhost:${PORT}`, bundle_version: bundle?.version ?? null }) }).catch(() => {});

export async function init() {
  let trust: { ca: PublicJwk; token: PublicJwk } | undefined;
  for (let attempt = 1; !trust; attempt++) {
    try {
      trust = await internal<{ ca: PublicJwk; token: PublicJwk }>('/internal/trust');
    } catch (e) {
      if (attempt >= 40) throw e;
      await new Promise((r) => setTimeout(r, 500)); // control plane still starting
    }
  }
  caKeys = new Map([[trust.ca.kid, fromJwk(trust.ca)]]);
  tokenKeys = new Map([[trust.token.kid, fromJwk(trust.token)]]);
  await refresh();
  void subscribe();
  setInterval(() => refresh().catch(() => {}), POLL_MS).unref();
  void heartbeat();
  setInterval(heartbeat, 10_000).unref();
}

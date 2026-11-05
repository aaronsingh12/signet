import { hostname } from 'node:os';
import type { KeyObject } from 'node:crypto';
import {
  canonicalize, devSecret, env, fromJwk, request, scopeKey, sha256, verifyJws,
  type CertificateBody, type CompiledPolicy, type DetectorConfig, type PolicyBundle, type PublicJwk, type Rollout, type ScopeState, type ToolAlias,
} from '@signet/core';
import { eraseAgentVault } from './vault';
import { eraseAgentLimits } from './limits';
import { eraseSessions } from './taint';
import { eraseAgentOutage } from './outage';
import { eraseAgentLedgerQueue } from './ledgerclient';

// Gateway-side cache of the signed policy bundle (BP 3, 5.2). Gateways are stateless apart from this
// cache: they enforce from memory and keep enforcing on the last bundle if the control plane is down.

export const CONTROL_URL = env('SIGNET_CONTROL_URL', 'http://localhost:4100').replace(/\/+$/, '');
const INTERNAL_TOKEN = devSecret('SIGNET_INTERNAL_TOKEN');
export const PORT = Number(process.env.PORT ?? env('SIGNET_GATEWAY_PORT', '8100'));
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
export const rollouts = new Map<string, Rollout>();
export const hitlWaitMs = () => (bundle?.hitl_wait_seconds ?? 120) * 1000;
let onHitl: (approvalId: string) => void = () => {};
export const setHitlListener = (fn: (approvalId: string) => void) => (onHitl = fn);
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
const erasedAgents = new Set<string>();
const erasedScopes = new Set<string>();
const erasedTokens = new Set<string>();
const agentRuntime = new Map<string, { sessions: Set<string>; instances: Set<string>; tokens: Set<string> }>();

/** Retain local cleanup identifiers until the signed bundle confirms agent erasure. */
export function rememberAgentRuntime(agentId: string, sessionId: string, instanceId: string, tokenId: string): void {
  const runtime = agentRuntime.get(agentId) ?? { sessions: new Set<string>(), instances: new Set<string>(), tokens: new Set<string>() };
  runtime.sessions.add(sessionId);
  runtime.instances.add(instanceId);
  runtime.tokens.add(tokenId);
  agentRuntime.set(agentId, runtime);
}

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
export const agentErased = (agentId: string): boolean => erasedAgents.has(sha256(agentId));
export const bundleExpired = () => !bundle || Date.parse(bundle.expires_at) < Date.now();

export function applyScope(key: string, state: ScopeState) {
  if (erasedScopes.has(sha256(key))) return;
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
  const erasedHashes = new Set(next.erased_agent_hashes ?? []);
  const knownAgents = new Set([...agentRuntime.keys(), ...[...certs.values()].map((cert) => cert.agent_id)]);
  for (const agentId of knownAgents) {
    if (!erasedHashes.has(sha256(agentId))) continue;
    await eraseAgentMemory(agentId, [], [], []);
  }
  for (const digest of erasedHashes) erasedAgents.add(digest);
  const verifiedCerts = new Map<string, CertificateBody>();
  const verifiedPolicies = new Map<string, CompiledPolicy>();
  const verifiedCertificates: string[] = [];
  for (const c of next.certificates) {
    const body = verifyJws<CertificateBody>(c, caKeys, 'signet-seal').payload; // each seal checked again
    if (erasedAgents.has(sha256(body.agent_id))) continue;
    const policy = next.policies[body.cert_id];
    // The compiled policy must be exactly the one the seal was signed over.
    if (!policy || sha256(canonicalize(policy)) !== body.policy_sha256) {
      console.error(`[gateway] policy for ${body.cert_id} does not match its seal; seal ignored`);
      continue;
    }
    verifiedCerts.set(body.cert_id, body);
    verifiedPolicies.set(body.cert_id, policy);
    verifiedCertificates.push(c);
  }
  certs.clear();
  policies.clear();
  for (const [k, v] of verifiedCerts) certs.set(k, v);
  for (const [k, v] of verifiedPolicies) policies.set(k, v);
  const killed = [...scopes].filter(([key, s]) => s.level === 'killed' && !erasedScopes.has(sha256(key)));
  const enforcement = Object.fromEntries(Object.entries(next.enforcement).filter(([key]) => !erasedScopes.has(sha256(key))));
  scopes = new Map(Object.entries(enforcement));
  for (const [k, s] of killed) scopes.set(k, s);
  for (const [k, s] of Object.entries(enforcement)) applyScope(k, s);
  tools.clear();
  for (const t of next.tools) tools.set(t.alias, t);
  detectors.clear();
  for (const d of next.detectors) detectors.set(d.id, d);
  rollouts.clear();
  for (const [k, v] of Object.entries(next.rollouts ?? {})) if (verifiedPolicies.has(k)) rollouts.set(k, v);
  const revokedTokens = next.revoked_jti.filter((token) => !erasedTokens.has(sha256(token)));
  revoked = new Set(revokedTokens);
  bundle = { ...next, certificates: verifiedCertificates, policies: Object.fromEntries(verifiedPolicies), enforcement, revoked_jti: revokedTokens, rollouts: Object.fromEntries(rollouts) };
}

function isUnknownSigningKey(error: unknown): boolean {
  return error instanceof Error && /^unknown signing key\b/.test(error.message);
}

async function refreshTrust() {
  const trust = await internal<{ ca: PublicJwk; token: PublicJwk }>('/internal/trust');
  caKeys = new Map([[trust.ca.kid, fromJwk(trust.ca)]]);
  tokenKeys = new Map([[trust.token.kid, fromJwk(trust.token)]]);
}

// Control-plane deployments can rotate the CA after the trust document has been
// read but before the bundle arrives. Re-read the authenticated trust document
// once, then verify the bundle again. Any other verification failure remains
// fail-closed.
async function refreshWithCurrentTrust() {
  try {
    await refresh();
  } catch (error) {
    if (!isUnknownSigningKey(error)) throw error;
    await refreshTrust();
    await refresh();
  }
}

async function eraseAgentMemory(agentId: string, sessionIds: string[], instanceIds: string[], tokenIds: string[]): Promise<void> {
  const runtime = agentRuntime.get(agentId);
  const sessions = [...new Set([...sessionIds, ...(runtime?.sessions ?? [])])];
  const instances = [...new Set([...instanceIds, ...(runtime?.instances ?? [])])];
  const tokens = [...new Set([...tokenIds, ...(runtime?.tokens ?? [])])];
  applyScope(scopeKey.agent(agentId), { level: 'killed' });
  const deadline = Date.now() + 5_000;
  while ([...inflight].some((entry) => entry.agentId === agentId)) {
    if (Date.now() >= deadline) throw new Error(`Agent ${agentId} still has in-flight calls; cleanup cannot complete`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  await eraseSessions(sessions.map((session) => `${agentId}:${session}`));
  await eraseAgentLedgerQueue(agentId);
  erasedAgents.add(sha256(agentId));
  const matches = (key: string): boolean => key === scopeKey.agent(agentId) || key.startsWith(`version:${agentId}@`) || instances.some((instance) => key === scopeKey.instance(instance));
  for (const key of [scopeKey.agent(agentId), ...instances.map((instance) => scopeKey.instance(instance)), ...[...scopes.keys()].filter(matches)]) erasedScopes.add(sha256(key));
  for (const token of tokens) erasedTokens.add(sha256(token));
  eraseAgentVault(agentId);
  eraseAgentLimits(agentId, sessions);
  eraseAgentOutage(agentId);
  agentRuntime.delete(agentId);
  for (const [id, cert] of certs) {
    if (cert.agent_id !== agentId) continue;
    certs.delete(id);
    policies.delete(id);
    rollouts.delete(id);
  }
  for (const key of scopes.keys()) if (matches(key)) scopes.delete(key);
  for (const token of tokens) revoked.delete(token);
  if (bundle) bundle = { ...bundle, enforcement: Object.fromEntries(Object.entries(bundle.enforcement).filter(([key]) => !matches(key))), revoked_jti: bundle.revoked_jti.filter((token) => !tokens.includes(token)) };
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
          if (type === 'agent.erase') {
            const strings = (value: unknown): string[] => {
              if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) throw new TypeError('Agent erasure event must contain string arrays');
              return value;
            };
            await eraseAgentMemory(String(ev.agent_id), strings(ev.sessions), strings(ev.instances), strings(ev.tokens));
            await refresh();
            await internal('/internal/agent-erasure-acks', { method: 'POST', body: JSON.stringify({ request_id: ev.request_id, node_id: NODE_ID }) });
          } else if (type === 'enforcement') {
            applyScope(String(ev.scope_key), ev.state as ScopeState); // apply first, then confirm
            internal('/internal/acks', { method: 'POST', body: JSON.stringify({ event_id: ev.event_id, node_id: NODE_ID }) }).catch(() => {});
            refreshWithCurrentTrust().catch(() => {});
          } else if (type === 'hitl') {
            onHitl(String(ev.approval_id));
          } else if (type === 'secret') {
            secretCache.delete(String(ev.secret_id));
          } else {
            refreshWithCurrentTrust().catch(() => {});
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
  internal('/internal/heartbeat', { method: 'POST', body: JSON.stringify({ node_id: NODE_ID, url: `http://localhost:${PORT}`, bundle_version: bundle?.version ?? null, llm_status: heartbeatExtra() }) }).catch(() => {});

// Set by the provider module, which imports this one (avoids an import cycle).
let heartbeatExtra: () => unknown = () => null;
export const setHeartbeatExtra = (fn: () => unknown) => (heartbeatExtra = fn);

export async function init() {
  for (let attempt = 1; ; attempt++) {
    try {
      await refreshTrust();
      break;
    } catch (e) {
      if (attempt >= 40) throw e;
      await new Promise((r) => setTimeout(r, 500)); // control plane still starting
    }
  }
  await refreshWithCurrentTrust();
  void subscribe();
  setInterval(() => refreshWithCurrentTrust().catch(() => {}), POLL_MS).unref();
  void heartbeat();
  setInterval(heartbeat, 10_000).unref();
}

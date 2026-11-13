import * as state from './state';

// Limits and repeat-violation counters are shared through the control plane, so every gateway
// instance (Vercel runs several and restarts them cold) counts against the same numbers. The local
// counters below stay as the fallback while the control plane cannot be reached.

const minute = new Map<string, number[]>();
const daily = new Map<string, { day: string; tokens: number; usd: number }>();
const outOfManifest = new Map<string, number[]>();
const sessionTools = new Map<string, { n: number; at: number }>();

const today = () => new Date().toISOString().slice(0, 10);

export function eraseAgentLimits(agentId: string, sessions: string[]): void {
  minute.delete(agentId);
  daily.delete(agentId);
  outOfManifest.delete(agentId);
  for (const session of sessions) sessionTools.delete(`${agentId}:${session}`);
}

// Requests per minute (BP 5.2 step 5), reduced by a throttle (ladder level 3), plus today's usage.
export async function takeRequest(agentId: string, rpm: number): Promise<{ allowed: boolean; tokens: number; usd: number }> {
  const local = takeLocalRequest(agentId, rpm);
  try {
    const shared = await state.internal<{ in_minute: number; tokens_today: number; usd_today: number }>('/internal/limits/take', { method: 'POST', body: JSON.stringify({ agent_id: agentId }) });
    return { allowed: shared.in_minute <= Math.max(1, Math.floor(rpm)), tokens: shared.tokens_today, usd: shared.usd_today };
  } catch {
    const u = usage(agentId);
    return { allowed: local, tokens: u.tokens, usd: u.usd };
  }
}

function takeLocalRequest(agentId: string, rpm: number): boolean {
  const now = Date.now();
  const hits = (minute.get(agentId) ?? []).filter((t) => now - t < 60_000);
  if (hits.length >= Math.max(1, Math.floor(rpm))) {
    minute.set(agentId, hits);
    return false;
  }
  hits.push(now);
  minute.set(agentId, hits);
  return true;
}

export function usage(agentId: string) {
  const u = daily.get(agentId);
  return u && u.day === today() ? u : { day: today(), tokens: 0, usd: 0 };
}

export function addUsage(agentId: string, tokens: number, usd: number) {
  const u = usage(agentId);
  daily.set(agentId, { day: u.day, tokens: u.tokens + tokens, usd: u.usd + usd });
  state.internal('/internal/limits/usage', { method: 'POST', body: JSON.stringify({ agent_id: agentId, tokens, usd }) })
    .catch((e: Error) => console.error(`[gateway] could not record shared usage for ${agentId}: ${e.message}`));
}

// Out-of-manifest attempts in a sliding 10-minute window (RB-KILL-04).
export async function recordOutOfManifest(agentId: string): Promise<number> {
  const local = recordLocalOutOfManifest(agentId);
  try {
    return (await state.internal<{ attempts: number }>('/internal/limits/out-of-manifest', { method: 'POST', body: JSON.stringify({ agent_id: agentId }) })).attempts;
  } catch {
    return local;
  }
}

function recordLocalOutOfManifest(agentId: string): number {
  const now = Date.now();
  const hits = (outOfManifest.get(agentId) ?? []).filter((t) => now - t < 10 * 60_000);
  hits.push(now);
  outOfManifest.set(agentId, hits);
  return hits.length;
}

// Unauthenticated refusals recorded per client address per minute (flood guard; per node is enough).
const ANONYMOUS_RECORDED_PER_MINUTE = 20;
const anonymous = new Map<string, number[]>();
export function takeAnonymousFailure(address: string): boolean {
  const now = Date.now();
  const hits = (anonymous.get(address) ?? []).filter((t) => now - t < 60_000);
  if (hits.length >= ANONYMOUS_RECORDED_PER_MINUTE) return false;
  hits.push(now);
  anonymous.set(address, hits);
  return true;
}

// Tool calls per session (seal limit tool_calls_per_session), shared through the control plane; the
// key is "<agent_id>:<session>". The higher of the shared and local counts is used.
const localToolCalls = (sessionKey: string) => sessionTools.get(sessionKey)?.n ?? 0;
export async function toolCallsIn(sessionKey: string): Promise<number> {
  try {
    const shared = (await state.internal<{ calls: number }>('/internal/limits/tool-calls/read', { method: 'POST', body: JSON.stringify({ session: sessionKey }) })).calls;
    return Math.max(shared, localToolCalls(sessionKey));
  } catch {
    return localToolCalls(sessionKey);
  }
}
export async function countToolCall(sessionKey: string): Promise<void> {
  sessionTools.set(sessionKey, { n: localToolCalls(sessionKey) + 1, at: Date.now() });
  await state.internal('/internal/limits/tool-call', { method: 'POST', body: JSON.stringify({ session: sessionKey }) })
    .catch((e: Error) => console.error(`[gateway] could not share the session tool count: ${e.message}`));
}

setInterval(() => {
  const cutoff = Date.now() - 3_600_000;
  for (const [k, v] of sessionTools) if (v.at < cutoff) sessionTools.delete(k);
  for (const [k, v] of anonymous) if (!v.some((t) => Date.now() - t < 60_000)) anonymous.delete(k);
}, 60_000).unref();

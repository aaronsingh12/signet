// Per-node counters for limits and repeat-violation rules. Dev runs two gateway nodes with these
// counters local to each; cluster-wide counters move to Valkey with the SaaS cells (BP 3 stack).

const minute = new Map<string, number[]>();
const daily = new Map<string, { day: string; tokens: number; usd: number }>();
const outOfManifest = new Map<string, number[]>();
const sessionTools = new Map<string, { n: number; at: number }>();

const today = () => new Date().toISOString().slice(0, 10);

// Requests per minute (BP 5.2 step 5), reduced by a throttle (ladder level 3).
export function takeRequest(agentId: string, rpm: number): boolean {
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
}

// Out-of-manifest attempts in a sliding 10-minute window (RB-KILL-04).
export function recordOutOfManifest(agentId: string): number {
  const now = Date.now();
  const hits = (outOfManifest.get(agentId) ?? []).filter((t) => now - t < 10 * 60_000);
  hits.push(now);
  outOfManifest.set(agentId, hits);
  return hits.length;
}

export const toolCallsIn = (sessionId: string) => sessionTools.get(sessionId)?.n ?? 0;
export function countToolCall(sessionId: string) {
  sessionTools.set(sessionId, { n: toolCallsIn(sessionId) + 1, at: Date.now() });
}

setInterval(() => {
  const cutoff = Date.now() - 3_600_000;
  for (const [k, v] of sessionTools) if (v.at < cutoff) sessionTools.delete(k);
}, 60_000).unref();

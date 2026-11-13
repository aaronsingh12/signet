import * as state from './state';

// Session taint (RB-BL-12): once a tool response or retrieved document scores Elevated or High on
// DET-INJ, the session stays tainted for up to 60 minutes and every privileged or critical action
// needs a person. "High" also arms the Hijack kill (RB-KILL-01).
// The taint is shared through the control plane, so a session tainted on one gateway instance stays
// tainted on every other one (Vercel runs several and restarts them). The local copy is the fallback,
// and keeps the source text for the ledger.

const TTL_MS = 60 * 60_000;
const sessions = new Map<string, { band: 'elevated' | 'high'; until: number; source: string }>();

export function taint(sessionId: string, band: 'elevated' | 'high', source: string): Promise<void> {
  const prior = localTaint(sessionId);
  sessions.set(sessionId, { band: prior?.band === 'high' ? 'high' : band, until: Date.now() + TTL_MS, source });
  return state.internal('/internal/limits/taint', { method: 'POST', body: JSON.stringify({ session: sessionId, band }) })
    .then(() => undefined)
    .catch((e: Error) => console.error(`[gateway] could not share session taint: ${e.message}`));
}

/** The session's taint from this node or any other node; the stronger band wins. */
export async function taintOf(sessionId: string): Promise<{ band: 'elevated' | 'high'; until: number; source: string } | null> {
  const local = localTaint(sessionId);
  try {
    const shared = (await state.internal<{ taint: { band: 'elevated' | 'high'; until: number } | null }>('/internal/limits/taint/read', { method: 'POST', body: JSON.stringify({ session: sessionId }) })).taint;
    if (!shared) return local;
    if (!local) return { ...shared, source: 'another gateway node' };
    return { band: shared.band === 'high' || local.band === 'high' ? 'high' : 'elevated', until: Math.max(shared.until, local.until), source: local.source };
  } catch {
    return local;
  }
}

function localTaint(sessionId: string) {
  const t = sessions.get(sessionId);
  if (!t) return null;
  if (t.until < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }
  return t;
}

// Detector verdicts still being computed for a session. A privileged or critical action waits for
// them (bounded), so scoring off the critical path can never let a hijack through.
const pending = new Map<string, Set<Promise<unknown>>>();

export async function eraseSessions(sessionIds: string[]): Promise<void> {
  const settled = await Promise.all(sessionIds.map((sessionId) => settle(sessionId, 5_000)));
  if (settled.some((complete) => !complete)) throw new Error('Agent deletion cannot complete while detector work is still running; retry after detector processing completes');
  for (const sessionId of sessionIds) { sessions.delete(sessionId); pending.delete(sessionId); }
}

export function trackPending(sessionId: string, p: Promise<unknown>) {
  const set = pending.get(sessionId) ?? new Set();
  set.add(p);
  pending.set(sessionId, set);
  void p.finally(() => {
    set.delete(p);
    if (!set.size) pending.delete(sessionId);
  });
}

export async function settle(sessionId: string, maxMs: number): Promise<boolean> {
  const set = pending.get(sessionId);
  if (!set?.size) return true;
  let timer: NodeJS.Timeout | undefined;
  const done = await Promise.race([Promise.allSettled([...set]).then(() => true), new Promise<boolean>((r) => (timer = setTimeout(() => r(false), maxMs)))]);
  clearTimeout(timer);
  return done;
}

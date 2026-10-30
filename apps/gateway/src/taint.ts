// Session taint (RB-BL-12): once a tool response or retrieved document scores Elevated or High on
// DET-INJ, the session stays tainted for up to 60 minutes and every privileged or critical action
// needs a person. "High" also arms the Hijack kill (RB-KILL-01).

const TTL_MS = 60 * 60_000;
const sessions = new Map<string, { band: 'elevated' | 'high'; until: number; source: string }>();

export function taint(sessionId: string, band: 'elevated' | 'high', source: string) {
  const prior = taintOf(sessionId);
  sessions.set(sessionId, { band: prior?.band === 'high' ? 'high' : band, until: Date.now() + TTL_MS, source });
}

export function taintOf(sessionId: string) {
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

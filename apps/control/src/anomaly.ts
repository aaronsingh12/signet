import { ANOM_THRESHOLDS, BASELINE_DAYS, anomalyBand, baselineReady, buildBaseline, scoreAnomaly, type AnomalyBaseline, type Tier } from '@signet/core';
import { db, nowIso } from './db';

// DET-ANOM (DA 3, SGC-MON-004): per-agent baselines built from the ledger, scored against the last 60
// minutes of shared counters. Baselines are rebuilt nightly; a missing or stale one is rebuilt on use.

const DAY = 86_400_000;
const BUCKET_MS = 5 * 60_000;
const WINDOW_MS = 60 * 60_000;
const cache = new Map<string, { at: number; b: AnomalyBaseline | null }>();

export async function computeBaseline(agentId: string, now = new Date()): Promise<AnomalyBaseline> {
  const to = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())); // whole days only
  const from = new Date(to.getTime() - BASELINE_DAYS * DAY);
  const rows = (await db.prepare(
    `SELECT ts, jsonb_extract_path_text(data::jsonb, 'cost_usd') AS cost, jsonb_extract_path_text(data::jsonb, 'outcome') AS outcome,
            jsonb_extract_path_text(data::jsonb, 'action_type') AS action, jsonb_extract_path_text(data::jsonb, 'target') AS target
       FROM ledger_record WHERE agent_id = ? AND kind = 'transaction' AND ts >= ? AND ts < ?
        AND jsonb_extract_path_text(data::jsonb, 'action_type') IN ('llm_call', 'tool_call')`,
  ).all(agentId, from.toISOString(), to.toISOString())) as { ts: string; cost: string | null; outcome: string | null; action: string | null; target: string | null }[];
  const b = buildBaseline(rows.map((r) => ({ ts: r.ts, cost_usd: Number(r.cost) || 0, ok: r.outcome === 'success', tool: r.action === 'tool_call' ? r.target : null })), from, to);
  await db.prepare(
    'INSERT INTO agent_baseline (agent_id, data, computed_at) VALUES (?, ?, ?) ON CONFLICT (agent_id) DO UPDATE SET data = excluded.data, computed_at = excluded.computed_at',
  ).run(agentId, JSON.stringify(b), nowIso());
  cache.set(agentId, { at: Date.now(), b });
  return b;
}

export async function baselineFor(agentId: string): Promise<AnomalyBaseline | null> {
  const hit = cache.get(agentId);
  if (hit && Date.now() - hit.at < 10 * 60_000) return hit.b;
  const row = (await db.prepare('SELECT data, computed_at FROM agent_baseline WHERE agent_id = ?').get(agentId)) as { data: string; computed_at: string } | undefined;
  let b = row ? (JSON.parse(row.data) as AnomalyBaseline) : null;
  // Stale (an earlier day) or missing: rebuild in the background; this request uses what there is.
  const today = new Date().toISOString().slice(0, 10);
  if (!row || row.computed_at.slice(0, 10) < today) void computeBaseline(agentId).catch((e) => console.error(`[control] baseline for ${agentId} failed: ${(e as Error).message}`));
  cache.set(agentId, { at: Date.now(), b });
  return b;
}

/** Nightly: rebuild baselines for every agent with traffic in the baseline window. */
export async function nightly(): Promise<{ agents: number }> {
  const since = new Date(Date.now() - BASELINE_DAYS * DAY).toISOString();
  const ids = ((await db.prepare("SELECT DISTINCT agent_id FROM ledger_record WHERE kind = 'transaction' AND agent_id IS NOT NULL AND ts >= ?").all(since)) as { agent_id: string }[]).map((r) => r.agent_id);
  for (const id of ids) await computeBaseline(id);
  return { agents: ids.length };
}

// --- live window (5-minute buckets in shared_counter: n = requests, usd = cost, tokens = errors) -------
const bucketKey = (agentId: string, now: number) => `anom:${agentId}:${Math.floor(now / BUCKET_MS)}`;
const expiry = (now: number) => (Math.floor(now / BUCKET_MS) + 1) * BUCKET_MS + WINDOW_MS;

export async function countRequest(agentId: string, now = Date.now()) {
  await db.prepare(
    'INSERT INTO shared_counter (key, n, tokens, usd, expires_ms) VALUES (?, 1, 0, 0, ?) ON CONFLICT (key) DO UPDATE SET n = shared_counter.n + 1',
  ).run(bucketKey(agentId, now), expiry(now));
}

export async function countOutcome(agentId: string, usd: number, error: boolean, now = Date.now()) {
  await db.prepare(
    'INSERT INTO shared_counter (key, n, tokens, usd, expires_ms) VALUES (?, 0, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET tokens = shared_counter.tokens + excluded.tokens, usd = shared_counter.usd + excluded.usd',
  ).run(bucketKey(agentId, now), error ? 1 : 0, Math.max(0, usd || 0), expiry(now));
}

async function window(agentId: string, now: number) {
  const first = Math.floor((now - WINDOW_MS) / BUCKET_MS) + 1;
  const keys = Array.from({ length: Math.floor(now / BUCKET_MS) - first + 1 }, (_, i) => `anom:${agentId}:${first + i}`);
  const rows = (await db.prepare(`SELECT n, tokens, usd FROM shared_counter WHERE key IN (${keys.map(() => '?').join(', ')})`).all(...keys)) as { n: number; tokens: number; usd: number }[];
  return rows.reduce((a, r) => ({ requests: a.requests + Number(r.n), errors: a.errors + Number(r.tokens), cost_usd: a.cost_usd + Number(r.usd) }), { requests: 0, errors: 0, cost_usd: 0 });
}

export interface LiveAnomaly {
  status: 'ready' | 'learning';
  version: string;
  score?: number;
  band?: 'low' | 'elevated' | 'high';
  z?: number;
  feature?: string;
  features?: Record<string, number>;
  high_for_ms?: number; // how long the score has stayed High (runaway kill, DA 4)
  baseline_days?: number;
  baseline_records?: number;
}

/** Score the agent now. Tracks how long the score has stayed High, shared across gateway nodes. */
export async function live(agentId: string, tier: Tier, tool?: string, now = Date.now()): Promise<LiveAnomaly> {
  const b = await baselineFor(agentId);
  if (!b || !baselineReady(b)) return { status: 'learning', version: b?.version ?? 'none', baseline_days: b?.days ?? 0, baseline_records: b?.records ?? 0 };
  const w = await window(agentId, now);
  const r = scoreAnomaly(b, { ...w, hour: new Date(now).getUTCHours(), tool });
  const band = anomalyBand(r.score, ANOM_THRESHOLDS[tier] ?? ANOM_THRESHOLDS.T2);
  let highFor = 0;
  const key = `anomhigh:${agentId}`;
  if (band === 'high') {
    // n holds when the High run started (seconds); the row lives while the run continues.
    const row = (await db.prepare(
      `INSERT INTO shared_counter (key, n, tokens, usd, expires_ms) VALUES (?, ?, 0, 0, ?)
       ON CONFLICT (key) DO UPDATE SET n = CASE WHEN shared_counter.expires_ms > ? THEN shared_counter.n ELSE excluded.n END, expires_ms = excluded.expires_ms
       RETURNING n`,
    ).get(key, Math.floor(now / 1000), now + 5 * 60_000, now)) as { n: number };
    highFor = now - Number(row.n) * 1000;
  } else {
    await db.prepare('DELETE FROM shared_counter WHERE key = ?').run(key);
  }
  return { status: 'ready', version: b.version, score: r.score, band, z: r.z, feature: r.feature, features: r.features, high_for_ms: highFor, baseline_days: b.days, baseline_records: b.records };
}

export async function eraseAgent(agentId: string) {
  cache.delete(agentId);
  await db.prepare('DELETE FROM agent_baseline WHERE agent_id = ?').run(agentId);
  await db.prepare('DELETE FROM shared_counter WHERE key LIKE ? OR key = ?').run(`anom:${agentId}:%`, `anomhigh:${agentId}`);
}

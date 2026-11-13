// DET-ANOM, behaviour anomaly (DA 3): statistics only, no neural network. Each agent is compared with
// its own baseline of volume, cost and errors by hour of day, plus its tool mix. Only rises count:
// less traffic than usual is not a risk. The score is deterministic, so Replay reproduces it exactly.

export const ANOM_VERSION = 'baseline-zscore-v1';
export const BASELINE_DAYS = 14; // history used for a baseline
export const MIN_BASELINE_DAYS = 7; // confidence floor (DA 2): below this the detector is unavailable
export const MIN_BASELINE_RECORDS = 100;

export interface AnomalyBaseline {
  version: string;
  computed_at: string;
  days: number; // days of history covered
  records: number;
  // Per hour of day (UTC, 0-23): mean and standard deviation over the covered days.
  requests_mean: number[];
  requests_std: number[];
  cost_mean: number[];
  cost_std: number[];
  error_rate: number; // share of transactions that were refused or failed
  tool_share: Record<string, number>; // share of tool calls per tool alias
}

export interface AnomalyWindow {
  requests: number; // in the last 60 minutes, this request included
  cost_usd: number;
  errors: number;
  hour: number; // UTC hour of day now
  tool?: string; // the tool this action calls, if any
}

export interface AnomalyResult {
  score: number; // 0-1
  z: number; // the largest deviation, in standard deviations
  feature: 'volume' | 'cost' | 'errors' | 'tool' | 'time_of_day' | 'none';
  features: Record<string, number>;
}

// Rulebook-style starting thresholds (Elevated / High) by tier; T1 is the strictest (DA 3 "thresholds per tier").
export const ANOM_THRESHOLDS: Record<'T1' | 'T2' | 'T3' | 'T4', [number, number]> = {
  T1: [0.5, 0.7], T2: [0.55, 0.75], T3: [0.6, 0.8], T4: [0.65, 0.85],
};

export const baselineReady = (b: AnomalyBaseline | null | undefined): boolean =>
  !!b && b.days >= MIN_BASELINE_DAYS && b.records >= MIN_BASELINE_RECORDS;

const round = (x: number, d = 3) => Math.round(x * 10 ** d) / 10 ** d;

// score = 1 - e^(-z/4) maps 3 SD to about 0.53 and 5 SD to about 0.71.
export const zToScore = (z: number) => round(1 - Math.exp(-Math.max(0, z) / 4));

export function scoreAnomaly(b: AnomalyBaseline, w: AnomalyWindow): AnomalyResult {
  const h = ((w.hour % 24) + 24) % 24;
  const features: Record<string, number> = {};
  // Volume and cost: the noise floor is at least the Poisson spread (sqrt of the mean) and 2 requests,
  // so a quiet agent sending a handful of requests is not an anomaly.
  const rm = b.requests_mean[h] ?? 0;
  features.volume = (w.requests - rm) / Math.max(b.requests_std[h] ?? 0, Math.sqrt(rm), 2);
  const cm = b.cost_mean[h] ?? 0;
  const costFloor = Math.max(b.cost_std[h] ?? 0, cm * 0.5, 0.05);
  features.cost = (w.cost_usd - cm) / costFloor;
  // Errors: a binomial z-score against the agent's usual refusal / failure rate.
  if (w.requests >= 5) {
    const p = Math.min(Math.max(b.error_rate, 0.01), 0.99);
    features.errors = (w.errors - w.requests * p) / Math.sqrt(w.requests * p * (1 - p) + 1);
  }
  // Tool mix: a tool this agent has never called (or almost never) in its baseline.
  if (w.tool) {
    const share = b.tool_share[w.tool] ?? 0;
    features.tool = share === 0 ? 3 : share < 0.01 ? 2 : 0;
  }
  // Time of day: activity in an hour the agent is normally idle.
  if (rm < 0.05) features.time_of_day = 3;
  let feature: AnomalyResult['feature'] = 'none';
  let z = 0;
  for (const [k, v] of Object.entries(features)) {
    features[k] = round(v, 2);
    if (v > z) { z = v; feature = k as AnomalyResult['feature']; }
  }
  return { score: zToScore(z), z: round(z, 2), feature, features };
}

export const anomalyBand = (score: number, [e, h]: [number, number]): 'low' | 'elevated' | 'high' => (score >= h ? 'high' : score >= e ? 'elevated' : 'low');

export interface BaselineRow { ts: string; cost_usd: number; ok: boolean; tool?: string | null }

/** Build a baseline from ledger transactions in [from, to). Days with no traffic count as zeros. */
export function buildBaseline(rows: BaselineRow[], from: Date, to: Date): AnomalyBaseline {
  const days = Math.max(1, Math.round((to.getTime() - from.getTime()) / 86_400_000));
  const firstSeen = rows.reduce((m, r) => Math.min(m, Date.parse(r.ts)), Infinity);
  // Only days since the agent's first record count, so a new agent is not compared with empty days.
  const covered = Number.isFinite(firstSeen) ? Math.min(days, Math.ceil((to.getTime() - firstSeen) / 86_400_000)) : 0;
  const startMs = to.getTime() - covered * 86_400_000;
  const req = Array.from({ length: 24 }, () => new Array<number>(Math.max(covered, 1)).fill(0));
  const cost = Array.from({ length: 24 }, () => new Array<number>(Math.max(covered, 1)).fill(0));
  let errors = 0;
  const tools: Record<string, number> = {};
  let toolCalls = 0;
  for (const r of rows) {
    const t = Date.parse(r.ts);
    if (t < startMs || t >= to.getTime()) continue;
    const d = Math.floor((t - startMs) / 86_400_000);
    const hr = new Date(t).getUTCHours();
    req[hr]![d]! += 1;
    cost[hr]![d]! += r.cost_usd || 0;
    if (!r.ok) errors++;
    if (r.tool) { tools[r.tool] = (tools[r.tool] ?? 0) + 1; toolCalls++; }
  }
  const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
  const std = (xs: number[]) => { const m = mean(xs); return Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / xs.length); };
  const counted = rows.filter((r) => { const t = Date.parse(r.ts); return t >= startMs && t < to.getTime(); }).length;
  return {
    version: ANOM_VERSION,
    computed_at: to.toISOString(),
    days: covered,
    records: counted,
    requests_mean: req.map((xs) => round(mean(xs))),
    requests_std: req.map((xs) => round(std(xs))),
    cost_mean: cost.map((xs) => round(mean(xs), 6)),
    cost_std: cost.map((xs) => round(std(xs), 6)),
    error_rate: counted ? round(errors / counted, 4) : 0,
    tool_share: Object.fromEntries(Object.entries(tools).map(([k, v]) => [k, round(v / toolCalls, 4)])),
  };
}

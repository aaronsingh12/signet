import { ANOM_THRESHOLDS, type DetectorResult, type Tier } from '@signet/core';
import { pinCheck } from './pins';
import * as state from './state';

// DET-ANOM (DA 3): the control plane scores the agent against its own baseline on the same call that
// counts the request (limits.takeRequest), so this adds no round trip. Learning (under 7 days or 100
// records of history) is the DA 2 confidence floor: the detector reports unavailable.

export interface LiveAnomaly {
  status: 'ready' | 'learning';
  version: string;
  score?: number;
  band?: 'low' | 'elevated' | 'high';
  z?: number;
  feature?: string;
  features?: Record<string, number>;
  high_for_ms?: number;
  baseline_days?: number;
  baseline_records?: number;
}

export type AnomalyResult = DetectorResult & { reason?: string; feature?: string; features?: Record<string, number>; high_for_ms?: number };

export const anomalyEnabled = () => {
  const m = state.detectors.get('DET-ANOM')?.mode;
  return m === 'shadow' || m === 'active';
};

export function anomalyResult(live: LiveAnomaly | null | undefined, tier: Tier = 'T2'): AnomalyResult | null {
  const cfg = state.detectors.get('DET-ANOM');
  if (!cfg || cfg.mode === 'off') return null;
  const pin = pinCheck('DET-ANOM');
  const base = { id: 'DET-ANOM', version: cfg.version, ...(pin.sha256 ? { sha256: pin.sha256 } : {}), thresholds: ANOM_THRESHOLDS[tier] };
  if (!pin.ok) return { ...base, status: 'unavailable', reason: `pin mismatch: ${pin.reason}` };
  if (!live) return { ...base, status: 'unavailable', reason: 'control plane unreachable' };
  if (live.status !== 'ready') return { ...base, status: 'unavailable', reason: `baseline still learning (${live.baseline_days ?? 0} of 7 days, ${live.baseline_records ?? 0} of 100 records)` };
  return { ...base, status: cfg.mode === 'active' ? 'ok' : 'shadow', score: live.score, band: live.band, feature: live.feature, features: live.features, high_for_ms: live.high_for_ms };
}

// Runaway kill (DA 4): a rule (cost or volume above 200% of the seal limit) plus the signal (DET-ANOM
// High for 10 minutes). A detector score alone never kills.
export const RUNAWAY_HIGH_MS = 10 * 60_000;
export function runaway(a: AnomalyResult | null, use: { in_minute: number; tokens: number; usd: number }, limits: { rpm: number; tokens_per_day: number; usd_per_day: number }): string | null {
  if (!a || a.status !== 'ok' || a.band !== 'high' || (a.high_for_ms ?? 0) < RUNAWAY_HIGH_MS) return null;
  if (use.in_minute >= 2 * limits.rpm) return `${use.in_minute} requests this minute, over 200% of the seal limit of ${limits.rpm}`;
  if (limits.tokens_per_day > 0 && use.tokens >= 2 * limits.tokens_per_day) return `${use.tokens} tokens today, over 200% of the seal limit of ${limits.tokens_per_day}`;
  if (limits.usd_per_day > 0 && use.usd >= 2 * limits.usd_per_day) return `$${use.usd.toFixed(2)} today, over 200% of the seal limit of $${limits.usd_per_day}`;
  return null;
}

export const tierOf = (t: string | undefined): Tier => (t === 'T1' || t === 'T2' || t === 'T3' || t === 'T4' ? t : 'T2');

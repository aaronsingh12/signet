import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { anomalyResult, runaway } from '../src/anomaly';
import * as state from '../src/state';

// DET-ANOM in the gateway: off / learning / shadow / active, and the runaway kill (DA 4), which needs
// both the rule (over 200% of a seal limit) and the signal (High for 10 minutes).
const limits = { rpm: 60, tokens_per_day: 100_000, usd_per_day: 10 };
const live = { status: 'ready' as const, version: 'v1', score: 0.9, band: 'high' as const, z: 9, feature: 'volume', features: { volume: 9 }, high_for_ms: 11 * 60_000 };

test('modes: off gives nothing, learning is unavailable, shadow scores without effect', () => {
  state.detectors.set('DET-ANOM', { id: 'DET-ANOM', version: 'v1', mode: 'off' });
  assert.equal(anomalyResult(live), null);
  state.detectors.set('DET-ANOM', { id: 'DET-ANOM', version: 'v1', mode: 'shadow' });
  assert.equal(anomalyResult({ status: 'learning', version: 'v1', baseline_days: 3, baseline_records: 40 })!.status, 'unavailable');
  assert.equal(anomalyResult(null)!.status, 'unavailable');
  assert.equal(anomalyResult(live)!.status, 'shadow');
  assert.equal(runaway(anomalyResult(live), { in_minute: 500, tokens: 0, usd: 0 }, limits), null, 'shadow never kills');
});

test('runaway kill: rule plus signal, never the score alone', () => {
  state.detectors.set('DET-ANOM', { id: 'DET-ANOM', version: 'v1', mode: 'active' });
  const a = anomalyResult(live);
  assert.equal(a!.status, 'ok');
  assert.match(runaway(a, { in_minute: 120, tokens: 0, usd: 0 }, limits)!, /over 200%/);
  assert.match(runaway(a, { in_minute: 1, tokens: 0, usd: 25 }, limits)!, /\$25.00 today/);
  assert.equal(runaway(a, { in_minute: 119, tokens: 0, usd: 19 }, limits), null, 'under 200% of every limit: no kill');
  assert.equal(runaway(anomalyResult({ ...live, high_for_ms: 9 * 60_000 }), { in_minute: 500, tokens: 0, usd: 0 }, limits), null, 'High for under 10 minutes: no kill');
  assert.equal(runaway(anomalyResult({ ...live, band: 'elevated' }), { in_minute: 500, tokens: 0, usd: 0 }, limits), null);
});

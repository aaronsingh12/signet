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

test('DET-GROUND sampling: reproducible by request ID, about the tier rate, and only with sources', async () => {
  const { groundingInput, sampled, sampleRate } = await import('../src/grounding');
  assert.equal(sampled('req_1', 0.5), sampled('req_1', 0.5));
  const hits = Array.from({ length: 4000 }, (_, i) => sampled(`req_${i}`, sampleRate('T1'))).filter(Boolean).length;
  assert.ok(hits > 120 && hits < 280, `about 5% of T1 answers (${hits} of 4000)`);
  assert.equal(groundingInput([{ role: 'user', content: 'hi' }], 'hello'), null, 'no sources: nothing to judge');
  assert.deepEqual(groundingInput([{ role: 'system', content: 'Refund policy: 30 days from delivery.' }, { role: 'user', content: 'Refund window?' }], '30 days')!.sources, ['Refund policy: 30 days from delivery.']);
});

test('pins: a detector whose running hash differs from the bundle pin reports unavailable', async () => {
  const { knownPin, ANOM_VERSION } = await import('@signet/core');
  const { pinCheck } = await import('../src/pins');
  state.detectors.set('DET-ANOM', { id: 'DET-ANOM', version: ANOM_VERSION, mode: 'active', sha256: knownPin('DET-ANOM', ANOM_VERSION) });
  assert.equal(pinCheck('DET-ANOM').ok, true);
  const ok = anomalyResult(live, 'T1')!;
  assert.equal(ok.status, 'ok');
  assert.equal(ok.sha256, knownPin('DET-ANOM', ANOM_VERSION));
  assert.deepEqual(ok.thresholds, [0.5, 0.7]);
  state.detectors.set('DET-ANOM', { id: 'DET-ANOM', version: ANOM_VERSION, mode: 'active', sha256: 'a'.repeat(64) });
  const bad = anomalyResult(live)!;
  assert.equal(bad.status, 'unavailable');
  assert.match(bad.reason!, /does not match the pinned/);
  state.detectors.set('DET-INJ', { id: 'DET-INJ', version: 'x', mode: 'active', sha256: 'b'.repeat(64) });
  assert.match(pinCheck('DET-INJ').reason!, /cannot hash/, 'no model loaded on this node: cannot prove the pin');
});

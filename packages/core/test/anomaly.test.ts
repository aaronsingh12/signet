import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { ANOM_THRESHOLDS, anomalyBand, baselineReady, buildBaseline, scoreAnomaly } from '../src/anomaly';

// DET-ANOM (DA 3): statistics only. A steady agent builds a baseline; bursts, cost spikes, error spikes,
// new tools and idle-hour activity raise the score; less traffic than usual does not.

const DAY = 86_400_000;
const to = new Date('2026-11-13T00:00:00Z');
const from = new Date(to.getTime() - 14 * DAY);
// 10 days of history: 6 requests each day at 09:00-09:59 UTC, $0.01 each, one tool, one failure a day.
const rows = Array.from({ length: 10 }, (_, d) => Array.from({ length: 6 }, (_, i) => ({
  ts: new Date(to.getTime() - (10 - d) * DAY + 9 * 3_600_000 + i * 60_000).toISOString(), cost_usd: 0.01, ok: i !== 0, tool: i % 2 ? 'crm.lookup' : null,
}))).flat();
const b = buildBaseline([...rows, ...rows.slice(0, 50)], from, to);

test('baseline: only days since the first record count; the 7-day / 100-record floor applies', () => {
  assert.equal(b.days, 10);
  assert.equal(b.records, 110);
  assert.equal(b.requests_mean[9], 11); // 110 requests over 10 days, all in hour 9
  assert.equal(b.requests_mean[3], 0);
  assert.deepEqual(b.tool_share, { 'crm.lookup': 1 });
  assert.ok(baselineReady(b));
  assert.ok(!baselineReady(buildBaseline(rows.slice(-20), from, to)), 'two days of history is below the floor');
});

test('scoring: normal traffic is low; a burst, a cost spike or errors raise it; quiet is not anomalous', () => {
  const normal = scoreAnomaly(b, { requests: 10, cost_usd: 0.1, errors: 2, hour: 9 });
  assert.equal(anomalyBand(normal.score, ANOM_THRESHOLDS.T2), 'low');
  const quiet = scoreAnomaly(b, { requests: 0, cost_usd: 0, errors: 0, hour: 9 });
  assert.equal(quiet.score, 0);
  const burst = scoreAnomaly(b, { requests: 120, cost_usd: 1.2, errors: 2, hour: 9 });
  assert.equal(burst.feature, 'volume');
  assert.equal(anomalyBand(burst.score, ANOM_THRESHOLDS.T2), 'high');
  const errors = scoreAnomaly(b, { requests: 12, cost_usd: 0.12, errors: 12, hour: 9 });
  assert.equal(errors.feature, 'errors');
  assert.notEqual(anomalyBand(errors.score, ANOM_THRESHOLDS.T1), 'low');
  const night = scoreAnomaly(b, { requests: 1, cost_usd: 0.01, errors: 0, hour: 3 });
  assert.equal(night.feature, 'time_of_day');
  const tool = scoreAnomaly(b, { requests: 5, cost_usd: 0.05, errors: 0, hour: 9, tool: 'payments.refund' });
  assert.equal(tool.feature, 'tool');
  assert.equal(anomalyBand(tool.score, ANOM_THRESHOLDS.T1), 'elevated', 'a never-used tool is elevated for T1');
  assert.equal(anomalyBand(tool.score, ANOM_THRESHOLDS.T4), 'low', 'and below the looser T4 threshold');
  assert.deepEqual(scoreAnomaly(b, { requests: 120, cost_usd: 1.2, errors: 2, hour: 9 }), burst, 'deterministic, so Replay reproduces it');
});

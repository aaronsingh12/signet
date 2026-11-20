import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { normalizeServiceNowExecutionDates } from '../src/external-normalize';

test('ServiceNow UTC database timestamps preserve the same instant across server timezones', () => {
  for (const timezone of ['Asia/Kolkata', 'America/Los_Angeles']) {
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
      import { normalizeServiceNowExecutionDates } from './apps/control/src/external-normalize.ts';
      const record = { id: 'execution', name: null, status: 'terminated', timestamp: '2026-11-19 10:58:32', metadata: { started_at: '2026-11-19 10:58:34', completed_at: '2026-11-19 10:58:42' } };
      const normalized = normalizeServiceNowExecutionDates(record);
      console.log(JSON.stringify({ normalized, original: record }));
    `], { env: { ...process.env, TZ: timezone }, encoding: 'utf8', windowsHide: true, timeout: 30000 });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout) as { normalized: { timestamp: string; metadata: { started_at: string; completed_at: string } }; original: { timestamp: string; metadata: { started_at: string } } };
    assert.equal(output.normalized.timestamp, '2026-11-19T10:58:32.000Z');
    assert.equal(output.normalized.metadata.started_at, '2026-11-19T10:58:34.000Z');
    assert.equal(output.normalized.metadata.completed_at, '2026-11-19T10:58:42.000Z');
    assert.equal(output.original.timestamp, '2026-11-19 10:58:32');
    assert.equal(output.original.metadata.started_at, '2026-11-19 10:58:34');
  }
  const record = { id: 'execution', name: null, status: 'completed', timestamp: '2026-11-19T16:28:32+05:30' };
  assert.equal(normalizeServiceNowExecutionDates(record).timestamp, '2026-11-19T10:58:32.000Z');
  assert.throws(() => normalizeServiceNowExecutionDates({ ...record, timestamp: '2026-02-30 10:58:32' }), /invalid calendar/);
  assert.throws(() => normalizeServiceNowExecutionDates({ ...record, timestamp: '2026-11-19T10:58:32' }), /explicit timezone/);
});

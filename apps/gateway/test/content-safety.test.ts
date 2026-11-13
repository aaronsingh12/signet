import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { combine } from '@signet/core';
import { contentSafety, SafetyUnavailable, withholdIfHighRisk, type SafetyVerdict } from '../src/content-safety';
import { Halt, newCtx } from '../src/ctx';
import * as state from '../src/state';

// DET-SAFE follows the Decision Architecture: off is not run, shadow never blocks, active blocks (would_block
// in a shadow deployment), and a failed check falls back to the rules with T1/T2 held (DA 2, RB-INV-06).
const unsafe = async (): Promise<SafetyVerdict> => ({ category: 'weapons', model: 'm', tokens: 1 });
const safe = async (): Promise<SafetyVerdict> => ({ category: 'allow', model: 'm', tokens: 1 });
const down = async (): Promise<SafetyVerdict> => { throw new SafetyUnavailable('timed out'); };
const mode = (m: 'off' | 'shadow' | 'active') => state.detectors.set('DET-SAFE', { id: 'DET-SAFE', version: 'v1', mode: m } as never);
const ctx = (shadowRollout = false) => Object.assign(newCtx('llm_call', 'm', {}), shadowRollout ? { shadow: true, rollout: 'shadow' } : {});

test('off: not run', async () => {
  mode('off');
  assert.equal(await contentSafety(ctx(), 'x', 8, unsafe), null);
});

test('active: unsafe content is blocked; safe content passes with band low', async () => {
  mode('active');
  await assert.rejects(contentSafety(ctx(), 'x', 8, unsafe), (e: unknown) => e instanceof Halt && e.status === 403 && /weapons/.test(e.message));
  assert.deepEqual(await contentSafety(ctx(), 'x', 8, safe), { id: 'DET-SAFE', version: 'v1', status: 'ok', score: 0, band: 'low' });
});

test('active in a shadow deployment: recorded as would_block, not blocked', async () => {
  mode('active');
  const c = ctx(true);
  const r = await contentSafety(c, 'x', 13, unsafe);
  assert.equal(r?.status, 'ok');
  assert.deepEqual(c.wouldBlock.map((w) => w.rules), [['DET-SAFE']]);
});

test('detector in shadow: never blocks', async () => {
  mode('shadow');
  const c = ctx();
  const r = await contentSafety(c, 'x', 8, unsafe);
  assert.equal(r?.status, 'shadow');
  assert.ok(c.reasons.some((x) => /would block/.test(x)));
});

test('failure: unavailable, so the rules decide; T1/T2 held, T3/T4 continue (no blanket block)', async () => {
  mode('active');
  const r = (await contentSafety(ctx(), 'x', 8, down))!;
  assert.equal(r.status, 'unavailable');
  assert.equal(combine('allow', [r], 'T2').outcome, 'require_approval');
  assert.equal(combine('allow', [r], 'T4').outcome, 'allow');
  assert.throws(() => withholdIfHighRisk(ctx(), 'T1'), (e: unknown) => e instanceof Halt && e.outcome === 'require_approval');
  assert.doesNotThrow(() => withholdIfHighRisk(ctx(), 'T3'));
});

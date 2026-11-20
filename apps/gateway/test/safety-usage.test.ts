import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import type { CatalogueModel } from '@signet/core';
import { newCtx } from '../src/ctx';
import { recordSafetyUsage, safetyModelUsage } from '../src/safety-usage';

test('safety usage retains provider input/output and rates across multiple chunks without inventing missing usage', () => {
  const catalogue: CatalogueModel[] = [{ model: 'safety-model', upstream_model: 'safety-model', family: 'test', region: 'unverified', code_approved: false, price_per_1k_usd: { in: 0.15, out: 0.6 } }];
  const usage = safetyModelUsage('safety-model', { prompt_tokens: 2000, completion_tokens: 500 }, catalogue);
  assert.equal(usage.cost_usd, 0.6);
  const ctx = newCtx('guardrail_check', 'servicenow://guardian', {});
  recordSafetyUsage(ctx, [usage]);
  recordSafetyUsage(ctx, [usage]);
  assert.deepEqual(ctx.extra.safety_usage, { model: 'safety-model', calls: 2, tokens_in: 4000, tokens_out: 1000, cost_usd: 1.2, unpriced_calls: 0, missing_usage_calls: 0, records: [usage, usage] });
  assert.equal(ctx.costUsd, 0, 'Safety cost is separate from main-request cost to avoid double counting');
  const missing = safetyModelUsage('safety-model', undefined, catalogue);
  assert.equal(missing.cost_usd, null);
  assert.equal(missing.tokens_in, null);
  assert.equal(safetyModelUsage('other-model', { prompt_tokens: 2, completion_tokens: 3 }, catalogue).cost_usd, null);
  assert.throws(() => safetyModelUsage('safety-model', { prompt_tokens: -1 }, catalogue), /nonnegative/);
  assert.throws(() => safetyModelUsage('safety-model', { completion_tokens: 1.5 }, catalogue), /nonnegative/);
});

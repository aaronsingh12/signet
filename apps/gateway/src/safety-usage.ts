import type { CatalogueModel } from '@signet/core';
import type { Ctx } from './ctx';
import type { ChatResponse } from './provider';

export interface SafetyModelUsage {
  model: string; tokens_in: number | null; tokens_out: number | null; cost_usd: number | null;
  price_per_1k_usd: { in: number; out: number } | null;
}
interface SafetyUsageSummary {
  model: string; calls: number; tokens_in: number; tokens_out: number; cost_usd: number;
  unpriced_calls: number; missing_usage_calls: number; records: SafetyModelUsage[];
}

/** Retain provider-reported token counts and the rate at review time; never infer usage from text length. */
export function safetyModelUsage(model: string, usage: ChatResponse['usage'], catalogue: CatalogueModel[]): SafetyModelUsage {
  const input = usage?.prompt_tokens;
  const output = usage?.completion_tokens;
  for (const count of [input, output]) if (count !== undefined && (!Number.isSafeInteger(count) || count < 0)) throw new TypeError('Safety provider token counts must be nonnegative integers');
  const price = catalogue.find(entry => entry.model === model)?.price_per_1k_usd;
  return {
    model, tokens_in: input ?? null, tokens_out: output ?? null,
    price_per_1k_usd: price ? { ...price } : null,
    cost_usd: price && input !== undefined && output !== undefined ? (input * price.in + output * price.out) / 1000 : null,
  };
}

/** Safety spend stays separate from the agent model budget and is recorded even when a review blocks. */
export function recordSafetyUsage(ctx: Ctx, records: SafetyModelUsage[]): void {
  const previous = ctx.extra.safety_usage as SafetyUsageSummary | undefined;
  const all = [...(previous?.records ?? []), ...records];
  if (!all.length) return;
  const models = new Set(all.map(record => record.model));
  if (models.size !== 1) throw new Error('Safety usage for one request must identify a single classifier model');
  ctx.extra.safety_usage = {
    model: all[0]!.model, calls: all.length,
    tokens_in: all.reduce((sum, record) => sum + (record.tokens_in ?? 0), 0),
    tokens_out: all.reduce((sum, record) => sum + (record.tokens_out ?? 0), 0),
    cost_usd: all.reduce((sum, record) => sum + (record.cost_usd ?? 0), 0),
    unpriced_calls: all.filter(record => !record.price_per_1k_usd || (record.price_per_1k_usd.in === 0 && record.price_per_1k_usd.out === 0)).length,
    missing_usage_calls: all.filter(record => record.tokens_in === null || record.tokens_out === null).length,
    records: all,
  } satisfies SafetyUsageSummary;
}

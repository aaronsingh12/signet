import type { CatalogueModel } from '@signet/core';
import { db } from './db';
import type { StoredValue } from './mongodb-schema';
import { tenant } from './tenant';

/** Safety-review calls that ran while their model had no rate, priced at the model's current rate. */
export interface SafetyCostEstimate { agent_id: string; model: string; calls: number; cost_usd: number }

function amount(value: StoredValue | undefined, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new TypeError(`Safety cost estimate field ${field} must be a nonnegative number`);
  return value;
}

/**
 * The ledger keeps what was recorded and is never rewritten. A call recorded with no rate (zero or missing price)
 * has no original price to preserve, so reports price it at the model's current rate and say it is an estimate.
 * Calls that ran at a real rate keep that rate. Only records whose calls were all unpriced and all carry provider
 * token counts are estimated; the rest stay reported as unpriced or missing usage.
 */
export async function unpricedSafetyEstimates(from: string, to: string, catalogue: CatalogueModel[]): Promise<SafetyCostEstimate[]> {
  const rows = await db.prepare(`SELECT agent_id,
      jsonb_extract_path_text(data::jsonb, 'safety_usage', 'model') AS model,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'calls'))::double precision, 0)) AS calls,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'tokens_in'))::double precision, 0)) AS tokens_in,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'tokens_out'))::double precision, 0)) AS tokens_out
    FROM ledger_record WHERE tenant_id = ? AND kind = 'transaction' AND ts >= ? AND ts <= ?
      AND jsonb_extract_path_text(data::jsonb, 'safety_usage', 'model') IS NOT NULL
      AND (jsonb_extract_path_text(data::jsonb, 'safety_usage', 'unpriced_calls'))::double precision > 0
      AND (jsonb_extract_path_text(data::jsonb, 'safety_usage', 'unpriced_calls'))::double precision = (jsonb_extract_path_text(data::jsonb, 'safety_usage', 'calls'))::double precision
      AND (jsonb_extract_path_text(data::jsonb, 'safety_usage', 'missing_usage_calls'))::double precision = 0
    GROUP BY agent_id, jsonb_extract_path_text(data::jsonb, 'safety_usage', 'model')`).all(tenant.id, from, to);
  const estimates: SafetyCostEstimate[] = [];
  for (const row of rows) {
    if (typeof row.agent_id !== 'string' || typeof row.model !== 'string') throw new TypeError('Safety cost estimate rows require agent and model');
    const price = catalogue.find(entry => entry.model === row.model)?.price_per_1k_usd;
    if (!price || (price.in === 0 && price.out === 0)) continue; // still no rate: stays reported as unpriced
    estimates.push({
      agent_id: row.agent_id, model: row.model, calls: amount(row.calls, 'calls'),
      cost_usd: (amount(row.tokens_in, 'tokens_in') * price.in + amount(row.tokens_out, 'tokens_out') * price.out) / 1000,
    });
  }
  return estimates;
}

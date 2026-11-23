import { parseGatewayCosts, type GatewayAgentCost, type GatewayCostsReport } from '@signet/core';
import { db } from './db';
import { invalid } from './errors';
import { reloadSettings, tenant } from './tenant';
import { unpricedSafetyEstimates } from './safety-cost-estimate';
import type { StoredValue } from './mongodb-schema';

interface AgentRow {
  id: string; name: string; handle: string; status: string; daily_budget_usd: number | null;
}
interface UsageRow {
  agent_id: string; action_type: 'llm_call' | 'tool_call'; target: string | null;
  calls: number; tokens_in: number; tokens_out: number; cost_usd: number;
}

function text(value: StoredValue | undefined, field: string): string {
  if (typeof value !== 'string') throw new TypeError(`Gateway costs database field ${field} must be text`);
  return value;
}

function amount(value: StoredValue | undefined, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new TypeError(`Gateway costs database field ${field} must be a nonnegative number`);
  return value;
}

/** All registered agents, including idle agents, with immutable recorded gateway spend and current rates. */
export async function gatewayCosts(days: number): Promise<GatewayCostsReport> {
  if (!Number.isSafeInteger(days) || days < 1 || days > 90) throw invalid('days must be an integer between 1 and 90');
  const to = new Date().toISOString();
  const from = new Date(Date.parse(to) - days * 86_400_000).toISOString();
  const settings = await reloadSettings();
  const agents: AgentRow[] = (await db.prepare(`SELECT a.id, a.name, a.handle, a.status,
      (jsonb_extract_path_text(c.body::jsonb, 'limits', 'usd_per_day'))::double precision AS daily_budget_usd
    FROM agent a LEFT JOIN certificate c ON c.agent_id = a.id AND c.status = 'active'
    WHERE a.tenant_id = ? ORDER BY a.name, a.id`).all(tenant.id)).map(row => ({
      id: text(row.id, 'id'), name: text(row.name, 'name'), handle: text(row.handle, 'handle'), status: text(row.status, 'status'),
      daily_budget_usd: row.daily_budget_usd === null ? null : amount(row.daily_budget_usd, 'daily_budget_usd'),
    }));
  const usage: UsageRow[] = (await db.prepare(`SELECT agent_id,
      jsonb_extract_path_text(data::jsonb, 'action_type') AS action_type,
      jsonb_extract_path_text(data::jsonb, 'target') AS target, COUNT(*) AS calls,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'tokens_in'))::double precision, 0)) AS tokens_in,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'tokens_out'))::double precision, 0)) AS tokens_out,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'cost_usd'))::double precision, 0)) AS cost_usd
    FROM ledger_record WHERE tenant_id = ? AND kind = 'transaction' AND ts >= ? AND ts <= ?
      AND jsonb_extract_path_text(data::jsonb, 'action_type') IN ('llm_call', 'tool_call')
    GROUP BY agent_id, jsonb_extract_path_text(data::jsonb, 'action_type'), jsonb_extract_path_text(data::jsonb, 'target')`).all(tenant.id, from, to)).map(row => {
      if (row.action_type !== 'llm_call' && row.action_type !== 'tool_call') throw new TypeError('Gateway costs database returned an unsupported action type');
      return {
        agent_id: text(row.agent_id, 'agent_id'), action_type: row.action_type, target: row.target === null ? null : text(row.target, 'target'),
        calls: amount(row.calls, 'calls'), tokens_in: amount(row.tokens_in, 'tokens_in'), tokens_out: amount(row.tokens_out, 'tokens_out'), cost_usd: amount(row.cost_usd, 'cost_usd'),
      };
    });
  const safety = await db.prepare(`SELECT agent_id,
      jsonb_extract_path_text(data::jsonb, 'safety_usage', 'model') AS model,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'calls'))::double precision, 0)) AS calls,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'tokens_in'))::double precision, 0)) AS tokens_in,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'tokens_out'))::double precision, 0)) AS tokens_out,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'cost_usd'))::double precision, 0)) AS cost_usd,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'unpriced_calls'))::double precision, 0)) AS unpriced,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'missing_usage_calls'))::double precision, 0)) AS missing
    FROM ledger_record WHERE tenant_id = ? AND kind = 'transaction' AND ts >= ? AND ts <= ?
      AND jsonb_extract_path_text(data::jsonb, 'safety_usage', 'model') IS NOT NULL
    GROUP BY agent_id, jsonb_extract_path_text(data::jsonb, 'safety_usage', 'model')`).all(tenant.id, from, to);
  const legacy = await db.prepare(`SELECT agent_id, COUNT(*) AS count FROM ledger_record
    WHERE tenant_id = ? AND kind = 'transaction' AND ts >= ? AND ts <= ?
      AND jsonb_extract_path_text(data::jsonb, 'guardrail_classifier', 'chunk_count') IS NOT NULL
      AND jsonb_extract_path_text(data::jsonb, 'safety_usage', 'model') IS NULL GROUP BY agent_id`).all(tenant.id, from, to);
  // Calls recorded with no rate are priced at today's rate (estimated); recorded costs are never recalculated.
  const estimates = await unpricedSafetyEstimates(from, to, settings.catalogue);
  const items: GatewayAgentCost[] = agents.map(agent => {
    const rows = usage.filter(row => row.agent_id === agent.id);
    const reviews = safety.filter(row => row.agent_id === agent.id);
    const estimate = estimates.filter(row => row.agent_id === agent.id);
    const estimatedFor = (model: string): number => estimate.filter(row => row.model === model).reduce((total, row) => total + row.cost_usd, 0);
    const estimatedUsd = estimate.reduce((total, row) => total + row.cost_usd, 0);
    const estimatedCalls = estimate.reduce((total, row) => total + row.calls, 0);
    const safetySum = (key: 'calls' | 'tokens_in' | 'tokens_out' | 'cost_usd' | 'unpriced' | 'missing'): number => reviews.reduce((sum, row) => sum + amount(row[key], key), 0);
    const sum = (key: 'tokens_in' | 'tokens_out' | 'cost_usd'): number => rows.reduce((total, row) => total + row[key], 0);
    return {
      ...agent,
      model_calls: rows.filter(row => row.action_type === 'llm_call').reduce((total, row) => total + row.calls, 0),
      tool_calls: rows.filter(row => row.action_type === 'tool_call').reduce((total, row) => total + row.calls, 0),
      tokens_in: sum('tokens_in') + safetySum('tokens_in'), tokens_out: sum('tokens_out') + safetySum('tokens_out'), cost_usd: sum('cost_usd') + safetySum('cost_usd') + estimatedUsd,
      safety_calls: safetySum('calls'), safety_tokens_in: safetySum('tokens_in'), safety_tokens_out: safetySum('tokens_out'), safety_cost_usd: safetySum('cost_usd') + estimatedUsd,
      estimated_safety_calls: estimatedCalls, estimated_safety_cost_usd: estimatedUsd,
      unpriced_safety_calls: safetySum('unpriced') - estimatedCalls, missing_safety_usage_calls: safetySum('missing'),
      legacy_safety_records: amount(legacy.find(row => row.agent_id === agent.id)?.count ?? 0, 'legacy count'),
      models: [
        ...rows.filter(row => row.action_type === 'llm_call').map(row => ({ source: 'agent_model' as const, model: row.target ?? 'Unrecorded model', calls: row.calls, tokens_in: row.tokens_in, tokens_out: row.tokens_out, cost_usd: row.cost_usd })),
        ...reviews.map(row => ({ source: 'safety_review' as const, model: text(row.model, 'safety model'), calls: amount(row.calls, 'calls'), tokens_in: amount(row.tokens_in, 'tokens_in'), tokens_out: amount(row.tokens_out, 'tokens_out'), cost_usd: amount(row.cost_usd, 'cost_usd') + estimatedFor(text(row.model, 'safety model')), estimated_cost_usd: estimatedFor(text(row.model, 'safety model')) })),
      ],
    };
  });
  return parseGatewayCosts({ days, from, to, currency: 'USD', models: settings.catalogue.map(model => ({ model: model.model, price_per_1k_usd: { ...model.price_per_1k_usd }, ...(model.price_source ? { price_source: model.price_source } : {}) })), agents: items });
}

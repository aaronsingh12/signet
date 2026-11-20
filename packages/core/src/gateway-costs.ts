export interface GatewayModelPrice {
  model: string;
  price_per_1k_usd: { in: number; out: number };
}

export interface GatewayModelUsage {
  source: 'agent_model' | 'safety_review';
  model: string;
  calls: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
}

export interface GatewayAgentCost {
  id: string;
  name: string;
  handle: string;
  status: string;
  daily_budget_usd: number | null;
  model_calls: number;
  tool_calls: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  safety_calls: number;
  safety_tokens_in: number;
  safety_tokens_out: number;
  safety_cost_usd: number;
  unpriced_safety_calls: number;
  missing_safety_usage_calls: number;
  legacy_safety_records: number;
  models: GatewayModelUsage[];
}

export interface GatewayCostsReport {
  days: number;
  from: string;
  to: string;
  currency: 'USD';
  models: GatewayModelPrice[];
  agents: GatewayAgentCost[];
}

/** Validate cost data consumed by Settings; unrelated fields may be present. */
export function parseGatewayCosts(value: GatewayCostsReport): GatewayCostsReport {
  if (!value || value.currency !== 'USD' || !Number.isSafeInteger(value.days) || value.days < 1 || value.days > 90 || !Number.isFinite(Date.parse(value.from)) || !Number.isFinite(Date.parse(value.to)) || !Array.isArray(value.models) || !Array.isArray(value.agents)) throw new TypeError('Gateway costs require a 1-90 day USD report with dates, models and agents');
  for (const entry of value.models) {
    if (!entry || typeof entry.model !== 'string' || !entry.model || !entry.price_per_1k_usd) throw new TypeError('Gateway model pricing requires a model and input/output prices');
    for (const direction of ['in', 'out'] as const) if (typeof entry.price_per_1k_usd[direction] !== 'number' || !Number.isFinite(entry.price_per_1k_usd[direction]) || entry.price_per_1k_usd[direction] < 0) throw new TypeError('Gateway model prices must be finite nonnegative numbers');
  }
  for (const agent of value.agents) {
    for (const key of ['id', 'name', 'handle', 'status'] as const) if (typeof agent?.[key] !== 'string') throw new TypeError(`Gateway agent ${key} must be a string`);
    if (agent.daily_budget_usd !== null && (typeof agent.daily_budget_usd !== 'number' || !Number.isFinite(agent.daily_budget_usd) || agent.daily_budget_usd < 0)) throw new TypeError('Gateway daily budget must be nonnegative or null');
    for (const key of ['model_calls', 'tool_calls', 'tokens_in', 'tokens_out', 'cost_usd', 'safety_calls', 'safety_tokens_in', 'safety_tokens_out', 'safety_cost_usd', 'unpriced_safety_calls', 'missing_safety_usage_calls', 'legacy_safety_records'] as const) if (typeof agent[key] !== 'number' || !Number.isFinite(agent[key]) || agent[key] < 0) throw new TypeError(`Gateway agent ${key} must be nonnegative`);
    if (!Array.isArray(agent.models)) throw new TypeError('Gateway agent model usage must be an array');
    for (const model of agent.models) {
      if (typeof model.model !== 'string') throw new TypeError('Gateway usage model must be a string');
      if (model.source !== 'agent_model' && model.source !== 'safety_review') throw new TypeError('Gateway usage must identify agent model or safety review source');
      for (const key of ['calls', 'tokens_in', 'tokens_out', 'cost_usd'] as const) if (typeof model[key] !== 'number' || !Number.isFinite(model[key]) || model[key] < 0) throw new TypeError(`Gateway model usage ${key} must be nonnegative`);
    }
  }
  return value;
}

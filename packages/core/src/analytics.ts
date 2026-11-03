export interface ActivityBucket {
  hour: string;
  requests: number;
  allowed: number;
  blocked: number;
  review: number;
  failed: number;
}

export interface AgentAnalytics {
  id: string;
  name: string;
  handle: string;
  purpose: string;
  owner: string;
  tier: string;
  status: string;
  enforcement: string;
  valid_to: string | null;
  requests: number;
  allowed: number;
  blocked: number;
  review: number;
  failed: number;
  tokens: number;
  cost_usd: number;
  avg_latency_ms: number | null;
  daily_budget_usd: number | null;
  last_activity: string | null;
  activity: ActivityBucket[];
}

export interface AgentAnalyticsResponse {
  from: string;
  to: string;
  agents: AgentAnalytics[];
}

/** Validate the fields the dashboard consumes, allowing unrelated API fields. */
export function parseAgentAnalytics(value: AgentAnalyticsResponse): AgentAnalyticsResponse {
  if (!value || typeof value !== 'object' || !Array.isArray(value.agents) || !Number.isFinite(Date.parse(value.from)) || !Number.isFinite(Date.parse(value.to))) {
    throw new TypeError('Agent analytics must include valid from/to dates and an agents array');
  }
  for (const agent of value.agents) {
    for (const key of ['id', 'name', 'handle', 'purpose', 'owner', 'tier', 'status', 'enforcement'] as const) {
      if (typeof agent?.[key] !== 'string') throw new TypeError(`Agent analytics ${key} must be a string`);
    }
    for (const key of ['requests', 'allowed', 'blocked', 'review', 'failed', 'tokens', 'cost_usd'] as const) {
      if (!Number.isFinite(agent[key]) || agent[key] < 0) throw new TypeError(`Agent ${agent.id} analytics ${key} must be nonnegative`);
    }
    for (const key of ['avg_latency_ms', 'daily_budget_usd'] as const) {
      if (agent[key] !== null && (!Number.isFinite(agent[key]) || agent[key]! < 0)) throw new TypeError(`Agent ${agent.id} analytics ${key} must be nonnegative or null`);
    }
    for (const key of ['valid_to', 'last_activity'] as const) {
      if (agent[key] !== null && !Number.isFinite(Date.parse(agent[key]!))) throw new TypeError(`Agent ${agent.id} analytics ${key} must be a date or null`);
    }
    if (!Array.isArray(agent.activity)) throw new TypeError(`Agent ${agent.id} activity must be an array`);
    for (const bucket of agent.activity) {
      if (!Number.isFinite(Date.parse(bucket.hour))) throw new TypeError(`Agent ${agent.id} activity hour must be a date`);
      for (const key of ['requests', 'allowed', 'blocked', 'review', 'failed'] as const) {
        if (!Number.isFinite(bucket[key]) || bucket[key] < 0) throw new TypeError(`Agent ${agent.id} hourly ${key} must be nonnegative`);
      }
    }
  }
  return value;
}

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
  provider: ProviderAnalytics;
  guardian: { reviews: number; flagged: number; unavailable: number; failed: number; last_review_at: string | null; native_blocked: number; native_signet: number };
  // flagged: Guardian reviews Signet blocked. native_blocked: blocks ServiceNow confirmed in its own logs, of which
  // native_signet carried out a Signet verdict (linked by signet_ref); the rest were ServiceNow's own decision.
  servicenow: { linked: boolean; monitoring: boolean; gateway_enforcement: boolean } | null;
}

export interface ProviderAnalytics {
  connection_ids: string[];
  last_sync_at: string | null;
  executions: number;
  succeeded: number;
  failed: number;
  other: number;
  avg_duration_ms: number | null;
  activity: { hour: string; executions: number }[];
  recent: { id: string; status: string | null; timestamp: string; duration_ms: number | null }[];
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
    if (!agent.guardian) throw new TypeError('Guardian analytics are required');
    for (const key of ['reviews', 'flagged', 'unavailable', 'failed', 'native_blocked', 'native_signet'] as const) {
      if (!Number.isSafeInteger(agent.guardian[key]) || agent.guardian[key] < 0) throw new TypeError(`Guardian ${key} must be a nonnegative integer`);
    }
    if (agent.guardian.native_signet > agent.guardian.native_blocked) throw new TypeError('Guardian native_signet cannot exceed native_blocked');
    if (agent.guardian.last_review_at !== null && !Number.isFinite(Date.parse(agent.guardian.last_review_at))) throw new TypeError('Guardian last review must be a date or null');
    if (agent.servicenow !== null && (!agent.servicenow || typeof agent.servicenow.linked !== 'boolean' || typeof agent.servicenow.monitoring !== 'boolean' || typeof agent.servicenow.gateway_enforcement !== 'boolean')) throw new TypeError('ServiceNow analytics coverage must be null or contain linked, monitoring and gateway_enforcement booleans');
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
    const provider = agent.provider;
    if (!provider || !Array.isArray(provider.connection_ids) || provider.connection_ids.some((id) => typeof id !== 'string') || !Array.isArray(provider.activity) || !Array.isArray(provider.recent)) throw new TypeError('Provider analytics must include connections, activity and recent executions');
    for (const key of ['executions', 'succeeded', 'failed', 'other'] as const) if (!Number.isSafeInteger(provider[key]) || provider[key] < 0) throw new TypeError(`Provider ${key} must be a nonnegative integer`);
    if (provider.avg_duration_ms !== null && (!Number.isFinite(provider.avg_duration_ms) || provider.avg_duration_ms < 0)) throw new TypeError('Provider duration must be nonnegative or null');
    if (provider.last_sync_at !== null && !Number.isFinite(Date.parse(provider.last_sync_at))) throw new TypeError('Provider last sync must be a date or null');
    for (const bucket of provider.activity) if (!Number.isFinite(Date.parse(bucket.hour)) || !Number.isSafeInteger(bucket.executions) || bucket.executions < 0) throw new TypeError('Invalid provider activity bucket');
    for (const record of provider.recent) if (typeof record.id !== 'string' || (record.status !== null && typeof record.status !== 'string') || !Number.isFinite(Date.parse(record.timestamp)) || (record.duration_ms !== null && (!Number.isFinite(record.duration_ms) || record.duration_ms < 0))) throw new TypeError('Invalid provider execution');
    for (const bucket of agent.activity) {
      if (!Number.isFinite(Date.parse(bucket.hour))) throw new TypeError(`Agent ${agent.id} activity hour must be a date`);
      for (const key of ['requests', 'allowed', 'blocked', 'review', 'failed'] as const) {
        if (!Number.isFinite(bucket[key]) || bucket[key] < 0) throw new TypeError(`Agent ${agent.id} hourly ${key} must be nonnegative`);
      }
    }
  }
  return value;
}

import type { ActivityBucket, AgentAnalytics, AgentAnalyticsResponse } from '@signet/core';
import { db } from './db';
import { agentLevel } from './enforcement';
import { tenant } from './tenant';
import { providerAnalytics } from './provider-analytics';
import { serviceNowAgentCoverage } from './servicenow-agents';
import { nativeGuardianBlocks } from './servicenow-guardian-events';

interface AgentRow {
  id: string; name: string; handle: string; purpose: string; owner: string; tier: string; status: string;
  valid_to: string | null; daily_budget_usd: number | null;
  servicenow_identity: boolean;
}

interface UsageRow {
  agent_id: string; hour: string; requests: number; allowed: number; blocked: number; review: number; failed: number;
  tokens: number; cost_usd: number; latency_total: number; latency_count: number; last_activity: string;
}

/** One tenant-scoped, rolling 24-hour snapshot; detector scores never count as agent requests. */
export async function agentAnalytics(): Promise<AgentAnalyticsResponse> {
  const serviceNowLinks = await db.prepare('SELECT DISTINCT agent_id FROM servicenow_agent_link WHERE tenant_id = ?').all(tenant.id) as { agent_id: string }[];
  const serviceNowIds = new Set(serviceNowLinks.map(link => link.agent_id));
  const to = new Date();
  const from = new Date(to.getTime() - 86_400_000);
  const firstHour = new Date(from);
  firstHour.setUTCMinutes(0, 0, 0);
  const hours: string[] = Array.from({ length: 25 }, (_, index) => new Date(firstHour.getTime() + index * 3_600_000).toISOString().slice(0, 13));
  const providers = await providerAnalytics(from.toISOString(), to.toISOString(), hours);
  const guardians = await db.prepare(`SELECT agent_id,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(data::jsonb, 'guardrail_review', 'decision') IS NOT NULL) AS reviews,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(data::jsonb, 'guardrail_review', 'decision') = 'flagged') AS flagged,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(data::jsonb, 'guardrail_review', 'status') = 'unavailable') AS unavailable,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(data::jsonb, 'error_code') IS NOT NULL AND jsonb_extract_path_text(data::jsonb, 'error_code') != 'blocked_by_signet') AS failed,
      MAX(CASE WHEN jsonb_extract_path_text(data::jsonb, 'guardrail_review', 'decision') IS NOT NULL THEN ts END) AS last_review_at
    FROM ledger_record WHERE tenant_id = ? AND kind = 'transaction' AND ts >= ? AND ts <= ?
      AND jsonb_extract_path_text(data::jsonb, 'action_type') = 'guardrail_check'
    GROUP BY agent_id`).all(tenant.id, from.toISOString(), to.toISOString()) as (AgentAnalytics['guardian'] & { agent_id: string })[];
  const agents = (await db.prepare(`SELECT a.id, a.name, a.handle, a.purpose, a.owner, a.tier, a.status, c.valid_to,
      COALESCE(a.vendor = 'ServiceNow' AND jsonb_extract_path_text(a.vendor_details::jsonb, 'external_agent_id') IS NOT NULL, false) AS servicenow_identity,
      (jsonb_extract_path_text(c.body::jsonb, 'limits', 'usd_per_day'))::double precision AS daily_budget_usd
    FROM agent a LEFT JOIN certificate c ON c.agent_id = a.id AND c.status = 'active'
    WHERE a.tenant_id = ? AND a.status != 'retired' ORDER BY a.created_at, a.id`).all(tenant.id)) as unknown as AgentRow[];
  const rows = (await db.prepare(`WITH requests AS (
      SELECT agent_id, ts, data,
        CASE WHEN jsonb_extract_path_text(data::jsonb, 'policy_decision') = 'require_approval' THEN 'review'
          WHEN jsonb_extract_path_text(data::jsonb, 'outcome') IN ('upstream_error', 'timeout') THEN 'failed'
          WHEN jsonb_extract_path_text(data::jsonb, 'outcome') = 'success' THEN 'allowed' ELSE 'blocked' END AS result
      FROM ledger_record WHERE tenant_id = ? AND kind = 'transaction' AND ts >= ? AND ts <= ?
        AND jsonb_extract_path_text(data::jsonb, 'action_type') IN ('llm_call', 'tool_call')
    ) SELECT agent_id, substr(ts, 1, 13) AS hour, COUNT(*) AS requests,
      COUNT(*) FILTER (WHERE result = 'allowed') AS allowed, COUNT(*) FILTER (WHERE result = 'blocked') AS blocked,
      COUNT(*) FILTER (WHERE result = 'review') AS review, COUNT(*) FILTER (WHERE result = 'failed') AS failed,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'tokens_in'))::double precision, 0) + COALESCE((jsonb_extract_path_text(data::jsonb, 'tokens_out'))::double precision, 0)) AS tokens,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'cost_usd'))::double precision, 0)) AS cost_usd,
      SUM(COALESCE((jsonb_extract_path_text(data::jsonb, 'latency_ms_gateway'))::double precision, 0) + COALESCE((jsonb_extract_path_text(data::jsonb, 'latency_ms_upstream'))::double precision, 0)) AS latency_total,
      COUNT((jsonb_extract_path_text(data::jsonb, 'latency_ms_gateway'))::double precision) AS latency_count, MAX(ts) AS last_activity
    FROM requests GROUP BY agent_id, substr(ts, 1, 13)`).all(tenant.id, from.toISOString(), to.toISOString())) as unknown as UsageRow[];
  const safetyCosts = await db.prepare(`SELECT agent_id, COALESCE(SUM((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'cost_usd'))::double precision), 0) AS cost,
      COALESCE(SUM((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'tokens_in'))::double precision), 0) + COALESCE(SUM((jsonb_extract_path_text(data::jsonb, 'safety_usage', 'tokens_out'))::double precision), 0) AS tokens
    FROM ledger_record WHERE tenant_id = ? AND kind = 'transaction' AND ts >= ? AND ts <= ? GROUP BY agent_id`).all(tenant.id, from.toISOString(), to.toISOString()) as { agent_id: string; cost: number; tokens: number }[];
  const items: AgentAnalytics[] = (await Promise.all(agents.map(async (agent) => {
    const usage = rows.filter((row) => row.agent_id === agent.id);
    const sum = (key: 'requests' | 'allowed' | 'blocked' | 'review' | 'failed' | 'tokens' | 'cost_usd' | 'latency_total' | 'latency_count'): number => usage.reduce((total, row) => total + row[key], 0);
    const activity: ActivityBucket[] = hours.map((hour) => {
      const bucket = usage.find((row) => row.hour === hour);
      return { hour: `${hour}:00:00.000Z`, requests: bucket?.requests ?? 0, allowed: bucket?.allowed ?? 0, blocked: bucket?.blocked ?? 0, review: bucket?.review ?? 0, failed: bucket?.failed ?? 0 };
    });
    const count = sum('latency_count');
    const serviceNowCoverage = serviceNowIds.has(agent.id) ? await serviceNowAgentCoverage(agent.id) : null;
    const nativeBlocks = serviceNowIds.has(agent.id) ? await nativeGuardianBlocks(agent.id) : [];
    return {
      ...agent, enforcement: (await agentLevel(agent.id)),
      guardian: { ...(guardians.find(row => row.agent_id === agent.id) ?? { reviews: 0, flagged: 0, unavailable: 0, failed: 0, last_review_at: null }), native_blocked: nativeBlocks.length, native_signet: nativeBlocks.filter((block) => block.signet_request_id !== null).length },
      servicenow: serviceNowCoverage ? { linked: true, monitoring: serviceNowCoverage.monitoring, gateway_enforcement: serviceNowCoverage.gateway_enforcement } : agent.servicenow_identity ? { linked: false, monitoring: false, gateway_enforcement: false } : null,
      provider: providers.get(agent.id) ?? { connection_ids: [], last_sync_at: null, executions: 0, succeeded: 0, failed: 0, other: 0, avg_duration_ms: null, activity: [], recent: [] },
      requests: sum('requests'), allowed: sum('allowed'), blocked: sum('blocked'), review: sum('review'), failed: sum('failed'),
      tokens: sum('tokens') + (safetyCosts.find(row => row.agent_id === agent.id)?.tokens ?? 0), cost_usd: sum('cost_usd') + (safetyCosts.find(row => row.agent_id === agent.id)?.cost ?? 0), avg_latency_ms: count ? sum('latency_total') / count : null,
      last_activity: usage.map((row) => row.last_activity).sort().at(-1) ?? null, activity,
    };
  })));
  return { from: from.toISOString(), to: to.toISOString(), agents: items };
}

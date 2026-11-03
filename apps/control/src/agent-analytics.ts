import type { ActivityBucket, AgentAnalytics, AgentAnalyticsResponse } from '@signet/core';
import { db } from './db';
import { agentLevel } from './enforcement';
import { tenant } from './tenant';

interface AgentRow {
  id: string; name: string; handle: string; purpose: string; owner: string; tier: string; status: string;
  valid_to: string | null; daily_budget_usd: number | null;
}

interface UsageRow {
  agent_id: string; hour: string; requests: number; allowed: number; blocked: number; review: number; failed: number;
  tokens: number; cost_usd: number; latency_total: number; latency_count: number; last_activity: string;
}

/** One tenant-scoped, rolling 24-hour snapshot; detector scores never count as agent requests. */
export function agentAnalytics(): AgentAnalyticsResponse {
  const to = new Date();
  const from = new Date(to.getTime() - 86_400_000);
  const firstHour = new Date(from);
  firstHour.setUTCMinutes(0, 0, 0);
  const hours: string[] = Array.from({ length: 25 }, (_, index) => new Date(firstHour.getTime() + index * 3_600_000).toISOString().slice(0, 13));
  const agents = db.prepare(`SELECT a.id, a.name, a.handle, a.purpose, a.owner, a.tier, a.status, c.valid_to,
      json_extract(c.body, '$.limits.usd_per_day') AS daily_budget_usd
    FROM agent a LEFT JOIN certificate c ON c.agent_id = a.id AND c.status = 'active'
    WHERE a.tenant_id = ? AND a.status != 'retired' ORDER BY a.created_at, a.id`).all(tenant.id) as unknown as AgentRow[];
  const rows = db.prepare(`WITH requests AS (
      SELECT agent_id, ts, data,
        CASE WHEN json_extract(data, '$.policy_decision') = 'require_approval' THEN 'review'
          WHEN json_extract(data, '$.outcome') IN ('upstream_error', 'timeout') THEN 'failed'
          WHEN json_extract(data, '$.outcome') = 'success' THEN 'allowed' ELSE 'blocked' END AS result
      FROM ledger_record WHERE tenant_id = ? AND kind = 'transaction' AND ts >= ? AND ts <= ?
        AND json_extract(data, '$.action_type') IN ('llm_call', 'tool_call')
    ) SELECT agent_id, substr(ts, 1, 13) AS hour, COUNT(*) AS requests,
      SUM(result = 'allowed') AS allowed, SUM(result = 'blocked') AS blocked,
      SUM(result = 'review') AS review, SUM(result = 'failed') AS failed,
      SUM(COALESCE(json_extract(data, '$.tokens_in'), 0) + COALESCE(json_extract(data, '$.tokens_out'), 0)) AS tokens,
      SUM(COALESCE(json_extract(data, '$.cost_usd'), 0)) AS cost_usd,
      SUM(COALESCE(json_extract(data, '$.latency_ms_gateway'), 0) + COALESCE(json_extract(data, '$.latency_ms_upstream'), 0)) AS latency_total,
      COUNT(json_extract(data, '$.latency_ms_gateway')) AS latency_count, MAX(ts) AS last_activity
    FROM requests GROUP BY agent_id, substr(ts, 1, 13)`).all(tenant.id, from.toISOString(), to.toISOString()) as unknown as UsageRow[];
  const items: AgentAnalytics[] = agents.map((agent) => {
    const usage = rows.filter((row) => row.agent_id === agent.id);
    const sum = (key: 'requests' | 'allowed' | 'blocked' | 'review' | 'failed' | 'tokens' | 'cost_usd' | 'latency_total' | 'latency_count'): number => usage.reduce((total, row) => total + row[key], 0);
    const activity: ActivityBucket[] = hours.map((hour) => {
      const bucket = usage.find((row) => row.hour === hour);
      return { hour: `${hour}:00:00.000Z`, requests: bucket?.requests ?? 0, allowed: bucket?.allowed ?? 0, blocked: bucket?.blocked ?? 0, review: bucket?.review ?? 0, failed: bucket?.failed ?? 0 };
    });
    const count = sum('latency_count');
    return {
      ...agent, enforcement: agentLevel(agent.id),
      requests: sum('requests'), allowed: sum('allowed'), blocked: sum('blocked'), review: sum('review'), failed: sum('failed'),
      tokens: sum('tokens'), cost_usd: sum('cost_usd'), avg_latency_ms: count ? sum('latency_total') / count : null,
      last_activity: usage.map((row) => row.last_activity).sort().at(-1) ?? null, activity,
    };
  });
  return { from: from.toISOString(), to: to.toISOString(), agents: items };
}

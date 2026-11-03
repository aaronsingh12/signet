import { db } from './db';
import { usageSummary } from './platforms';
import { tenant } from './tenant';

// Cost, ROI inputs and quality (Phase C3/C4) over a window: what each agent did through Signet (from the
// ledger), the judge scores of its sampled answers, and AI usage outside Signet reported by OpenAI and
// Anthropic. Every figure is computed from records; nothing is estimated.

export async function costs(days = 30) {
  const window = Math.min(Math.max(Math.floor(days), 1), 90);
  const since = new Date(Date.now() - window * 86_400_000).toISOString();
  const agents = (await db.prepare(`
    SELECT a.id, a.name, a.handle, a.tier,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(l.data::jsonb, 'action_type') IN ('llm_call', 'tool_call')) AS requests,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(l.data::jsonb, 'action_type') = 'llm_call') AS model_calls,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(l.data::jsonb, 'action_type') = 'tool_call') AS tool_calls,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(l.data::jsonb, 'action_type') IN ('llm_call', 'tool_call') AND jsonb_extract_path_text(l.data::jsonb, 'outcome') = 'blocked') AS blocked,
      COALESCE(SUM((jsonb_extract_path_text(l.data::jsonb, 'tokens_in'))::double precision), 0) AS tokens_in,
      COALESCE(SUM((jsonb_extract_path_text(l.data::jsonb, 'tokens_out'))::double precision), 0) AS tokens_out,
      COALESCE(SUM((jsonb_extract_path_text(l.data::jsonb, 'cost_usd'))::double precision), 0) AS cost_usd,
      COUNT(*) FILTER (WHERE jsonb_extract_path_text(l.data::jsonb, 'action_type') = 'evaluation') AS evaluations,
      AVG((jsonb_extract_path_text(l.data::jsonb, 'scores', 'helpfulness'))::double precision) AS helpfulness,
      AVG((jsonb_extract_path_text(l.data::jsonb, 'scores', 'safety'))::double precision) AS safety,
      AVG((jsonb_extract_path_text(l.data::jsonb, 'scores', 'on_policy'))::double precision) AS on_policy,
      COUNT(*) FILTER (WHERE jsonb_array_length(COALESCE(jsonb_extract_path(l.data::jsonb, 'flags'), '[]'::jsonb)) > 0) AS flagged
    FROM agent a JOIN ledger_record l ON l.agent_id = a.id AND l.kind = 'transaction' AND l.ts >= ?
    WHERE a.tenant_id = ?
    GROUP BY a.id, a.name, a.handle, a.tier
    ORDER BY COALESCE(SUM((jsonb_extract_path_text(l.data::jsonb, 'cost_usd'))::double precision), 0) DESC`).all(since, tenant.id)) as Record<string, number | string | null>[];
  return { days: window, since, agents, outside_signet: await usageSummary(window) };
}

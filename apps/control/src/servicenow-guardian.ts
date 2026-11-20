import { SERVICENOW_GUARDIAN_REQUEST, SERVICENOW_GUARDIAN_RESPONSE } from '@signet/core';
import { db } from './db';
import { gatewayAddress } from './connection-settings';
import { assertCan, getAgent } from './registry';
import { invalid } from './errors';
import { serviceNowLinksForAgent } from './servicenow-agents';
import type { Principal } from './rbac';
import { tenant } from './tenant';
import { nativeGuardianBlocks } from './servicenow-guardian-events';

interface GuardianSetup {
  endpoint: string; request_transformer: string; response_transformer: string;
  reviews_24h: number; flagged_24h: number; unavailable_24h: number; last_review_at: string | null;
  blocking_verified: boolean;
  blocked_24h: number;
  recent_blocks: { event_id: string; execution_id: string; at: string; categories: string[]; signet_request_id: string | null }[];
  failed_24h: number;
  last_error: { at: string; code: string; detail: string | null } | null;
  recent_reviews: { at: string; request_id: string | null; decision: string | null; status: string | null; categories: string[]; error_code: string | null }[];
}

/** Reports submitted Guardian verdicts, never inferring native-chat interception or ServiceNow blocking. */
export async function serviceNowGuardianSetup(agentRef: string, actor: Principal): Promise<GuardianSetup> {
  const agent = await getAgent(agentRef);
  assertCan(actor, 'identity.bootstrap', agent);
  if (!(await serviceNowLinksForAgent(agent.id)).length) throw invalid('Link this agent to its ServiceNow record before configuring Guardian');
  const since = new Date(Date.now() - 86400000).toISOString();
  const rows = await db.prepare(`SELECT ts,
    jsonb_extract_path_text(data::jsonb, 'guardrail_review', 'decision') AS decision,
    jsonb_extract_path_text(data::jsonb, 'guardrail_review', 'status') AS status,
    jsonb_extract_path_text(data::jsonb, 'error_code') AS error_code,
    jsonb_extract_path_text(data::jsonb, 'guardrail_input_error') AS error_detail,
    jsonb_extract_path_text(data::jsonb, 'request_id') AS request_id,
    jsonb_extract_path_text(data::jsonb, 'guardrail_categories') AS categories
    FROM ledger_record WHERE tenant_id = ? AND agent_id = ? AND kind = 'transaction'
      AND jsonb_extract_path_text(data::jsonb, 'action_type') = 'guardrail_check' AND ts >= ?
    ORDER BY seq DESC`).all(tenant.id, agent.id, since) as { ts: string; decision: string | null; status: string | null; error_code: string | null; error_detail: string | null; request_id: string | null; categories: string | null }[];
  // A Signet block is a completed review, not a failed one.
  const failed = rows.filter(row => row.error_code !== null && row.error_code !== 'blocked_by_signet');
  const blocks = await nativeGuardianBlocks(agent.id);
  return {
    endpoint: `${await gatewayAddress()}/v1/guardrails/servicenow`,
    request_transformer: SERVICENOW_GUARDIAN_REQUEST, response_transformer: SERVICENOW_GUARDIAN_RESPONSE,
    reviews_24h: rows.filter(row => row.decision !== null).length,
    flagged_24h: rows.filter(row => row.decision === 'flagged').length,
    unavailable_24h: rows.filter(row => row.status === 'unavailable').length,
    last_review_at: rows.find(row => row.decision !== null)?.ts ?? null,
    blocking_verified: blocks.length > 0,
    blocked_24h: blocks.length,
    recent_blocks: blocks.slice(0, 20),
    recent_reviews: rows.slice(0, 20).map(row => ({ at: row.ts, request_id: row.request_id, decision: row.decision, status: row.status, categories: reviewCategories(row.categories), error_code: row.error_code })),
    failed_24h: failed.length,
    last_error: failed[0] ? { at: failed[0].ts, code: failed[0].error_code!, detail: failed[0].error_detail } : null,
  };
}

function reviewCategories(value: string | null): string[] {
  if (value === null) return [];
  const categories: string[] = JSON.parse(value);
  if (!Array.isArray(categories) || categories.some(category => typeof category !== 'string')) throw new TypeError('Guardian ledger categories must be a string array');
  return categories;
}

import { SCAN_CHECKS, SCAN_RESULTS, type ScanEntry, type ScanCheck, type ScanSource } from '../../../packages/core/src/scan-history';
import { db } from './db';
import { getAgent } from './registry';
import { tenant } from './tenant';

interface StoredScan {
  seq: number; record_id: string; scanned_at: string; action_type: string | null; event: string | null;
  outcome: string | null; policy_decision: string | null; input_category: string | null; output_category: string | null;
  review_decision: string | null; review_status: string | null; steps: string | null;
}
interface ScanStep { n: number; result: 'pass' | 'fail' | 'note' }

function recordedSteps(value: string | null): ScanStep[] {
  if (value === null) return [];
  const steps: ScanStep[] = JSON.parse(value);
  if (!Array.isArray(steps) || steps.some(step => !step || !Number.isSafeInteger(step.n) || !['pass', 'fail', 'note'].includes(step.result))) throw new TypeError('Stored gateway check steps are invalid');
  return steps;
}

function toolCheck(steps: ScanStep[], stage: number): ScanCheck {
  if (steps.some(step => step.n === stage && step.result === 'fail')) return 'blocked';
  if (steps.some(step => step.n === stage && step.result === 'pass')) return 'passed';
  return steps.some(step => step.n < stage && step.result === 'fail') ? 'not_run' : 'not_recorded';
}

/** Exposes recorded check metadata only; submitted Guardian content has no assumed input/reply stage. */
export async function scanHistory(agentRef: string, beforeSeq: number | null, limit: number, source: ScanSource | null): Promise<{ items: ScanEntry[]; next_cursor: number | null }> {
  const agent = await getAgent(agentRef);
  const sourceConditions: Record<ScanSource, string> = { gateway_model: "data::jsonb->>'action_type' = 'llm_call'", gateway_tool: "data::jsonb->>'action_type' = 'tool_call'", servicenow_guardian: "data::jsonb->>'action_type' = 'guardrail_check'", servicenow_native: "data::jsonb->>'event' = 'servicenow.guardian_blocked'" };
  const stored = await db.prepare(`SELECT seq, record_id,
      CASE WHEN kind = 'admin' THEN data::jsonb->>'at' ELSE ts END AS scanned_at,
      data::jsonb->>'action_type' AS action_type, data::jsonb->>'event' AS event,
      data::jsonb->>'outcome' AS outcome, data::jsonb->>'policy_decision' AS policy_decision,
      data::jsonb#>>'{input_safety,category}' AS input_category, data::jsonb#>>'{output_safety,category}' AS output_category,
      data::jsonb#>>'{guardrail_review,decision}' AS review_decision, data::jsonb#>>'{guardrail_review,status}' AS review_status,
      data::jsonb->>'steps' AS steps
    FROM ledger_record WHERE tenant_id = ? AND agent_id = ? AND
      ((kind = 'transaction' AND data::jsonb->>'action_type' IN ('llm_call', 'tool_call', 'guardrail_check'))
       OR (kind = 'admin' AND data::jsonb->>'event' = 'servicenow.guardian_blocked'))
      ${source === null ? '' : `AND (${sourceConditions[source]})`}
      ${beforeSeq === null ? '' : 'AND seq < ?'} ORDER BY seq DESC LIMIT ?`).all(tenant.id, agent.id, ...(beforeSeq === null ? [] : [beforeSeq]), limit + 1) as unknown as StoredScan[];
  const rows = stored.map((row): ScanEntry & { seq: number } => {
    const native = row.event === 'servicenow.guardian_blocked';
    const guardian = row.action_type === 'guardrail_check';
    const result: ScanEntry['result'] = native ? 'blocked' : guardian
      // A flagged verdict is Signet's block (ServiceNow carries it out), including the fail-closed "unavailable" one.
      ? row.review_decision === 'flagged' ? 'blocked' : row.review_decision === null ? 'failed' : 'completed'
      // What happened decides: a hold that ended in a refusal (approval timeout or rejection) is a block; only a
      // request still waiting for a person is in review.
      : row.outcome === 'pending' ? 'review' : row.outcome === 'blocked' ? 'blocked' : row.outcome === 'success' ? 'completed' : row.policy_decision === 'require_approval' ? 'review' : 'failed';
    const steps = recordedSteps(row.steps);
    const categoryCheck = (category: string | null): ScanCheck => category === null ? 'not_recorded' : category === 'allow' ? 'passed' : result === 'blocked' ? 'blocked' : 'flagged';
    const input = native || guardian ? 'not_recorded' : row.action_type === 'tool_call' ? toolCheck(steps, 8) : categoryCheck(row.input_category);
    const output = native || guardian ? 'not_recorded' : row.action_type === 'tool_call'
      ? toolCheck(steps, 13)
      : row.output_category === null && input === 'blocked' ? 'not_run' : categoryCheck(row.output_category);
    const content: ScanCheck = native ? 'flagged' : guardian ? row.review_status === 'unavailable' ? 'unavailable' : row.review_decision === 'flagged' ? 'blocked' : row.review_decision === 'clear' ? 'passed' : 'not_recorded' : 'not_run';
    if (!Number.isSafeInteger(row.seq) || typeof row.record_id !== 'string' || !Number.isFinite(Date.parse(row.scanned_at)) || !SCAN_RESULTS.includes(result) || !SCAN_CHECKS.includes(input) || !SCAN_CHECKS.includes(output)) throw new TypeError('Stored scan metadata is invalid');
    return { seq: row.seq, record_id: row.record_id, scanned_at: row.scanned_at, result, input_check: input, output_check: output, content_check: content, source: native ? 'servicenow_native' : guardian ? 'servicenow_guardian' : row.action_type === 'tool_call' ? 'gateway_tool' : 'gateway_model' };
  });
  const items = rows.slice(0, limit);
  return { items: items.map(({ seq, ...item }) => item), next_cursor: rows.length > limit ? items[items.length - 1]!.seq : null };
}

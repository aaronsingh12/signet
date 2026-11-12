import { SCAN_CHECKS, SCAN_RESULTS, type ScanEntry } from '../../../packages/core/src/scan-history';
import { db } from './db';
import { getAgent } from './registry';
import { tenant } from './tenant';

/** Project only date, decision and check statuses, never prompts, replies, reasons or session IDs. */
export async function scanHistory(agentRef: string, beforeSeq: number | null, limit: number): Promise<{ items: ScanEntry[]; next_cursor: number | null }> {
  const agent = await getAgent(agentRef);
  const stored = await db.prepare(`SELECT seq, record_id, ts AS scanned_at,
    CASE WHEN data::jsonb->>'outcome' = 'pending' OR data::jsonb->>'policy_decision' = 'require_approval' THEN 'review'
         WHEN data::jsonb->>'outcome' = 'blocked' THEN 'blocked'
         WHEN data::jsonb->>'outcome' = 'success' THEN 'completed' ELSE 'failed' END AS result,
    CASE WHEN data::jsonb#>>'{input_safety,category}' = 'allow' THEN 'passed'
         WHEN data::jsonb#>>'{input_safety,category}' IS NOT NULL THEN 'blocked' ELSE 'not_recorded' END AS input_check,
    CASE WHEN data::jsonb#>>'{output_safety,category}' = 'allow' THEN 'passed'
         WHEN data::jsonb#>>'{output_safety,category}' IS NOT NULL THEN 'blocked'
         WHEN data::jsonb#>>'{input_safety,category}' IS NOT NULL AND data::jsonb#>>'{input_safety,category}' <> 'allow' THEN 'not_run'
         ELSE 'not_recorded' END AS output_check
    FROM ledger_record WHERE tenant_id = ? AND agent_id = ? AND kind = 'transaction'
      AND data::jsonb->>'action_type' = 'llm_call' ${beforeSeq === null ? '' : 'AND seq < ?'}
    ORDER BY seq DESC LIMIT ?`).all(tenant.id, agent.id, ...(beforeSeq === null ? [] : [beforeSeq]), limit + 1);
  const rows = stored.map((row): ScanEntry & { seq: number } => {
    const result = SCAN_RESULTS.find((value) => value === row.result);
    const input = SCAN_CHECKS.find((value) => value === row.input_check);
    const output = SCAN_CHECKS.find((value) => value === row.output_check);
    if (typeof row.seq !== 'number' || !Number.isSafeInteger(row.seq) || typeof row.record_id !== 'string' || typeof row.scanned_at !== 'string' || !Number.isFinite(Date.parse(row.scanned_at)) || !result || !input || !output) throw new TypeError('Stored gateway scan metadata is invalid');
    return { seq: row.seq, record_id: row.record_id, scanned_at: row.scanned_at, result, input_check: input, output_check: output };
  });
  const items = rows.slice(0, limit);
  return { items: items.map(({ record_id, scanned_at, result, input_check, output_check }) => ({ record_id, scanned_at, result, input_check, output_check })), next_cursor: rows.length > limit ? items[items.length - 1]!.seq : null };
}

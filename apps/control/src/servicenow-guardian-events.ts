import { SIGNET_BLOCKED_MESSAGE, SIGNET_REF } from '@signet/core';
import { db, nowIso, tx } from './db';
import { invalid } from './errors';
import { object, type Json } from './external-contract';
import { normalizeServiceNowExecutionDates } from './external-normalize';
import { tenant } from './tenant';
import * as ledger from './ledger';

export type GuardianTable = 'sn_aia_execution_task' | 'sn_aia_gen_ai_m2m' | 'sys_gen_ai_log_metadata' | 'sys_generative_ai_metric';
export type GuardianTableReader = (table: GuardianTable, query: string, fields: string) => Promise<Json>;
// signet_request_id: the Signet Guardian review whose flagged verdict ServiceNow carried out, read from the
// signet_ref category in the Raw Response; null when ServiceNow blocked on a verdict without one.
interface GuardianBlock { event_id: string; execution_id: string; at: string; categories: string[]; signet_request_id: string | null }

const REQUEST_ID = /^req_[A-Za-z0-9]{10,40}$/;

/** Splits Signet's reference and blocked message out of the verdict categories ServiceNow stored. */
export function signetReference(categories: string[]): { categories: string[]; signet_request_id: string | null } {
  const refs = [...new Set(categories.filter((c) => c.startsWith(SIGNET_REF)).map((c) => c.slice(SIGNET_REF.length)))];
  if (refs.length > 1) throw invalid('ServiceNow Guardian verdict references more than one Signet review; block evidence is ambiguous');
  if (refs[0] !== undefined && !REQUEST_ID.test(refs[0])) throw invalid('ServiceNow Guardian verdict carries a malformed Signet reference');
  return { categories: categories.filter((c) => !c.startsWith(SIGNET_REF) && !SIGNET_BLOCKED_MESSAGE.test(c)), signet_request_id: refs[0] ?? null };
}
interface GuardianSource { connection_id: string; external_agent_id: string; agent_id: string; instance_url: string }

function rows(value: Json): Record<string, unknown>[] {
  const result = object(value, 'ServiceNow Guardian table response').result;
  if (!Array.isArray(result) || result.length > 1000) throw invalid('ServiceNow Guardian response must contain at most 1000 rows; narrow execution history before retrying');
  return result.map(row => object(row, 'ServiceNow Guardian row'));
}

function text(row: Record<string, unknown>, field: string): string {
  if (typeof row[field] !== 'string') throw invalid(`ServiceNow Guardian row requires string field ${field}`);
  return row[field];
}

function identifier(value: string): string {
  if (!/^[a-f0-9]{32}$/i.test(value)) throw invalid('ServiceNow Guardian references must be 32-character sys_ids');
  return value;
}

/** An explicit native moderation error plus the invocation's flagged verdict and BLOCK setting prove a block. */
export function nativeGuardianCategories(errorCode: string, error: string, metrics: { name: string; value: string }[]): string[] | null {
  if (errorCode !== '300000' || error !== 'Error 300000: Check guardrail response for flagged moderation checks.') return null;
  const values = new Map<string, string>();
  for (const metric of metrics) {
    if (values.has(metric.name)) throw invalid(`Duplicate ServiceNow Guardian metric ${metric.name}; block evidence is ambiguous`);
    values.set(metric.name, metric.value);
  }
  const raw = values.get('Raw Response');
  if (!raw) return null;
  let parsed: Json;
  try { parsed = JSON.parse(raw) as Json; }
  catch (error) {
    if (error instanceof SyntaxError) throw invalid('ServiceNow Guardian Raw Response metric is not valid JSON; inspect the response transformer');
    throw error;
  }
  const verdict = object(parsed, 'ServiceNow Guardian verdict');
  const categories: string[] = [];
  let blocked = false;
  for (const [field, setting, detection] of [['security', 'Prompt Injection Setting', 'Prompt Injection'], ['safety', 'Offensiveness Setting', 'Offensiveness']] as const) {
    const flag = object(verdict[field], `ServiceNow Guardian ${field} verdict`);
    if (typeof flag.flagged !== 'boolean' || !Array.isArray(flag.categories) || flag.categories.length > 100 || flag.categories.some(category => typeof category !== 'string' || category.length > 200)) throw invalid('ServiceNow Guardian verdict requires boolean flagged and bounded string categories');
    if (flag.flagged && values.get(setting) === 'BLOCK' && values.get(detection) === 'true') { blocked = true; categories.push(...flag.categories as string[]); }
  }
  return blocked ? [...new Set(categories)] : null;
}

/** Joins explicit execution/task/log references; neither timestamps alone nor execution_failed imply blocking. */
export async function syncNativeGuardianBlocks(source: GuardianSource, executionIds: string[], read: GuardianTableReader): Promise<void> {
  const blocks: GuardianBlock[] = [];
  for (let offset = 0; offset < executionIds.length; offset += 25) {
    const plans = new Set(executionIds.slice(offset, offset + 25).map(identifier));
    const tasks = rows(await read('sn_aia_execution_task', `execution_planIN${[...plans].join(',')}`, 'sys_id,execution_plan,status'));
    const planByTask = new Map(tasks.filter(row => plans.has(text(row, 'execution_plan')) && text(row, 'status') === 'cancelled').map(row => [identifier(text(row, 'sys_id')), text(row, 'execution_plan')]));
    if (!planByTask.size) continue;
    const links = rows(await read('sn_aia_gen_ai_m2m', `source_table=sn_aia_execution_task^source_idIN${[...planByTask.keys()].join(',')}`, 'source_id,source_table,gen_ai_log_metadata'));
    const planByLog = new Map<string, string>();
    for (const row of links) {
      const plan = planByTask.get(text(row, 'source_id'));
      if (plan && text(row, 'source_table') === 'sn_aia_execution_task') {
        const log = identifier(text(row, 'gen_ai_log_metadata'));
        if (planByLog.has(log) && planByLog.get(log) !== plan) throw invalid('ServiceNow Guardian log references multiple execution plans');
        planByLog.set(log, plan);
      }
    }
    if (!planByLog.size) continue;
    const logs = rows(await read('sys_gen_ai_log_metadata', `sys_idIN${[...planByLog.keys()].join(',')}`, 'sys_id,status,error_code,error'));
    const metrics = rows(await read('sys_generative_ai_metric', `sys_gen_ai_log_metadataIN${[...planByLog.keys()].join(',')}^type=Guardian^nameINRaw Response,Prompt Injection Setting,Prompt Injection,Offensiveness Setting,Offensiveness`, 'sys_id,sys_gen_ai_log_metadata,name,value,sys_created_on'));
    for (const log of logs) {
      const logId = text(log, 'sys_id');
      const execution = planByLog.get(logId);
      if (!execution || text(log, 'status') !== 'error') continue;
      const evidence = metrics.filter(row => text(row, 'sys_gen_ai_log_metadata') === logId);
      const categories = nativeGuardianCategories(text(log, 'error_code'), text(log, 'error'), evidence.map(row => ({ name: text(row, 'name'), value: text(row, 'value') })));
      if (categories === null) continue;
      const raw = evidence.find(row => text(row, 'name') === 'Raw Response')!;
      const timestamp = normalizeServiceNowExecutionDates({ id: logId, name: null, status: null, timestamp: text(raw, 'sys_created_on') }).timestamp!;
      blocks.push({ event_id: logId, execution_id: execution, at: timestamp, ...signetReference(categories) });
    }
  }
  await tx(async () => {
    for (const block of blocks) {
      const prior = await db.prepare("SELECT external_id FROM external_observation WHERE connection_id = ? AND external_agent_id = ? AND kind = 'guardian_block' AND external_id = ?").get(source.connection_id, source.external_agent_id, block.event_id);
      const metadata = { ...block, instance_url: source.instance_url, status: 'blocked', evidence: 'native_guardian_metrics' };
      await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(connection_id, external_agent_id, kind, external_id) DO UPDATE SET metadata = excluded.metadata, observed_at = excluded.observed_at').run(source.connection_id, source.external_agent_id, block.event_id, 'guardian_block', JSON.stringify(metadata), nowIso());
      if (!prior) await ledger.append({ kind: 'admin', agent_id: source.agent_id, data: { event: 'servicenow.guardian_blocked', connection_id: source.connection_id, ...metadata } });
    }
  });
}

/** Counts native events once across sources without claiming a Signet request-ID correlation. */
export async function nativeGuardianBlocks(agentId: string): Promise<GuardianBlock[]> {
  const now = new Date();
  return nativeGuardianBlocksBetween(agentId, new Date(now.getTime() - 86400000).toISOString(), now.toISOString());
}

export async function nativeGuardianBlocksBetween(agentId: string, from: string, to: string): Promise<GuardianBlock[]> {
  const data = await db.prepare(`SELECT o.metadata FROM external_observation o JOIN external_connection c ON c.id = o.connection_id
    JOIN external_agent_mapping m ON m.connection_id = o.connection_id AND m.external_id = o.external_agent_id
    WHERE c.tenant_id = ? AND m.agent_id = ? AND o.kind = 'guardian_block'`).all(tenant.id, agentId) as { metadata: string }[];
  const unique = new Map<string, GuardianBlock>();
  const now = Date.parse(to);
  const since = Date.parse(from);
  if (!Number.isFinite(now) || !Number.isFinite(since) || since > now) throw invalid('Native Guardian history requires valid from/to timestamps in chronological order');
  for (const row of data) {
    const block = object(JSON.parse(row.metadata), 'native Guardian evidence');
    const at = text(block, 'at');
    if (!Number.isFinite(Date.parse(at))) throw invalid('Native Guardian evidence requires a valid timestamp');
    if (Date.parse(at) < since || Date.parse(at) > now) continue;
    const categories = block.categories;
    if (!Array.isArray(categories) || categories.some(value => typeof value !== 'string')) throw invalid('Native Guardian evidence requires string categories');
    const event = identifier(text(block, 'event_id'));
    const ref = block.signet_request_id;
    if (ref !== undefined && ref !== null && (typeof ref !== 'string' || !REQUEST_ID.test(ref))) throw invalid('Native Guardian evidence carries a malformed Signet reference');
    unique.set(`${text(block, 'instance_url')}/${event}`, { event_id: event, execution_id: identifier(text(block, 'execution_id')), at, categories: categories as string[], signet_request_id: typeof ref === 'string' ? ref : null });
  }
  return [...unique.values()].sort((left, right) => right.at.localeCompare(left.at));
}

import { invalid } from './errors';
import type { ImportedRecord, Json } from './external-contract';

/** ServiceNow Table API database date-times are UTC even when their wire format omits a zone. */
export function normalizeServiceNowExecutionDates(record: ImportedRecord): ImportedRecord {
  const metadata = { ...record.metadata };
  for (const key of ['started_at', 'completed_at']) {
    const value = metadata[key];
    if (value === undefined) continue;
    if (typeof value !== 'string') throw invalid(`ServiceNow execution ${key} must be a date-time string`);
    metadata[key] = serviceNowDate(value);
  }
  return { ...record, timestamp: record.timestamp === null ? null : serviceNowDate(record.timestamp), metadata };
}

function serviceNowDate(value: string): string {
  const databaseDate = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value);
  const input = databaseDate ? value.replace(' ', 'T') + 'Z' : value;
  if (!databaseDate && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(input)) throw invalid('ServiceNow execution date-time must use UTC database format YYYY-MM-DD HH:mm:ss or ISO 8601 with an explicit timezone');
  const parsed = Date.parse(input);
  if (!Number.isFinite(parsed)) throw invalid('ServiceNow execution date-time is invalid');
  const normalized = new Date(parsed).toISOString();
  if (databaseDate && normalized.slice(0, 19) !== input.slice(0, 19)) throw invalid('ServiceNow execution date-time contains an invalid calendar date or time');
  return normalized;
}

/** Missing provider measurements remain null; no token, cost, timing or quality values are fabricated. */
export function normalizeExecution(record: ImportedRecord): Json {
  const metadata = record.metadata ?? {};
  for (const key of ['started_at', 'completed_at']) if (metadata[key] !== undefined && (typeof metadata[key] !== 'string' || !Number.isFinite(Date.parse(metadata[key] as string)))) throw invalid(`Execution ${key} must be an ISO timestamp`);
  if (metadata.duration_ms !== undefined && (typeof metadata.duration_ms !== 'number' || !Number.isFinite(metadata.duration_ms) || metadata.duration_ms < 0)) throw invalid('Execution duration_ms must be a non-negative finite number');
  if (metadata.error_category !== undefined && typeof metadata.error_category !== 'string') throw invalid('Execution error_category must be a string');
  if (metadata.metrics !== undefined && (metadata.metrics === null || typeof metadata.metrics !== 'object' || Array.isArray(metadata.metrics))) throw invalid('Execution metrics must be a JSON object');
  return { external_execution_id: record.id, status: record.status, timestamp: record.timestamp, started_at: metadata.started_at ?? null, completed_at: metadata.completed_at ?? null, duration_ms: metadata.duration_ms ?? null, error_category: metadata.error_category ?? null, metrics: metadata.metrics ?? null, metadata };
}

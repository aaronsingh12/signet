import { invalid } from './errors';
import type { ImportedRecord, Json } from './external-contract';

/** Missing provider measurements remain null; no token, cost, timing or quality values are fabricated. */
export function normalizeExecution(record: ImportedRecord): Json {
  const metadata = record.metadata ?? {};
  for (const key of ['started_at', 'completed_at']) if (metadata[key] !== undefined && (typeof metadata[key] !== 'string' || !Number.isFinite(Date.parse(metadata[key] as string)))) throw invalid(`Execution ${key} must be an ISO timestamp`);
  if (metadata.duration_ms !== undefined && (typeof metadata.duration_ms !== 'number' || !Number.isFinite(metadata.duration_ms) || metadata.duration_ms < 0)) throw invalid('Execution duration_ms must be a non-negative finite number');
  if (metadata.error_category !== undefined && typeof metadata.error_category !== 'string') throw invalid('Execution error_category must be a string');
  if (metadata.metrics !== undefined && (metadata.metrics === null || typeof metadata.metrics !== 'object' || Array.isArray(metadata.metrics))) throw invalid('Execution metrics must be a JSON object');
  return { external_execution_id: record.id, status: record.status, timestamp: record.timestamp, started_at: metadata.started_at ?? null, completed_at: metadata.completed_at ?? null, duration_ms: metadata.duration_ms ?? null, error_category: metadata.error_category ?? null, metrics: metadata.metrics ?? null, metadata };
}

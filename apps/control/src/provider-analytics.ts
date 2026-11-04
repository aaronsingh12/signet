import type { ProviderAnalytics } from '@signet/core';
import { db } from './db';
import { tenant } from './tenant';

interface Connection { agent_id: string; connection_id: string; last_sync_at: string | null }
interface Execution { agent_id: string; connection_id: string; external_id: string; status: string | null; timestamp: string; duration_ms: number | null }

/** Provider executions remain separate from signed Gateway decisions and use event time, not polling time. */
export async function providerAnalytics(from: string, to: string, hours: string[]): Promise<Map<string, ProviderAnalytics>> {
  const connections: Connection[] = (await db.prepare(`SELECT m.agent_id, c.id AS connection_id,
      jsonb_extract_path_text(c.health::jsonb, 'last_sync_at') AS last_sync_at
    FROM external_agent_mapping m JOIN external_connection c ON c.id = m.connection_id
    JOIN agent a ON a.id = m.agent_id WHERE c.tenant_id = ? AND a.tenant_id = ?`).all(tenant.id, tenant.id)).map((row) => ({ agent_id: row.agent_id as string, connection_id: row.connection_id as string, last_sync_at: row.last_sync_at as string | null }));
  const rows: Execution[] = (await db.prepare(`WITH events AS (
      SELECT m.agent_id, o.connection_id, o.external_id,
        jsonb_extract_path_text(o.metadata::jsonb, 'status') AS status,
        COALESCE(jsonb_extract_path_text(o.metadata::jsonb, 'timestamp'), jsonb_extract_path_text(o.metadata::jsonb, 'started_at'), jsonb_extract_path_text(o.metadata::jsonb, 'completed_at')) AS event_time,
        (jsonb_extract_path_text(o.metadata::jsonb, 'duration_ms'))::double precision AS duration_ms
      FROM external_observation o JOIN external_connection c ON c.id = o.connection_id
      JOIN external_agent_mapping m ON m.connection_id = o.connection_id AND m.external_id = o.external_agent_id
      JOIN agent a ON a.id = m.agent_id
      WHERE c.tenant_id = ? AND a.tenant_id = ? AND o.kind = 'execution'
    ) SELECT agent_id, connection_id, external_id, status, event_time AS timestamp, duration_ms FROM events
      WHERE event_time::timestamptz >= ?::timestamptz AND event_time::timestamptz <= ?::timestamptz
      ORDER BY event_time::timestamptz DESC, connection_id, external_id`).all(tenant.id, tenant.id, from, to)).map((row) => ({ agent_id: row.agent_id as string, connection_id: row.connection_id as string, external_id: row.external_id as string, status: row.status as string | null, timestamp: row.timestamp as string, duration_ms: row.duration_ms as number | null }));
  const result = new Map<string, ProviderAnalytics>();
  for (const agentId of new Set(connections.map((connection) => connection.agent_id))) {
    const linked = connections.filter((connection) => connection.agent_id === agentId);
    const executions = rows.filter((row) => row.agent_id === agentId);
    const succeeded = executions.filter((row) => ['success', 'succeeded', 'completed'].includes(row.status ?? '')).length;
    const failed = executions.filter((row) => ['error', 'failed', 'failure', 'timeout'].includes(row.status ?? '')).length;
    const measured = executions.filter((row) => row.duration_ms !== null);
    result.set(agentId, {
      connection_ids: linked.map((connection) => connection.connection_id),
      last_sync_at: linked.map((connection) => connection.last_sync_at).filter((date): date is string => date !== null).sort().at(-1) ?? null,
      executions: executions.length, succeeded, failed, other: executions.length - succeeded - failed,
      avg_duration_ms: measured.length ? measured.reduce((sum, row) => sum + row.duration_ms!, 0) / measured.length : null,
      activity: hours.map((hour) => ({ hour: `${hour}:00:00.000Z`, executions: executions.filter((row) => new Date(row.timestamp).toISOString().slice(0, 13) === hour).length })),
      recent: executions.slice(0, 20).map((row) => ({ id: `${row.connection_id}/${row.external_id}`, status: row.status, timestamp: row.timestamp, duration_ms: row.duration_ms })),
    });
  }
  return result;
}

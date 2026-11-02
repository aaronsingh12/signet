import { newId } from '@signet/core';
import { db, nowIso } from './db';
import { tenant } from './tenant';

// Connector outbox (BP 10.4, 10.9). Signet events are queued for every active connector and sent by
// the connector worker with retry and dead letters, so a failing connector never blocks enforcement,
// lifecycle progression or kills.

export type OutboundEvent =
  | 'risk.upsert'          // agent classified T1-T3 -> sn_risk_risk
  | 'issue.upsert'         // gap found, violation, or level 4+ event -> sn_grc_issue
  | 'incident.create'      // level 4-6 event -> incident
  | 'ci.upsert'            // deploy / ladder state / retire -> AI Agent CI via IRE
  | 'indicator.result'     // automated control evaluated -> sn_grc_indicator_result
  | 'control_test.create'; // Test stage completed -> sn_compliance_control_test

export const correlation = (object: string, id: string) => `signet:${tenant.id}:${object}:${id}`;

export function enqueue(event: OutboundEvent, objectKey: string, payload: Record<string, unknown>) {
  const connectors = db.prepare("SELECT id FROM connector WHERE status = 'active'").all() as { id: string }[];
  for (const c of connectors) {
    db.prepare('INSERT INTO connector_outbox (id, connector_id, event, object_key, payload, status, next_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      newId('evt').replace('evt_', 'obx_'), c.id, event, objectKey, JSON.stringify(payload), 'pending', Date.now(), nowIso(),
    );
  }
  return connectors.length;
}

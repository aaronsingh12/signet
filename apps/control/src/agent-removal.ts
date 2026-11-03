import { db, tx } from './db';
import { PolicyError, forbidden, invalid } from './errors';
import { getAgent } from './registry';
import { applyLadder, agentLevel } from './enforcement';
import * as hub from './hub';
import { forgetAgent } from './live';
import type { Principal } from './rbac';
import { eraseAgentLedger } from './erasure-ledger';
import { eraseDeploymentArtifacts, eraseEvidenceFiles } from './erasure-files';

function assertAdministrator(actor: Principal): void {
  if (actor.kind !== 'human' || !actor.permissions.includes('agents.delete')) throw forbidden('RBAC', 'Permanent agent deletion requires a human workspace administrator with agents.delete permission');
}

export function agentRemovalPreview(agentRef: string, actor: Principal): { id: string; name: string; handle: string; certificates: number; deployments: number; credentials: number; records: number } {
  assertAdministrator(actor);
  const agent = getAgent(agentRef);
  const count = (sql: string): number => (db.prepare(sql).get(agent.id) as { count: number }).count;
  return {
    id: agent.id, name: agent.name, handle: agent.handle,
    certificates: count('SELECT COUNT(*) AS count FROM certificate WHERE agent_id = ?'),
    deployments: count('SELECT COUNT(*) AS count FROM agent_instance WHERE agent_id = ?'),
    credentials: count('SELECT COUNT(*) AS count FROM deployment_credential WHERE agent_id = ?') + count('SELECT COUNT(*) AS count FROM bootstrap_credential WHERE agent_id = ?'),
    records: count('SELECT COUNT(*) AS count FROM ledger_record WHERE agent_id = ?'),
  };
}

/** Explicit administrator erasure: stop execution, clear every gateway, erase owned data and retain anonymous signed chain commitments. */
export async function removeAgent(agentRef: string, confirmation: string, actor: Principal): Promise<{ deleted: true; erased_records: number }> {
  assertAdministrator(actor);
  const agent = getAgent(agentRef);
  if (confirmation !== agent.handle) throw invalid(`Type the exact agent handle ${agent.handle} to permanently delete this agent and its data`);
  const nodes = (db.prepare('SELECT id FROM gateway_node').all() as { id: string }[]).map((node) => node.id);
  const unavailable = nodes.filter((node) => !hub.connectedNodes().includes(node));
  if (unavailable.length) throw new PolicyError('ERASURE_GATEWAY', `Deletion was not started. Reconnect registered gateways ${unavailable.join(', ')} so their agent data can be cleared, then retry.`, 503);
  if (agentLevel(agent.id) !== 'killed') applyLadder({ agentId: agent.id }, 'kill', { actor: actor.id, reason: 'Administrator requested permanent agent and data erasure' });
  const tokens = (db.prepare('SELECT jti FROM issued_token WHERE agent_id = ?').all(agent.id) as { jti: string }[]).map((row) => row.jti);
  const instances = (db.prepare('SELECT id FROM agent_instance WHERE agent_id = ?').all(agent.id) as { id: string }[]).map((row) => row.id);
  const certificates = (db.prepare('SELECT id FROM certificate WHERE agent_id = ?').all(agent.id) as { id: string }[]).map((row) => row.id);
  const sessions = (db.prepare("SELECT DISTINCT json_extract(data, '$.session_id') AS id FROM ledger_record WHERE agent_id = ? AND json_type(data, '$.session_id') = 'text'").all(agent.id) as { id: string }[]).map((row) => row.id);
  await hub.eraseAgentOnGateways(agent.id, [...new Set([...sessions, ...tokens])], instances, tokens, nodes);
  db.exec('PRAGMA secure_delete = ON');
  let erased: { records: number; days: string[] };
  try {
    erased = tx(() => {
    const lifecycles = (db.prepare('SELECT id FROM lifecycle WHERE agent_id = ?').all(agent.id) as { id: string }[]).map((row) => row.id);
    const requests = (db.prepare('SELECT id FROM approval_request WHERE agent_id = ?').all(agent.id) as { id: string }[]).map((row) => row.id);
    const result = eraseAgentLedger(agent.id, [agent.id, agent.handle, ...certificates, ...instances, ...tokens, ...lifecycles, ...requests]);
    const cached = db.prepare('DELETE FROM idempotency_key WHERE instr(body, ?) > 0 OR instr(path, ?) > 0');
    for (const identifier of [agent.id, ...certificates, ...instances, ...tokens]) cached.run(identifier, identifier);
    const byHandle = `/api/v1/agents/${agent.handle}`;
    db.prepare('DELETE FROM idempotency_key WHERE path = ? OR path LIKE ?').run(byHandle, `${byHandle}/%`);
    db.prepare('DELETE FROM kill_ack WHERE event_id IN (SELECT id FROM enforcement_event WHERE agent_id = ?)').run(agent.id);
    db.prepare('DELETE FROM enforcement_event WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM enforcement_state WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM revoked_jti WHERE jti IN (SELECT jti FROM issued_token WHERE agent_id = ?)').run(agent.id);
    db.prepare('DELETE FROM issued_token WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM deployment_credential WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM bootstrap_credential WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM agent_diagnostic WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM agent_client WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM agent_instance WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM certificate WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM agent_team_member WHERE agent_id = ?').run(agent.id);
    const breakers = db.prepare('SELECT id, matched FROM circuit_breaker').all() as { id: string; matched: string }[];
    for (const breaker of breakers) {
      const matched = JSON.parse(breaker.matched) as string[];
      if (!Array.isArray(matched) || !matched.every((id) => typeof id === 'string')) throw new TypeError(`Invalid matched agent list for circuit breaker ${breaker.id}`);
      db.prepare('UPDATE circuit_breaker SET matched = ? WHERE id = ?').run(JSON.stringify(matched.filter((id) => id !== agent.id)), breaker.id);
    }
    for (const identifier of [agent.id, ...lifecycles, ...requests]) {
      db.prepare('DELETE FROM notification WHERE instr(link, ?) > 0').run(identifier);
      db.prepare('DELETE FROM connector_outbox WHERE instr(object_key, ?) > 0 OR instr(payload, ?) > 0').run(identifier, identifier);
      db.prepare('DELETE FROM connector_mapping WHERE instr(object_key, ?) > 0').run(identifier);
      cached.run(identifier, identifier);
    }
    db.prepare('DELETE FROM hitl_grant WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM approval_decision WHERE request_id IN (SELECT id FROM approval_request WHERE agent_id = ?)').run(agent.id);
    db.prepare('DELETE FROM approval_request WHERE agent_id = ?').run(agent.id);
    for (const table of ['stage_record', 'classification', 'assessment', 'gap', 'test_run']) db.prepare(`DELETE FROM ${table} WHERE lifecycle_id IN (SELECT id FROM lifecycle WHERE agent_id = ?)`).run(agent.id);
    db.prepare('DELETE FROM lifecycle WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM attestation WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM discovered_asset WHERE agent_id = ?').run(agent.id);
    db.prepare('DELETE FROM control_result WHERE scope = ?').run(`agent:${agent.id}`);
    db.prepare('DELETE FROM agent WHERE id = ?').run(agent.id);
    eraseEvidenceFiles(result.days);
    eraseDeploymentArtifacts(agent.id);
    return result;
    });
  } catch (error) {
    if (error instanceof PolicyError) throw error;
    throw new PolicyError('ERASURE_FAILED', `The agent is stopped, but permanent data erasure did not complete: ${error instanceof Error ? error.message : String(error)}. Resolve this error and retry deletion.`, 500);
  }
  forgetAgent(agent.id);
  hub.publish('bundle', { reason: 'agent.erased' });
  const checkpoint = db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get() as { busy: number };
  if (checkpoint.busy) throw new PolicyError('ERASURE_CHECKPOINT', 'Agent data was removed, but a database reader is preventing WAL cleanup. Close external SQLite connections and run PRAGMA wal_checkpoint(TRUNCATE) before treating disk cleanup as complete.', 503);
  return { deleted: true, erased_records: erased.records };
}

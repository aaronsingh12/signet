import { db, tx } from './db';
import { PolicyError, forbidden, invalid } from './errors';
import { getAgent } from './registry';
import { applyLadder, agentLevel } from './enforcement';
import * as hub from './hub';
import { forgetAgent } from './live';
import type { Principal } from './rbac';
import { eraseAgentLedger } from './erasure-ledger';
import { GATEWAY_STALE_MS, eraseAgent as eraseAgentCounters } from './counters';
import { eraseDeploymentArtifacts, eraseEvidenceFiles } from './erasure-files';

function assertAdministrator(actor: Principal): void {
  if (actor.kind !== 'human' || !actor.permissions.includes('agents.delete')) throw forbidden('RBAC', 'Permanent agent deletion requires a human workspace administrator with agents.delete permission');
}

export async function agentRemovalPreview(agentRef: string, actor: Principal): Promise<{ id: string; name: string; handle: string; certificates: number; deployments: number; credentials: number; records: number }> {
  assertAdministrator(actor);
  const agent = (await getAgent(agentRef));
  const count = async (sql: string): Promise<number> => ((await db.prepare(sql).get(agent.id)) as { count: number }).count;
  return {
    id: agent.id, name: agent.name, handle: agent.handle,
    certificates: (await count('SELECT COUNT(*) AS count FROM certificate WHERE agent_id = ?')),
    deployments: (await count('SELECT COUNT(*) AS count FROM agent_instance WHERE agent_id = ?')),
    credentials: (await count('SELECT COUNT(*) AS count FROM deployment_credential WHERE agent_id = ?')) + (await count('SELECT COUNT(*) AS count FROM bootstrap_credential WHERE agent_id = ?')),
    records: (await count('SELECT COUNT(*) AS count FROM ledger_record WHERE agent_id = ?')),
  };
}

/** Clear Gateway state for runtime identities; unprovisioned proposals have no Gateway state to erase. */
async function gatewaysForErasure(agentId: string): Promise<string[]> {
  const runtime = await db.prepare(`
    SELECT 1 AS present FROM certificate WHERE agent_id = ?
    UNION ALL SELECT 1 FROM agent_instance WHERE agent_id = ?
    UNION ALL SELECT 1 FROM issued_token WHERE agent_id = ?
    UNION ALL SELECT 1 FROM ledger_record WHERE agent_id = ? AND kind = 'transaction'
      AND jsonb_extract_path_text(data::jsonb, 'action_type') IN ('llm_call', 'tool_call')
    LIMIT 1
  `).get(agentId, agentId, agentId, agentId);
  if (!runtime) return [];
  // Only gateways seen recently can hold agent state; containers from earlier deploys are gone.
  return ((await db.prepare('SELECT id FROM gateway_node WHERE last_seen >= ?').all(new Date(Date.now() - GATEWAY_STALE_MS).toISOString())) as { id: string }[]).map((node) => node.id);
}

/** Explicit administrator erasure: stop execution, clear applicable gateways, erase owned data and retain anonymous signed chain commitments. */
export async function removeAgent(agentRef: string, confirmation: string, actor: Principal): Promise<{ deleted: true; erased_records: number }> {
  assertAdministrator(actor);
  const agent = (await getAgent(agentRef));
  if (confirmation !== agent.handle) throw invalid(`Type the exact agent handle ${agent.handle} to permanently delete this agent and its data`);
  const nodes = await gatewaysForErasure(agent.id);
  const unavailable = nodes.filter((node) => !hub.connectedNodes().includes(node));
  if (unavailable.length) throw new PolicyError('ERASURE_GATEWAY', `Deletion was not started. Reconnect registered gateways ${unavailable.join(', ')} so their agent data can be cleared, then retry.`, 503);
  if ((await agentLevel(agent.id)) !== 'killed') (await applyLadder({ agentId: agent.id }, 'kill', { actor: actor.id, reason: 'Administrator requested permanent agent and data erasure' }));
  const tokens = ((await db.prepare('SELECT jti FROM issued_token WHERE agent_id = ?').all(agent.id)) as { jti: string }[]).map((row) => row.jti);
  const instances = ((await db.prepare('SELECT id FROM agent_instance WHERE agent_id = ?').all(agent.id)) as { id: string }[]).map((row) => row.id);
  const certificates = ((await db.prepare('SELECT id FROM certificate WHERE agent_id = ?').all(agent.id)) as { id: string }[]).map((row) => row.id);
  const sessions = ((await db.prepare("SELECT DISTINCT jsonb_extract_path_text(data::jsonb, 'session_id') AS id FROM ledger_record WHERE agent_id = ? AND jsonb_typeof(data::jsonb -> 'session_id') = 'string'").all(agent.id)) as { id: string }[]).map((row) => row.id);
  await hub.eraseAgentOnGateways(agent.id, [...new Set([...sessions, ...tokens])], instances, tokens, nodes);
  let erased: { records: number; days: string[] };
  try {
    erased = (await tx(async () => {
    const lifecycles = ((await db.prepare('SELECT id FROM lifecycle WHERE agent_id = ?').all(agent.id)) as { id: string }[]).map((row) => row.id);
    const requests = ((await db.prepare('SELECT id FROM approval_request WHERE agent_id = ?').all(agent.id)) as { id: string }[]).map((row) => row.id);
    const result = (await eraseAgentLedger(agent.id, [agent.id, agent.handle, ...certificates, ...instances, ...tokens, ...lifecycles, ...requests]));
    const cached = db.prepare('DELETE FROM idempotency_key WHERE strpos(body, ?) > 0 OR strpos(path, ?) > 0');
    for (const identifier of [agent.id, ...certificates, ...instances, ...tokens]) (await cached.run(identifier, identifier));
    const byHandle = `/api/v1/agents/${agent.handle}`;
    (await db.prepare('DELETE FROM idempotency_key WHERE path = ? OR path LIKE ?').run(byHandle, `${byHandle}/%`));
    (await db.prepare('DELETE FROM kill_ack WHERE event_id IN (SELECT id FROM enforcement_event WHERE agent_id = ?)').run(agent.id));
    (await db.prepare('DELETE FROM enforcement_event WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM enforcement_state WHERE agent_id = ?').run(agent.id));
    await eraseAgentCounters(agent.id);
    (await db.prepare('DELETE FROM revoked_jti WHERE jti IN (SELECT jti FROM issued_token WHERE agent_id = ?)').run(agent.id));
    (await db.prepare('DELETE FROM issued_token WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM deployment_credential WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM bootstrap_credential WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM agent_diagnostic WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM agent_client WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM agent_instance WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM certificate WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM agent_team_member WHERE agent_id = ?').run(agent.id));
    const breakers = (await db.prepare('SELECT id, matched FROM circuit_breaker').all()) as { id: string; matched: string }[];
    for (const breaker of breakers) {
      const matched = JSON.parse(breaker.matched) as string[];
      if (!Array.isArray(matched) || !matched.every((id) => typeof id === 'string')) throw new TypeError(`Invalid matched agent list for circuit breaker ${breaker.id}`);
      (await db.prepare('UPDATE circuit_breaker SET matched = ? WHERE id = ?').run(JSON.stringify(matched.filter((id) => id !== agent.id)), breaker.id));
    }
    for (const identifier of [agent.id, ...lifecycles, ...requests]) {
      (await db.prepare('DELETE FROM notification WHERE strpos(link, ?) > 0').run(identifier));
      (await db.prepare('DELETE FROM connector_outbox WHERE strpos(object_key, ?) > 0 OR strpos(payload, ?) > 0').run(identifier, identifier));
      (await db.prepare('DELETE FROM connector_mapping WHERE strpos(object_key, ?) > 0').run(identifier));
      (await cached.run(identifier, identifier));
    }
    (await db.prepare('DELETE FROM hitl_grant WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM approval_decision WHERE request_id IN (SELECT id FROM approval_request WHERE agent_id = ?)').run(agent.id));
    (await db.prepare('DELETE FROM approval_request WHERE agent_id = ?').run(agent.id));
    for (const table of ['stage_record', 'classification', 'assessment', 'gap', 'test_run']) (await db.prepare(`DELETE FROM ${table} WHERE lifecycle_id IN (SELECT id FROM lifecycle WHERE agent_id = ?)`).run(agent.id));
    (await db.prepare('DELETE FROM lifecycle WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM attestation WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM discovered_asset WHERE agent_id = ?').run(agent.id));
    (await db.prepare('DELETE FROM control_result WHERE scope = ?').run(`agent:${agent.id}`));
    (await db.prepare('DELETE FROM external_observation WHERE (connection_id, external_agent_id) IN (SELECT connection_id, external_id FROM external_agent_mapping WHERE agent_id = ?)').run(agent.id));
    const connectionSecrets = (await db.prepare('SELECT secret_id FROM external_connection WHERE agent_id = ?').all(agent.id)) as { secret_id: string }[];
    (await db.prepare('DELETE FROM external_connection WHERE agent_id = ?').run(agent.id));
    for (const secret of connectionSecrets) (await db.prepare('DELETE FROM secret WHERE id = ?').run(secret.secret_id));
    (await db.prepare('DELETE FROM agent WHERE id = ?').run(agent.id));
    (await eraseEvidenceFiles(result.days));
    eraseDeploymentArtifacts(agent.id);
    return result;
    }));
  } catch (error) {
    if (error instanceof PolicyError) throw error;
    throw new PolicyError('ERASURE_FAILED', `The agent is stopped, but permanent data erasure did not complete: ${error instanceof Error ? error.message : String(error)}. Resolve this error and retry deletion.`, 500);
  }
  forgetAgent(agent.id);
  hub.publish('bundle', { reason: 'agent.erased' });
  return { deleted: true, erased_records: erased.records };
}

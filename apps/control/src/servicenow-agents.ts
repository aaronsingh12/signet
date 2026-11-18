import { sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, invalid } from './errors';
import { registerAgent, getAgent } from './registry';
import type { Principal } from './rbac';
import { serviceNowSettings } from './servicenow-mcp-settings';
import { status } from './connectivity';
import { tenant } from './tenant';
import * as workflow from './workflow';
import { serviceNowConfiguration } from './servicenow-mcp-settings';
import { serviceNowAccessToken } from './servicenow-gateway';
import { readJson } from './external-http';
import { object } from './external-contract';
import type { Json } from './external-contract';

export interface AvailableServiceNowAgent { id: string; name: string; description: string }

/** Reads the documented AI agent table using the authorized user's ServiceNow ACLs. */
export async function availableServiceNowAgents(connectionId: string): Promise<AvailableServiceNowAgent[]> {
  const config = await serviceNowConfiguration(connectionId);
  const token = await serviceNowAccessToken(connectionId);
  const agents: AvailableServiceNowAgent[] = [];
  for (let offset = 0; offset <= 1000; offset += 100) {
    const url = new URL('/api/now/table/sn_aia_agent', config.instance);
    url.search = new URLSearchParams({ sysparm_fields: 'sys_id,name,description', sysparm_limit: '100', sysparm_offset: String(offset), sysparm_query: 'active=true^ORDERBYsys_id' }).toString();
    let data: Json;
    try { data = await readJson({ url, method: 'GET', headers: { authorization: `Bearer ${token}`, accept: 'application/json' }, body: null, timeout: 15000 }); }
    catch (error) {
      if (error instanceof PolicyError && error.extra.upstream_status === 403) throw new PolicyError('SERVICENOW_PERMISSIONS', 'ServiceNow denied GET /api/now/table/sn_aia_agent (HTTP 403). Check the authorized user\'s read ACLs for the AI agent table and selected fields, and the OAuth integration\'s API access policies. MCP tool access does not grant Table API access. Correct those permissions, then retry Load agents from ServiceNow', 403);
      throw error;
    }
    const response = object(data, 'ServiceNow AI agents response');
    if (!Array.isArray(response.result)) throw new PolicyError('SERVICENOW_SCHEMA', 'ServiceNow AI agent table response is missing its result array; verify Table API permissions', 502);
    if (agents.length + response.result.length > 1000) throw new PolicyError('SERVICENOW_SCHEMA', 'ServiceNow returned more than 1000 active agents; link the required agent by its sys_id', 502);
    for (const value of response.result) {
      const row = object(value, 'ServiceNow AI agent');
      if (typeof row.sys_id !== 'string' || !/^[a-f0-9]{32}$/i.test(row.sys_id) || typeof row.name !== 'string' || !row.name.trim() || (row.description !== undefined && typeof row.description !== 'string')) throw new PolicyError('SERVICENOW_SCHEMA', 'ServiceNow agent records require a valid sys_id and readable name/description fields; verify field ACLs', 502);
      agents.push({ id: row.sys_id, name: row.name, description: typeof row.description === 'string' ? row.description : '' });
    }
    if (response.result.length < 100) return agents;
  }
  throw new PolicyError('SERVICENOW_SCHEMA', 'ServiceNow agent pagination exceeded its 1000-record limit', 502);
}

export interface LinkedServiceNowAgent {
  agent_id: string; external_id: string; name: string; handle: string; purpose: string;
  connection_id: string; monitoring: boolean; last_sync_at: string | null; gateway_enforcement: boolean;
}

/** Links a user-selected ServiceNow identity without claiming discovery, execution access or runtime approval. */
export async function linkServiceNowAgent(connectionId: string, input: { external_id: string; name: string; purpose: string }, actor: Principal): Promise<{ agent_id: string }> {
  if (!actor.permissions.includes('agents.write')) throw new PolicyError('RBAC', 'Linking a ServiceNow agent requires agents.write', 403);
  const settings = await serviceNowSettings(connectionId);
  if (!settings) throw new PolicyError('SERVICENOW_CONFIG', 'ServiceNow connection was not found in this tenant', 404);
  if (typeof input.external_id !== 'string' || !/^[a-f0-9]{32}$/i.test(input.external_id.trim())) throw invalid('Enter the ServiceNow AI agent sys_id: exactly 32 hexadecimal characters');
  if (typeof input.name !== 'string' || !input.name.trim() || input.name.length > 200) throw invalid('Agent name is required and must not exceed 200 characters');
  if (typeof input.purpose !== 'string' || input.purpose.trim().length < 10 || input.purpose.length > 4000) throw invalid('Agent purpose must contain 10–4000 characters');
  const externalId = input.external_id.trim().toLowerCase();
  return tx(async () => {
    await db.prepare('SELECT id FROM servicenow_mcp_account WHERE id = ? AND tenant_id = ? FOR UPDATE').get(connectionId, tenant.id);
    const prior = await db.prepare(`SELECT id AS agent_id FROM agent WHERE tenant_id = ? AND vendor = 'ServiceNow'
      AND jsonb_extract_path_text(vendor_details::jsonb, 'instance_url') = ?
      AND jsonb_extract_path_text(vendor_details::jsonb, 'external_agent_id') = ? LIMIT 1`).get(tenant.id, settings.instance_url, externalId) as { agent_id: string } | undefined;
    const agent = prior ? await getAgent(prior.agent_id) : await registerAgent({
      handle: `servicenow-${sha256(`${settings.instance_url}:${externalId}`).slice(0, 24)}`,
      name: input.name.trim(), purpose: input.purpose.trim(), sponsor: actor.id, owner: actor.id,
      autonomy_level: 'L0', kind: 'third_party', vendor: 'ServiceNow', connection_method: 'oauth',
      vendor_details: { instance_url: settings.instance_url, external_agent_id: externalId },
    }, actor);
    if (!prior) await workflow.start(agent, {}, actor, 'initial', null);
    await db.prepare('INSERT INTO servicenow_agent_link (connection_id, agent_id, external_id, tenant_id, instance_url, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (connection_id, external_id) DO NOTHING')
      .run(connectionId, agent.id, externalId, tenant.id, settings.instance_url, nowIso());
    return { agent_id: agent.id };
  });
}

/** Computes coverage from verified source syncs and gateway evidence instead of the MCP authorization flag. */
export async function linkedServiceNowAgents(connectionId: string): Promise<LinkedServiceNowAgent[]> {
  if (!await serviceNowSettings(connectionId)) throw new PolicyError('SERVICENOW_CONFIG', 'ServiceNow connection was not found in this tenant', 404);
  const rows = await db.prepare(`SELECT l.agent_id, l.external_id, l.connection_id, a.name, a.handle, a.purpose
    FROM servicenow_agent_link l JOIN agent a ON a.id = l.agent_id WHERE l.tenant_id = ? AND a.tenant_id = ? AND l.connection_id = ? ORDER BY a.name`)
    .all(tenant.id, tenant.id, connectionId) as { agent_id: string; external_id: string; connection_id: string; name: string; handle: string; purpose: string }[];
  return Promise.all(rows.map(async row => ({ ...row, ...await serviceNowAgentCoverage(row.agent_id) })));
}

export async function serviceNowAgentCoverage(agentId: string): Promise<{ monitoring: boolean; last_sync_at: string | null; gateway_enforcement: boolean }> {
    const sources = await db.prepare(`SELECT c.health FROM external_connection c
      JOIN external_agent_mapping m ON m.connection_id = c.id
      WHERE c.tenant_id = ? AND m.agent_id = ? AND c.state = 'enabled'`).all(tenant.id, agentId) as { health: string }[];
    const health = sources.map(source => JSON.parse(source.health) as { monitoring: boolean; last_sync_at: string | null });
    const connection = await status(agentId);
    return { monitoring: health.some(source => source.monitoring && source.last_sync_at !== null),
      last_sync_at: health.map(source => source.last_sync_at).filter((value): value is string => value !== null).sort().at(-1) ?? null,
      gateway_enforcement: connection.gateway_enforcement_active };
}

export async function serviceNowLinksForAgent(agentId: string): Promise<LinkedServiceNowAgent[]> {
  const agent = await getAgent(agentId);
  const rows = await db.prepare('SELECT connection_id FROM servicenow_agent_link WHERE tenant_id = ? AND agent_id = ?').all(tenant.id, agent.id) as { connection_id: string }[];
  const linked = await Promise.all(rows.map(row => linkedServiceNowAgents(row.connection_id)));
  return linked.flat().filter(row => row.agent_id === agent.id);
}

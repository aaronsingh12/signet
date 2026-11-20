import { newId, sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, invalid, notFound } from './errors';
import * as ledger from './ledger';
import * as platforms from './platforms';
import { DRIVERS, copilotBot, copilotBots, copilotEnvironment, type CopilotBot } from './platform-drivers';
import type { Principal } from './rbac';
import { getAgent, registerAgent } from './registry';
import { revealPlatformCredential } from './secrets';
import { status } from './connectivity';
import { tenant } from './tenant';
import * as workflow from './workflow';

// Microsoft Copilot Studio agents. An admin connects a Dataverse environment once (an Entra app
// registration added there as an application user). Signet lists the environment's agents and links
// a chosen one as a vendor-hosted agent; review, approval, seal and gateway credentials then follow the
// normal lifecycle. Linking registers identity only: it never creates or changes the agent in Microsoft.

export const COPILOT_VENDOR = 'Microsoft Copilot Studio';
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface CopilotConnectionRow { id: string; label: string; secret_id: string; status: string; status_detail: string | null; created_at: string }

export interface CopilotConnectionView {
  id: string; label: string; environment_url: string; status: string; status_detail: string | null; created_at: string; linked_agents: number;
}

export interface LinkedCopilotAgent {
  agent_id: string; bot_id: string; connection_id: string; name: string; handle: string; purpose: string; gateway_enforcement: boolean;
}

async function connectionRow(id: string): Promise<CopilotConnectionRow & { secret: string }> {
  const row = await db.prepare("SELECT id, label, secret_id, status, status_detail, created_at FROM platform_connection WHERE tenant_id = ? AND id = ? AND platform = 'copilot' AND revoked_at IS NULL").get(tenant.id, id) as CopilotConnectionRow | undefined;
  if (!row) throw notFound(`Copilot Studio connection ${id}`);
  return { ...row, secret: await revealPlatformCredential(row.secret_id) };
}

async function view(row: CopilotConnectionRow & { secret: string }): Promise<CopilotConnectionView> {
  const linked = await db.prepare('SELECT COUNT(*) AS n FROM platform_link WHERE tenant_id = ? AND connection_id = ?').get(tenant.id, row.id) as { n: number };
  return { id: row.id, label: row.label, environment_url: copilotEnvironment(row.secret), status: row.status, status_detail: row.status_detail, created_at: row.created_at, linked_agents: Number(linked.n) };
}

export async function listCopilotConnections(): Promise<CopilotConnectionView[]> {
  const rows = await db.prepare("SELECT id FROM platform_connection WHERE tenant_id = ? AND platform = 'copilot' AND revoked_at IS NULL ORDER BY created_at DESC").all(tenant.id) as { id: string }[];
  return Promise.all(rows.map(async (row) => view(await connectionRow(row.id))));
}

export async function copilotConnection(id: string): Promise<CopilotConnectionView> {
  return view(await connectionRow(id));
}

/** Proves the app registration can sign in and read the environment before anything is stored. */
export async function createCopilotConnection(input: platforms.CreateInput, actor: Principal): Promise<CopilotConnectionView> {
  const created = await platforms.create({ ...input, platform: 'copilot' }, actor);
  return copilotConnection(created.id);
}

/** Signs in to Microsoft again with the stored credentials and records the result. */
export async function testCopilotConnection(id: string, actor: Principal): Promise<CopilotConnectionView> {
  const row = await connectionRow(id);
  let state = 'connected';
  let detail: string;
  try { detail = await DRIVERS.copilot.validate(row.secret, {}); }
  catch (error) {
    if (!(error instanceof PolicyError)) throw error;
    state = 'error';
    detail = error.message;
  }
  await db.prepare('UPDATE platform_connection SET status = ?, status_detail = ? WHERE tenant_id = ? AND id = ?').run(state, detail, tenant.id, id);
  await ledger.append({ kind: 'admin', data: { event: 'copilot.connection_tested', connection_id: id, status: state, actor: actor.id } });
  return copilotConnection(id);
}

export async function removeCopilotConnection(id: string, actor: Principal): Promise<{ disconnected: true }> {
  await connectionRow(id);
  await platforms.remove(id, actor);
  return { disconnected: true };
}

/** Reads the environment's agents with the application user's Dataverse permissions. */
export async function availableCopilotAgents(id: string): Promise<CopilotBot[]> {
  const row = await connectionRow(id);
  try { return await copilotBots(row.secret); }
  catch (error) {
    if (error instanceof PolicyError && error.rule === 'PLATFORM_AUTH') throw new PolicyError('COPILOT_PERMISSIONS', `Microsoft refused to list Copilot Studio agents (${error.message}). Check that the app registration is an application user in this environment with a security role that can read the Copilot (bot) table, then retry Load agents`, 403);
    throw error;
  }
}

/** Links one existing Copilot Studio agent as a vendor-hosted agent; it is never created or changed in Microsoft. */
export async function linkCopilotAgent(connectionId: string, input: { bot_id?: unknown; name?: unknown; purpose?: unknown }, actor: Principal): Promise<{ agent_id: string }> {
  if (!actor.permissions.includes('agents.write')) throw new PolicyError('RBAC', 'Linking a Copilot Studio agent requires agents.write', 403);
  if (typeof input.bot_id !== 'string' || !GUID.test(input.bot_id.trim())) throw invalid('Enter the Copilot Studio agent ID: a GUID such as 1a2b3c4d-1234-5678-9abc-1234567890ab');
  if (typeof input.name !== 'string' || !input.name.trim() || input.name.length > 200) throw invalid('Agent name is required and must not exceed 200 characters');
  if (typeof input.purpose !== 'string' || input.purpose.trim().length < 10 || input.purpose.length > 4000) throw invalid('Agent purpose must contain 10–4000 characters');
  const botId = input.bot_id.trim().toLowerCase();
  const name = input.name.trim();
  const purpose = input.purpose.trim();
  const row = await connectionRow(connectionId);
  const environment = copilotEnvironment(row.secret);
  // The agent must exist in this environment: a typo must not register an identity nobody can govern.
  const bot = await copilotBot(row.secret, botId);
  if (!bot) throw new PolicyError('COPILOT_AGENT_NOT_FOUND', `No Copilot Studio agent ${botId} exists in ${environment}. Open the agent in Copilot Studio and copy the ID after /agents/ in the browser address, or use Load agents`, 404);
  const workloadId = `copilot:${botId}`;
  return tx(async () => {
    await db.prepare('SELECT id FROM platform_connection WHERE tenant_id = ? AND id = ? FOR UPDATE').get(tenant.id, connectionId);
    const viaLink = await db.prepare('SELECT agent_id FROM platform_link WHERE tenant_id = ? AND connection_id = ? AND workload_id = ?').get(tenant.id, connectionId, workloadId) as { agent_id: string } | undefined;
    const viaVendor = viaLink ? undefined : await db.prepare(`SELECT id AS agent_id FROM agent WHERE tenant_id = ? AND vendor = ?
      AND jsonb_extract_path_text(vendor_details::jsonb, 'environment_url') = ?
      AND jsonb_extract_path_text(vendor_details::jsonb, 'bot_id') = ? LIMIT 1`).get(tenant.id, COPILOT_VENDOR, environment, botId) as { agent_id: string } | undefined;
    const prior = viaLink ?? viaVendor;
    const agent = prior ? await getAgent(prior.agent_id) : await registerAgent({
      handle: `copilot-${sha256(`${environment}:${botId}`).slice(0, 24)}`,
      name, purpose, sponsor: actor.id, owner: actor.id,
      autonomy_level: 'L0', kind: 'third_party', vendor: COPILOT_VENDOR, connection_method: 'oauth',
      vendor_details: { environment_url: environment, bot_id: botId, ...(bot.schema_name ? { schema_name: bot.schema_name } : {}) },
    }, actor);
    if (!prior) await workflow.start(agent, {}, actor, 'initial', null);
    const now = nowIso();
    const inserted = await db.prepare('INSERT INTO platform_link (id, tenant_id, connection_id, workload_id, workload_name, agent_id, settings, state, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (connection_id, workload_id) DO NOTHING')
      .run(newId('pll'), tenant.id, connectionId, workloadId, bot.name, agent.id, '{}', 'registered', actor.id, now, now);
    if (inserted.changes) await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'copilot.agent_linked', connection_id: connectionId, environment_url: environment, bot_id: botId, bot_name: bot.name, actor: actor.id } });
    return { agent_id: agent.id };
  });
}

/** Linked agents with gateway coverage taken from real gateway evidence, not from the link itself. */
export async function linkedCopilotAgents(connectionId: string): Promise<LinkedCopilotAgent[]> {
  await connectionRow(connectionId);
  const rows = await db.prepare(`SELECT l.agent_id, l.workload_id, l.connection_id, a.name, a.handle, a.purpose
    FROM platform_link l JOIN agent a ON a.id = l.agent_id WHERE l.tenant_id = ? AND a.tenant_id = ? AND l.connection_id = ? ORDER BY a.name`)
    .all(tenant.id, tenant.id, connectionId) as { agent_id: string; workload_id: string; connection_id: string; name: string; handle: string; purpose: string }[];
  return Promise.all(rows.map(async (row) => ({
    agent_id: row.agent_id, bot_id: row.workload_id.replace(/^copilot:/, ''), connection_id: row.connection_id,
    name: row.name, handle: row.handle, purpose: row.purpose,
    gateway_enforcement: (await status(row.agent_id)).gateway_enforcement_active,
  })));
}

import { newId } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError } from './errors';
import { putSecret, revealPlatformCredential, rotateSecret } from './secrets';
import type { Principal } from './rbac';
import { tenant } from './tenant';

export interface ServiceNowSettingsInput {
  name: string;
  gateway_url: string;
  instance_url: string;
  mcp_url: string;
  client_id: string;
  client_secret: string;
}

export interface SettingsRow {
  id: string;
  name: string;
  gateway_url: string;
  instance_url: string;
  mcp_url: string;
  client_id: string;
  client_secret_id: string;
}

export interface ServiceNowSettingsView {
  id: string;
  name: string;
  gateway_url: string;
  instance_url: string;
  mcp_url: string;
  client_id: string;
  has_client_secret: boolean;
  callback_url: string;
}

function httpsUrl(value: string, field: string): URL {
  if (typeof value !== 'string' || !value.trim()) throw new PolicyError('SERVICENOW_CONFIG', `${field} is required`, 400);
  let url: URL;
  try { url = new URL(value.trim()); } catch { throw new PolicyError('SERVICENOW_CONFIG', `${field} must be an absolute HTTPS URL`, 400); }
  if (url.protocol !== 'https:' || url.port || url.username || url.password || url.search || url.hash) throw new PolicyError('SERVICENOW_CONFIG', `${field} must use HTTPS without a custom port, credentials, query or fragment`, 400);
  return url;
}

function settingsView(row: SettingsRow): ServiceNowSettingsView {
  return { id: row.id, name: row.name, gateway_url: row.gateway_url, instance_url: row.instance_url, mcp_url: row.mcp_url, client_id: row.client_id,
    has_client_secret: true, callback_url: `${row.gateway_url}/api/v1/plugins/servicenow/callback` };
}

async function settingsRow(id: string): Promise<SettingsRow | undefined> {
  return await db.prepare('SELECT id, name, gateway_url, instance_url, mcp_url, client_id, client_secret_id FROM servicenow_mcp_account WHERE tenant_id = ? AND id = ?').get(tenant.id, id) as SettingsRow | undefined;
}

/** Returns saved configuration without exposing the client secret or its broker identifier. */
export async function serviceNowSettings(id: string): Promise<ServiceNowSettingsView | null> {
  const row = await settingsRow(id);
  return row ? settingsView(row) : null;
}

/** All ServiceNow OAuth settings come from tenant-scoped MongoDB, never environment variables. */
export async function serviceNowConfiguration(id: string): Promise<{ instance: string; endpoint: string; clientId: string; clientSecret: string; redirectUri: string }> {
  const row = await settingsRow(id);
  if (!row) throw new PolicyError('SERVICENOW_CONFIG', 'Open Add ServiceNow AI Agents and save your connection settings before authorizing', 409);
  return { instance: row.instance_url, endpoint: row.mcp_url, clientId: row.client_id,
    clientSecret: await revealPlatformCredential(row.client_secret_id), redirectUri: settingsView(row).callback_url };
}

export function validatedSettings(input: ServiceNowSettingsInput): { gateway: URL; instance: URL; endpoint: URL } {
  if (typeof input.name !== 'string' || !input.name.trim() || input.name.trim().length > 120) throw new PolicyError('SERVICENOW_CONFIG', 'Connection name is required and must not exceed 120 characters', 400);
  const gateway = httpsUrl(input.gateway_url, 'Public Signet URL');
  const instance = httpsUrl(input.instance_url, 'ServiceNow instance URL');
  const endpoint = httpsUrl(input.mcp_url, 'ServiceNow MCP server URL');
  if (gateway.pathname !== '/') throw new PolicyError('SERVICENOW_CONFIG', 'Public Signet URL must be an origin without a path', 400);
  if (!instance.hostname.endsWith('.service-now.com') || instance.pathname !== '/') throw new PolicyError('SERVICENOW_CONFIG', 'ServiceNow instance URL must be a service-now.com origin without a path', 400);
  if (endpoint.origin !== instance.origin || !endpoint.pathname.startsWith('/sncapps/mcp-server/mcp/') || endpoint.pathname === '/sncapps/mcp-server/mcp/') throw new PolicyError('SERVICENOW_CONFIG', 'MCP server URL must identify a server under /sncapps/mcp-server/mcp/ on the configured instance', 400);
  if (typeof input.client_id !== 'string' || !input.client_id.trim() || input.client_id.length > 256) throw new PolicyError('SERVICENOW_CONFIG', 'OAuth Client ID is required and must not exceed 256 characters', 400);
  if (typeof input.client_secret !== 'string' || input.client_secret.length > 4096 || (input.client_secret && input.client_secret.length < 8)) throw new PolicyError('SERVICENOW_CONFIG', 'OAuth Client Secret must contain 8–4096 characters; leave it empty only to keep an existing secret', 400);
  return { gateway, instance, endpoint };
}

/** Creates a separate connection and encrypted credential for every saved form. */
export async function createServiceNowSettings(input: ServiceNowSettingsInput, actor: Principal): Promise<ServiceNowSettingsView> {
  const { gateway, instance, endpoint } = validatedSettings(input);
  if (!input.client_secret) throw new PolicyError('SERVICENOW_CONFIG', 'OAuth Client Secret is required for a new connection', 400);
  const id = newId('evt').replace('evt_', 'con_');
  return tx(async () => {
    const secret = await putSecret({ name: 'servicenow-client-' + id.slice(-20).toLowerCase(), kind: 'platform', value: input.client_secret }, actor);
    await db.prepare('INSERT INTO servicenow_mcp_account (id, name, tenant_id, gateway_url, instance_url, mcp_url, client_id, client_secret_id, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, input.name.trim(), tenant.id, gateway.origin, instance.origin, endpoint.href, input.client_id.trim(), secret.id, actor.id, nowIso());
    return settingsView({ id, name: input.name.trim(), gateway_url: gateway.origin, instance_url: instance.origin, mcp_url: endpoint.href, client_id: input.client_id.trim(), client_secret_id: secret.id });
  });
}

/** Updates only the selected tenant connection and keeps its encrypted secret when the field is blank. */
export async function updateServiceNowSettings(id: string, input: ServiceNowSettingsInput, actor: Principal): Promise<ServiceNowSettingsView> {
  const { gateway, instance, endpoint } = validatedSettings(input);
  return tx(async () => {
    const existing = await settingsRow(id);
    if (!existing) throw new PolicyError('SERVICENOW_CONFIG', 'ServiceNow connection was not found in this tenant', 404);
    if (input.client_secret) await rotateSecret(existing.client_secret_id, input.client_secret, actor);
    const changed = existing.gateway_url !== gateway.origin || existing.instance_url !== instance.origin || existing.mcp_url !== endpoint.href || existing.client_id !== input.client_id.trim() || Boolean(input.client_secret);
    await db.prepare('UPDATE servicenow_mcp_account SET name = ?, gateway_url = ?, instance_url = ?, mcp_url = ?, client_id = ?, updated_by = ?, updated_at = ? WHERE tenant_id = ? AND id = ?')
      .run(input.name.trim(), gateway.origin, instance.origin, endpoint.href, input.client_id.trim(), actor.id, nowIso(), tenant.id, id);
    await db.prepare('DELETE FROM servicenow_mcp_oauth_state WHERE tenant_id = ? AND connection_id = ?').run(tenant.id, id);
    if (changed) await db.prepare('UPDATE servicenow_mcp_account SET expires_at = 0, tools_json = NULL, discovered_at = NULL WHERE tenant_id = ? AND id = ?').run(tenant.id, id);
    if (changed) {
      const route = await db.prepare('DELETE FROM servicenow_gateway_route WHERE connection_id = ? RETURNING alias, secret_id').get(id) as { alias: string; secret_id: string } | undefined;
      if (route) {
        await db.prepare('DELETE FROM tool WHERE tenant_id = ? AND alias = ?').run(tenant.id, route.alias);
        await db.prepare('DELETE FROM secret WHERE tenant_id = ? AND id = ?').run(tenant.id, route.secret_id);
      }
    }
    return settingsView({ id, name: input.name.trim(), gateway_url: gateway.origin, instance_url: instance.origin, mcp_url: endpoint.href, client_id: input.client_id.trim(), client_secret_id: existing.client_secret_id });
  });
}

/** Erases one tenant connection, its pending consent, legacy migration copies and encrypted credentials atomically. */
export async function removeServiceNowConnection(id: string): Promise<{ removed: true }> {
  return tx(async () => {
    const account = await db.prepare('SELECT client_secret_id, token_secret_id FROM servicenow_mcp_account WHERE tenant_id = ? AND id = ? FOR UPDATE')
      .get(tenant.id, id) as { client_secret_id: string; token_secret_id: string | null } | undefined;
    if (!account) throw new PolicyError('SERVICENOW_CONFIG', 'ServiceNow connection was not found in this tenant', 404);
    const secretIds = new Set<string>([account.client_secret_id]);
    if (account.token_secret_id) secretIds.add(account.token_secret_id);
    const sources = await db.prepare(`DELETE FROM external_connection WHERE tenant_id = ? AND agent_id IN (
      SELECT l.agent_id FROM servicenow_agent_link l WHERE l.connection_id = ? AND l.tenant_id = ?
      AND NOT EXISTS (SELECT 1 FROM servicenow_agent_link other WHERE other.agent_id = l.agent_id AND other.connection_id <> ?)
    ) RETURNING secret_id, webhook_secret_id`).all(tenant.id, id, tenant.id, id) as { secret_id: string; webhook_secret_id: string | null }[];
    for (const source of sources) {
      secretIds.add(source.secret_id);
      if (source.webhook_secret_id) secretIds.add(source.webhook_secret_id);
    }
    const route = await db.prepare('DELETE FROM servicenow_gateway_route WHERE connection_id = ? RETURNING alias, secret_id').get(id) as { alias: string; secret_id: string } | undefined;
    if (route) {
      await db.prepare('DELETE FROM tool WHERE tenant_id = ? AND alias = ?').run(tenant.id, route.alias);
      secretIds.add(route.secret_id);
    }
    await db.prepare('DELETE FROM servicenow_mcp_oauth_state WHERE tenant_id = ? AND connection_id = ?').run(tenant.id, id);
    await db.prepare('DELETE FROM servicenow_mcp_account WHERE tenant_id = ? AND id = ?').run(tenant.id, id);
    if (id === `snm_${tenant.id}`) {
      const legacySettings = await db.prepare('DELETE FROM servicenow_mcp_settings WHERE tenant_id = ? RETURNING client_secret_id').get(tenant.id) as { client_secret_id: string } | undefined;
      const legacyTokens = await db.prepare('DELETE FROM servicenow_mcp_connection WHERE tenant_id = ? RETURNING secret_id').get(tenant.id) as { secret_id: string } | undefined;
      if (legacySettings) secretIds.add(legacySettings.client_secret_id);
      if (legacyTokens) secretIds.add(legacyTokens.secret_id);
      await db.prepare('DELETE FROM servicenow_mcp_oauth_state WHERE tenant_id = ? AND connection_id IS NULL').run(tenant.id);
    }
    for (const secretId of secretIds) await db.prepare('DELETE FROM secret WHERE tenant_id = ? AND id = ?').run(tenant.id, secretId);
    return { removed: true };
  });
}

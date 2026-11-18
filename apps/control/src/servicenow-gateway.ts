import { db, nowIso, tx } from './db';
import { PolicyError, invalid } from './errors';
import { object, type Json } from './external-contract';
import { requestJson } from './external-http';
import { putSecret, revealPlatformCredential, rotateSecret } from './secrets';
import { registerTool } from './tools';
import { serviceNowConfiguration, serviceNowSettings } from './servicenow-mcp-settings';
import type { ServiceNowTool } from './servicenow-mcp-discovery';
import type { Principal } from './rbac';
import { tenant } from './tenant';

const SERVICE_ACTOR: Principal = { id: 'servicenow-oauth', name: 'ServiceNow OAuth', kind: 'service', roles: [], permissions: [], groups: [], mfa: false, auth: 'bearer', auth_time: null };

/** Refresh delegated ServiceNow tokens under a row lock so gateway requests never use an expired cached token. */
export async function serviceNowAccessToken(id: string): Promise<string> {
  return tx(async () => {
    const row = await db.prepare('SELECT token_secret_id, expires_at, client_id, instance_url FROM servicenow_mcp_account WHERE tenant_id = ? AND id = ? FOR UPDATE').get(tenant.id, id) as { token_secret_id: string | null; expires_at: number | null; client_id: string; instance_url: string } | undefined;
    if (!row?.token_secret_id || !row.expires_at) throw new PolicyError('SERVICENOW_AUTH', 'Authorize this ServiceNow connection before preparing or using its gateway route', 409);
    const credential = object(JSON.parse(await revealPlatformCredential(row.token_secret_id)) as Json, 'Stored ServiceNow OAuth credential');
    if (typeof credential.access_token !== 'string' || !credential.access_token || typeof credential.refresh_token !== 'string' || !credential.refresh_token) throw new PolicyError('SERVICENOW_AUTH', 'Stored ServiceNow OAuth tokens are invalid; reauthorize this connection', 409);
    if (row.expires_at > Date.now() + 90000) return credential.access_token;
    const config = await serviceNowConfiguration(id);
    const result = object(await requestJson({ url: new URL('/oauth_token.do', config.instance), method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({ grant_type: 'refresh_token', client_id: config.clientId, client_secret: config.clientSecret, refresh_token: credential.refresh_token }).toString(), timeout: 15000 }), 'ServiceNow refresh token response');
    if (typeof result.access_token !== 'string' || !result.access_token || typeof result.expires_in !== 'number' || !Number.isFinite(result.expires_in) || result.expires_in <= 90 || typeof result.token_type !== 'string' || result.token_type.toLowerCase() !== 'bearer' || (result.refresh_token !== undefined && (typeof result.refresh_token !== 'string' || !result.refresh_token))) throw new PolicyError('SERVICENOW_AUTH', 'ServiceNow refresh response requires access_token, Bearer token_type and expires_in greater than 90 seconds to cover gateway credential caching; check the token lifetime and reauthorize', 502);
    // OAuth providers can retain the current refresh token instead of returning a rotated one.
    await rotateSecret(row.token_secret_id, JSON.stringify({ access_token: result.access_token, refresh_token: result.refresh_token ?? credential.refresh_token }), SERVICE_ACTOR);
    await db.prepare('UPDATE servicenow_mcp_account SET expires_at = ?, updated_at = ? WHERE tenant_id = ? AND id = ?').run(Date.now() + result.expires_in * 1000, nowIso(), tenant.id, id);
    return result.access_token;
  });
}

export async function serviceNowGatewayRoute(id: string): Promise<{ alias: string; url: string } | null> {
  const settings = await serviceNowSettings(id);
  if (!settings) throw new PolicyError('SERVICENOW_CONFIG', 'ServiceNow connection was not found in this tenant', 404);
  const row = await db.prepare('SELECT alias FROM servicenow_gateway_route WHERE connection_id = ?').get(id) as { alias: string } | undefined;
  return row ? { alias: row.alias, url: `${settings.gateway_url}/v1/mcp/${row.alias}` } : null;
}

/** Registers discovered tools as a gateway destination; certificate approval is still required per agent/action. */
export async function prepareServiceNowGateway(id: string, alias: string, actor: Principal): Promise<{ alias: string; url: string }> {
  if (!actor.permissions.includes('tools.manage')) throw new PolicyError('RBAC', 'Preparing a ServiceNow gateway route requires tools.manage', 403);
  if (typeof alias !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(alias) || alias.length > 63) throw invalid('Gateway alias must be kebab-case and at most 63 characters');
  const config = await serviceNowConfiguration(id);
  const bearer = await serviceNowAccessToken(id);
  return tx(async () => {
    const row = await db.prepare('SELECT tools_json FROM servicenow_mcp_account WHERE tenant_id = ? AND id = ? FOR UPDATE').get(tenant.id, id) as { tools_json: string | null } | undefined;
    if (!row?.tools_json) throw invalid('Discover ServiceNow tools before preparing their gateway route');
    const tools = JSON.parse(row.tools_json) as ServiceNowTool[];
    if (!tools.length) throw invalid('This ServiceNow connection has no discovered tools to route');
    const existing = await db.prepare('SELECT alias FROM servicenow_gateway_route WHERE connection_id = ?').get(id) as { alias: string } | undefined;
    if (existing && existing.alias !== alias) throw new PolicyError('SERVICENOW_CONFIG', 'A gateway route already exists for this connection; use its registered alias', 409);
    if (!existing) {
      const secret = await putSecret({ name: `sn-gateway-${id.slice(-20).toLowerCase()}`, kind: 'tool', value: bearer }, actor);
      await registerTool({ alias, kind: 'mcp', url: config.endpoint, secret: secret.id, auth_header: 'authorization', actions: Object.fromEntries(tools.map(tool => [tool.name, { method: 'POST', path: '/' }])) }, actor);
      await db.prepare('INSERT INTO servicenow_gateway_route (connection_id, alias, secret_id) VALUES (?, ?, ?)').run(id, alias, secret.id);
    }
    return { alias, url: `${new URL(config.redirectUri).origin}/v1/mcp/${alias}` };
  });
}

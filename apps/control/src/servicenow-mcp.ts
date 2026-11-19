import { createHash, randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import { newId, sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError } from './errors';
import { requestJson } from './external-http';
import { object } from './external-contract';
import { serviceNowConfiguration, serviceNowSettings } from './servicenow-mcp-settings';
import type { Principal } from './rbac';
import { putSecret, rotateSecret } from './secrets';
import { type ServiceNowTool } from './servicenow-mcp-discovery';
import { tenant } from './tenant';
import { linkedServiceNowAgents } from './servicenow-agents';

interface PendingAuthorization {
  connection_id: string | null;
  principal_id: string;
  verifier: string;
  instance_url: string;
  client_id: string;
  redirect_uri: string;
  expires_at: number;
}

/** Starts tenant-admin consent with an expiring, single-use state and PKCE verifier. */
export async function startServiceNowConnection(id: string, res: Response, actor: Principal): Promise<void> {
  const config = await serviceNowConfiguration(id);
  const state = randomBytes(32).toString('base64url');
  const verifier = randomBytes(48).toString('base64url');
  await db.prepare('DELETE FROM servicenow_mcp_oauth_state WHERE expires_at < ?').run(Date.now());
  await db.prepare('INSERT INTO servicenow_mcp_oauth_state (state_hash, tenant_id, principal_id, verifier, instance_url, client_id, redirect_uri, expires_at, connection_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(sha256(state), tenant.id, actor.id, verifier, config.instance, config.clientId, config.redirectUri, Date.now() + 10 * 60_000, id);
  const url = new URL('/oauth_auth.do', config.instance);
  url.search = new URLSearchParams({ response_type: 'code', client_id: config.clientId, redirect_uri: config.redirectUri, state,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
  res.setHeader('cache-control', 'no-store');
  res.redirect(url.href);
}

/** Exchanges consent once and stores tokens in the encrypted broker, never in a response or URL. */
export async function completeServiceNowConnection(req: Request, res: Response, actor: Principal): Promise<void> {
  if (typeof req.query.state !== 'string') throw new PolicyError('SERVICENOW_AUTH', 'ServiceNow OAuth state is missing; start the connection again', 400);
  const pending = await db.prepare('DELETE FROM servicenow_mcp_oauth_state WHERE state_hash = ? AND tenant_id = ? AND principal_id = ? RETURNING connection_id, principal_id, verifier, instance_url, client_id, redirect_uri, expires_at')
    .get(sha256(req.query.state), tenant.id, actor.id) as PendingAuthorization | undefined;
  if (!pending || !pending.connection_id || pending.expires_at < Date.now()) throw new PolicyError('SERVICENOW_AUTH', 'ServiceNow OAuth state is expired, already used, or belongs to another user; start again', 400);
  const id = pending.connection_id;
  const config = await serviceNowConfiguration(id);
  if (pending.instance_url !== config.instance || pending.client_id !== config.clientId || pending.redirect_uri !== config.redirectUri) throw new PolicyError('SERVICENOW_AUTH', 'ServiceNow configuration changed during authorization; start again', 400);
  if (typeof req.query.error === 'string') throw new PolicyError('SERVICENOW_AUTH', 'ServiceNow authorization was denied; check the integration permissions and start again', 401);
  if (typeof req.query.code !== 'string' || !req.query.code) throw new PolicyError('SERVICENOW_AUTH', 'ServiceNow did not return an authorization code; start again', 400);
  const result = object(await requestJson({
    url: new URL('/oauth_token.do', config.instance), method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: config.clientId, client_secret: config.clientSecret,
      code: req.query.code, code_verifier: pending.verifier, redirect_uri: config.redirectUri }).toString(), timeout: 15000,
  }), 'ServiceNow OAuth token response');
  if (typeof result.access_token !== 'string' || !result.access_token || typeof result.refresh_token !== 'string' || !result.refresh_token || typeof result.expires_in !== 'number' || !Number.isFinite(result.expires_in) || result.expires_in <= 0 || typeof result.token_type !== 'string' || result.token_type.toLowerCase() !== 'bearer') {
    throw new PolicyError('SERVICENOW_AUTH', 'ServiceNow token response must contain access_token, refresh_token, a positive numeric expires_in, and Bearer token_type; check the OAuth grant configuration', 502);
  }
  const credential = JSON.stringify({ access_token: result.access_token, refresh_token: result.refresh_token });
  const expiresAt = Date.now() + result.expires_in * 1000;
  await saveServiceNowAuthorization(id, credential, expiresAt, actor);
  res.setHeader('cache-control', 'no-store');
  res.redirect('/settings/accounts');
}

/** Replaces OAuth tokens on the existing connection without resetting discovery or agent onboarding. */
export async function saveServiceNowAuthorization(id: string, credential: string, expiresAt: number, actor: Principal): Promise<void> {
  await tx(async () => {
    const existing = await db.prepare('SELECT token_secret_id AS secret_id FROM servicenow_mcp_account WHERE tenant_id = ? AND id = ? FOR UPDATE').get(tenant.id, id) as { secret_id: string | null } | undefined;
    if (!existing) throw new PolicyError('SERVICENOW_CONFIG', 'This ServiceNow connection was removed during authorization; create a new connection to continue', 404);
    const secret = existing?.secret_id ? await rotateSecret(existing.secret_id, credential, actor)
      : await putSecret({ name: `servicenow-mcp-${newId('sec').slice(-16).toLowerCase()}`, kind: 'platform', value: credential }, actor);
    await db.prepare('UPDATE servicenow_mcp_account SET token_secret_id = ?, expires_at = ?, updated_by = ?, updated_at = ? WHERE tenant_id = ? AND id = ?')
      .run(secret.id, expiresAt, actor.id, nowIso(), tenant.id, id);
  });
}

export interface ServiceNowConnectionView {
  id: string; name: string; configured: boolean; authorized: boolean; callback_url: string; mcp_url: string;
  expires_at: number | null; monitoring: boolean; tools: ServiceNowTool[]; discovered_at: string | null;
}

export async function serviceNowConnection(id: string): Promise<ServiceNowConnectionView> {
  const row = await db.prepare('SELECT expires_at, tools_json, discovered_at FROM servicenow_mcp_account WHERE tenant_id = ? AND id = ?').get(tenant.id, id) as { expires_at: number | null; tools_json: string | null; discovered_at: string | null } | undefined;
  const settings = await serviceNowSettings(id);
  if (!row || !settings) throw new PolicyError('SERVICENOW_CONFIG', 'ServiceNow connection was not found in this tenant', 404);
  return { id, name: settings.name, configured: true, authorized: Boolean(row.expires_at && row.expires_at > Date.now()), callback_url: settings.callback_url,
    mcp_url: settings.mcp_url, expires_at: row.expires_at, monitoring: (await linkedServiceNowAgents(id)).some(agent => agent.monitoring),
    tools: row.tools_json ? JSON.parse(row.tools_json) as ServiceNowTool[] : [], discovered_at: row.discovered_at };
}

export async function listServiceNowConnections(): Promise<ServiceNowConnectionView[]> {
  const rows = await db.prepare('SELECT id FROM servicenow_mcp_account WHERE tenant_id = ? ORDER BY updated_at DESC, id').all(tenant.id) as { id: string }[];
  return Promise.all(rows.map(row => serviceNowConnection(row.id)));
}

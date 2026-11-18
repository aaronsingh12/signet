import { createHash, randomBytes } from 'node:crypto';
import { sha256 } from '@signet/core';
import { db, tx } from './db';
import { PolicyError } from './errors';
import { authenticateWorkloadClient, exchangeClientCredentials, usableCertificate } from './identity';
import { assertCan, getAgent } from './registry';
import type { Principal } from './rbac';
import * as ledger from './ledger';

interface OAuthClient { client_id: string; agent_id: string; redirect_uri: string; environment: string; revoked_at: string | null }
interface AuthorizationRequest {
  request_hash: string; client_id: string; agent_id: string; principal_id: string; redirect_uri: string;
  state: string; challenge: string; scope: string; cert_id: string; expires_at: number;
}
interface OAuthGrant { token_hash: string; client_id: string; agent_id: string; redirect_uri: string; challenge: string; cert_id: string; scope: string; expires_at: number }
export interface AuthorizationInput {
  response_type: string; client_id: string; redirect_uri: string; state: string;
  code_challenge: string; code_challenge_method: string; scope: string;
}
export interface AuthorizationPreview { agent_name: string; client_id: string; redirect_uri: string; environment: string; scope: string }
export interface OAuthTokens { access_token: string; token_type: string; expires_in: number; refresh_token: string; scope: string }

function oauthError(error: string, message: string, status: number): PolicyError {
  return new PolicyError('OAUTH', message, status, { oauth_error: error });
}

/** Only exact HTTPS callback URLs are accepted; localhost HTTP is allowed for development. */
export function validateRedirectUri(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw oauthError('invalid_request', 'Redirect URI must be an absolute HTTPS URL', 400); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (value.length > 2048 || url.hash || url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && local))) {
    throw oauthError('invalid_request', 'Redirect URI must use HTTPS without credentials or a fragment; HTTP is allowed only on localhost', 400);
  }
  return value;
}

async function oauthClient(clientId: string): Promise<OAuthClient> {
  const client = await db.prepare('SELECT client_id, agent_id, environment, revoked_at FROM agent_client WHERE client_id = ?').get(clientId) as Omit<OAuthClient, 'redirect_uri'> | undefined;
  if (!client || client.revoked_at) throw oauthError('invalid_client', 'OAuth client is unknown or revoked', 401);
  const callback = await db.prepare('SELECT redirect_uri FROM workload_oauth_client WHERE client_id = ?').get(clientId) as { redirect_uri: string } | undefined;
  if (!callback) throw oauthError('invalid_request', 'Register this client callback URL in Gateway setup before authorizing', 400);
  return { ...client, redirect_uri: callback.redirect_uri };
}

/** Configures one explicit callback for a workload client and invalidates its outstanding grants. */
export async function configureOAuthClient(clientId: string, redirectUri: string, actor: Principal): Promise<{ redirect_uri: string }> {
  const redirect = validateRedirectUri(redirectUri);
  const client = await db.prepare('SELECT agent_id, revoked_at FROM agent_client WHERE client_id = ?').get(clientId) as { agent_id: string; revoked_at: string | null } | undefined;
  if (!client || client.revoked_at) throw oauthError('invalid_client', 'Select an active workload client before saving a callback URL', 400);
  assertCan(actor, 'identity.bootstrap', await getAgent(client.agent_id));
  await tx(async () => {
    await db.prepare('INSERT INTO workload_oauth_client (client_id, redirect_uri) VALUES (?, ?) ON CONFLICT (client_id) DO UPDATE SET redirect_uri = EXCLUDED.redirect_uri').run(clientId, redirect);
    await db.prepare('DELETE FROM workload_oauth_request WHERE client_id = ?').run(clientId);
    await db.prepare('DELETE FROM workload_oauth_code WHERE client_id = ?').run(clientId);
    await db.prepare('DELETE FROM workload_oauth_refresh WHERE client_id = ?').run(clientId);
    await ledger.append({ kind: 'admin', agent_id: client.agent_id, data: { event: 'identity.oauth_callback_saved', client_id: clientId, redirect_uri: redirect, actor: actor.id } });
  });
  return { redirect_uri: redirect };
}

export async function oauthClientSettings(clientId: string, actor: Principal): Promise<{ redirect_uri: string }> {
  const client = await db.prepare('SELECT agent_id FROM agent_client WHERE client_id = ?').get(clientId) as { agent_id: string } | undefined;
  if (!client) throw oauthError('invalid_client', 'OAuth client was not found', 404);
  assertCan(actor, 'identity.bootstrap', await getAgent(client.agent_id));
  const config = await db.prepare('SELECT redirect_uri FROM workload_oauth_client WHERE client_id = ?').get(clientId) as { redirect_uri: string } | undefined;
  return { redirect_uri: config?.redirect_uri ?? '' };
}

/** Validates the request before any login or redirect, preventing open redirects and PKCE downgrade. */
export async function validateAuthorization(input: AuthorizationInput): Promise<OAuthClient> {
  const client = await oauthClient(input.client_id);
  if (input.redirect_uri !== client.redirect_uri) throw oauthError('invalid_request', 'redirect_uri must exactly match the registered callback URL', 400);
  if (input.response_type !== 'code') throw oauthError('unsupported_response_type', 'Only response_type=code is supported', 400);
  if (!input.state || input.state.length > 2048) throw oauthError('invalid_request', 'A nonempty state of at most 2048 characters is required', 400);
  if (input.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(input.code_challenge)) throw oauthError('invalid_request', 'PKCE S256 code_challenge is required', 400);
  if (input.scope && input.scope !== 'mcp') throw oauthError('invalid_scope', 'Only the mcp scope is supported; access remains limited by the agent seal', 400);
  return client;
}

function assertHumanSession(actor: Principal): void {
  if (actor.kind !== 'human' || actor.auth !== 'session') throw oauthError('access_denied', 'Sign in to Signet with a human account to authorize this client', 403);
}

/** Creates a short-lived consent request bound to the signed-in agent owner or administrator. */
export async function beginAuthorization(input: AuthorizationInput, actor: Principal): Promise<string> {
  assertHumanSession(actor);
  const client = await validateAuthorization(input);
  assertCan(actor, 'identity.bootstrap', await getAgent(client.agent_id));
  const cert = await usableCertificate(client.agent_id);
  if (!cert.environments.includes(client.environment)) throw oauthError('access_denied', 'The client environment is not covered by the current seal', 403);
  const request = randomBytes(32).toString('base64url');
  await db.prepare('DELETE FROM workload_oauth_request WHERE expires_at < ?').run(Date.now());
  await db.prepare('INSERT INTO workload_oauth_request (request_hash, client_id, agent_id, principal_id, redirect_uri, state, challenge, scope, cert_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(sha256(request), client.client_id, client.agent_id, actor.id, client.redirect_uri, input.state, input.code_challenge, 'mcp', cert.cert_id, Date.now() + 10 * 60_000);
  return request;
}

async function pendingRequest(request: string, actor: Principal): Promise<AuthorizationRequest> {
  assertHumanSession(actor);
  const pending = await db.prepare('SELECT * FROM workload_oauth_request WHERE request_hash = ?').get(sha256(request)) as AuthorizationRequest | undefined;
  if (!pending || pending.principal_id !== actor.id || pending.expires_at <= Date.now()) throw oauthError('invalid_request', 'Authorization request expired, already used, or belongs to another user; restart from your OAuth client', 400);
  assertCan(actor, 'identity.bootstrap', await getAgent(pending.agent_id));
  const client = await oauthClient(pending.client_id);
  const cert = await usableCertificate(pending.agent_id);
  if (client.redirect_uri !== pending.redirect_uri || cert.cert_id !== pending.cert_id || !cert.environments.includes(client.environment)) throw oauthError('access_denied', 'Client settings or agent seal changed; restart authorization', 400);
  return pending;
}

export async function authorizationPreview(request: string, actor: Principal): Promise<AuthorizationPreview> {
  const pending = await pendingRequest(request, actor);
  const client = await oauthClient(pending.client_id);
  const agent = await getAgent(pending.agent_id);
  return { agent_name: agent.name, client_id: pending.client_id, redirect_uri: pending.redirect_uri, environment: client.environment, scope: pending.scope };
}

function callbackUrl(pending: AuthorizationRequest): URL {
  const url = new URL(pending.redirect_uri);
  url.searchParams.set('state', pending.state);
  return url;
}

/** Consent tokens and authorization codes are consumed atomically and stored only as hashes. */
export async function approveAuthorization(request: string, actor: Principal): Promise<{ redirect_to: string }> {
  return tx(async () => {
    const pending = await pendingRequest(request, actor);
    const deleted = await db.prepare('DELETE FROM workload_oauth_request WHERE request_hash = ? RETURNING request_hash').get(pending.request_hash);
    if (!deleted) throw oauthError('invalid_request', 'Authorization request was already used', 400);
    const code = randomBytes(32).toString('base64url');
    await db.prepare('DELETE FROM workload_oauth_code WHERE expires_at < ?').run(Date.now());
    await db.prepare('INSERT INTO workload_oauth_code (token_hash, client_id, agent_id, redirect_uri, challenge, cert_id, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(sha256(code), pending.client_id, pending.agent_id, pending.redirect_uri, pending.challenge, pending.cert_id, pending.scope, Date.now() + 5 * 60_000);
    await ledger.append({ kind: 'admin', agent_id: pending.agent_id, data: { event: 'identity.oauth_authorized', client_id: pending.client_id, actor: actor.id, scope: pending.scope } });
    const url = callbackUrl(pending);
    url.searchParams.set('code', code);
    return { redirect_to: url.href };
  });
}

export async function denyAuthorization(request: string, actor: Principal): Promise<{ redirect_to: string }> {
  return tx(async () => {
    const pending = await pendingRequest(request, actor);
    const deleted = await db.prepare('DELETE FROM workload_oauth_request WHERE request_hash = ? RETURNING request_hash').get(pending.request_hash);
    if (!deleted) throw oauthError('invalid_request', 'Authorization request was already used', 400);
    const url = callbackUrl(pending);
    url.searchParams.set('error', 'access_denied');
    return { redirect_to: url.href };
  });
}

async function validateGrant(grant: OAuthGrant | undefined, clientId: string): Promise<OAuthGrant> {
  if (!grant || grant.client_id !== clientId || grant.expires_at <= Date.now()) throw oauthError('invalid_grant', 'Grant is expired, invalid, already used, or issued to another client; authorize again', 400);
  const client = await oauthClient(clientId);
  const cert = await usableCertificate(grant.agent_id);
  if (client.redirect_uri !== grant.redirect_uri || cert.cert_id !== grant.cert_id || !cert.environments.includes(client.environment)) throw oauthError('invalid_grant', 'Client callback, seal or environment changed; authorize again', 400);
  return grant;
}

async function grantTokens(grant: OAuthGrant, clientId: string, secret: string): Promise<OAuthTokens> {
  const access = await exchangeClientCredentials(clientId, secret);
  const refresh = randomBytes(32).toString('base64url');
  await db.prepare('DELETE FROM workload_oauth_refresh WHERE expires_at < ?').run(Date.now());
  await db.prepare('INSERT INTO workload_oauth_refresh (token_hash, client_id, agent_id, redirect_uri, challenge, cert_id, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(sha256(refresh), clientId, grant.agent_id, grant.redirect_uri, grant.challenge, grant.cert_id, grant.scope, Date.now() + 30 * 24 * 60 * 60_000);
  return { access_token: access.token, token_type: access.token_type, expires_in: access.expires_in, refresh_token: refresh, scope: grant.scope };
}

/** Exchanges a client-authenticated, redirect-bound PKCE code once for workload tokens. */
export async function exchangeAuthorizationCode(clientId: string, secret: string, code: string, redirectUri: string, verifier: string): Promise<OAuthTokens> {
  await authenticateWorkloadClient(clientId, secret);
  return tx(async () => {
    const row = await db.prepare('SELECT * FROM workload_oauth_code WHERE token_hash = ?').get(sha256(code)) as OAuthGrant | undefined;
    const grant = await validateGrant(row, clientId);
    if (redirectUri !== grant.redirect_uri || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || createHash('sha256').update(verifier).digest('base64url') !== grant.challenge) throw oauthError('invalid_grant', 'redirect_uri or PKCE code_verifier does not match this authorization code', 400);
    const deleted = await db.prepare('DELETE FROM workload_oauth_code WHERE token_hash = ? RETURNING token_hash').get(grant.token_hash);
    if (!deleted) throw oauthError('invalid_grant', 'Authorization code was already used', 400);
    return grantTokens(grant, clientId, secret);
  });
}

/** Rotates refresh tokens atomically; seal changes and client/instance revocation stop renewal. */
export async function exchangeOAuthRefresh(clientId: string, secret: string, refresh: string): Promise<OAuthTokens> {
  await authenticateWorkloadClient(clientId, secret);
  return tx(async () => {
    const row = await db.prepare('SELECT * FROM workload_oauth_refresh WHERE token_hash = ?').get(sha256(refresh)) as OAuthGrant | undefined;
    const grant = await validateGrant(row, clientId);
    const deleted = await db.prepare('DELETE FROM workload_oauth_refresh WHERE token_hash = ? RETURNING token_hash').get(grant.token_hash);
    if (!deleted) throw oauthError('invalid_grant', 'Refresh token was already used; use the latest rotated token', 400);
    return grantTokens(grant, clientId, secret);
  });
}

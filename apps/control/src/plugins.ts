import { createHash, randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import { devSecret, env, newId, seal } from '@signet/core';
import { db, nowIso } from './db';
import { PolicyError } from './errors';
import { OIDC } from './oidc';
import type { Principal } from './rbac';
import { tenant } from './tenant';

const TOKEN_KEY = Buffer.from(devSecret('SIGNET_BROKER_KEY'), 'base64url').subarray(0, 32);
const AUTHORIZE_URL = 'https://vercel.com/oauth/authorize';
const TOKEN_URL = 'https://api.vercel.com/login/oauth/token';
const USERINFO_URL = 'https://api.vercel.com/login/oauth/userinfo';
const PENDING_TTL_MS = 10 * 60_000;

interface PendingConnection {
  actorId: string;
  verifier: string;
  at: number;
}

interface TokenResponse {
  access_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  error?: unknown;
  error_description?: unknown;
}

interface UserInfoResponse {
  sub?: unknown;
  email?: unknown;
  name?: unknown;
}

const pending = new Map<string, PendingConnection>();

const configured = () => Boolean(process.env.SIGNET_VERCEL_CLIENT_ID && process.env.SIGNET_VERCEL_CLIENT_SECRET);
const callbackUrl = () => `${OIDC.publicUrl}/api/v1/plugins/vercel/callback`;

function clearExpiredPending(): void {
  const oldest = Date.now() - PENDING_TTL_MS;
  for (const [state, connection] of pending) if (connection.at < oldest) pending.delete(state);
}

function configError(): PolicyError {
  return new PolicyError('PLUGIN_CONFIG', 'Vercel integration requires SIGNET_VERCEL_CLIENT_ID and SIGNET_VERCEL_CLIENT_SECRET', 503);
}

export function startVercelConnection(res: Response, actor: Principal): void {
  if (!configured()) throw configError();
  clearExpiredPending();
  const state = randomBytes(32).toString('base64url');
  const verifier = randomBytes(48).toString('base64url');
  pending.set(state, { actorId: actor.id, verifier, at: Date.now() });
  const authorizationUrl = new URL(AUTHORIZE_URL);
  authorizationUrl.search = new URLSearchParams({
    client_id: env('SIGNET_VERCEL_CLIENT_ID', ''),
    redirect_uri: callbackUrl(),
    response_type: 'code',
    scope: 'openid email profile offline_access',
    state,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
  }).toString();
  res.redirect(authorizationUrl.toString());
}

function tokenExpiry(expiresIn: unknown): string | null {
  if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn <= 0) return null;
  return new Date(Date.now() + expiresIn * 1000).toISOString();
}

async function exchangeCode(code: string, verifier: string): Promise<{ accessToken: string; refreshToken: string | null; expiresAt: string | null }> {
  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: env('SIGNET_VERCEL_CLIENT_ID', ''),
      client_secret: env('SIGNET_VERCEL_CLIENT_SECRET', ''),
      code,
      code_verifier: verifier,
      redirect_uri: callbackUrl(),
    }),
  });
  const result = await response.json() as TokenResponse;
  if (!response.ok || typeof result.access_token !== 'string') {
    throw new PolicyError('PLUGIN_AUTH', `Vercel token exchange failed (${response.status}): ${String(result.error_description ?? result.error ?? 'no access token returned')}`, 502);
  }
  return { accessToken: result.access_token, refreshToken: typeof result.refresh_token === 'string' ? result.refresh_token : null, expiresAt: tokenExpiry(result.expires_in) };
}

async function userInfo(accessToken: string): Promise<{ id: string; email: string | null; name: string | null }> {
  const response = await fetch(USERINFO_URL, { method: 'POST', headers: { authorization: `Bearer ${accessToken}` } });
  const result = await response.json() as UserInfoResponse;
  if (!response.ok || typeof result.sub !== 'string') throw new PolicyError('PLUGIN_AUTH', `Vercel user profile request failed (${response.status})`, 502);
  return { id: result.sub, email: typeof result.email === 'string' ? result.email : null, name: typeof result.name === 'string' ? result.name : null };
}

export async function completeVercelConnection(req: Request, res: Response, actor: Principal): Promise<void> {
  if (!configured()) throw configError();
  const state = typeof req.query.state === 'string' ? req.query.state : '';
  const connection = pending.get(state);
  pending.delete(state);
  if (!connection || connection.at + PENDING_TTL_MS < Date.now()) throw new PolicyError('PLUGIN_AUTH', 'Vercel connection state is unknown or expired; start again', 400);
  if (connection.actorId !== actor.id) throw new PolicyError('PLUGIN_AUTH', 'Vercel connection must be completed by the user who started it', 403);
  if (req.query.error) throw new PolicyError('PLUGIN_AUTH', `Vercel authorization was refused: ${String(req.query.error)}`, 401);
  const code = typeof req.query.code === 'string' ? req.query.code : '';
  if (!code) throw new PolicyError('PLUGIN_AUTH', 'Vercel did not return an authorization code', 400);
  const tokens = await exchangeCode(code, connection.verifier);
  const profile = await userInfo(tokens.accessToken);
  const now = nowIso();
  (await db.prepare(`INSERT INTO vercel_connection (id, tenant_id, principal_id, vercel_user_id, email, name, access_token_sealed, refresh_token_sealed, expires_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(tenant_id, principal_id) DO UPDATE SET vercel_user_id = excluded.vercel_user_id, email = excluded.email, name = excluded.name, access_token_sealed = excluded.access_token_sealed, refresh_token_sealed = excluded.refresh_token_sealed, expires_at = excluded.expires_at, updated_at = excluded.updated_at)`)
    .run(newId('vrc'), tenant.id, actor.id, profile.id, profile.email, profile.name, seal(tokens.accessToken, TOKEN_KEY), tokens.refreshToken ? seal(tokens.refreshToken, TOKEN_KEY) : null, tokens.expiresAt, now, now));
  res.redirect(`${OIDC.publicUrl}/plugins?vercel=connected`);
}

export async function vercelConnection(actor: Principal): Promise<{ configured: boolean; connected: boolean; email: string | null; name: string | null; expires_at: string | null }> {
  const row = (await db.prepare('SELECT email, name, expires_at FROM vercel_connection WHERE tenant_id = ? AND principal_id = ?').get(tenant.id, actor.id)) as { email: string | null; name: string | null; expires_at: string | null } | undefined;
  return { configured: configured(), connected: Boolean(row), email: row?.email ?? null, name: row?.name ?? null, expires_at: row?.expires_at ?? null };
}

export async function disconnectVercel(actor: Principal): Promise<{ disconnected: true }> {
  (await db.prepare('DELETE FROM vercel_connection WHERE tenant_id = ? AND principal_id = ?').run(tenant.id, actor.id));
  return { disconnected: true };
}

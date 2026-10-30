import { createHash, randomBytes } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { checkTimes, env, keyFromJwk, sha256, verifyJwtSignature, decodeJwt } from '@signet/core';
import { db, nowIso } from './db';
import { PolicyError } from './errors';
import { permissionsFor, rolesFor, type Principal } from './rbac';
import { tenant } from './tenant';

// Single sign-on (BP 2 principle: OIDC/SAML to the customer IdP; Signet stores no passwords).
// Humans sign in through the authorization-code flow with PKCE, state and nonce; the console then
// holds an HttpOnly session cookie. Machine clients send OAuth 2.0 bearer tokens from the same IdP.

export const OIDC = {
  issuer: env('SIGNET_OIDC_ISSUER', 'http://localhost:8180/realms/signet'),
  clientId: env('SIGNET_OIDC_CLIENT_ID', 'signet-console'),
  clientSecret: env('SIGNET_OIDC_CLIENT_SECRET', 'signet-console-dev-secret'),
  publicUrl: env('SIGNET_PUBLIC_URL', 'http://localhost:5174'),
  // Clients whose access tokens the API accepts (azp claim).
  apiClients: env('SIGNET_OIDC_API_CLIENTS', 'signet-console,signet-dev-cli,signet-automation').split(','),
};

const SESSION_COOKIE = 'signet_session';
const IDLE_MS = 30 * 60_000; // BP 18.5: 30 min idle
const ABSOLUTE_MS = 12 * 3_600_000; // 12 h absolute

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
}

let discovery: Discovery | null = null;
const jwks = new Map<string, KeyObject>();
let jwksFetchedAt = 0;

async function getDiscovery(): Promise<Discovery> {
  if (discovery) return discovery;
  const r = await fetch(`${OIDC.issuer}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(5_000) });
  if (!r.ok) throw new PolicyError('AUTH', `identity provider unavailable (${r.status})`, 503);
  discovery = (await r.json()) as Discovery;
  return discovery;
}

async function keyFor(kid: string | undefined): Promise<KeyObject> {
  if (kid && jwks.has(kid)) return jwks.get(kid)!;
  if (Date.now() - jwksFetchedAt > 10_000) {
    const d = await getDiscovery();
    const r = await fetch(d.jwks_uri, { signal: AbortSignal.timeout(5_000) });
    const set = (await r.json()) as { keys: (Record<string, unknown> & { kid: string; use?: string })[] };
    jwks.clear();
    for (const k of set.keys) if (k.use !== 'enc') jwks.set(k.kid, keyFromJwk(k));
    jwksFetchedAt = Date.now();
  }
  const key = kid ? jwks.get(kid) : undefined;
  if (!key) throw new PolicyError('AUTH', 'token signed with an unknown key', 401);
  return key;
}

interface IdClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  azp?: string;
  email?: string;
  preferred_username?: string;
  name?: string;
  groups?: string[];
  acr?: string;
  amr?: string[];
  auth_time?: number;
  nonce?: string;
  exp: number;
  client_id?: string;
}

async function verifyIdpToken(token: string): Promise<IdClaims> {
  const { header } = decodeJwt(token);
  const { payload } = verifyJwtSignature(token, await keyFor(header.kid));
  checkTimes(payload);
  const claims = payload as unknown as IdClaims;
  if (claims.iss !== OIDC.issuer) throw new PolicyError('AUTH', 'token from an unexpected issuer', 401);
  return claims;
}

function principalFromClaims(c: IdClaims, auth: Principal['auth']): Principal {
  const isService = (c.preferred_username ?? '').startsWith('service-account-');
  const groups = c.groups ?? [];
  const roles = rolesFor(groups, tenant.settings.group_roles);
  return {
    id: isService ? `svc:${c.azp ?? c.client_id}` : (c.email ?? c.preferred_username ?? c.sub).toLowerCase(),
    name: c.name ?? c.preferred_username ?? c.sub,
    kind: isService ? 'service' : 'human',
    roles,
    permissions: permissionsFor(roles),
    groups,
    mfa: c.acr === 'mfa' || (c.amr ?? []).some((m) => ['mfa', 'otp', 'hwk', 'swk'].includes(m)),
    auth,
    auth_time: c.auth_time ?? null,
  };
}

// --- authorization-code flow with PKCE (state and verifier held server-side for 10 minutes) ---
const pending = new Map<string, { verifier: string; nonce: string; returnTo: string; at: number }>();

export async function login(req: Request, res: Response) {
  const d = await getDiscovery();
  const state = randomBytes(24).toString('base64url');
  const verifier = randomBytes(32).toString('base64url');
  const nonce = randomBytes(24).toString('base64url');
  const returnTo = typeof req.query.return_to === 'string' && req.query.return_to.startsWith('/') ? req.query.return_to : '/';
  pending.set(state, { verifier, nonce, returnTo, at: Date.now() });
  for (const [k, v] of pending) if (Date.now() - v.at > 10 * 60_000) pending.delete(k);
  const url = new URL(d.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: OIDC.clientId,
    redirect_uri: `${OIDC.publicUrl}/api/v1/auth/callback`,
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...(typeof req.query.login_hint === 'string' ? { login_hint: req.query.login_hint } : {}),
    ...(req.query.max_age ? { max_age: String(req.query.max_age) } : {}),
  }).toString();
  res.redirect(url.toString());
}

export async function callback(req: Request, res: Response) {
  const state = String(req.query.state ?? '');
  const p = pending.get(state);
  pending.delete(state);
  if (!p) throw new PolicyError('AUTH', 'sign-in state is unknown or expired; start again', 400);
  if (req.query.error) throw new PolicyError('AUTH', `identity provider refused sign-in: ${req.query.error}`, 401);
  const d = await getDiscovery();
  const tr = await fetch(d.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${OIDC.clientId}:${OIDC.clientSecret}`).toString('base64')}` },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: String(req.query.code ?? ''), redirect_uri: `${OIDC.publicUrl}/api/v1/auth/callback`, code_verifier: p.verifier }),
  });
  const tokens = (await tr.json()) as { id_token?: string; error?: string };
  if (!tr.ok || !tokens.id_token) throw new PolicyError('AUTH', `code exchange failed: ${tokens.error ?? tr.status}`, 401);
  const claims = await verifyIdpToken(tokens.id_token);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(OIDC.clientId)) throw new PolicyError('AUTH', 'ID token audience mismatch', 401);
  if (claims.nonce !== p.nonce) throw new PolicyError('AUTH', 'ID token nonce mismatch', 401);
  const principal = principalFromClaims(claims, 'session');
  const sid = randomBytes(32).toString('base64url');
  const now = Date.now();
  db.prepare('INSERT INTO session (id_hash, tenant_id, principal, id_token, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    sha256(sid), tenant.id, JSON.stringify(principal), tokens.id_token, nowIso(), new Date(now + ABSOLUTE_MS).toISOString(), nowIso(),
  );
  res.cookie(SESSION_COOKIE, sid, { httpOnly: true, sameSite: 'lax', secure: OIDC.publicUrl.startsWith('https'), path: '/', maxAge: ABSOLUTE_MS });
  res.redirect(`${OIDC.publicUrl}${p.returnTo}`);
}

export async function logout(req: Request, res: Response) {
  const sid = readCookie(req, SESSION_COOKIE);
  let idToken: string | null = null;
  if (sid) {
    const row = db.prepare('SELECT id_token FROM session WHERE id_hash = ?').get(sha256(sid)) as { id_token: string | null } | undefined;
    idToken = row?.id_token ?? null;
    db.prepare('DELETE FROM session WHERE id_hash = ?').run(sha256(sid));
  }
  res.clearCookie(SESSION_COOKIE, { path: '/' });
  const d = await getDiscovery().catch(() => null);
  if (d?.end_session_endpoint) {
    const url = new URL(d.end_session_endpoint);
    url.search = new URLSearchParams({ post_logout_redirect_uri: `${OIDC.publicUrl}/login`, client_id: OIDC.clientId, ...(idToken ? { id_token_hint: idToken } : {}) }).toString();
    return res.json({ redirect: url.toString() });
  }
  res.json({ redirect: '/login' });
}

function readCookie(req: Request, name: string): string | null {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

// Resolves the caller from a session cookie or a bearer token. Unauthenticated requests continue
// without a principal; route guards decide.
export async function authenticate(req: Request, res: Response, next: NextFunction) {
  try {
    const bearer = (req.headers.authorization ?? '').match(/^Bearer\s+(.+)$/i)?.[1];
    if (bearer) {
      const claims = await verifyIdpToken(bearer);
      const azp = claims.azp ?? claims.client_id ?? '';
      if (!OIDC.apiClients.includes(azp)) throw new PolicyError('AUTH', `client ${azp} may not call the API`, 401);
      res.locals.principal = principalFromClaims(claims, 'bearer');
    } else {
      const sid = readCookie(req, SESSION_COOKIE);
      if (sid) {
        const row = db.prepare('SELECT principal, expires_at, last_seen_at FROM session WHERE id_hash = ?').get(sha256(sid)) as
          | { principal: string; expires_at: string; last_seen_at: string }
          | undefined;
        const now = Date.now();
        if (row && Date.parse(row.expires_at) > now && now - Date.parse(row.last_seen_at) < IDLE_MS) {
          // State-changing calls from the console must be JSON, which a cross-site form cannot send.
          if (req.method !== 'GET' && !String(req.headers['content-type'] ?? '').includes('application/json')) {
            throw new PolicyError('AUTH', 'state-changing requests must be application/json', 415);
          }
          db.prepare('UPDATE session SET last_seen_at = ? WHERE id_hash = ?').run(nowIso(), sha256(sid));
          res.locals.principal = JSON.parse(row.principal) as Principal;
        } else if (row) {
          db.prepare('DELETE FROM session WHERE id_hash = ?').run(sha256(sid));
        }
      }
    }
    const p = res.locals.principal as Principal | undefined;
    if (p && p.kind === 'human' && tenant.settings.require_mfa && !p.mfa) {
      throw new PolicyError('AUTH-MFA', 'this tenant requires MFA at the identity provider', 403);
    }
    next();
  } catch (e) {
    next(e instanceof PolicyError ? e : new PolicyError('AUTH', (e as Error).message, 401));
  }
}

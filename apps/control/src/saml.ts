import type { Request, Response } from 'express';
import { SAML, ValidateInResponseTo, type CacheProvider, type Profile } from '@node-saml/node-saml';
import { env } from '@signet/core';
import { db, nowIso } from './db';
import { PolicyError } from './errors';
import * as ledger from './ledger';
import { OIDC, createSession, principalFromClaims } from './oidc';

// SAML 2.0 single sign-on (BP 2 principle 8, 11.4: "any OIDC/SAML"). Signet is the service provider; the
// customer's identity provider (Microsoft Entra ID, Okta, Ping, ADFS, Google Workspace, Keycloak ...)
// signs the assertion. Signature, audience, time window and InResponseTo checks are done by the
// open-source @node-saml/node-saml library (MIT). Every request ID is stored in PostgreSQL and used once,
// so responses that were not asked for, or that are replayed, are refused on every Signet instance.
//
//   SIGNET_AUTH_MODE=saml
//   SIGNET_SAML_IDP_SSO_URL      the identity provider's SSO (HTTP-Redirect) URL
//   SIGNET_SAML_IDP_CERT         its signing certificate, PEM or base64 (several separated by ";" during rotation)
//   SIGNET_SAML_IDP_ENTITY_ID    optional: refuse assertions from any other issuer
//   SIGNET_SAML_SP_ENTITY_ID     default <public URL>/api/v1/auth/saml/metadata
//   SIGNET_SAML_ATTR_EMAIL / _NAME / _GROUPS   attribute names when the defaults below do not match
// The identity provider needs: ACS URL <public URL>/api/v1/auth/saml/acs, the SP entity ID above, signed
// assertions, and a groups attribute (roles come from groups, as with OIDC).

const CLAIM = {
  email: ['email', 'mail', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', 'urn:oid:0.9.2342.19200300.100.1.3'],
  name: ['name', 'displayName', 'http://schemas.microsoft.com/identity/claims/displayname', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', 'urn:oid:2.16.840.1.113730.3.1.241'],
  groups: ['groups', 'memberOf', 'Role', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'],
};
// Signals that the identity provider used more than one factor.
const MFA = /MultiFactor|multipleauthn|mfa|TimeSyncToken|Smartcard|X509|PhishingResistant/i;

const REQUEST_TTL_MS = 10 * 60_000;

/** Request IDs in the database, so the AuthnRequest and the response can land on different instances. */
export const dbCache: CacheProvider = {
  async saveAsync(key, value) {
    await db.prepare('INSERT INTO saml_request (id, value, expires_ms) VALUES (?, ?, ?) ON CONFLICT (id) DO NOTHING').run(key, value, Date.now() + REQUEST_TTL_MS);
    await db.prepare('DELETE FROM saml_request WHERE expires_ms < ?').run(Date.now());
    return { value, createdAt: Date.now() };
  },
  async getAsync(key) {
    const r = (await db.prepare('SELECT value FROM saml_request WHERE id = ? AND expires_ms > ?').get(key, Date.now())) as { value: string } | undefined;
    return r?.value ?? null;
  },
  async removeAsync(key) {
    if (!key) return null;
    const r = (await db.prepare('DELETE FROM saml_request WHERE id = ? RETURNING id').get(key)) as { id: string } | undefined;
    return r?.id ?? null;
  },
};

const pem = (raw: string) => raw.replace(/\\n/g, '\n').trim();

export function samlConfig(e = process.env) {
  const entryPoint = e.SIGNET_SAML_IDP_SSO_URL?.trim();
  const certs = (e.SIGNET_SAML_IDP_CERT ?? '').split(';').map(pem).filter(Boolean);
  if (!entryPoint || !certs.length) throw new PolicyError('AUTH', 'SAML sign-in needs SIGNET_SAML_IDP_SSO_URL and SIGNET_SAML_IDP_CERT', 503);
  const publicUrl = OIDC.publicUrl.replace(/\/$/, '');
  return {
    entryPoint,
    idpCert: certs.length === 1 ? certs[0]! : certs,
    idpIssuer: e.SIGNET_SAML_IDP_ENTITY_ID?.trim() || undefined,
    issuer: e.SIGNET_SAML_SP_ENTITY_ID?.trim() || `${publicUrl}/api/v1/auth/saml/metadata`,
    callbackUrl: `${publicUrl}/api/v1/auth/saml/acs`,
    attrs: { email: e.SIGNET_SAML_ATTR_EMAIL, name: e.SIGNET_SAML_ATTR_NAME, groups: e.SIGNET_SAML_ATTR_GROUPS },
  };
}

function client(e = process.env) {
  const c = samlConfig(e);
  return new SAML({
    entryPoint: c.entryPoint,
    idpCert: c.idpCert,
    idpIssuer: c.idpIssuer,
    issuer: c.issuer,
    audience: c.issuer,
    callbackUrl: c.callbackUrl,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false, // many providers sign only the assertion; the assertion signature is required
    signatureAlgorithm: 'sha256',
    validateInResponseTo: ValidateInResponseTo.always, // no unsolicited (IdP-initiated) or replayed responses
    requestIdExpirationPeriodMs: REQUEST_TTL_MS,
    cacheProvider: dbCache,
    acceptedClockSkewMs: 120_000,
    identifierFormat: null,
    disableRequestedAuthnContext: true,
  });
}

const safeReturn = (v: unknown) => (typeof v === 'string' && v.startsWith('/') && !v.startsWith('//') ? v : '/');

export async function login(req: Request, res: Response) {
  const url = await client().getAuthorizeUrlAsync(safeReturn(req.query.return_to), undefined, {});
  res.redirect(url);
}

const first = (p: Profile, names: (string | undefined)[]): unknown => {
  for (const n of names) if (n && p[n] !== undefined && p[n] !== null && p[n] !== '') return p[n];
  return undefined;
};
const asList = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)]);

/** The person in a validated SAML profile, in the same shape as an OIDC sign-in (roles from groups). */
export function principalFromProfile(p: Profile, attrs: { email?: string; name?: string; groups?: string[] | string } = {}) {
  const email = String(first(p, [attrs.email as string, ...CLAIM.email]) ?? (/@/.test(p.nameID) ? p.nameID : '')).toLowerCase();
  if (!email) throw new PolicyError('AUTH', 'the SAML assertion has no email address (set SIGNET_SAML_ATTR_EMAIL)', 401);
  const groups = asList(first(p, [attrs.groups as string, ...CLAIM.groups])).map((g) => g.replace(/^.*[\\/]/, '').trim()).filter(Boolean);
  const context = JSON.stringify(p.getAssertion?.() ?? {});
  const now = Math.floor(Date.now() / 1000);
  return principalFromClaims({
    iss: `saml:${p.issuer}`, sub: p.nameID, aud: 'signet', email, name: String(first(p, [attrs.name as string, ...CLAIM.name]) ?? email),
    groups, amr: MFA.test(context) ? ['mfa'] : [], auth_time: now, exp: now + 3600,
  }, 'session');
}

/** Assertion Consumer Service: validate the signed response, then start a session. */
export async function acs(req: Request, res: Response) {
  const body = req.body as Record<string, string> | undefined;
  if (!body?.SAMLResponse) throw new PolicyError('AUTH', 'SAMLResponse is missing', 400);
  const c = samlConfig();
  let profile: Profile | null;
  try {
    ({ profile } = await client().validatePostResponseAsync({ SAMLResponse: body.SAMLResponse }));
  } catch (e) {
    await ledger.append({ kind: 'admin', data: { event: 'auth.saml_rejected', reason: (e as Error).message.slice(0, 300), at: nowIso() } });
    throw new PolicyError('AUTH', `SAML sign-in refused: ${(e as Error).message}`, 401);
  }
  if (!profile) throw new PolicyError('AUTH', 'SAML response carried no sign-in', 401);
  const principal = principalFromProfile(profile, { email: c.attrs.email, name: c.attrs.name, groups: c.attrs.groups });
  await createSession(res, principal, null);
  await ledger.append({ kind: 'admin', data: { event: 'auth.saml_signed_in', actor: principal.id, issuer: profile.issuer, roles: principal.roles, mfa: principal.mfa } });
  res.redirect(`${OIDC.publicUrl}${safeReturn(body.RelayState)}`);
}

/** Service provider metadata for the identity provider. */
export function metadata(res: Response) {
  res.type('application/samlmetadata+xml').send(client().generateServiceProviderMetadata(null, null));
}

export const samlSettings = () => {
  try {
    const c = samlConfig();
    return { configured: true, sp_entity_id: c.issuer, acs_url: c.callbackUrl, idp_sso_url: c.entryPoint, idp_entity_id: c.idpIssuer ?? null };
  } catch {
    return { configured: false, mode_active: env('SIGNET_AUTH_MODE', 'local') === 'saml' };
  }
};

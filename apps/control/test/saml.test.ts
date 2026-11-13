import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// SAML 2.0 sign-in (BP 11.4). Signature checks are node-saml's; this covers Signet's side: settings, the
// one-time request store, and turning a validated profile into a person with roles from groups.
// The full flow was checked against Keycloak as a SAML identity provider (sign-in, replay and tampering).
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-saml-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const saml = await import('../src/saml');
after(dropTestDatabase);

test('settings: SSO URL and certificate are required; several certificates allowed during rotation', () => {
  assert.throws(() => saml.samlConfig({}), /SIGNET_SAML_IDP_SSO_URL/);
  const c = saml.samlConfig({ SIGNET_SAML_IDP_SSO_URL: 'https://idp/sso', SIGNET_SAML_IDP_CERT: 'AAA;BBB' });
  assert.deepEqual(c.idpCert, ['AAA', 'BBB']);
  assert.match(c.callbackUrl, /\/api\/v1\/auth\/saml\/acs$/);
});

test('request IDs: stored, read once, then gone (no replay across instances)', async () => {
  await saml.dbCache.saveAsync('_req1', '2026-11-13T10:00:00Z');
  assert.equal(await saml.dbCache.getAsync('_req1'), '2026-11-13T10:00:00Z');
  assert.equal(await saml.dbCache.removeAsync('_req1'), '_req1');
  assert.equal(await saml.dbCache.getAsync('_req1'), null);
  assert.equal(await saml.dbCache.removeAsync('_req1'), null);
});

test('profile to person: Entra claim names, groups to roles, MFA from the authentication context', () => {
  const entra = saml.principalFromProfile({
    issuer: 'https://sts.windows.net/t/', nameID: 'abc', nameIDFormat: 'persistent',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'Priya.Menon@Northwind.example',
    'http://schemas.microsoft.com/identity/claims/displayname': 'Priya Menon',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups': ['signet-risk-officers', 'everyone'],
    getAssertion: () => ({ AuthnContextClassRef: 'http://schemas.microsoft.com/claims/multipleauthn' }),
  } as never);
  assert.deepEqual([entra.id, entra.name, entra.roles, entra.mfa], ['priya.menon@northwind.example', 'Priya Menon', ['risk_officer'], true]);
  const plain = saml.principalFromProfile({ issuer: 'okta', nameID: 'jonas@northwind.example', nameIDFormat: 'email', groups: '/signet/signet-security-officers' } as never);
  assert.deepEqual([plain.id, plain.roles, plain.mfa], ['jonas@northwind.example', ['security_officer'], false]);
  assert.throws(() => saml.principalFromProfile({ issuer: 'x', nameID: 'opaque-id', nameIDFormat: 'persistent' } as never), /no email/);
});

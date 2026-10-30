import { env } from './env';

// Dev-only helpers for scripts and CLIs: get OAuth tokens from the dev identity provider.
// People use the dev realm's password grant (enabled only for the signet-dev-cli client in the dev
// realm); machines use client credentials, as CI/CD would in production (BP 13).

const ISSUER = () => env('SIGNET_OIDC_ISSUER', 'http://localhost:8180/realms/signet');

async function token(params: Record<string, string>): Promise<string> {
  const r = await fetch(`${ISSUER()}/protocol/openid-connect/token`, { method: 'POST', body: new URLSearchParams(params) });
  const j = (await r.json()) as { access_token?: string; error_description?: string };
  if (!j.access_token) throw new Error(`identity provider refused the token request: ${j.error_description ?? r.status}`);
  return j.access_token;
}

export const devUserToken = (username: string, password = env('SIGNET_DEV_PASSWORD', 'Signet!2026')) =>
  token({ grant_type: 'password', client_id: 'signet-dev-cli', username, password, scope: 'openid' });

export const automationToken = () =>
  token({ grant_type: 'client_credentials', client_id: env('SIGNET_AUTOMATION_CLIENT_ID', 'signet-automation'), client_secret: env('SIGNET_AUTOMATION_CLIENT_SECRET', 'signet-automation-dev-secret') });

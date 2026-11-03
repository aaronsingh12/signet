import type { IncomingHttpHeaders } from 'node:http';
import { request, sha256 } from '@signet/core';
import * as state from './state';

// No-code connection (Phase A1): many agents and platforms can only be configured with a base URL and an
// API key (OPENAI_BASE_URL + OPENAI_API_KEY, or a framework's "API key" field). They can send Signet's
// deployment credential (sdc_…) as that key. The gateway exchanges it for the agent's short-lived
// workload token, so every check downstream is exactly the one a token-holding agent gets.
// Exchanges are cached for 60 s only, so revoking the credential takes effect within a minute; a kill or
// quarantine revokes the token itself and is refused at once.

const CACHE_MS = 60_000;
const cache = new Map<string, { token: string; until: number }>();

function presentedKey(headers: IncomingHttpHeaders): { key: string; from: 'authorization' | 'x-api-key' | 'api-key' } | null {
  const bearer = String(headers.authorization ?? '').match(/^Bearer\s+(sdc_[A-Za-z0-9_-]+)$/);
  if (bearer) return { key: bearer[1]!, from: 'authorization' };
  for (const h of ['x-api-key', 'api-key'] as const) {
    const v = headers[h];
    if (typeof v === 'string' && /^sdc_[A-Za-z0-9_-]+$/.test(v)) return { key: v, from: h };
  }
  return null;
}

export class ApiKeyRefused extends Error {
  constructor(readonly status: number, readonly body: string) {
    super(`deployment credential refused (${status})`);
  }
}

/** Swap a presented deployment credential for a workload token in place; no-op for other headers. */
export async function resolveApiKey(headers: IncomingHttpHeaders): Promise<void> {
  const found = presentedKey(headers);
  if (!found) return;
  const id = sha256(found.key);
  const hit = cache.get(id);
  let token = hit && hit.until > Date.now() ? hit.token : null;
  if (!token) {
    const r = await request(`${state.CONTROL_URL}/api/v1/identity/deployment-token`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ deployment_credential: found.key }), timeoutMs: 5000,
    });
    if (!r.ok) {
      cache.delete(id);
      throw new ApiKeyRefused(r.status, r.text());
    }
    const body = r.json<{ token: string; expires_in: number }>();
    token = body.token;
    cache.set(id, { token, until: Date.now() + Math.min(CACHE_MS, Math.max(0, body.expires_in * 1000 - 30_000)) });
    if (cache.size > 5000) for (const [k, v] of cache) if (v.until < Date.now()) cache.delete(k);
  }
  headers.authorization = `Bearer ${token}`;
  delete headers['x-api-key'];
  delete headers['api-key'];
}

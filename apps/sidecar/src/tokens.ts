import { readFileSync } from 'node:fs';
import { request } from '@signet/core';

// Workload identity for Node runtimes: exchange the one-time bootstrap credential (or OAuth client
// credentials) for a short-lived token and refresh it before it expires. The sidecar uses this; a
// Node SDK would expose the same class.

export interface IdentityConfig {
  controlUrl: string;
  bootstrapCredential?: string;
  clientId?: string;
  clientSecret?: string;
  deploymentCredential?: string;
}

export interface Claims {
  agent_id: string;
  ver: string;
  ins: string;
  tier: string;
  exp: number;
  iat: number;
  [k: string]: unknown;
}

export class AuthError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

const REFRESH_MARGIN_S = 120;

export function decodeClaims(token: string): Claims {
  return JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8')) as Claims;
}

export function identityFromEnv(env = process.env): IdentityConfig {
  const controlUrl = env.SIGNET_CONTROL_URL?.replace(/\/$/, '');
  if (!controlUrl) throw new Error('SIGNET_CONTROL_URL is required');
  let bootstrap = env.SIGNET_BOOTSTRAP_CREDENTIAL?.trim();
  if (!bootstrap && env.SIGNET_BOOTSTRAP_FILE) bootstrap = readFileSync(env.SIGNET_BOOTSTRAP_FILE, 'utf8').trim();
  return { controlUrl, bootstrapCredential: bootstrap || undefined, clientId: env.SIGNET_CLIENT_ID?.trim() || undefined, clientSecret: env.SIGNET_CLIENT_SECRET?.trim() || undefined };
}

export class TokenManager {
  private token: string | null = null;
  private claimsCache: Claims | null = null;
  private bootstrapUsed = false;
  private inflight: Promise<string> | null = null;
  lastError: string | null = null;

  constructor(readonly config: IdentityConfig) {}

  get claims() {
    return this.claimsCache;
  }

  async get(): Promise<string> {
    const now = Date.now() / 1000;
    if (this.token && this.claimsCache && this.claimsCache.exp - REFRESH_MARGIN_S > now) return this.token;
    this.inflight ??= this.renew().finally(() => (this.inflight = null));
    return this.inflight;
  }

  invalidate() {
    this.token = null;
    this.claimsCache = null;
  }

  private async renew(): Promise<string> {
    const now = Date.now() / 1000;
    try {
      if (this.token && this.claimsCache && this.claimsCache.exp > now + 5) {
        try {
          return this.set(await this.post('/api/v1/identity/token/refresh', {}, { authorization: `Bearer ${this.token}` }));
        } catch (e) {
          if (!(e instanceof AuthError)) throw e;
          this.invalidate();
        }
      }
      const c = this.config;
      if (c.deploymentCredential) return this.set(await this.post('/api/v1/identity/deployment-token', { deployment_credential: c.deploymentCredential }));
      if (c.clientId && c.clientSecret) return this.set(await this.post('/api/v1/identity/token', { grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret }));
      if (c.bootstrapCredential && !this.bootstrapUsed) {
        this.bootstrapUsed = true; // single use, whatever the outcome
        return this.set(await this.post('/api/v1/identity/token', { bootstrap_credential: c.bootstrapCredential }));
      }
      throw new AuthError(c.bootstrapCredential ? 'the workload token lapsed and the bootstrap credential was already used; redeploy with a new one' : 'no credentials: set SIGNET_BOOTSTRAP_CREDENTIAL (or _FILE), or SIGNET_CLIENT_ID and SIGNET_CLIENT_SECRET');
    } catch (e) {
      this.lastError = (e as Error).message;
      throw e;
    }
  }

  private set(body: { token?: string; access_token?: string }) {
    const t = body.token ?? body.access_token;
    if (!t) throw new AuthError('Signet did not return a token');
    this.token = t;
    this.claimsCache = decodeClaims(t);
    this.lastError = null;
    return t;
  }

  private async post(path: string, body: unknown, headers: Record<string, string> = {}) {
    let r;
    try {
      r = await request(`${this.config.controlUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), timeoutMs: 15_000 });
    } catch (e) {
      throw new Error(`cannot reach the Signet control plane at ${this.config.controlUrl}: ${(e as Error).message}`);
    }
    const text = r.text();
    const json = text ? (JSON.parse(text) as Record<string, string>) : {};
    if (r.status >= 500) throw new Error(`Signet control plane error ${r.status}: ${json.detail ?? text.slice(0, 200)}`);
    if (!r.ok) throw new AuthError(json.detail ?? `identity request refused (${r.status})`, r.status);
    return json;
  }
}

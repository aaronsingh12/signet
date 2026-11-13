import { createHash, randomBytes } from 'node:crypto';
import { devSecret, seal, signAws, unseal } from '@signet/core';

// Key service for the Secrets Broker (BP 3 C9, 15.2, 18.2). Every secret is sealed with its own random
// data key (AES-256-GCM); the data key is wrapped by a key-encryption key that lives in a key service
// the customer controls. Revoking that key (BYOK) makes every brokered credential unreadable to Signet,
// so agents stop: fail closed.
//
//   SIGNET_KMS_PROVIDER=local     (default) data keys wrapped with SIGNET_BROKER_KEY
//   SIGNET_KMS_PROVIDER=vault     HashiCorp Vault or OpenBao transit engine
//       SIGNET_VAULT_ADDR, SIGNET_VAULT_TOKEN, SIGNET_VAULT_TRANSIT_MOUNT (transit), SIGNET_VAULT_TRANSIT_KEY (signet),
//       SIGNET_VAULT_NAMESPACE (optional, Vault Enterprise / HCP)
//   SIGNET_KMS_PROVIDER=aws-kms   AWS KMS (symmetric key)
//       SIGNET_AWS_KMS_KEY_ID, SIGNET_AWS_KMS_REGION, SIGNET_AWS_KMS_ACCESS_KEY_ID, SIGNET_AWS_KMS_SECRET_ACCESS_KEY
//
// Sealed format: "env1.<provider>.<wrapped data key, base64url>.<iv>.<tag>.<ciphertext>". Values sealed before
// envelope encryption (three dot-separated parts) are still read with SIGNET_BROKER_KEY.

export type ProviderId = 'local' | 'vault' | 'aws-kms';
interface Provider { id: ProviderId; describe: string; wrap(dek: Buffer): Promise<string>; unwrap(wrapped: string): Promise<Buffer> }

const b64u = (b: Buffer | string) => Buffer.from(b).toString('base64url');
const localKey = () => Buffer.from(devSecret('SIGNET_BROKER_KEY'), 'base64url').subarray(0, 32);

const local: Provider = {
  id: 'local',
  describe: 'local key (SIGNET_BROKER_KEY)',
  async wrap(dek) { return b64u(seal(dek.toString('base64'), localKey())); },
  async unwrap(w) { return Buffer.from(unseal(Buffer.from(w, 'base64url').toString(), localKey()), 'base64'); },
};

function vault(env: NodeJS.ProcessEnv): Provider {
  const addr = env.SIGNET_VAULT_ADDR?.replace(/\/$/, '');
  const token = env.SIGNET_VAULT_TOKEN;
  if (!addr || !token) throw new Error('SIGNET_VAULT_ADDR and SIGNET_VAULT_TOKEN are required for SIGNET_KMS_PROVIDER=vault');
  const mount = env.SIGNET_VAULT_TRANSIT_MOUNT ?? 'transit';
  const key = env.SIGNET_VAULT_TRANSIT_KEY ?? 'signet';
  const call = async (op: 'encrypt' | 'decrypt', body: Record<string, string>) => {
    const r = await fetch(`${addr}/v1/${mount}/${op}/${encodeURIComponent(key)}`, {
      method: 'POST', body: JSON.stringify(body), signal: AbortSignal.timeout(10_000),
      headers: { 'content-type': 'application/json', 'x-vault-token': token, ...(env.SIGNET_VAULT_NAMESPACE ? { 'x-vault-namespace': env.SIGNET_VAULT_NAMESPACE } : {}) },
    });
    const j = (await r.json().catch(() => ({}))) as { data?: { ciphertext?: string; plaintext?: string }; errors?: string[] };
    if (!r.ok) throw new Error(`Vault transit ${op} failed (${r.status}: ${(j.errors ?? []).join('; ').slice(0, 200)})`);
    return j.data ?? {};
  };
  return {
    id: 'vault',
    describe: `Vault/OpenBao transit key ${mount}/${key} at ${addr}`,
    async wrap(dek) { const c = (await call('encrypt', { plaintext: dek.toString('base64') })).ciphertext; if (!c) throw new Error('Vault returned no ciphertext'); return b64u(c); },
    async unwrap(w) { const p = (await call('decrypt', { ciphertext: Buffer.from(w, 'base64url').toString() })).plaintext; if (!p) throw new Error('Vault returned no plaintext'); return Buffer.from(p, 'base64'); },
  };
}

function awsKms(env: NodeJS.ProcessEnv): Provider {
  const keyId = env.SIGNET_AWS_KMS_KEY_ID;
  const region = env.SIGNET_AWS_KMS_REGION;
  const creds = { access_key_id: env.SIGNET_AWS_KMS_ACCESS_KEY_ID ?? '', secret_access_key: env.SIGNET_AWS_KMS_SECRET_ACCESS_KEY ?? '', session_token: env.SIGNET_AWS_KMS_SESSION_TOKEN };
  if (!keyId || !region || !creds.access_key_id || !creds.secret_access_key) throw new Error('SIGNET_AWS_KMS_KEY_ID, SIGNET_AWS_KMS_REGION, SIGNET_AWS_KMS_ACCESS_KEY_ID and SIGNET_AWS_KMS_SECRET_ACCESS_KEY are required for SIGNET_KMS_PROVIDER=aws-kms');
  const endpoint = env.SIGNET_AWS_KMS_ENDPOINT ?? `https://kms.${region}.amazonaws.com/`;
  const call = async (target: 'Encrypt' | 'Decrypt', body: Record<string, string>) => {
    const url = new URL(endpoint);
    const text = JSON.stringify(body);
    const headers = signAws({ method: 'POST', url, region, service: 'kms', body: text, credentials: creds, headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': `TrentService.${target}` } });
    delete headers.host;
    const r = await fetch(url, { method: 'POST', headers, body: text, signal: AbortSignal.timeout(10_000) });
    const j = (await r.json().catch(() => ({}))) as { CiphertextBlob?: string; Plaintext?: string; message?: string; __type?: string };
    if (!r.ok) throw new Error(`AWS KMS ${target} failed (${r.status}: ${j.__type ?? ''} ${j.message ?? ''})`.trim());
    return j;
  };
  return {
    id: 'aws-kms',
    describe: `AWS KMS key ${keyId} (${region})`,
    async wrap(dek) { const c = (await call('Encrypt', { KeyId: keyId, Plaintext: dek.toString('base64') })).CiphertextBlob; if (!c) throw new Error('KMS returned no ciphertext'); return b64u(Buffer.from(c, 'base64')); },
    async unwrap(w) { const p = (await call('Decrypt', { KeyId: keyId, CiphertextBlob: Buffer.from(w, 'base64url').toString('base64') })).Plaintext; if (!p) throw new Error('KMS returned no plaintext'); return Buffer.from(p, 'base64'); },
  };
}

export function provider(id?: string, env = process.env): Provider {
  const which = (id ?? env.SIGNET_KMS_PROVIDER ?? 'local').toLowerCase();
  if (which === 'local') return local;
  if (which === 'vault') return vault(env);
  if (which === 'aws-kms') return awsKms(env);
  throw new Error(`SIGNET_KMS_PROVIDER must be local, vault or aws-kms (got ${which})`);
}

// Unwrapped data keys are cached in memory for a short time, so reading the same secret again (every
// policy bundle build) does not call the key service each time. Revoking the key takes effect within the
// cache lifetime.
const CACHE_MS = 5 * 60_000;
const cache = new Map<string, { dek: Buffer; until: number }>();
async function unwrapCached(p: Provider, wrapped: string): Promise<Buffer> {
  const k = createHash('sha256').update(`${p.id}.${wrapped}`).digest('hex');
  const hit = cache.get(k);
  if (hit && hit.until > Date.now()) return hit.dek;
  const dek = await p.unwrap(wrapped);
  if (dek.length !== 32) throw new Error('the key service returned a data key of the wrong length');
  if (cache.size > 2000) cache.clear();
  cache.set(k, { dek, until: Date.now() + CACHE_MS });
  return dek;
}
export const clearKeyCache = () => cache.clear();

/** Seal a value with a fresh data key wrapped by the configured key service. */
export async function sealValue(value: string): Promise<string> {
  const p = provider();
  const dek = randomBytes(32);
  return `env1.${p.id}.${await p.wrap(dek)}.${seal(value, dek)}`;
}

/** Open a sealed value, whichever key service sealed it. */
export async function openValue(sealed: string): Promise<string> {
  if (!sealed.startsWith('env1.')) return unseal(sealed, localKey()); // sealed before envelope encryption
  const [, pid, wrapped, ...rest] = sealed.split('.');
  return unseal(rest.join('.'), await unwrapCached(provider(pid), wrapped!));
}

/** Which key service sealed this value ("legacy" = before envelope encryption). */
export const sealedBy = (sealed: string): string => (sealed.startsWith('env1.') ? sealed.split('.')[1]! : 'legacy');

/** Round trip through the configured key service. */
export async function checkProvider(): Promise<{ provider: string; describe: string; ok: boolean; detail: string }> {
  try {
    const p = provider();
    const dek = randomBytes(32);
    const back = await p.unwrap(await p.wrap(dek));
    return { provider: p.id, describe: p.describe, ok: back.equals(dek), detail: back.equals(dek) ? 'wrap and unwrap work' : 'the key service returned a different key' };
  } catch (e) {
    return { provider: process.env.SIGNET_KMS_PROVIDER ?? 'local', describe: '', ok: false, detail: (e as Error).message };
  }
}

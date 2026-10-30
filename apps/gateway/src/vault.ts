import { randomBytes } from 'node:crypto';
import { devSecret, seal, unseal, type DataTag } from '@signet/core';

// Tokenisation vault (BP 5.3): values are swapped for tokens before they reach the cloud LLM and
// restored only in responses to the same agent and session (RB-DATA-06).
// Phase 1 keeps the vault in gateway memory; the per-tenant vault with KMS keys follows with the
// Secrets Broker.

const KEY = Buffer.from(devSecret('SIGNET_VAULT_KEY'), 'base64url').subarray(0, 32);
const TTL_MS = 24 * 3_600_000;
const TOKEN_RE = /<tok:([a-z_]+):([0-9a-f]{12})>/g;

interface Entry {
  sealed: string;
  agentId: string;
  sessionId: string;
  expires: number;
}

const entries = new Map<string, Entry>();

export function tokenise(value: string, tag: DataTag, agentId: string, sessionId: string): string {
  const token = `<tok:${tag}:${randomBytes(6).toString('hex')}>`;
  entries.set(token, { sealed: seal(value, KEY), agentId, sessionId, expires: Date.now() + TTL_MS });
  return token;
}

export function detokenise(text: string, agentId: string, sessionId: string): { text: string; restored: number } {
  let restored = 0;
  const out = text.replace(TOKEN_RE, (token) => {
    const e = entries.get(token);
    if (!e || e.expires < Date.now() || e.agentId !== agentId || e.sessionId !== sessionId) return token;
    restored++;
    return unseal(e.sealed, KEY);
  });
  return { text: out, restored };
}

setInterval(() => {
  const now = Date.now();
  for (const [k, e] of entries) if (e.expires < now) entries.delete(k);
}, 60_000).unref();

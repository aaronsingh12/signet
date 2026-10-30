import { randomBytes } from 'node:crypto';

// ULIDs (BP 4.1): 10 chars of millisecond time + 16 chars of randomness, Crockford base32.
// They sort by creation time and need no central counter.
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function ulid(now = Date.now()): string {
  let t = now;
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = B32[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const r = randomBytes(16);
  let rand = '';
  for (const b of r) rand += B32[b & 31];
  return time + rand;
}

export type IdPrefix = 'agt' | 'crt' | 'ins' | 'rec' | 'evt' | 'tnt' | 'boot' | 'jti' | 'bnd' | 'req' | 'sec' | 'cbk' | 'fnd' | 'ses';

export const newId = (prefix: IdPrefix) => `${prefix}_${ulid()}`;

export const agentUrn = (tenantId: string, agentId: string) => `urn:signet:${tenantId}:agent:${agentId}`;
export const spiffeId = (tenantId: string, agentId: string, version: string) => `spiffe://${tenantId}.signet/agent/${agentId}/v/${version}`;

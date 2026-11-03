import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DATA_DIR, generateSigningKey, loadSigningKey, toJwk, ulid, type SigningKey, type StoredKey } from '@signet/core';

// Three tenant keys (BP 4.2, 4.3, 8.3): the certificate authority (seals and policy bundles),
// the workload token issuer, and the ledger key (daily roots). Dev keeps them on disk;
// production holds them in KMS/HSM.
type KeyRole = 'ca' | 'token' | 'ledger';

const file = join(DATA_DIR, 'keys.json');
const stored: Record<KeyRole, StoredKey> = existsSync(file)
  ? JSON.parse(readFileSync(file, 'utf8'))
  : { ca: generateSigningKey(`ca-${ulid()}`), token: generateSigningKey(`tok-${ulid()}`), ledger: generateSigningKey(`ldg-${ulid()}`) };
if (!existsSync(file)) writeFileSync(file, JSON.stringify(stored, null, 2), { mode: 0o600 });

export const keys: Record<KeyRole, SigningKey> = {
  ca: loadSigningKey(stored.ca),
  token: loadSigningKey(stored.token),
  ledger: loadSigningKey(stored.ledger),
};

export const jwks = () => ({ keys: [toJwk(keys.ca), toJwk(keys.token), toJwk(keys.ledger)] });

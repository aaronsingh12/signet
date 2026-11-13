import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { devSecret, seal } from '@signet/core';
import { dropTestDatabase } from './database';

// Secrets Broker envelope encryption (BP 18.2): per-secret data keys wrapped by a key service.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-keyring-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
delete process.env.SIGNET_KMS_PROVIDER;
const keyring = await import('../src/keyring');
const { db } = await import('../src/db');
const secrets = await import('../src/secrets');
const { permissionsFor } = await import('../src/rbac');
after(dropTestDatabase);
const admin = { id: 'sec@x.example', name: 'sec', kind: 'human' as const, roles: ['platform_admin' as const], permissions: permissionsFor(['platform_admin']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };

test('local key service: per-secret data keys; secrets sealed before envelope encryption still open', async () => {
  const a = await keyring.sealValue('sk-test-value-1');
  const b = await keyring.sealValue('sk-test-value-1');
  assert.ok(a.startsWith('env1.local.') && a !== b, 'a fresh data key every time');
  assert.equal(await keyring.openValue(a), 'sk-test-value-1');
  const legacy = seal('old-secret-value', Buffer.from(devSecret('SIGNET_BROKER_KEY'), 'base64url').subarray(0, 32));
  assert.equal(keyring.sealedBy(legacy), 'legacy');
  assert.equal(await keyring.openValue(legacy), 'old-secret-value');
  assert.throws(() => keyring.provider('nope'), /local, vault or aws-kms/);
  assert.throws(() => keyring.provider('aws-kms', {}), /SIGNET_AWS_KMS_KEY_ID/);
});

const vaultAddr = process.env.SIGNET_TEST_VAULT_ADDR;
test('Vault/OpenBao transit: wrap, re-wrap every secret, and fail closed when the key is gone', { skip: !vaultAddr && 'set SIGNET_TEST_VAULT_ADDR and SIGNET_TEST_VAULT_TOKEN to run' }, async () => {
  const s = await secrets.putSecret({ name: 'tool-before-vault', kind: 'tool', value: 'tool-credential-1' }, admin);
  Object.assign(process.env, { SIGNET_KMS_PROVIDER: 'vault', SIGNET_VAULT_ADDR: vaultAddr, SIGNET_VAULT_TOKEN: process.env.SIGNET_TEST_VAULT_TOKEN, SIGNET_VAULT_TRANSIT_KEY: 'signet' });
  assert.equal((await keyring.checkProvider()).ok, true);
  const status = await secrets.keyStatus();
  assert.deepEqual(status.sealed_by, { local: 1 });
  const r = await secrets.rewrapAll(admin);
  assert.deepEqual([r.provider, r.rewrapped], ['vault', 1]);
  const row = (await db.prepare('SELECT sealed FROM secret WHERE id = ?').get(s.id)) as { sealed: string };
  assert.match(row.sealed, /^env1\.vault\./);
  assert.equal((await secrets.revealForGateway(s.id)).value, 'tool-credential-1');
  assert.equal((await secrets.getSecretMeta(s.id)).fingerprint, s.fingerprint, 'same credential, same fingerprint');

  // The customer revokes Signet's access to the key: credentials can no longer be opened (fail closed).
  keyring.clearKeyCache();
  process.env.SIGNET_VAULT_TOKEN = 'revoked-token';
  await assert.rejects(secrets.revealForGateway(s.id), /Vault transit decrypt failed/);
  process.env.SIGNET_VAULT_TOKEN = process.env.SIGNET_TEST_VAULT_TOKEN;
  delete process.env.SIGNET_KMS_PROVIDER;
});

import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';

test('local administrator requires configured credentials and does not provision demo identities', async () => {
  const password = randomBytes(32).toString('hex');
  process.env.SIGNET_ADMIN_ID = 'test-admin';
  process.env.SIGNET_ADMIN_PASSWORD = password;
  const { localAdminProfile, verifyLocalAdminCredentials } = await import('../src/local-admin');
  const profile = localAdminProfile();
  assert.equal(profile.id, 'test-admin');
  assert.ok(!JSON.stringify(profile).includes(password));
  assert.doesNotThrow(() => verifyLocalAdminCredentials('test-admin', password));
  assert.throws(() => verifyLocalAdminCredentials('unconfigured-user', password), /invalid administrator ID or password/);
  assert.throws(() => verifyLocalAdminCredentials('test-admin', 'incorrect-password'), /invalid administrator ID or password/);
  delete process.env.SIGNET_ADMIN_PASSWORD;
  assert.throws(() => verifyLocalAdminCredentials('test-admin', password), /SIGNET_ADMIN_PASSWORD must be configured/);
});

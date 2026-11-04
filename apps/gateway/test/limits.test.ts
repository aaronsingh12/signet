import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-gw-limits-'));
// Nothing listens here, so the shared counters are unreachable and the local fallback is used.
process.env.SIGNET_CONTROL_URL = 'http://127.0.0.1:9';

const limits = await import('../src/limits');

test('unauthenticated refusals are recorded 20 times a minute per address, then not at all', () => {
  for (let i = 0; i < 20; i++) assert.equal(limits.takeAnonymousFailure('203.0.113.50'), true);
  assert.equal(limits.takeAnonymousFailure('203.0.113.50'), false);
  assert.equal(limits.takeAnonymousFailure('198.51.100.1'), true, 'other addresses are unaffected');
});

test('without the control plane, rate limits fall back to this node\'s counters', async () => {
  assert.equal((await limits.takeRequest('agt_fallback', 2)).allowed, true);
  assert.equal((await limits.takeRequest('agt_fallback', 2)).allowed, true);
  assert.equal((await limits.takeRequest('agt_fallback', 2)).allowed, false);
});

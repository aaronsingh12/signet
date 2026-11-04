import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Counters shared across instances: limits, sign-in throttling and stale gateway cleanup.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-counters-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);

after(async () => {
  await dropTestDatabase();
});

const counters = await import('../src/counters');
const { db } = await import('../src/db');

test('request windows and daily usage are counted in the database, not per instance', async () => {
  const first = await counters.takeRequest('agt_counter_a');
  const second = await counters.takeRequest('agt_counter_a');
  assert.equal(second.in_minute, first.in_minute + 1);
  await counters.addUsage('agt_counter_a', 120, 0.5);
  await counters.addUsage('agt_counter_a', 30, 0.25);
  const third = await counters.takeRequest('agt_counter_a');
  assert.equal(third.tokens_today, 150);
  assert.equal(third.usd_today, 0.75);
  assert.equal((await counters.takeRequest('agt_counter_b')).in_minute, 1, 'agents count separately');
});

test('out-of-manifest attempts accumulate and erasing the agent clears its counters', async () => {
  assert.equal(await counters.recordOutOfManifest('agt_counter_c'), 1);
  assert.equal(await counters.recordOutOfManifest('agt_counter_c'), 2);
  await counters.eraseAgent('agt_counter_c');
  assert.equal(await counters.recordOutOfManifest('agt_counter_c'), 1);
});

test('failed sign-ins lock out an address after ten attempts, other addresses keep working', async () => {
  for (let i = 0; i < 10; i++) {
    await counters.assertLoginAllowed('203.0.113.7', 'admin');
    await counters.recordLoginFailure('203.0.113.7', 'admin');
  }
  await assert.rejects(counters.assertLoginAllowed('203.0.113.7', 'admin'), (e: { status: number }) => e.status === 429);
  await counters.assertLoginAllowed('198.51.100.9', 'someone-else');
});

test('sweep removes expired counters and gateway nodes that stopped sending heartbeats', async () => {
  await db.prepare('INSERT INTO shared_counter (key, n, tokens, usd, expires_ms) VALUES (?, 1, 0, 0, ?)').run('rpm:old:1', Date.now() - 1);
  await db.prepare('INSERT INTO gateway_node (id, url, last_seen) VALUES (?, ?, ?)').run('gw-old', 'http://localhost:3000', new Date(Date.now() - 3_600_000).toISOString());
  await db.prepare('INSERT INTO gateway_node (id, url, last_seen) VALUES (?, ?, ?)').run('gw-live', 'http://localhost:3000', new Date().toISOString());
  await counters.sweep();
  assert.equal(await db.prepare('SELECT 1 FROM shared_counter WHERE key = ?').get('rpm:old:1'), undefined);
  const nodes = ((await db.prepare('SELECT id FROM gateway_node').all()) as { id: string }[]).map((n) => n.id);
  assert.ok(nodes.includes('gw-live') && !nodes.includes('gw-old'));
});

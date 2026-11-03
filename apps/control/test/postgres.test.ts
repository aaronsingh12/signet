import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-pg-'));
process.env.SIGNET_DB_SCHEMA = `test_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
after(dropTestDatabase);

test('PostgreSQL isolates concurrent transactions and serializes the append-only ledger', { timeout: 60_000 }, async () => {
  const { db, tx } = await import('../src/db');
  const ledger = await import('../src/ledger');
  const insert = db.prepare('INSERT INTO notification (id, recipient, kind, title, created_at) VALUES (?, ?, ?, ?, ?)');
  await Promise.all([
    assert.rejects(tx(async () => {
      await insert.run('rolled-back', 'owner', 'test', 'Rollback', new Date().toISOString());
      await setTimeout(100);
      throw new Error('intentional transaction rollback');
    }), /intentional transaction rollback/),
    tx(async () => { await insert.run('committed', 'owner', 'test', 'Commit', new Date().toISOString()); }),
  ]);
  assert.equal(await db.prepare('SELECT id FROM notification WHERE id = ?').get('rolled-back'), undefined);
  assert.equal((await db.prepare('SELECT id FROM notification WHERE id = ?').get('committed'))?.id, 'committed');
  const records = await Promise.all(Array.from({ length: 8 }, (_, index) => ledger.append({ kind: 'admin', data: { event: 'postgres.concurrent', index } })));
  assert.equal(new Set(records.map((record) => record.seq)).size, 8);
  assert.equal((await ledger.verify()).ok, true);
  await assert.rejects(db.prepare('UPDATE ledger_record SET data = ?').run('{}'), /append-only/);
  await assert.rejects(db.prepare('DELETE FROM ledger_record').run(), /append-only/);
  await assert.rejects(db.exec('TRUNCATE TABLE ledger_record'), /append-only/);
  assert.equal((await ledger.all()).length, 8);
});

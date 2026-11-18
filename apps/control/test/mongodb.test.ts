import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-mongo-'));
process.env.MONGODB_DATABASE = `test_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
after(dropTestDatabase);

test('MongoDB isolates concurrent transactions and serializes the append-only ledger', { timeout: 60_000 }, async () => {
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
  const records = await Promise.all(Array.from({ length: 8 }, (_, index) => ledger.append({ kind: 'admin', data: { event: 'mongodb.concurrent', index } })));
  assert.equal(new Set(records.map((record) => record.seq)).size, 8);
  assert.equal((await ledger.verify()).ok, true);
  await assert.rejects(db.prepare('UPDATE ledger_record SET data = ?').run('{}'), /append-only/);
  await assert.rejects(db.prepare('DELETE FROM ledger_record').run(), /append-only/);
  await assert.rejects(db.exec('TRUNCATE TABLE ledger_record'), /append-only/);
  assert.equal((await ledger.all()).length, 8);
});

test('application records persist in native MongoDB collections across connections, with unique keys and required relationships', async () => {
  const { db } = await import('../src/db');
  const { MongoDatabase } = await import('../src/mongodb');
  const { MongoClient } = await import('mongodb');
  const uri = process.env.MONGODB_URL;
  if (!uri) throw new Error('MONGODB_URL is required for the real MongoDB integration test');
  const insert = db.prepare('INSERT INTO notification (id, recipient, kind, title, created_at) VALUES (?, ?, ?, ?, ?)');
  await insert.run('persistence-check', 'owner', 'test', 'MongoDB persistence', new Date().toISOString());
  await assert.rejects(insert.run('persistence-check', 'owner', 'test', 'Duplicate', new Date().toISOString()), { code: 11000 });
  const native = new MongoClient(uri);
  await native.connect();
  try {
    const document = await native.db(db.name).collection<{ id: string; title: string }>('notification').findOne({ id: 'persistence-check' });
    assert.equal(document?.title, 'MongoDB persistence');
  } finally { await native.close(); }
  const reopened = new MongoDatabase(uri, db.name);
  try {
    await reopened.initialize();
    assert.equal((await reopened.prepare('SELECT title FROM notification WHERE id = ?').get('persistence-check'))?.title, 'MongoDB persistence');
    await assert.rejects(reopened.prepare('INSERT INTO connection_settings (tenant_id, control_url, gateway_url, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)').run('missing-tenant', 'https://signet.example', 'https://signet.example', new Date().toISOString(), 'owner'), /references a missing tenant record/);
  } finally { await reopened.close(); }
});

import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// SGC-MON-001 checks the hash chain incrementally from a checkpoint, with a full re-check once a day.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-ledger-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const { db } = await import('../src/db');
const ledger = await import('../src/ledger');
after(dropTestDatabase);

const add = async (n: number) => { for (let i = 0; i < n; i++) await ledger.append({ kind: 'admin', data: { event: 'test.event', i } }); };

test('incremental chain check: only new records, checkpoint tamper found, old tamper found by the daily full check', async () => {
  await add(5);
  const first = await ledger.verifyIncremental();
  assert.ok(first.ok && first.full && first.checked >= 5);
  await add(3);
  const second = await ledger.verifyIncremental();
  assert.ok(second.ok && !second.full);
  assert.equal(second.checked, 3, 'only the new records are read');

  // Simulate an attacker with database access: switch off the append-only guard for this test schema.
  await db.exec('ALTER TABLE ledger_record DISABLE TRIGGER ledger_no_update');
  // Tampering with an old record is not seen by the quick run, but the daily full check finds it.
  await db.prepare("UPDATE ledger_record SET data = ? WHERE seq = 2").run(JSON.stringify({ event: 'edited' }));
  assert.ok((await ledger.verifyIncremental()).ok);
  const cp = JSON.parse(((await db.prepare("SELECT value FROM library_state WHERE key = 'ledger_checkpoint'").get()) as { value: string }).value);
  await db.prepare("UPDATE library_state SET value = ? WHERE key = 'ledger_checkpoint'").run(JSON.stringify({ ...cp, full_at: 0 }));
  const full = await ledger.verifyIncremental();
  assert.equal(full.ok, false);
  assert.equal(full.error?.seq, 2);

  // Changing the checkpoint record itself is caught on the next quick run.
  await db.prepare("UPDATE library_state SET value = ? WHERE key = 'ledger_checkpoint'").run(JSON.stringify({ ...cp, full_at: Date.now() }));
  await db.prepare('UPDATE ledger_record SET record_hash = ? WHERE seq = ?').run('0'.repeat(64), cp.seq);
  assert.match((await ledger.verifyIncremental()).error?.reason ?? '', /checkpoint record changed/);
});

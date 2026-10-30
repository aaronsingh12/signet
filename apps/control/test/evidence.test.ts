import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { GENESIS_HASH, hashRecord, verifyInclusion, type LedgerRecord } from '@signet/core';

// Daily roots need a finished UTC day, so this test writes yesterday's records directly into a
// throwaway database and checks the signed root, the WORM copy and the inclusion proofs.
const dir = mkdtempSync(join(tmpdir(), 'signet-evidence-'));
process.env.SIGNET_DATA_DIR = dir;
process.env.SIGNET_DB = join(dir, 'test.db');

test('a finished day is rolled into a signed Merkle root and every record proves inclusion', async () => {
  const { db } = await import('../src/db');
  const evidence = await import('../src/evidence');
  const { tenant } = await import('../src/tenant');
  const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
  let prev = GENESIS_HASH;
  const ids: string[] = [];
  for (let i = 1; i <= 7; i++) {
    const rec: Omit<LedgerRecord, 'record_hash'> = { record_id: `rec_test_${i}`, seq: i, tenant_id: tenant.id, kind: 'transaction', ts: `${yesterday}T10:00:0${i}.000Z`, agent_id: 'agt_x', cert_id: null, data: { i }, prev_hash: prev };
    const h = hashRecord(rec);
    db.prepare('INSERT INTO ledger_record (seq, record_id, tenant_id, kind, ts, agent_id, cert_id, data, prev_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(i, rec.record_id, rec.tenant_id, rec.kind, rec.ts, rec.agent_id, null, JSON.stringify(rec.data), prev, h);
    prev = h;
    ids.push(rec.record_id);
  }
  assert.deepEqual(evidence.sealFinishedDays(), [yesterday]);
  const [root] = evidence.roots(5) as unknown as { day: string; jws: string; count: number; worm: boolean }[];
  assert.equal(root!.day, yesterday);
  assert.equal(root!.count, 7);
  assert.equal(root!.worm, true);
  const payload = evidence.verifyRootJws(root!.jws);
  assert.equal(payload.chain_head, prev);
  for (const id of ids) {
    const p = evidence.proofFor(id);
    assert.equal(p.provisional, false);
    assert.equal(verifyInclusion(p.record_hash, p.index, p.tree_size, p.proof, payload.merkle_root), true);
  }
  // A signed root can never be rewritten (append-only table).
  assert.throws(() => db.prepare('UPDATE daily_root SET merkle_root = ? WHERE day = ?').run('00', yesterday), /append-only/);
  assert.throws(() => db.prepare('DELETE FROM ledger_record WHERE seq = 1').run(), /append-only/);
});

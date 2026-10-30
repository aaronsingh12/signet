import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import {
  GENESIS_HASH, canonicalize, combine, generateSigningKey, hashRecord, ibanValid, inclusionProof, loadSigningKey, luhn, merkleRoot, scan,
  sha256, signJws, strictest, ulid, verifyChain, verifyInclusion, verifyJws, type DetectorResult, type LedgerRecord,
} from '../src/index';

test('canonical JSON sorts keys and drops undefined', () => {
  assert.equal(canonicalize({ b: 1, a: [true, null, 'x'], c: undefined, d: { z: 1, y: 2 } }), '{"a":[true,null,"x"],"b":1,"d":{"y":2,"z":1}}');
  assert.throws(() => canonicalize({ n: Number.NaN }));
});

test('ULIDs are 26 chars and sort by time', () => {
  const a = ulid(1_000);
  const b = ulid(2_000);
  assert.equal(a.length, 26);
  assert.ok(a < b);
});

test('JWS round-trips and rejects tampering, unknown keys and wrong typ', () => {
  const key = loadSigningKey(generateSigningKey('k1'));
  const jws = signJws({ hello: 'world' }, key, 'signet-seal');
  const keys = new Map([['k1', key.publicKey]]);
  assert.deepEqual(verifyJws(jws, keys, 'signet-seal').payload, { hello: 'world' });
  const [h, , s] = jws.split('.');
  const forged = `${h}.${Buffer.from('{"hello":"mars"}').toString('base64url')}.${s}`;
  assert.throws(() => verifyJws(forged, keys), /signature/);
  assert.throws(() => verifyJws(jws, new Map()), /unknown signing key/);
  assert.throws(() => verifyJws(jws, keys, 'JWT'), /typ/);
});

function chain(n: number): LedgerRecord[] {
  const out: LedgerRecord[] = [];
  let prev = GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const rec = { record_id: `rec_${i}`, seq: i, tenant_id: 't', kind: 'transaction' as const, ts: `2026-10-29T00:00:0${i}Z`, agent_id: 'a', cert_id: null, data: { i }, prev_hash: prev };
    const full = { ...rec, record_hash: hashRecord(rec) };
    out.push(full);
    prev = full.record_hash;
  }
  return out;
}

test('ledger chain verifies and pinpoints a tampered record', () => {
  const recs = chain(5);
  assert.equal(verifyChain(recs).ok, true);
  const tampered = recs.map((r) => (r.seq === 3 ? { ...r, data: { i: 999 } } : r));
  const res = verifyChain(tampered);
  assert.equal(res.ok, false);
  assert.equal(res.error?.seq, 3);
  const gap = recs.filter((r) => r.seq !== 4);
  assert.match(verifyChain(gap).error!.reason, /sequence gap/);
});

test('Merkle inclusion proofs verify for every leaf and fail when tampered', () => {
  for (const n of [1, 2, 3, 5, 8, 13]) {
    const leaves = Array.from({ length: n }, (_, i) => sha256(`record-${i}`));
    const root = merkleRoot(leaves);
    for (let i = 0; i < n; i++) {
      const proof = inclusionProof(leaves, i);
      assert.equal(verifyInclusion(leaves[i]!, i, n, proof, root), true, `n=${n} i=${i}`);
      assert.equal(verifyInclusion(sha256('forged'), i, n, proof, root), false);
    }
  }
});

test('DLP checksums: Luhn and IBAN', () => {
  assert.equal(luhn('4111 1111 1111 1111'), true);
  assert.equal(luhn('4111 1111 1111 1112'), false);
  assert.equal(ibanValid('DE89 3704 0044 0532 0130 00'), true);
  assert.equal(ibanValid('DE89 3704 0044 0532 0130 01'), false);
});

test('DLP scan finds secrets before cards and ignores invalid card numbers', () => {
  const tags = (s: string) => scan(s).map((f) => `${f.recogniser}:${f.tag}`);
  assert.deepEqual(tags('card 4111 1111 1111 1111'), ['payment_card:payment_card']);
  assert.deepEqual(tags('card 4111 1111 1111 1112'), []);
  assert.deepEqual(tags('key AKIAABCDEFGHIJKLMNOP here'), ['aws_access_key:secrets']);
  assert.deepEqual(tags('mail maria.lopez@mail.example now'), ['email:personal']);
  assert.deepEqual(tags('call +44 20 7946 0958 today'), ['phone:personal']);
  assert.deepEqual(tags('ref 4111111111111112'), []);
});

test('combiner: only rules allow; unavailable detectors hold T1/T2 allows (RB-INV-04, RB-INV-06)', () => {
  const down: DetectorResult[] = [{ id: 'DET-INJ', version: 'x', status: 'unavailable' }];
  assert.equal(combine('allow', down, 'T2').outcome, 'require_approval');
  assert.equal(combine('allow', down, 'T3').outcome, 'allow');
  assert.equal(combine('deny', [{ id: 'DET-INJ', version: 'x', status: 'ok', band: 'low' }], 'T4').outcome, 'deny');
  const high: DetectorResult[] = [{ id: 'DET-INJ', version: 'x', status: 'ok', band: 'high' }];
  assert.equal(combine('allow', high, 'T1').outcome, 'quarantine');
  assert.equal(combine('allow', high, 'T4').outcome, 'require_approval');
  // a detector can never turn a deny into an allow
  for (const band of ['low', 'elevated', 'high'] as const) {
    assert.notEqual(combine('deny', [{ id: 'D', version: 'x', status: 'ok', band }], 'T4').outcome, 'allow');
  }
  assert.equal(strictest('allow', 'throttle', 'deny'), 'deny');
});

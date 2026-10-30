import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createGzip } from 'node:zlib';
import type { Writable } from 'node:stream';
import { DATA_DIR, canonicalize, inclusionProof, merkleRoot, signJws, toJwk, verifyJws } from '@signet/core';
import { db, nowIso } from './db';
import { notFound } from './errors';
import { keys } from './keys';
import * as ledger from './ledger';
import { tenant } from './tenant';

// Evidence store (BP 8.3, E05, E31). Each UTC day's records are rolled into a Merkle tree; the root is
// signed with the tenant ledger key and written, with the day's records, to write-once storage.
// Dev backend: files under data/worm made read-only after one write. Production backend: S3 Object
// Lock in compliance mode (same interface).

const WORM_DIR = join(DATA_DIR, 'worm', tenant.id);

export interface RootPayload {
  format: 'signet-daily-root/1';
  tenant: string;
  day: string;
  first_seq: number;
  last_seq: number;
  count: number;
  merkle_root: string;
  chain_head: string; // record_hash of last_seq, ties the root to the hash chain
  signed_at: string;
}

function writeOnce(rel: string, content: string) {
  const file = join(WORM_DIR, rel);
  if (existsSync(file)) {
    if (readFileSync(file, 'utf8') !== content) throw new Error(`WORM object ${rel} exists with different content`);
    return;
  }
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, content, { flag: 'wx' });
  chmodSync(file, 0o444);
}

const dayOf = (ts: string) => ts.slice(0, 10);
const today = () => new Date().toISOString().slice(0, 10);

function recordsOfDay(day: string) {
  return (db.prepare('SELECT seq, record_hash FROM ledger_record WHERE ts >= ? AND ts < ? ORDER BY seq').all(`${day}T00:00:00.000Z`, `${day}T99`) as { seq: number; record_hash: string }[]);
}

// Seals every finished day that has records but no root yet. Runs at start and every 10 minutes,
// so the root for a day lands shortly after 00:00 UTC.
export function sealFinishedDays(): string[] {
  const days = (db.prepare('SELECT DISTINCT substr(ts, 1, 10) AS d FROM ledger_record WHERE substr(ts, 1, 10) < ? AND substr(ts, 1, 10) NOT IN (SELECT day FROM daily_root) ORDER BY d').all(today()) as { d: string }[]).map((r) => r.d);
  for (const day of days) sealDay(day);
  return days;
}

export function sealDay(day: string) {
  const recs = recordsOfDay(day);
  if (!recs.length) return null;
  const payload: RootPayload = {
    format: 'signet-daily-root/1',
    tenant: tenant.id,
    day,
    first_seq: recs[0]!.seq,
    last_seq: recs[recs.length - 1]!.seq,
    count: recs.length,
    merkle_root: merkleRoot(recs.map((r) => r.record_hash)),
    chain_head: recs[recs.length - 1]!.record_hash,
    signed_at: nowIso(),
  };
  const jws = signJws(payload, keys.ledger, 'signet-root');
  db.prepare('INSERT INTO daily_root (day, first_seq, last_seq, count, merkle_root, jws, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(day, payload.first_seq, payload.last_seq, payload.count, payload.merkle_root, jws, nowIso());
  writeOnce(`roots/${day}.jws`, jws);
  writeOnce(`segments/${day}.jsonl`, [...ledger.range(payload.first_seq, payload.last_seq)].map((r) => JSON.stringify(r)).join('\n') + '\n');
  ledger.append({ kind: 'admin', data: { event: 'ledger.daily_root', day, count: payload.count, merkle_root: payload.merkle_root, key: keys.ledger.kid } });
  return payload;
}

export function roots(limit = 30) {
  return (db.prepare('SELECT day, first_seq, last_seq, count, merkle_root, jws, created_at FROM daily_root ORDER BY day DESC LIMIT ?').all(limit) as { jws: string }[]).map((r) => ({
    ...r,
    worm: existsSync(join(WORM_DIR, `roots/${(r as unknown as { day: string }).day}.jws`)),
  }));
}

// Inclusion proof for one record against its day's signed root (or today's provisional root).
export function proofFor(recordId: string) {
  const rec = ledger.get(recordId);
  const day = dayOf(rec.ts);
  const recs = recordsOfDay(day);
  const index = recs.findIndex((r) => r.seq === rec.seq);
  if (index < 0) throw notFound('record in its day');
  const root = db.prepare('SELECT jws, count FROM daily_root WHERE day = ?').get(day) as { jws: string; count: number } | undefined;
  const hashes = recs.slice(0, root ? root.count : recs.length).map((r) => r.record_hash);
  return {
    record_id: rec.record_id,
    record_hash: rec.record_hash,
    day,
    index,
    tree_size: hashes.length,
    proof: inclusionProof(hashes, index),
    merkle_root: merkleRoot(hashes),
    signed_root: root?.jws ?? null,
    provisional: !root,
  };
}

// Evidence Package (.sep, format signet-evidence-package/1): gzip of newline-delimited JSON.
// Lines: one manifest, the signed daily roots, the records, then an end line whose signature covers
// the SHA-256 of every preceding line. Specified in docs/evidence-package.md.
export function writePackage(out: Writable, opts: { fromDay?: string; toDay?: string; actor: string }) {
  const from = opts.fromDay ?? '0000-00-00';
  const to = opts.toDay ?? '9999-99-99';
  const span = db.prepare('SELECT MIN(seq) AS a, MAX(seq) AS b, COUNT(*) AS n FROM ledger_record WHERE substr(ts, 1, 10) BETWEEN ? AND ?').get(from, to) as { a: number | null; b: number | null; n: number };
  const rootRows = db.prepare('SELECT day, jws FROM daily_root WHERE day BETWEEN ? AND ? ORDER BY day').all(from, to) as { day: string; jws: string }[];
  const gz = createGzip();
  gz.pipe(out);
  const hash = createHash('sha256');
  const line = (obj: unknown) => {
    const s = `${JSON.stringify(obj)}\n`;
    hash.update(s);
    gz.write(s);
  };
  line({
    type: 'manifest',
    format: 'signet-evidence-package/1',
    tenant: tenant.id,
    tenant_name: tenant.name,
    created_at: nowIso(),
    created_by: opts.actor,
    range: { from_day: opts.fromDay ?? null, to_day: opts.toDay ?? null, from_seq: span.a, to_seq: span.b },
    record_count: span.n,
    start_prev_hash: span.a ? ledger.prevHashOf(span.a) : null,
    keys: { ledger: toJwk(keys.ledger), ca: toJwk(keys.ca) },
    payloads_included: false,
  });
  for (const r of rootRows) line({ type: 'root', day: r.day, jws: r.jws });
  if (span.a && span.b) for (const r of ledger.range(span.a, span.b)) line({ type: 'record', record: r });
  const digest = hash.digest('hex');
  const sig = signJws({ format: 'signet-evidence-package/1', sha256: digest, record_count: span.n, roots: rootRows.length }, keys.ledger, 'signet-sep');
  gz.end(`${JSON.stringify({ type: 'end', sha256: digest, signature: sig })}\n`);
  ledger.append({ kind: 'admin', data: { event: 'evidence.exported', from_seq: span.a, to_seq: span.b, record_count: span.n, roots: rootRows.length, sha256: digest, actor: opts.actor } });
}

export function verifyRootJws(jws: string) {
  return verifyJws<RootPayload>(jws, new Map([[keys.ledger.kid, keys.ledger.publicKey]]), 'signet-root').payload;
}

export const canonicalRoot = (p: RootPayload) => canonicalize(p);

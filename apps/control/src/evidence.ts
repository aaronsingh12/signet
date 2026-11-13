import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createGzip } from 'node:zlib';
import type { Writable } from 'node:stream';
import { DATA_DIR, canonicalize, inclusionProof, merkleRoot, signJws, toJwk, verifyJws } from '@signet/core';
import { db, nowIso, tx } from './db';
import { checkBucket, putOnce, s3Config } from './evidence-store';
import { timestamp, tsaUrl } from './tsa';
import { notFound } from './errors';
import { keys } from './keys';
import * as ledger from './ledger';
import { tenant } from './tenant';

// Evidence store (BP 8.3, E05, E31). Each UTC day's records are rolled into a Merkle tree; the root is
// signed with the tenant ledger key and written, with the day's records, to write-once storage.
// Local copies use read-only files. Vercel copies use PostgreSQL with append-only signed roots;
// this is application-enforced retention, not independently administered S3 Object Lock.

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

async function writeOnce(rel: string, content: string): Promise<void> {
  if (process.env.VERCEL) {
    await db.prepare('INSERT INTO evidence_object (tenant_id, path, content) VALUES (?, ?, ?) ON CONFLICT DO NOTHING').run(tenant.id, rel, content);
    const stored = await db.prepare('SELECT content FROM evidence_object WHERE tenant_id = ? AND path = ?').get(tenant.id, rel);
    if (stored?.content !== content) throw new Error(`Evidence object ${rel} exists with different content`);
    return;
  }
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

async function recordsOfDay(day: string) {
  return ((await db.prepare('SELECT seq, record_hash FROM ledger_record WHERE ts >= ? AND ts < ? ORDER BY seq').all(`${day}T00:00:00.000Z`, `${day}T99`)) as { seq: number; record_hash: string }[]);
}

// Seals every finished day that has records but no root yet. Runs at start and every 10 minutes,
// so the root for a day lands shortly after 00:00 UTC.
export async function sealFinishedDays(): Promise<string[]> {
  const days = ((await db.prepare('SELECT DISTINCT substr(ts, 1, 10) AS d FROM ledger_record WHERE substr(ts, 1, 10) < ? AND substr(ts, 1, 10) NOT IN (SELECT day FROM daily_root) ORDER BY d').all(today())) as { d: string }[]).map((r) => r.d);
  for (const day of days) (await sealDay(day));
  return days;
}

export async function sealDay(day: string) {
  return tx(async () => {
    await db.prepare('SELECT pg_advisory_xact_lock(hashtextextended(?, 0))').get(`${db.schema}:daily-root:${day}`);
    const existing = await db.prepare('SELECT jws FROM daily_root WHERE day = ?').get(day);
    if (existing) return verifyRootJws(String(existing.jws));
    return sealDayRecords(day);
  });
}

async function sealDayRecords(day: string) {
  const recs = (await recordsOfDay(day));
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
  (await db.prepare('INSERT INTO daily_root (day, first_seq, last_seq, count, merkle_root, jws, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(day, payload.first_seq, payload.last_seq, payload.count, payload.merkle_root, jws, nowIso()));
  await writeOnce(`roots/${day}.jws`, jws);
  await writeOnce(`segments/${day}.jsonl`, (await segmentOf(payload.first_seq, payload.last_seq)));
  (await ledger.append({ kind: 'admin', data: { event: 'ledger.daily_root', day, count: payload.count, merkle_root: payload.merkle_root, key: keys.ledger.kid } }));
  return payload;
}

const segmentOf = async (first: number, last: number) => [...(await ledger.range(first, last))].map((r) => JSON.stringify(r)).join('\n') + '\n';

// Outside anchors (BP 8.3). After a day is sealed, its signed root and records are copied to S3 with
// Object Lock and the root is timestamped by an RFC 3161 authority, when those are configured. This runs
// after sealing (and catches up older days), so an outage of S3 or the TSA never blocks the ledger; the
// day simply stays "not anchored yet" and is retried on the next run.
export async function anchorPending(limit = 30): Promise<{ stored: string[]; timestamped: string[]; errors: string[] }> {
  const out = { stored: [] as string[], timestamped: [] as string[], errors: [] as string[] };
  const cfg = s3Config();
  const tsa = tsaUrl();
  if (!cfg && !tsa) return out;
  const rows = (await db.prepare(
    `SELECT r.day, r.first_seq, r.last_seq, r.jws,
       EXISTS (SELECT 1 FROM evidence_anchor a WHERE a.day = r.day AND a.kind = 's3') AS has_s3,
       EXISTS (SELECT 1 FROM evidence_anchor a WHERE a.day = r.day AND a.kind = 'tsa') AS has_tsa
     FROM daily_root r ORDER BY r.day`,
  ).all()) as { day: string; first_seq: number; last_seq: number; jws: string; has_s3: boolean; has_tsa: boolean }[];
  for (const r of rows.filter((x) => (cfg && !x.has_s3) || (tsa && !x.has_tsa)).slice(0, limit)) {
    if (cfg && !r.has_s3) {
      try {
        const root = await putOnce(cfg, `${tenant.id}/roots/${r.day}.jws`, r.jws);
        const segment = await putOnce(cfg, `${tenant.id}/segments/${r.day}.jsonl`, await segmentOf(Number(r.first_seq), Number(r.last_seq)));
        await tx(async () => {
          await db.prepare("INSERT INTO evidence_anchor (day, kind, ref, created_at) VALUES (?, 's3', ?, ?) ON CONFLICT DO NOTHING").run(r.day, JSON.stringify({ root, segment }), nowIso());
          await ledger.append({ kind: 'admin', data: { event: 'evidence.worm_stored', day: r.day, root: root.url, segment: segment.url, mode: root.mode, retain_until: root.retain_until } });
        });
        out.stored.push(r.day);
      } catch (e) {
        out.errors.push(`${r.day} S3: ${(e as Error).message}`);
      }
    }
    if (tsa && !r.has_tsa) {
      try {
        const t = await timestamp(tsa, r.jws);
        await tx(async () => {
          await db.prepare("INSERT INTO evidence_anchor (day, kind, ref, created_at) VALUES (?, 'tsa', ?, ?) ON CONFLICT DO NOTHING").run(r.day, JSON.stringify(t), nowIso());
          await ledger.append({ kind: 'admin', data: { event: 'evidence.timestamped', day: r.day, tsa: t.tsa_url, time: t.time, digest: t.digest } });
        });
        out.timestamped.push(r.day);
      } catch (e) {
        out.errors.push(`${r.day} timestamp: ${(e as Error).message}`);
      }
    }
  }
  return out;
}

/** What the evidence anchors are set up to do, and how far behind they are. */
export async function storageStatus() {
  const cfg = (() => { try { return { cfg: s3Config(), error: null }; } catch (e) { return { cfg: null, error: (e as Error).message }; } })();
  const counts = (await db.prepare(
    `SELECT COUNT(*) AS roots,
       SUM(CASE WHEN EXISTS (SELECT 1 FROM evidence_anchor a WHERE a.day = r.day AND a.kind = 's3') THEN 1 ELSE 0 END) AS s3,
       SUM(CASE WHEN EXISTS (SELECT 1 FROM evidence_anchor a WHERE a.day = r.day AND a.kind = 'tsa') THEN 1 ELSE 0 END) AS tsa
     FROM daily_root r`,
  ).get()) as { roots: number; s3: number | null; tsa: number | null };
  return {
    roots: Number(counts.roots),
    s3: cfg.cfg ? { configured: true, bucket: cfg.cfg.bucket, endpoint: cfg.cfg.endpoint, mode: cfg.cfg.mode, retention_days: cfg.cfg.retentionDays, stored: Number(counts.s3 ?? 0), ...(await checkBucket(cfg.cfg)) } : { configured: false, error: cfg.error, stored: Number(counts.s3 ?? 0) },
    tsa: { configured: !!tsaUrl(), url: tsaUrl(), timestamped: Number(counts.tsa ?? 0) },
    local_copy: process.env.VERCEL ? 'database (append-only table)' : 'read-only files on this server',
  };
}

export async function roots(limit = 30) {
  const anchors = new Map<string, { s3?: unknown; tsa?: { time: string; tsa_url: string } }>();
  for (const a of (await db.prepare('SELECT day, kind, ref FROM evidence_anchor').all()) as { day: string; kind: string; ref: string }[]) {
    anchors.set(a.day, { ...anchors.get(a.day), [a.kind]: JSON.parse(a.ref) });
  }
  const withAnchors = <T extends { day: string }>(r: T) => { const a = anchors.get(r.day); return { ...r, s3: a?.s3 ?? null, timestamp: a?.tsa ? { time: a.tsa.time, tsa_url: a.tsa.tsa_url } : null }; };
  return (await rootsLocal(limit)).map(withAnchors);
}

async function rootsLocal(limit: number) {
  if (process.env.VERCEL) return await db.prepare("SELECT day, first_seq, last_seq, count, merkle_root, jws, created_at, EXISTS (SELECT 1 FROM evidence_object WHERE tenant_id = ? AND path = 'roots/' || daily_root.day || '.jws') AS worm FROM daily_root ORDER BY day DESC LIMIT ?").all(tenant.id, limit) as { day: string; jws: string; worm: boolean }[];
  return ((await db.prepare('SELECT day, first_seq, last_seq, count, merkle_root, jws, created_at FROM daily_root ORDER BY day DESC LIMIT ?').all(limit)) as { day: string; jws: string }[]).map((r) => ({
    ...r,
    worm: existsSync(join(WORM_DIR, `roots/${r.day}.jws`)),
  }));
}

// Inclusion proof for one record against its day's signed root (or today's provisional root).
export async function proofFor(recordId: string) {
  const rec = (await ledger.get(recordId));
  const day = dayOf(rec.ts);
  const recs = (await recordsOfDay(day));
  const index = recs.findIndex((r) => r.seq === rec.seq);
  if (index < 0) throw notFound('record in its day');
  const root = (await db.prepare('SELECT jws, count FROM daily_root WHERE day = ?').get(day)) as { jws: string; count: number } | undefined;
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
export async function writePackage(out: Writable, opts: { fromDay?: string; toDay?: string; actor: string }) {
  const from = opts.fromDay ?? '0000-00-00';
  const to = opts.toDay ?? '9999-99-99';
  const span = (await db.prepare('SELECT MIN(seq) AS a, MAX(seq) AS b, COUNT(*) AS n FROM ledger_record WHERE substr(ts, 1, 10) BETWEEN ? AND ?').get(from, to)) as { a: number | null; b: number | null; n: number };
  const rootRows = (await db.prepare("SELECT r.day, r.jws, (SELECT a.ref FROM evidence_anchor a WHERE a.day = r.day AND a.kind = 'tsa') AS tsa FROM daily_root r WHERE r.day BETWEEN ? AND ? ORDER BY r.day").all(from, to)) as { day: string; jws: string; tsa: string | null }[];
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
    start_prev_hash: span.a ? (await ledger.prevHashOf(span.a)) : null,
    keys: { ledger: toJwk(keys.ledger), ca: toJwk(keys.ca) },
    payloads_included: false,
  });
  // A root's RFC 3161 token (base64 TimeStampResp) travels with it, for `openssl ts -verify` offline.
  for (const r of rootRows) line({ type: 'root', day: r.day, jws: r.jws, ...(r.tsa ? { timestamp: JSON.parse(r.tsa) } : {}) });
  if (span.a && span.b) for (const r of (await ledger.range(span.a, span.b))) line({ type: 'record', record: r });
  const digest = hash.digest('hex');
  const sig = signJws({ format: 'signet-evidence-package/1', sha256: digest, record_count: span.n, roots: rootRows.length }, keys.ledger, 'signet-sep');
  gz.end(`${JSON.stringify({ type: 'end', sha256: digest, signature: sig })}\n`);
  (await ledger.append({ kind: 'admin', data: { event: 'evidence.exported', from_seq: span.a, to_seq: span.b, record_count: span.n, roots: rootRows.length, sha256: digest, actor: opts.actor } }));
}

export function verifyRootJws(jws: string) {
  return verifyJws<RootPayload>(jws, new Map([[keys.ledger.kid, keys.ledger.publicKey]]), 'signet-root').payload;
}

export const canonicalRoot = (p: RootPayload) => canonicalize(p);

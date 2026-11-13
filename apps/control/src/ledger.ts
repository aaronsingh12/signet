import { GENESIS_HASH, hashRecord, newId, verifyChain, type LedgerKind, type LedgerRecord } from '@signet/core';
import { db, nowIso, tx } from './db';
import { notFound } from './errors';
import { tenant } from './tenant';
import { keys } from './keys';

type Row = Omit<LedgerRecord, 'data' | 'erasure_proof'> & { data: string; erasure_proof: string | null };

export const toRecord = ({ erasure_proof, ...row }: Row): LedgerRecord => ({ ...row, data: JSON.parse(row.data) as Record<string, unknown>, ...(erasure_proof ? { erasure_proof } : {}) });

const insert = db.prepare(
  'INSERT INTO ledger_record (seq, record_id, tenant_id, kind, ts, agent_id, cert_id, data, prev_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
);
const head = db.prepare('SELECT seq, record_hash FROM ledger_record ORDER BY seq DESC LIMIT 1');

export interface LedgerEntry {
  kind: LedgerKind;
  agent_id?: string | null;
  cert_id?: string | null;
  data: Record<string, unknown>;
}

const listeners = new Set<(r: LedgerRecord) => void | Promise<void>>();
export const onAppend = (fn: (r: LedgerRecord) => void | Promise<void>) => (listeners.add(fn), () => listeners.delete(fn));

// A transaction-level lock serializes the hash chain across PostgreSQL clients.
export async function append(entry: LedgerEntry): Promise<LedgerRecord> {
  return (await tx(async () => {
  await db.prepare('SELECT pg_advisory_xact_lock(hashtextextended(?, 0))').get(`${db.schema}:ledger`);
  if (entry.agent_id && !(await db.prepare('SELECT 1 FROM agent WHERE id = ? AND tenant_id = ?').get(entry.agent_id, tenant.id))) throw notFound('agent for ledger entry; removed agents cannot write new records');
  const last = (await head.get()) as { seq: number; record_hash: string } | undefined;
  const rec: Omit<LedgerRecord, 'record_hash'> = {
    record_id: newId('rec'),
    seq: (last?.seq ?? 0) + 1,
    tenant_id: tenant.id,
    kind: entry.kind,
    ts: nowIso(),
    agent_id: entry.agent_id ?? null,
    cert_id: entry.cert_id ?? null,
    data: entry.data,
    prev_hash: last?.record_hash ?? GENESIS_HASH,
  };
  const full: LedgerRecord = { ...rec, record_hash: hashRecord(rec) };
  (await insert.run(full.seq, full.record_id, full.tenant_id, full.kind, full.ts, full.agent_id, full.cert_id, JSON.stringify(full.data), full.prev_hash, full.record_hash));
  for (const fn of listeners) {
    try {
      await fn(full);
    } catch (error) {
      console.error('ledger subscriber failed', { record_id: full.record_id, error });
    }
  }
  return full;
  }));
}

// Group commit: one transaction for a batch of records from a gateway node.
export async function appendMany(entries: LedgerEntry[]): Promise<LedgerRecord[]> {
  return (await tx(async () => {
    const records: LedgerRecord[] = [];
    for (const entry of entries) records.push(await append(entry));
    return records;
  }));
}

export interface ListOptions {
  agent?: string;
  kind?: string;
  decision?: string;
  before_seq?: number | null;
  limit: number;
}

export async function list(o: ListOptions) {
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (o.agent) (where.push('agent_id = ?'), args.push(o.agent));
  if (o.kind) (where.push('kind = ?'), args.push(o.kind));
  if (o.decision) (where.push("jsonb_extract_path_text(data::jsonb, 'policy_decision') = ?"), args.push(o.decision));
  if (o.before_seq) (where.push('seq < ?'), args.push(o.before_seq));
  args.push(o.limit + 1);
  const rows = ((await db.prepare(`SELECT * FROM ledger_record ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY seq DESC LIMIT ?`).all(...args)) as Row[]).map(toRecord);
  const more = rows.length > o.limit;
  const items = rows.slice(0, o.limit);
  return { items, next_cursor: more ? items[items.length - 1]!.seq : null };
}

export async function get(id: string): Promise<LedgerRecord> {
  const r = (await db.prepare('SELECT * FROM ledger_record WHERE record_id = ?').get(id)) as Row | undefined;
  if (!r) throw notFound(`ledger record ${id}`);
  return toRecord(r);
}

export async function neighbours(seq: number) {
  return ((await db.prepare('SELECT * FROM ledger_record WHERE seq BETWEEN ? AND ? ORDER BY seq').all(seq - 2, seq + 1)) as Row[]).map(toRecord);
}

export async function range(fromSeq = 1, toSeq = Number.MAX_SAFE_INTEGER): Promise<LedgerRecord[]> {
  return ((await db.prepare('SELECT * FROM ledger_record WHERE seq BETWEEN ? AND ? ORDER BY seq').all(fromSeq, toSeq)) as Row[]).map(toRecord);
}

export const all = async () => (await range());

export async function prevHashOf(seq: number): Promise<string> {
  if (seq <= 1) return GENESIS_HASH;
  const r = (await db.prepare('SELECT record_hash FROM ledger_record WHERE seq = ?').get(seq - 1)) as { record_hash: string } | undefined;
  return r?.record_hash ?? GENESIS_HASH;
}

// Continuous chain check (SGC-MON-001) without loading the whole ledger into memory: each run checks
// only the records added since the last checkpoint, in batches, and re-checks everything once a day so an
// edit to an old record is still found. The checkpoint itself is compared with the stored record each run.
const BATCH = 5000;
export async function verifyIncremental(): Promise<{ ok: boolean; checked: number; head_seq: number; full: boolean; error?: { seq: number; reason: string } }> {
  const saved = (await db.prepare("SELECT value FROM library_state WHERE key = 'ledger_checkpoint'").get()) as { value: string } | undefined;
  const cp = saved ? (JSON.parse(saved.value) as { seq: number; head: string; full_at: number }) : null;
  const full = !cp || Date.now() - cp.full_at > 86_400_000;
  if (cp && !full) {
    const at = (await db.prepare('SELECT record_hash FROM ledger_record WHERE seq = ?').get(cp.seq)) as { record_hash: string } | undefined;
    if (at?.record_hash !== cp.head) return { ok: false, checked: 0, head_seq: cp.seq, full, error: { seq: cp.seq, reason: 'checkpoint record changed since it was verified' } };
  }
  const trusted = new Map([[keys.ledger.kid, keys.ledger.publicKey]]);
  let start = full ? 1 : cp!.seq + 1;
  let prev = full ? GENESIS_HASH : cp!.head;
  let checked = 0;
  let last = full ? 0 : cp!.seq;
  for (;;) {
    const batch = await range(start, start + BATCH - 1);
    if (!batch.length) break;
    if (batch[0]!.seq !== start) return { ok: false, checked, head_seq: last, full, error: { seq: batch[0]!.seq, reason: `sequence gap: expected ${start}` } };
    const r = verifyChain(batch, prev, trusted);
    if (!r.ok) return { ok: false, checked: checked + r.count, head_seq: last, full, error: { seq: r.error!.seq, reason: r.error!.reason } };
    checked += r.count;
    prev = r.head;
    last = batch[batch.length - 1]!.seq;
    if (batch.length < BATCH) break;
    start += BATCH;
  }
  if (last > 0) {
    const value = JSON.stringify({ seq: last, head: prev, full_at: full ? Date.now() : cp!.full_at });
    await db.prepare("INSERT INTO library_state (key, value, updated_at) VALUES ('ledger_checkpoint', ?, ?) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at").run(value, new Date().toISOString());
  }
  return { ok: true, checked, head_seq: last, full };
}

export async function verify(fromSeq = 1, toSeq = Number.MAX_SAFE_INTEGER) {
  return verifyChain((await range(fromSeq, toSeq)), (await prevHashOf(fromSeq)), new Map([[keys.ledger.kid, keys.ledger.publicKey]]));
}

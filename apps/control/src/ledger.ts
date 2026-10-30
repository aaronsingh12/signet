import { GENESIS_HASH, hashRecord, newId, verifyChain, type LedgerKind, type LedgerRecord } from '@signet/core';
import { db, nowIso, tx } from './db';
import { notFound } from './errors';
import { tenant } from './tenant';

type Row = Omit<LedgerRecord, 'data'> & { data: string };

export const toRecord = (r: Row): LedgerRecord => ({ ...r, data: JSON.parse(r.data) as Record<string, unknown> });

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

const listeners = new Set<(r: LedgerRecord) => void>();
export const onAppend = (fn: (r: LedgerRecord) => void) => (listeners.add(fn), () => listeners.delete(fn));

// Synchronous append (RB-INV-15): the caller gets the record hash back only after it is stored.
export function append(entry: LedgerEntry): LedgerRecord {
  const last = head.get() as { seq: number; record_hash: string } | undefined;
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
  insert.run(full.seq, full.record_id, full.tenant_id, full.kind, full.ts, full.agent_id, full.cert_id, JSON.stringify(full.data), full.prev_hash, full.record_hash);
  for (const fn of listeners) {
    try {
      fn(full);
    } catch {
      // listeners never affect the write
    }
  }
  return full;
}

// Group commit: one transaction for a batch of records from a gateway node.
export function appendMany(entries: LedgerEntry[]): LedgerRecord[] {
  return tx(() => entries.map((e) => append(e)));
}

export interface ListOptions {
  agent?: string;
  kind?: string;
  decision?: string;
  before_seq?: number | null;
  limit: number;
}

export function list(o: ListOptions) {
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (o.agent) (where.push('agent_id = ?'), args.push(o.agent));
  if (o.kind) (where.push('kind = ?'), args.push(o.kind));
  if (o.decision) (where.push("json_extract(data, '$.policy_decision') = ?"), args.push(o.decision));
  if (o.before_seq) (where.push('seq < ?'), args.push(o.before_seq));
  args.push(o.limit + 1);
  const rows = (db.prepare(`SELECT * FROM ledger_record ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY seq DESC LIMIT ?`).all(...args) as Row[]).map(toRecord);
  const more = rows.length > o.limit;
  const items = rows.slice(0, o.limit);
  return { items, next_cursor: more ? items[items.length - 1]!.seq : null };
}

export function get(id: string): LedgerRecord {
  const r = db.prepare('SELECT * FROM ledger_record WHERE record_id = ?').get(id) as Row | undefined;
  if (!r) throw notFound(`ledger record ${id}`);
  return toRecord(r);
}

export function neighbours(seq: number) {
  return (db.prepare('SELECT * FROM ledger_record WHERE seq BETWEEN ? AND ? ORDER BY seq').all(seq - 2, seq + 1) as Row[]).map(toRecord);
}

export function* range(fromSeq = 1, toSeq = Number.MAX_SAFE_INTEGER): Generator<LedgerRecord> {
  for (const r of db.prepare('SELECT * FROM ledger_record WHERE seq BETWEEN ? AND ? ORDER BY seq').iterate(fromSeq, toSeq) as Iterable<Row>) yield toRecord(r);
}

export const all = () => range();

export function prevHashOf(seq: number): string {
  if (seq <= 1) return GENESIS_HASH;
  const r = db.prepare('SELECT record_hash FROM ledger_record WHERE seq = ?').get(seq - 1) as { record_hash: string } | undefined;
  return r?.record_hash ?? GENESIS_HASH;
}

export function verify(fromSeq = 1, toSeq = Number.MAX_SAFE_INTEGER) {
  return verifyChain(range(fromSeq, toSeq), prevHashOf(fromSeq));
}

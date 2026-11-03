import { canonicalize } from './canonical';
import { sha256, verifyJws } from './crypto';
import type { KeyObject } from 'node:crypto';

// Hash-chained evidence ledger (BP 8.3):
// record_hash = SHA-256(canonical_json(record without record_hash) || prev_hash).

// BP 8.1 ledgers: transactions, lifecycle stages, human decisions, ladder events, admin audit.
export type LedgerKind = 'transaction' | 'enforcement' | 'lifecycle' | 'decision' | 'admin';

export interface LedgerRecord {
  record_id: string;
  seq: number;
  tenant_id: string;
  kind: LedgerKind;
  ts: string;
  agent_id: string | null;
  cert_id: string | null;
  data: Record<string, unknown>;
  prev_hash: string;
  record_hash: string;
  erasure_proof?: string;
}

export const GENESIS_HASH = '0'.repeat(64);

export function hashRecord(rec: Omit<LedgerRecord, 'record_hash'>): string {
  return sha256(canonicalize(rec) + rec.prev_hash);
}

export interface ChainCheck {
  ok: boolean;
  count: number;
  head: string;
  error?: { seq: number; record_id: string; reason: string };
  erased_count?: number;
}

// Verifies linkage, sequence and every record hash. Works offline on an export.
export function verifyChain(records: Iterable<LedgerRecord>, startPrev = GENESIS_HASH, erasureKeys?: ReadonlyMap<string, KeyObject>): ChainCheck {
  let prev = startPrev;
  let expectSeq: number | null = null;
  let count = 0;
  let erased = 0;
  for (const r of records) {
    const fail = (reason: string): ChainCheck => ({ ok: false, count, head: prev, error: { seq: r.seq, record_id: r.record_id, reason } });
    if (expectSeq !== null && r.seq !== expectSeq) return fail(`sequence gap: expected ${expectSeq}, found ${r.seq}`);
    if (r.prev_hash !== prev) return fail('prev_hash does not match the previous record');
    const { record_hash, erasure_proof, ...rest } = r;
    if (erasure_proof) {
      if (!erasureKeys) return fail('erased record requires a trusted ledger signing key');
      try {
        const proof = verifyJws<{ format: string; record: Omit<LedgerRecord, 'erasure_proof'> }>(erasure_proof, erasureKeys, 'signet-erasure').payload;
        if (proof.format !== 'signet-ledger-erasure/1' || canonicalize(proof.record) !== canonicalize({ ...rest, record_hash })) return fail('erasure marker does not match its signed replacement');
      } catch {
        return fail('erasure marker signature is invalid');
      }
      erased++;
    } else if (hashRecord(rest) !== record_hash) return fail('record content does not match its hash (tampered)');
    prev = record_hash;
    expectSeq = r.seq + 1;
    count++;
  }
  return { ok: true, count, head: prev, ...(erased ? { erased_count: erased } : {}) };
}

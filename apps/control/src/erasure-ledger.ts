import { newId, sha256, signJws, type LedgerRecord } from '@signet/core';
import { db } from './db';
import { keys } from './keys';
import * as ledger from './ledger';

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function eraseText(text: string, identifiers: string[]): string {
  return identifiers.reduce((result, identifier) => {
    const escaped = identifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return result.replace(new RegExp(`(^|[^a-zA-Z0-9_-])${escaped}(?=$|[^a-zA-Z0-9_-])`, 'g'), '$1[erased]');
  }, text);
}

function eraseReferences(value: Json, identifiers: string[]): Json {
  if (typeof value === 'string') return eraseText(value, identifiers);
  if (Array.isArray(value)) return value.map((item) => eraseReferences(item, identifiers));
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([key]) => eraseText(key, identifiers) === key).map(([key, item]) => [key, eraseReferences(item, identifiers)]));
  return value;
}

/** Replace erased payloads with signed, anonymous commitments without rewriting any chain hashes. Caller owns the transaction. */
export function eraseAgentLedger(agentId: string, identifiers: string[]): { records: number; days: string[] } {
  const replacements: LedgerRecord[] = [];
  for (const record of ledger.all()) {
    const { erasure_proof, ...original } = record;
    const redacted = eraseReferences(original.data as Json, identifiers);
    if (record.agent_id !== agentId && JSON.stringify(redacted) === JSON.stringify(original.data)) continue;
    const replacement: Omit<LedgerRecord, 'erasure_proof'> = record.agent_id === agentId
      ? { record_id: newId('rec'), seq: record.seq, tenant_id: record.tenant_id, kind: 'admin', ts: `${record.ts.slice(0, 10)}T00:00:00.000Z`, agent_id: null, cert_id: null, data: { event: 'record.erased', subject_hash: sha256(agentId) }, prev_hash: record.prev_hash, record_hash: record.record_hash }
      : { ...original, data: redacted as Record<string, Json> };
    replacements.push({ ...replacement, erasure_proof: signJws({ format: 'signet-ledger-erasure/1', record: replacement }, keys.ledger, 'signet-erasure') });
  }
  db.exec('DROP TRIGGER ledger_no_update');
  const update = db.prepare('UPDATE ledger_record SET record_id = ?, kind = ?, ts = ?, agent_id = ?, cert_id = ?, data = ?, erasure_proof = ? WHERE seq = ?');
  for (const record of replacements) update.run(record.record_id, record.kind, record.ts, record.agent_id, record.cert_id, JSON.stringify(record.data), record.erasure_proof!, record.seq);
  db.exec("CREATE TRIGGER ledger_no_update BEFORE UPDATE ON ledger_record BEGIN SELECT RAISE(ABORT, 'ledger_record is append-only'); END");
  return { records: replacements.length, days: [...new Set(replacements.map((record) => record.ts.slice(0, 10)))] };
}

import type { Response } from 'express';
import type { LedgerRecord } from '@signet/core';
import { db } from './db';
import * as ledger from './ledger';

// Live Traffic feed for the console (BP 14.1): decisions as they happen. Payload values never appear,
// only classes, counts and hashes, the same as the ledger record.

const clients = new Set<Response>();
const handles = new Map<string, string>();

const handleOf = (agentId: string | null) => {
  if (!agentId) return null;
  if (!handles.has(agentId)) {
    const r = db.prepare('SELECT handle FROM agent WHERE id = ?').get(agentId) as { handle: string } | undefined;
    if (r) handles.set(agentId, r.handle);
  }
  return handles.get(agentId) ?? null;
};

export const summarise = (r: LedgerRecord) => ({
  seq: r.seq,
  record_id: r.record_id,
  ts: r.ts,
  kind: r.kind,
  agent_id: r.agent_id,
  handle: handleOf(r.agent_id),
  event: r.data.event ?? null,
  action_type: r.data.action_type ?? null,
  target: r.data.target ?? null,
  decision: r.data.policy_decision ?? r.data.level ?? null,
  dlp_actions: r.data.dlp_actions ?? null,
  latency_ms_gateway: r.data.latency_ms_gateway ?? null,
  outcome: r.data.outcome ?? null,
  rule_ids: r.data.policy_rule_ids ?? (r.data.rule_id ? [r.data.rule_id] : []),
});

ledger.onAppend((r) => {
  if (r.kind !== 'transaction' && r.kind !== 'enforcement') return;
  const frame = `event: record\ndata: ${JSON.stringify(summarise(r))}\n\n`;
  for (const c of clients) c.write(frame);
});

export function attach(res: Response) {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', 'x-accel-buffering': 'no' });
  res.write(': live\n\n');
  clients.add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 15_000);
  res.on('close', () => {
    clearInterval(ping);
    clients.delete(res);
  });
}

import { newId } from '@signet/core';
import { db, nowIso, tx } from './db';
import { invalid, notFound } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';

// Discovery Inbox (BP 1B.3 Key Sweep, C10). Phase 1 ingests Key Sweep findings from the `signet
// keysweep` CLI (repos, CI files, env files); platform API connectors are Phase 3. Findings carry a
// fingerprint of the key, never the key itself.

export interface FindingInput {
  type: 'unmanaged_key' | 'direct_traffic' | 'unregistered_agent';
  summary: string;
  location: string;
  fingerprint: string;
}

export function ingest(source: string, items: FindingInput[], p: Principal) {
  if (!source || !Array.isArray(items)) throw invalid('source and items[] are required');
  let added = 0;
  tx(() => {
    for (const f of items) {
      if (!/^[0-9a-f]{16}$/.test(f.fingerprint ?? '')) throw invalid('fingerprint must be 16 hex characters (sha256 prefix)');
      const existing = db.prepare('SELECT id FROM discovered_asset WHERE tenant_id = ? AND fingerprint = ? AND location = ?').get(tenant.id, f.fingerprint, f.location) as { id: string } | undefined;
      if (existing) db.prepare('UPDATE discovered_asset SET last_seen = ? WHERE id = ?').run(nowIso(), existing.id);
      else {
        // Already in the broker under the same fingerprint: the copy in code is a leftover to remove.
        const brokered = db.prepare('SELECT name FROM secret WHERE tenant_id = ? AND fingerprint = ?').get(tenant.id, f.fingerprint) as { name: string } | undefined;
        db.prepare('INSERT INTO discovered_asset (id, tenant_id, source, type, summary, location, fingerprint, status, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
          newId('fnd'), tenant.id, source, f.type, brokered ? `${f.summary} (brokered as ${brokered.name}; remove this copy)` : f.summary, f.location, f.fingerprint, 'open', nowIso(), nowIso(),
        );
        added++;
      }
    }
    ledger.append({ kind: 'admin', data: { event: 'discovery.scan_ingested', source, findings: items.length, new: added, actor: p.id } });
  });
  return { received: items.length, new: added };
}

export function list(status?: string) {
  return status
    ? db.prepare('SELECT * FROM discovered_asset WHERE tenant_id = ? AND status = ? ORDER BY last_seen DESC').all(tenant.id, status)
    : db.prepare('SELECT * FROM discovered_asset WHERE tenant_id = ? ORDER BY status, last_seen DESC').all(tenant.id);
}

export function resolve(id: string, status: 'migrated' | 'blocked' | 'dismissed', note: string, p: Principal) {
  const row = db.prepare('SELECT * FROM discovered_asset WHERE tenant_id = ? AND id = ?').get(tenant.id, id);
  if (!row) throw notFound(`finding ${id}`);
  db.prepare('UPDATE discovered_asset SET status = ?, resolved_by = ? WHERE id = ?').run(status, p.id, id);
  ledger.append({ kind: 'admin', data: { event: `discovery.${status}`, finding_id: id, note, actor: p.id } });
  return db.prepare('SELECT * FROM discovered_asset WHERE id = ?').get(id);
}

// Findings whose fingerprint now lives in the broker are marked migrated automatically.
export function reconcileWithBroker() {
  return db.prepare("UPDATE discovered_asset SET status = 'migrated', resolved_by = 'broker-match' WHERE status = 'open' AND fingerprint IN (SELECT fingerprint FROM secret)").run().changes;
}

export function keylessKpi() {
  const open = (db.prepare("SELECT COUNT(*) AS n FROM discovered_asset WHERE tenant_id = ? AND type = 'unmanaged_key' AND status = 'open'").get(tenant.id) as { n: number }).n;
  const total = (db.prepare("SELECT COUNT(*) AS n FROM discovered_asset WHERE tenant_id = ? AND type = 'unmanaged_key'").get(tenant.id) as { n: number }).n;
  const sealed = (db.prepare("SELECT COUNT(*) AS n FROM agent WHERE tenant_id = ? AND status IN ('sealed', 'quarantined')").get(tenant.id) as { n: number }).n;
  // Every Signet-sealed agent authenticates with workload tokens only (RB-INV-03); open findings are the gap.
  return { sealed_agents: sealed, keyless_agents: sealed, unmanaged_keys_open: open, unmanaged_keys_total: total };
}

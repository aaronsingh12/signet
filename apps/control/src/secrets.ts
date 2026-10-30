import { devSecret, newId, seal, sha256, unseal } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, invalid, notFound } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';

// Secrets Broker (BP 3 C9, E32 Keyless Agents): model and tool credentials live here, sealed with
// AES-256-GCM. No API returns a value; only gateway nodes fetch them over the internal channel to
// inject per call. Dev keeps the broker key in data/dev-secrets.json; production uses OpenBao or a KMS.

const KEY = Buffer.from(devSecret('SIGNET_BROKER_KEY'), 'base64url').subarray(0, 32);

export type SecretKind = 'llm_provider' | 'tool';

export interface SecretMeta {
  id: string;
  name: string;
  kind: SecretKind;
  fingerprint: string;
  version: number;
  created_by: string;
  created_at: string;
  rotated_at: string | null;
  rotation_due: string | null;
}

export const fingerprintOf = (value: string) => sha256(value).slice(0, 16);

export function putSecret(input: { name: string; kind: SecretKind; value: string }, p: Principal): SecretMeta {
  if (!/^[a-z0-9][a-z0-9._-]{1,62}$/.test(input.name ?? '')) throw invalid('secret name must be lower-case, 2-63 characters');
  if (!['llm_provider', 'tool'].includes(input.kind)) throw invalid('kind must be llm_provider or tool');
  if (typeof input.value !== 'string' || input.value.length < 8) throw invalid('value must be at least 8 characters');
  const id = newId('sec');
  return tx(() => {
    if (db.prepare('SELECT 1 FROM secret WHERE tenant_id = ? AND name = ?').get(tenant.id, input.name)) throw new PolicyError('VALIDATION', `secret ${input.name} exists; rotate it instead`, 409);
    db.prepare('INSERT INTO secret (id, tenant_id, name, kind, sealed, fingerprint, version, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)').run(
      id, tenant.id, input.name, input.kind, seal(input.value, KEY), fingerprintOf(input.value), p.id, nowIso(),
    );
    ledger.append({ kind: 'admin', data: { event: 'secret.created', secret_id: id, name: input.name, kind: input.kind, fingerprint: fingerprintOf(input.value), actor: p.id } });
    return getSecretMeta(id);
  });
}

export function rotateSecret(id: string, value: string, p: Principal): SecretMeta {
  if (typeof value !== 'string' || value.length < 8) throw invalid('value must be at least 8 characters');
  const meta = getSecretMeta(id);
  tx(() => {
    db.prepare('UPDATE secret SET sealed = ?, fingerprint = ?, version = version + 1, rotated_at = ?, rotation_due = NULL WHERE id = ?').run(seal(value, KEY), fingerprintOf(value), nowIso(), id);
    ledger.append({ kind: 'admin', data: { event: 'secret.rotated', secret_id: id, name: meta.name, version: meta.version + 1, actor: p.id } });
  });
  return getSecretMeta(id);
}

// After a kill, credentials the agent could use are flagged for rotation (BP 5.4). Rotation itself
// runs through the credential's connector, which Phase 1 does not have, so it is a tracked task.
export function markRotationDue(ids: string[], reason: string) {
  for (const id of ids) db.prepare('UPDATE secret SET rotation_due = ? WHERE id = ? AND rotation_due IS NULL').run(`${nowIso()} · ${reason}`, id);
}

export function getSecretMeta(id: string): SecretMeta {
  const row = db.prepare('SELECT id, name, kind, fingerprint, version, created_by, created_at, rotated_at, rotation_due FROM secret WHERE tenant_id = ? AND (id = ? OR name = ?)').get(tenant.id, id, id) as
    | SecretMeta
    | undefined;
  if (!row) throw notFound(`secret ${id}`);
  return row;
}

export const listSecrets = () =>
  db.prepare('SELECT id, name, kind, fingerprint, version, created_by, created_at, rotated_at, rotation_due FROM secret WHERE tenant_id = ? ORDER BY name').all(tenant.id) as unknown as SecretMeta[];

// Internal only: gateway nodes fetch values to inject them (BP 5.2 step 11).
export function revealForGateway(id: string): { id: string; version: number; value: string } {
  const row = db.prepare('SELECT id, version, sealed FROM secret WHERE id = ?').get(id) as { id: string; version: number; sealed: string } | undefined;
  if (!row) throw notFound(`secret ${id}`);
  return { id: row.id, version: row.version, value: unseal(row.sealed, KEY) };
}

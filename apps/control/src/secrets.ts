import { newId, sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { checkProvider, openValue, provider, sealValue, sealedBy } from './keyring';
import { PolicyError, invalid, notFound } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';

// Secrets Broker (BP 3 C9, E32 Keyless Agents): model and tool credentials live here, each sealed with
// its own AES-256-GCM data key, wrapped by the key service in keyring.ts (local key, Vault/OpenBao
// transit or AWS KMS). Console APIs return metadata only; gateway nodes and authenticated runners read
// assigned tool credentials to inject per call.

// platform = a connector's API credential (Vercel, AWS ...): opened only inside the control plane, never
// sent to a gateway node, because it can change and redeploy whole applications.
export type SecretKind = 'llm_provider' | 'tool' | 'platform';

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

export async function putSecret(input: { name: string; kind: SecretKind; value: string }, p: Principal): Promise<SecretMeta> {
  if (!/^[a-z0-9][a-z0-9._-]{1,62}$/.test(input.name ?? '')) throw invalid('secret name must be lower-case, 2-63 characters');
  if (!['llm_provider', 'tool', 'platform'].includes(input.kind)) throw invalid('kind must be llm_provider, tool or platform');
  if (typeof input.value !== 'string' || input.value.length < 8) throw invalid('value must be at least 8 characters');
  const id = newId('sec');
  const sealed = await sealValue(input.value);
  return (await tx(async () => {
    if ((await db.prepare('SELECT 1 FROM secret WHERE tenant_id = ? AND name = ?').get(tenant.id, input.name))) throw new PolicyError('VALIDATION', `secret ${input.name} exists; rotate it instead`, 409);
    (await db.prepare('INSERT INTO secret (id, tenant_id, name, kind, sealed, fingerprint, version, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)').run(
      id, tenant.id, input.name, input.kind, sealed, fingerprintOf(input.value), p.id, nowIso(),
    ));
    (await ledger.append({ kind: 'admin', data: { event: 'secret.created', secret_id: id, name: input.name, kind: input.kind, fingerprint: fingerprintOf(input.value), actor: p.id } }));
    return (await getSecretMeta(id));
  }));
}

export async function rotateSecret(id: string, value: string, p: Principal): Promise<SecretMeta> {
  if (typeof value !== 'string' || value.length < 8) throw invalid('value must be at least 8 characters');
  const meta = (await getSecretMeta(id));
  const sealed = await sealValue(value);
  (await tx(async () => {
    (await db.prepare('UPDATE secret SET sealed = ?, fingerprint = ?, version = version + 1, rotated_at = ?, rotation_due = NULL WHERE id = ?').run(sealed, fingerprintOf(value), nowIso(), id));
    (await ledger.append({ kind: 'admin', data: { event: 'secret.rotated', secret_id: id, name: meta.name, version: meta.version + 1, actor: p.id } }));
  }));
  return (await getSecretMeta(id));
}

// After a kill, credentials the agent could use are flagged for rotation (BP 5.4). Rotation itself
// runs through the credential's connector, which Phase 1 does not have, so it is a tracked task.
export async function markRotationDue(ids: string[], reason: string) {
  for (const id of ids) (await db.prepare('UPDATE secret SET rotation_due = ? WHERE id = ? AND rotation_due IS NULL').run(`${nowIso()} · ${reason}`, id));
}

export async function getSecretMeta(id: string): Promise<SecretMeta> {
  const row = (await db.prepare('SELECT id, name, kind, fingerprint, version, created_by, created_at, rotated_at, rotation_due FROM secret WHERE tenant_id = ? AND (id = ? OR name = ?)').get(tenant.id, id, id)) as
    | SecretMeta
    | undefined;
  if (!row) throw notFound(`secret ${id}`);
  return row;
}

export const listSecrets = async () =>
  (await db.prepare('SELECT id, name, kind, fingerprint, version, created_by, created_at, rotated_at, rotation_due FROM secret WHERE tenant_id = ? ORDER BY name').all(tenant.id)) as unknown as SecretMeta[];

// Internal only: gateway nodes fetch values to inject them (BP 5.2 step 11).
export async function revealForGateway(id: string): Promise<{ id: string; version: number; value: string }> {
  const row = (await db.prepare('SELECT id, version, sealed, kind FROM secret WHERE id = ?').get(id)) as { id: string; version: number; sealed: string; kind: SecretKind } | undefined;
  if (!row || row.kind === 'platform') throw notFound(`secret ${id}`);
  return { id: row.id, version: row.version, value: await openValue(row.sealed) };
}

// In-process only: a platform connector opens its own API credential. No route exposes this.
export async function revealPlatformCredential(id: string): Promise<string> {
  const row = (await db.prepare("SELECT sealed FROM secret WHERE id = ? AND tenant_id = ? AND kind = 'platform'").get(id, tenant.id)) as { sealed: string } | undefined;
  if (!row) throw notFound(`platform credential ${id}`);
  return openValue(row.sealed);
}

/** Which key service protects the secrets, whether it answers, and how many secrets each one sealed. */
export async function keyStatus() {
  const rows = (await db.prepare('SELECT sealed FROM secret WHERE tenant_id = ?').all(tenant.id)) as { sealed: string }[];
  const by: Record<string, number> = {};
  for (const r of rows) by[sealedBy(r.sealed)] = (by[sealedBy(r.sealed)] ?? 0) + 1;
  return { ...(await checkProvider()), secrets: rows.length, sealed_by: by };
}

/**
 * Re-seal every secret with a fresh data key from the configured key service, for example after moving
 * from the local key to Vault or KMS. Values and fingerprints do not change; versions do not change either,
 * because the credential itself is the same. Written to the ledger.
 */
export async function rewrapAll(p: Principal) {
  const target = provider().id;
  const rows = (await db.prepare('SELECT id, sealed FROM secret WHERE tenant_id = ?').all(tenant.id)) as { id: string; sealed: string }[];
  let moved = 0;
  for (const r of rows) {
    if (sealedBy(r.sealed) === target) continue;
    const resealed = await sealValue(await openValue(r.sealed));
    await db.prepare('UPDATE secret SET sealed = ? WHERE id = ? AND sealed = ?').run(resealed, r.id, r.sealed);
    moved++;
  }
  await ledger.append({ kind: 'admin', data: { event: 'secret.rewrapped', provider: target, rewrapped: moved, total: rows.length, actor: p.id } });
  return { provider: target, rewrapped: moved, total: rows.length };
}

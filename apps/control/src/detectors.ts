import type { DetectorMode } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, forbidden, invalid, notFound } from './errors';
import * as hub from './hub';
import * as ledger from './ledger';
import type { Principal } from './rbac';

// Detector registry (DA 3, 6; E38-E40). A new detector version runs in shadow (scores logged, never
// enforced) for at least 14 days before a person promotes it (RB-MOD-03, RB-INV-10). The DA 3
// detectors start off: DET-INJ ships as a ready-made open model; DET-JB and DET-PII models are later.

const SHADOW_DAYS = 14;

const SEED = [
  { id: 'DET-INJ', version: 'deberta-v3-base-injection-v2-fp32', notes: 'protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0), fp32 ONNX; int8 dynamic quantisation was rejected (scored a planted instruction 0.10 vs 1.00)' },
  { id: 'DET-JB', version: 'not-deployed', notes: 'model not selected yet (E39)' },
  { id: 'DET-PII', version: 'not-deployed', notes: 'pattern DLP covers structured identifiers; ML recogniser is E39' },
];

for (const d of SEED) {
  db.prepare('INSERT OR IGNORE INTO detector (id, version, mode, notes) VALUES (?, ?, ?, ?)').run(d.id, d.version, d.version === 'not-deployed' ? 'off' : 'shadow', d.notes);
  db.prepare("UPDATE detector SET shadow_since = COALESCE(shadow_since, ?) WHERE id = ? AND mode = 'shadow'").run(nowIso(), d.id);
}

export const list = () => db.prepare('SELECT * FROM detector ORDER BY id').all();

export function setMode(id: string, mode: DetectorMode, p: Principal, opts: { reason: string; dev_override?: boolean; model_sha256?: string }) {
  if (!['off', 'shadow', 'active'].includes(mode)) throw invalid('mode must be off, shadow or active');
  if (p.kind !== 'human') throw forbidden('RB-INV-10', 'detector promotion is human-only');
  if (!opts.reason?.trim()) throw invalid('a reason is required');
  const d = db.prepare('SELECT * FROM detector WHERE id = ?').get(id) as { id: string; version: string; mode: DetectorMode; shadow_since: string | null } | undefined;
  if (!d) throw notFound(`detector ${id}`);
  if (d.version === 'not-deployed' && mode !== 'off') throw new PolicyError('E39', `${id} has no model deployed`, 409);
  let override = false;
  if (mode === 'active') {
    const days = d.shadow_since ? (Date.now() - Date.parse(d.shadow_since)) / 86_400_000 : 0;
    if (d.mode !== 'shadow') throw new PolicyError('RB-MOD-03', `${id} must run in shadow before it is promoted`, 409);
    if (days < SHADOW_DAYS) {
      // Dev installs may skip the wait, but the override is written to the ledger and shown on the detector.
      if (!(opts.dev_override && (process.env.SIGNET_ENV ?? 'dev') === 'dev')) {
        throw new PolicyError('RB-MOD-03', `${id} has been in shadow ${days.toFixed(1)} days; promotion needs ${SHADOW_DAYS}`, 409);
      }
      override = true;
    }
  }
  tx(() => {
    db.prepare('UPDATE detector SET mode = ?, shadow_since = CASE WHEN ? = ? THEN ? ELSE shadow_since END, promoted_by = ?, promoted_at = ?, model_sha256 = COALESCE(?, model_sha256) WHERE id = ?').run(
      mode, mode, 'shadow', nowIso(), p.id, nowIso(), opts.model_sha256 ?? null, id,
    );
    ledger.append({ kind: 'admin', data: { event: 'detector.mode_changed', detector: id, version: d.version, from: d.mode, to: mode, reason: opts.reason, shadow_period_skipped: override, actor: p.id } });
  });
  hub.publish('bundle', { reason: 'detector.mode_changed', detector: id });
  return db.prepare('SELECT * FROM detector WHERE id = ?').get(id);
}

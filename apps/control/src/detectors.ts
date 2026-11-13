import { DEV_OVERRIDE_DISABLED, devOverridesAllowed, knownPin, specHash, type DetectorMode } from '@signet/core';
import { GROUND_SPEC } from './grounding';
import * as benchmarks from './benchmarks';
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
  { id: 'DET-ANOM', version: 'baseline-zscore-v1', notes: 'statistics, no neural network: per-agent baselines of volume, cost and errors by hour of day plus tool mix from the last 14 days of the ledger (DA 3)' },
  { id: 'DET-GROUND', version: 'tenant-llm-judge-v1', notes: 'Tier 2, offline: the approved cloud model of the tenant judges a sample of answers (1%, 5% for T1) against their sources; findings only, never changes a decision (DA 3)' },
  { id: 'DET-PII', version: 'presidio-analyzer-2', notes: 'Microsoft Presidio (MIT) for names and addresses in free text; gateway calls SIGNET_PRESIDIO_URL. Pattern DLP still covers structured identifiers.' },
  // DET-SAFE was blocking unsafe content before it was registered here, so it starts active (recorded as
  // grandfathered in the ledger) rather than silently dropping to shadow. It uses the cloud LLM as a
  // classifier until a small safety model (Llama Guard / Granite Guardian / ShieldGemma family) replaces it.
  { id: 'DET-SAFE', version: 'gpt-oss-120b-safety-prompt-v1', notes: 'cloud LLM used as a safety classifier (interim; DA 3 asks for a small classifier); grandfathered active', mode: 'active' as const },
];

// DET-PII used to ship as not-deployed; it now has a model, so it moves to shadow (RB-MOD-03: 14 days before it may be promoted).
(await db.prepare("UPDATE detector SET version = 'presidio-analyzer-2', mode = 'shadow', shadow_since = ?, notes = ? WHERE id = 'DET-PII' AND version = 'not-deployed'").run(nowIso(), 'Microsoft Presidio (MIT) for names and addresses in free text; gateway calls SIGNET_PRESIDIO_URL. Pattern DLP still covers structured identifiers.'));

for (const d of SEED) {
  const known = await db.prepare('SELECT id FROM detector WHERE id = ?').get(d.id);
  const mode: string = ('mode' in d && d.mode) || (d.version === 'not-deployed' ? 'off' : 'shadow');
  (await db.prepare('INSERT INTO detector (id, version, mode, notes) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING').run(d.id, d.version, mode, d.notes));
  if (!known && mode === 'active') (await ledger.append({ kind: 'admin', data: { event: 'detector.registered', detector: d.id, version: d.version, mode, grandfathered: true, reason: 'was enforcing before it was registered; kept active so protection does not drop', actor: 'system' } }));
  (await db.prepare("UPDATE detector SET shadow_since = COALESCE(shadow_since, ?) WHERE id = ? AND mode = 'shadow'").run(nowIso(), d.id));
}

// Pin every detector version Signet knows from code (DA 3): model weights for DET-INJ, the specification
// hash for the others. A pin is set once per version; a different hash for the same version is refused
// by the gateway (the detector reports unavailable) until a person pins a new release.
const pinFor = (id: string, version: string) => knownPin(id, version) ?? (id === 'DET-GROUND' && version === GROUND_SPEC.version ? specHash(GROUND_SPEC) : null);
for (const d of (await db.prepare('SELECT id, version, model_sha256 FROM detector').all()) as { id: string; version: string; model_sha256: string | null }[]) {
  const pin = pinFor(d.id, d.version);
  if (!pin) continue;
  if (!d.model_sha256) {
    (await db.prepare('UPDATE detector SET model_sha256 = ? WHERE id = ? AND model_sha256 IS NULL').run(pin, d.id));
    (await ledger.append({ kind: 'admin', data: { event: 'detector.pinned', detector: d.id, version: d.version, sha256: pin, actor: 'system' } }));
  }
  (await db.prepare('INSERT INTO detector_pin (detector_id, version, sha256, pinned_by, pinned_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING').run(d.id, d.version, d.model_sha256 ?? pin, 'system', nowIso()));
}
// A version already active (DET-SAFE, grandfathered) is the champion a new version must beat.
(await db.prepare("UPDATE detector_pin SET activated_at = ? WHERE activated_at IS NULL AND (detector_id, sha256) IN (SELECT id, model_sha256 FROM detector WHERE mode = 'active')").run(nowIso()));

/** Hashes each detector has ever been pinned to (Replay checks recorded hashes against these). */
export async function pinsOf(id: string): Promise<Set<string>> {
  return new Set(((await db.prepare('SELECT sha256 FROM detector_pin WHERE detector_id = ?').all(id)) as { sha256: string }[]).map((r) => r.sha256));
}

export const list = async () => (await db.prepare('SELECT * FROM detector ORDER BY id').all());

export async function setMode(id: string, mode: DetectorMode, p: Principal, opts: { reason: string; dev_override?: boolean; model_sha256?: string }) {
  if (!['off', 'shadow', 'active'].includes(mode)) throw invalid('mode must be off, shadow or active');
  if (p.kind !== 'human') throw forbidden('RB-INV-10', 'detector promotion is human-only');
  if (!opts.reason?.trim()) throw invalid('a reason is required');
  const d = (await db.prepare('SELECT * FROM detector WHERE id = ?').get(id)) as { id: string; version: string; mode: DetectorMode; shadow_since: string | null } | undefined;
  if (!d) throw notFound(`detector ${id}`);
  if (d.version === 'not-deployed' && mode !== 'off') throw new PolicyError('E39', `${id} has no model deployed`, 409);
  let override = false;
  let skipped: string[] = [];
  if (mode === 'active') {
    const days = d.shadow_since ? (Date.now() - Date.parse(d.shadow_since)) / 86_400_000 : 0;
    if (d.mode !== 'shadow') throw new PolicyError('RB-MOD-03', `${id} must run in shadow before it is promoted`, 409);
    if (days < SHADOW_DAYS) {
      // Dev installs may skip the wait, but the override is written to the ledger and shown on the detector.
      if (!(opts.dev_override && devOverridesAllowed())) {
        throw new PolicyError('RB-MOD-03', `${id} has been in shadow ${days.toFixed(1)} days; promotion needs ${SHADOW_DAYS}${opts.dev_override ? `; ${DEV_OVERRIDE_DISABLED}` : ''}`, 409);
      }
      override = true;
    }
    // Release gate (DA 6 mechanism 4, SGC-SELF-004): benchmark passed, beats the champion, Security and AI Assurance approved.
    const g = await benchmarks.gate(id);
    if (!g.ok) {
      const failed = g.checks.filter((c) => !c.ok);
      if (!(opts.dev_override && devOverridesAllowed())) throw new PolicyError('SGC-SELF-004', `${id} cannot be promoted: ${failed.map((c) => `${c.what}: ${c.detail}`).join('; ')}`, 409);
      override = true;
      skipped = failed.map((c) => c.what);
    }
  }
  (await tx(async () => {
    (await db.prepare('UPDATE detector SET mode = ?, shadow_since = CASE WHEN ? = ? THEN ? ELSE shadow_since END, promoted_by = ?, promoted_at = ?, model_sha256 = COALESCE(?, model_sha256) WHERE id = ?').run(
      mode, mode, 'shadow', nowIso(), p.id, nowIso(), opts.model_sha256 ?? null, id,
    ));
    (await ledger.append({ kind: 'admin', data: { event: 'detector.mode_changed', detector: id, version: d.version, from: d.mode, to: mode, reason: opts.reason, shadow_period_skipped: override, release_checks_skipped: skipped, actor: p.id } }));
  }));
  if (mode === 'active') await benchmarks.markActivated(id);
  hub.publish('bundle', { reason: 'detector.mode_changed', detector: id });
  return (await db.prepare('SELECT * FROM detector WHERE id = ?').get(id));
}

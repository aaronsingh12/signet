import { combine, combineWithDetectorOutageAudit, newId, zToScore, type DetectorResult, type Outcome } from '@signet/core';
import { db, nowIso } from './db';
import { pinsOf } from './detectors';
import { notFound } from './errors';
import * as ledger from './ledger';

// Replay (DA 6 mechanism 3, SGC-SELF-007). The ledger keeps hashes, not prompts, so Replay re-runs the
// decision from what was recorded: the Tier 0 rule result, the tier, each detector's version hash,
// score and thresholds. It re-bands every score, recomputes DET-ANOM from its features, checks each
// hash was a released pin, and runs the decision combiner again. The outcome must match. Every replay
// is written to the ledger as evidence.

type Band = 'low' | 'elevated' | 'high';
interface RecordedDetector { id: string; version: string; status: DetectorResult['status']; score?: number; band?: Band; sha256?: string; thresholds?: [number, number]; features?: Record<string, number> }
interface DecisionInputs { tier: 'T1' | 'T2' | 'T3' | 'T4'; rule_outcome: Outcome; combiner: 'strict' | 'outage_audit'; combined: Outcome; detectors: RecordedDetector[] }
export interface Check { what: string; ok: boolean; detail: string }
export interface ReplayResult { record_id: string; status: 'reproduced' | 'mismatch' | 'not_replayable'; recorded?: Outcome; replayed?: Outcome; bundle_version?: number | null; checks: Check[]; reason?: string }

const bandOf = (s: number, [e, h]: [number, number]): Band => (s >= h ? 'high' : s >= e ? 'elevated' : 'low');

export async function replayData(recordId: string, data: Record<string, unknown>): Promise<ReplayResult> {
  const di = data.decision_inputs as DecisionInputs | undefined;
  if (!di) return { record_id: recordId, status: 'not_replayable', checks: [], reason: 'no decision inputs on this record (a rule-only refusal, or written before Replay inputs were logged)' };
  const checks: Check[] = [];
  const pins = new Map<string, Set<string>>();
  const rebanded: DetectorResult[] = [];
  const seen = [...di.detectors, ...((data.detectors as RecordedDetector[] | undefined) ?? [])];
  for (const d of seen) {
    const id = d.id.split('.')[0]!; // DET-INJ.tool, DET-SAFE.output
    if (d.sha256) {
      if (!pins.has(id)) pins.set(id, await pinsOf(id));
      const known = pins.get(id)!;
      if (known.size) checks.push({ what: `${d.id} version`, ok: known.has(d.sha256), detail: known.has(d.sha256) ? `hash ${d.sha256.slice(0, 12)} is a released pin` : `hash ${d.sha256.slice(0, 12)} was never pinned for ${id}` });
    }
    if (d.features && typeof d.score === 'number') {
      const score = zToScore(Math.max(0, ...Object.values(d.features)));
      checks.push({ what: `${d.id} score`, ok: Math.abs(score - d.score) < 0.0015, detail: `recomputed ${score} from features, recorded ${d.score}` });
    }
    if (typeof d.score === 'number' && d.thresholds && d.band && (d.status === 'ok' || d.status === 'shadow')) {
      const b = bandOf(d.score, d.thresholds);
      checks.push({ what: `${d.id} band`, ok: b === d.band, detail: `score ${d.score} with thresholds ${d.thresholds.join(' / ')} gives ${b}, recorded ${d.band}` });
    }
  }
  for (const d of di.detectors) {
    rebanded.push({ id: d.id, version: d.version, status: d.status, score: d.score, band: typeof d.score === 'number' && d.thresholds && d.band ? bandOf(d.score, d.thresholds) : d.band });
  }
  const run = di.combiner === 'outage_audit' ? combineWithDetectorOutageAudit : combine;
  const replayed = run(di.rule_outcome, rebanded, di.tier).outcome;
  checks.push({ what: 'decision', ok: replayed === di.combined, detail: `rule ${di.rule_outcome} with ${rebanded.length} detector result(s) on ${di.tier} gives ${replayed}, recorded ${di.combined}` });
  return { record_id: recordId, status: checks.every((c) => c.ok) ? 'reproduced' : 'mismatch', recorded: di.combined, replayed, bundle_version: (data.bundle_version as number | null) ?? null, checks };
}

export async function replay(recordId: string, actor: string): Promise<ReplayResult> {
  const row = (await db.prepare("SELECT record_id, data FROM ledger_record WHERE record_id = ? AND kind = 'transaction'").get(recordId)) as { record_id: string; data: string } | undefined;
  if (!row) throw notFound(`transaction record ${recordId}`);
  const r = await replayData(row.record_id, JSON.parse(row.data));
  await ledger.append({ kind: 'admin', data: { event: 'replay.run', record_id: recordId, status: r.status, recorded: r.recorded ?? null, replayed: r.replayed ?? null, failed_checks: r.checks.filter((c) => !c.ok).map((c) => c.what), actor } });
  return r;
}

/** Daily sample (SGC-SELF-007): replay up to `n` random decisions from the last 24 hours. */
export async function sample(n = 100, actor = 'system') {
  const since = new Date(Date.now() - 86_400_000).toISOString();
  const rows = (await db.prepare(
    "SELECT record_id, data FROM ledger_record WHERE kind = 'transaction' AND ts >= ? AND data::jsonb -> 'decision_inputs' IS NOT NULL ORDER BY random() LIMIT ?",
  ).all(since, n)) as { record_id: string; data: string }[];
  const results = await Promise.all(rows.map((r) => replayData(r.record_id, JSON.parse(r.data))));
  const mismatched = results.filter((r) => r.status === 'mismatch');
  const run = { id: newId('job'), sampled: results.length, reproduced: results.filter((r) => r.status === 'reproduced').length, mismatched: mismatched.length, created_at: nowIso(), actor };
  await db.prepare('INSERT INTO replay_run (id, sampled, reproduced, mismatched, details, actor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(run.id, run.sampled, run.reproduced, run.mismatched, JSON.stringify(mismatched.slice(0, 20)), actor, run.created_at);
  await ledger.append({ kind: 'admin', data: { event: 'replay.sample', run_id: run.id, sampled: run.sampled, reproduced: run.reproduced, mismatched: run.mismatched, mismatched_records: mismatched.slice(0, 20).map((r) => r.record_id), actor } });
  return { ...run, mismatches: mismatched.slice(0, 20) };
}

export async function runs(limit = 30) {
  const rows = (await db.prepare('SELECT * FROM replay_run ORDER BY created_at DESC LIMIT ?').all(limit)) as { id: string; sampled: number; reproduced: number; mismatched: number; details: string; actor: string; created_at: string }[];
  return rows.map((r) => ({ ...r, details: JSON.parse(r.details) }));
}

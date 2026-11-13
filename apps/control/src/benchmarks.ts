import { BENCHMARK_SETS, PII_ENTITIES, SAFETY_CATEGORIES, SAFETY_POLICY, beats, meetsTargets, metrics, newId, runAnomBenchmark, setHash, type BenchDetector, type Metrics } from '@signet/core';
import { db, nowIso } from './db';
import { PolicyError, forbidden, invalid, notFound } from './errors';
import * as grounding from './grounding';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { askTenantModel } from './tenant-model';

// Detector release process (DA 6 mechanism 4, SGC-SELF-004 / 005):
//   benchmark   each version is scored on a fixed, versioned set; precision / recall targets and FPR <= 1%
//   shadow      14 days beside live traffic, scoring only (detectors.setMode)
//   champion    a new version is promoted only if it beats the version that was last active, on the same set
//   approval    Security and AI Assurance sign off (security_officer and risk_officer, two different people)
// Every step is written to the ledger. DET-INJ is benchmarked by scripts/bench-inj.mts where the model
// runs; DET-ANOM, DET-SAFE, DET-PII and DET-GROUND can be run from the control plane.

export const APPROVAL_DAYS = 30;
const ROLE_FOR = { security: 'security_officer', ai_assurance: 'risk_officer' } as const;

export interface BenchmarkRow { id: string; detector_id: string; version: string; sha256: string; set_id: string; set_sha256: string; metrics: Metrics; passed: boolean; failures: string[]; runner: string; ran_by: string; created_at: string }

const rowOf = (r: Record<string, unknown>): BenchmarkRow => ({ ...(r as unknown as BenchmarkRow), metrics: JSON.parse(String(r.metrics)), failures: JSON.parse(String(r.failures)), passed: Number(r.passed) === 1 });

export async function record(x: { detector: string; version: string; sha256: string; metrics: Metrics; ran_by: string; runner: string }): Promise<BenchmarkRow> {
  const set = BENCHMARK_SETS[x.detector as BenchDetector];
  if (!set) throw invalid(`no benchmark set for ${x.detector}`);
  const gate = meetsTargets(x.detector, x.metrics);
  const row = { id: newId('job'), detector_id: x.detector, version: x.version, sha256: x.sha256, set_id: set.id, set_sha256: setHash(x.detector as BenchDetector), runner: x.runner, ran_by: x.ran_by, created_at: nowIso() };
  await db.prepare('INSERT INTO detector_benchmark (id, detector_id, version, sha256, set_id, set_sha256, metrics, passed, failures, runner, ran_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(row.id, row.detector_id, row.version, row.sha256, row.set_id, row.set_sha256, JSON.stringify(x.metrics), gate.passed ? 1 : 0, JSON.stringify(gate.failures), row.runner, row.ran_by, row.created_at);
  const { by_lang: _l, ...summary } = x.metrics;
  await ledger.append({ kind: 'admin', data: { event: 'detector.benchmarked', detector: x.detector, version: x.version, sha256: x.sha256, set: set.id, set_sha256: row.set_sha256, metrics: summary, passed: gate.passed, failures: gate.failures, actor: x.ran_by } });
  return { ...row, metrics: x.metrics, passed: gate.passed, failures: gate.failures };
}

// --- runners for detectors the control plane can run itself -------------------------------------------
async function predictSafe(text: string): Promise<boolean | null> {
  const r = await askTenantModel([{ role: 'system', content: SAFETY_POLICY }, { role: 'user', content: text }], 1024);
  const label = r?.text.trim();
  const cat = SAFETY_CATEGORIES.find((c) => c === label);
  return cat ? cat !== 'allow' : null;
}

async function predictPii(url: string, text: string): Promise<boolean | null> {
  try {
    const r = await fetch(`${url}/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(10_000), body: JSON.stringify({ text, language: 'en', entities: Object.keys(PII_ENTITIES), score_threshold: Number(process.env.SIGNET_PRESIDIO_MIN_SCORE ?? 0.6) }) });
    if (!r.ok) return null;
    return ((await r.json()) as unknown[]).length > 0;
  } catch {
    return null;
  }
}

export async function run(detectorId: string, p: Principal): Promise<BenchmarkRow> {
  const d = (await db.prepare('SELECT id, version, model_sha256 FROM detector WHERE id = ?').get(detectorId)) as { id: string; version: string; model_sha256: string | null } | undefined;
  if (!d) throw notFound(`detector ${detectorId}`);
  if (!d.model_sha256) throw new PolicyError('SGC-SELF-001', `${detectorId} has no pinned hash to benchmark`, 409);
  let m: Metrics;
  if (detectorId === 'DET-ANOM') m = runAnomBenchmark(BENCHMARK_SETS['DET-ANOM'].cases);
  else if (detectorId === 'DET-SAFE') {
    const cases = BENCHMARK_SETS['DET-SAFE'].cases;
    m = metrics(await Promise.all(cases.map(async (c) => ({ label: c.label, lang: c.lang, predicted: await predictSafe(c.text) }))));
  } else if (detectorId === 'DET-PII') {
    const url = process.env.SIGNET_PRESIDIO_URL?.trim().replace(/\/$/, '');
    if (!url) throw new PolicyError('SGC-SELF-004', 'SIGNET_PRESIDIO_URL is not set on the control plane', 409);
    const cases = BENCHMARK_SETS['DET-PII'].cases;
    m = metrics(await Promise.all(cases.map(async (c) => ({ label: c.label, lang: c.lang, predicted: await predictPii(url, c.text) }))));
  } else if (detectorId === 'DET-GROUND') {
    const cases = BENCHMARK_SETS['DET-GROUND'].cases;
    m = metrics(await Promise.all(cases.map(async (c) => { const j = await grounding.judge(c); return { label: c.label, lang: c.lang, predicted: j ? j.score < grounding.GROUND_SPEC.threshold : null }; })));
  } else throw new PolicyError('SGC-SELF-004', `${detectorId} runs in the gateway; benchmark it with scripts/bench-${detectorId.slice(4).toLowerCase()}.mts where the model is installed`, 409);
  return record({ detector: detectorId, version: d.version, sha256: d.model_sha256, metrics: m, ran_by: p.id, runner: 'control-plane' });
}

export async function list(detectorId: string, limit = 20): Promise<BenchmarkRow[]> {
  return ((await db.prepare('SELECT * FROM detector_benchmark WHERE detector_id = ? ORDER BY created_at DESC LIMIT ?').all(detectorId, limit)) as Record<string, unknown>[]).map(rowOf);
}

async function latestFor(detectorId: string, sha256: string, setSha: string): Promise<BenchmarkRow | null> {
  const r = (await db.prepare('SELECT * FROM detector_benchmark WHERE detector_id = ? AND sha256 = ? AND set_sha256 = ? ORDER BY created_at DESC LIMIT 1').get(detectorId, sha256, setSha)) as Record<string, unknown> | undefined;
  return r ? rowOf(r) : null;
}

// --- approvals ------------------------------------------------------------------------------------------
export async function approve(detectorId: string, p: Principal, body: { as?: string; reason?: string }) {
  if (p.kind !== 'human') throw forbidden('RB-INV-10', 'detector promotion approvals are human-only');
  const as = body.as === 'security' || body.as === 'ai_assurance' ? body.as : null;
  if (!as) throw invalid("as must be 'security' or 'ai_assurance'");
  if (!p.roles.includes(ROLE_FOR[as])) throw forbidden('DA-6', `${as === 'security' ? 'Security' : 'AI Assurance'} approval needs the ${ROLE_FOR[as]} role`);
  if (!body.reason?.trim()) throw invalid('a reason is required');
  const d = (await db.prepare('SELECT version, model_sha256 FROM detector WHERE id = ?').get(detectorId)) as { version: string; model_sha256: string | null } | undefined;
  if (!d?.model_sha256) throw notFound(`pinned detector ${detectorId}`);
  await db.prepare('INSERT INTO detector_approval (detector_id, version, sha256, role, approver, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (detector_id, sha256, role) DO UPDATE SET approver = excluded.approver, reason = excluded.reason, created_at = excluded.created_at')
    .run(detectorId, d.version, d.model_sha256, as, p.id, body.reason.trim(), nowIso());
  await ledger.append({ kind: 'admin', data: { event: 'detector.promotion_approved', detector: detectorId, version: d.version, sha256: d.model_sha256, as, actor: p.id, reason: body.reason.trim() } });
  return gate(detectorId);
}

/** Everything that must hold before a version may become active. */
export async function gate(detectorId: string): Promise<{ ok: boolean; checks: { what: string; ok: boolean; detail: string }[] }> {
  const d = (await db.prepare('SELECT id, version, model_sha256 FROM detector WHERE id = ?').get(detectorId)) as { id: string; version: string; model_sha256: string | null } | undefined;
  if (!d) throw notFound(`detector ${detectorId}`);
  const checks: { what: string; ok: boolean; detail: string }[] = [];
  const set = BENCHMARK_SETS[detectorId as BenchDetector];
  if (!d.model_sha256) checks.push({ what: 'pinned', ok: false, detail: 'no pinned hash' });
  else if (!set) checks.push({ what: 'benchmark', ok: false, detail: 'no benchmark set for this detector yet' });
  else {
    const setSha = setHash(detectorId as BenchDetector);
    const b = await latestFor(detectorId, d.model_sha256, setSha);
    checks.push({ what: 'benchmark', ok: !!b?.passed, detail: !b ? `not benchmarked on ${set.id}` : b.passed ? `passed ${set.id}: precision ${b.metrics.precision}, recall ${b.metrics.recall}, FPR ${b.metrics.fpr}` : `failed ${set.id}: ${b.failures.join('; ')}` });
    // Champion: the last version that was active, if it is a different one.
    const champ = (await db.prepare('SELECT sha256, version FROM detector_pin WHERE detector_id = ? AND sha256 != ? AND activated_at IS NOT NULL ORDER BY activated_at DESC LIMIT 1').get(detectorId, d.model_sha256)) as { sha256: string; version: string } | undefined;
    if (champ) {
      const cb = await latestFor(detectorId, champ.sha256, setSha);
      if (!cb) checks.push({ what: 'champion', ok: false, detail: `the current champion ${champ.version} has no result on ${set.id}; benchmark it so the two can be compared` });
      else if (b) { const v = beats(b.metrics, cb.metrics); checks.push({ what: 'champion', ok: v.ok, detail: `${v.ok ? 'beats' : 'does not beat'} ${champ.version}: ${v.why}` }); }
    } else checks.push({ what: 'champion', ok: true, detail: 'no earlier active version to beat' });
  }
  const since = new Date(Date.now() - APPROVAL_DAYS * 86_400_000).toISOString();
  const approvals = (await db.prepare('SELECT role, approver FROM detector_approval WHERE detector_id = ? AND sha256 = ? AND created_at >= ?').all(detectorId, d.model_sha256 ?? '', since)) as { role: string; approver: string }[];
  const sec = approvals.find((a) => a.role === 'security');
  const ai = approvals.find((a) => a.role === 'ai_assurance');
  checks.push({ what: 'Security approval', ok: !!sec, detail: sec ? `by ${sec.approver}` : `needed from a security_officer within ${APPROVAL_DAYS} days` });
  checks.push({ what: 'AI Assurance approval', ok: !!ai && ai.approver !== sec?.approver, detail: !ai ? `needed from a risk_officer within ${APPROVAL_DAYS} days` : ai.approver === sec?.approver ? 'must be a different person from the Security approver' : `by ${ai.approver}` });
  return { ok: checks.every((c) => c.ok), checks };
}

/** Called when a version becomes active: it is the champion the next version must beat. */
export async function markActivated(detectorId: string) {
  await db.prepare('UPDATE detector_pin SET activated_at = ? WHERE detector_id = ? AND sha256 = (SELECT model_sha256 FROM detector WHERE id = ?)').run(nowIso(), detectorId, detectorId);
}

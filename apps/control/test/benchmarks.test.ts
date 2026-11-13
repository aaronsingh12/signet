import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Detector release process (DA 6 mechanism 4, SGC-SELF-004): benchmark, champion/challenger, and
// Security plus AI Assurance sign-off by two different people before a version may become active.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-bench-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
process.env.SIGNET_SINGLE_OPERATOR = 'false'; // a team install: separation of duties applies
const core = await import('@signet/core');
const detectors = await import('../src/detectors');
const benchmarks = await import('../src/benchmarks');
const { db } = await import('../src/db');
const { permissionsFor } = await import('../src/rbac');
type Role = Parameters<typeof permissionsFor>[0][number];
const person = (id: string, roles: Role[]) => ({ id, name: id, kind: 'human' as const, roles, permissions: permissionsFor(roles), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) });
const admin = person('admin@x.example', ['tenant_admin']);
const sec = person('sec@x.example', ['security_officer']);
const risk = person('risk@x.example', ['risk_officer']);
const both = person('both@x.example', ['security_officer', 'risk_officer']);
after(dropTestDatabase);

test('metrics: no answer on benign traffic counts against the detector', () => {
  const m = core.metrics([{ label: 1, predicted: true, lang: 'en' }, { label: 0, predicted: null, lang: 'en' }, { label: 0, predicted: false, lang: 'hi' }]);
  assert.deepEqual([m.tp, m.fp, m.tn, m.errors, m.fpr], [1, 1, 1, 1, 0.5]);
  assert.equal(core.meetsTargets('DET-INJ', m).passed, false);
  assert.equal(core.beats({ ...m, f1: 0.9, recall: 0.9, fpr: 0 }, { ...m, f1: 0.8, recall: 0.9, fpr: 0 }).ok, true);
  assert.equal(core.beats({ ...m, f1: 0.95, recall: 0.9, fpr: 0.02 }, { ...m, f1: 0.8, recall: 0.9, fpr: 0 }).ok, false, 'more false positives never wins');
});

test('promotion needs a passing benchmark and two different approvers; every step is recorded', async () => {
  await db.prepare("UPDATE detector SET mode = 'shadow', shadow_since = ? WHERE id = 'DET-ANOM'").run(new Date(Date.now() - 15 * 86_400_000).toISOString());
  await assert.rejects(detectors.setMode('DET-ANOM', 'active', admin, { reason: 'go' }), /not benchmarked/);
  const b = await benchmarks.run('DET-ANOM', admin);
  assert.equal(b.passed, true, b.failures.join('; '));
  assert.equal(b.set_id, 'det-anom-v1');
  await assert.rejects(detectors.setMode('DET-ANOM', 'active', admin, { reason: 'go' }), /Security approval/);
  await assert.rejects(benchmarks.approve('DET-ANOM', admin, { as: 'security', reason: 'ok' }), /security_officer/);
  await benchmarks.approve('DET-ANOM', both, { as: 'security', reason: 'reviewed shadow results' });
  const same = await benchmarks.approve('DET-ANOM', both, { as: 'ai_assurance', reason: 'reviewed benchmark' });
  assert.equal(same.ok, false, 'one person cannot give both sign-offs');
  await benchmarks.approve('DET-ANOM', sec, { as: 'security', reason: 'reviewed shadow results' });
  await benchmarks.approve('DET-ANOM', risk, { as: 'ai_assurance', reason: 'reviewed benchmark' });
  assert.equal((await benchmarks.gate('DET-ANOM')).ok, true);
  const r = (await detectors.setMode('DET-ANOM', 'active', admin, { reason: 'release 1' })) as { mode: string };
  assert.equal(r.mode, 'active');
  const pin = (await db.prepare("SELECT activated_at FROM detector_pin WHERE detector_id = 'DET-ANOM'").get()) as { activated_at: string | null };
  assert.ok(pin.activated_at, 'now the champion');
  const events = ((await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin'").all()) as { data: string }[]).map((x) => JSON.parse(x.data).event);
  for (const e of ['detector.benchmarked', 'detector.promotion_approved', 'detector.mode_changed']) assert.ok(events.includes(e), e);
});

test('a challenger must beat the champion on the same set', async () => {
  // A new DET-ANOM version (different hash) that scores worse than the champion.
  await db.prepare("UPDATE detector SET version = 'baseline-zscore-v2', model_sha256 = ?, mode = 'shadow', shadow_since = ? WHERE id = 'DET-ANOM'").run('9'.repeat(64), new Date(Date.now() - 20 * 86_400_000).toISOString());
  await db.prepare("INSERT INTO detector_pin (detector_id, version, sha256, pinned_by, pinned_at) VALUES ('DET-ANOM', 'baseline-zscore-v2', ?, 'test', ?)").run('9'.repeat(64), new Date().toISOString());
  const worse = { ...core.runAnomBenchmark(), tp: 17, fn: 3, recall: 0.85, f1: 0.919 };
  await benchmarks.record({ detector: 'DET-ANOM', version: 'baseline-zscore-v2', sha256: '9'.repeat(64), metrics: worse, ran_by: 'test', runner: 'test' });
  await benchmarks.approve('DET-ANOM', sec, { as: 'security', reason: 'r' });
  await benchmarks.approve('DET-ANOM', risk, { as: 'ai_assurance', reason: 'r' });
  const g = await benchmarks.gate('DET-ANOM');
  assert.equal(g.checks.find((c) => c.what === 'benchmark')!.ok, true, 'meets the absolute targets');
  assert.equal(g.checks.find((c) => c.what === 'champion')!.ok, false, 'but does not beat the champion');
  await assert.rejects(detectors.setMode('DET-ANOM', 'active', admin, { reason: 'v2' }), /does not beat/);
});

test('single-operator install: the one administrator gives both sign-offs, recorded as a waiver', async () => {
  process.env.SIGNET_SINGLE_OPERATOR = 'true';
  try {
    await db.prepare("DELETE FROM detector_approval WHERE detector_id = 'DET-ANOM'").run();
    await benchmarks.approve('DET-ANOM', admin, { as: 'security', reason: 'solo' });
    const g = await benchmarks.approve('DET-ANOM', admin, { as: 'ai_assurance', reason: 'solo' });
    assert.match(g.checks.find((c) => c.what === 'AI Assurance approval')!.detail, /waived/);
    const last = JSON.parse(((await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin' ORDER BY seq DESC LIMIT 1").get()) as { data: string }).data);
    assert.equal(last.separation_of_duties, 'waived_single_operator');
  } finally {
    process.env.SIGNET_SINGLE_OPERATOR = 'false';
  }
});

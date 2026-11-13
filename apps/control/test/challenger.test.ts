import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Model detector releases and champion / challenger (DA 3, DA 6 mechanism 4).
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-challenger-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
process.env.SIGNET_SINGLE_OPERATOR = 'false';
const core = await import('@signet/core');
const { db } = await import('../src/db');
const detectors = await import('../src/detectors');
const benchmarks = await import('../src/benchmarks');
const { permissionsFor } = await import('../src/rbac');
type Role = Parameters<typeof permissionsFor>[0][number];
const person = (id: string, roles: Role[]) => ({ id, name: id, kind: 'human' as const, roles, permissions: permissionsFor(roles), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) });
const admin = person('admin@x.example', ['tenant_admin']);
const sec = person('sec@x.example', ['security_officer']);
const risk = person('risk@x.example', ['risk_officer']);
after(dropTestDatabase);

const row = async (id: string) => (await db.prepare('SELECT * FROM detector WHERE id = ?').get(id)) as { version: string; mode: string; model_sha256: string; challenger_version: string | null; challenger_sha256: string | null };

test('new installs run the benchmarked models in shadow, pinned to their weights', async () => {
  const inj = await row('DET-INJ');
  const jb = await row('DET-JB');
  assert.deepEqual([inj.version, inj.mode, inj.model_sha256], [core.MODEL_DETECTORS['DET-INJ'].version, 'shadow', core.MODEL_DETECTORS['DET-INJ'].sha256]);
  assert.deepEqual([jb.version, jb.mode, jb.model_sha256], [core.MODEL_DETECTORS['DET-JB'].version, 'shadow', core.MODEL_DETECTORS['DET-JB'].sha256]);
});

test('DET-SAFE: Granite Guardian runs as a challenger and replaces the cloud prompt only through the gate', async () => {
  await assert.rejects(detectors.startChallenger('DET-SAFE', 'made-up-v9', admin, 'try'), /can pin/);
  await detectors.startChallenger('DET-SAFE', core.GRANITE_SAFE.version, admin, 'small safety model (DA 3)');
  const safe = await row('DET-SAFE');
  assert.equal(safe.mode, 'active', 'the champion keeps protecting');
  assert.equal(safe.challenger_sha256, core.knownPin('DET-SAFE', core.GRANITE_SAFE.version));
  const champion = safe.version;

  await assert.rejects(detectors.promoteChallenger('DET-SAFE', admin, { reason: 'go' }), /0\.0 days|for 0/);
  await db.prepare("UPDATE detector SET challenger_since = ? WHERE id = 'DET-SAFE'").run(new Date(Date.now() - 15 * 86_400_000).toISOString());
  await assert.rejects(detectors.promoteChallenger('DET-SAFE', admin, { reason: 'go' }), /benchmark/);

  // Benchmarks: the champion (cloud prompt) and the challenger on the same set; the challenger is better.
  const m = (tp: number, fp: number) => core.metrics([...Array.from({ length: 15 }, (_, i) => ({ label: 1 as const, lang: 'en', predicted: i < tp })), ...Array.from({ length: 20 }, (_, i) => ({ label: 0 as const, lang: 'en', predicted: i < fp }))]);
  await benchmarks.record({ detector: 'DET-SAFE', version: champion, sha256: safe.model_sha256, metrics: m(13, 1), ran_by: 'test', runner: 'test' });
  await benchmarks.record({ detector: 'DET-SAFE', version: core.GRANITE_SAFE.version, sha256: safe.challenger_sha256!, metrics: m(15, 0), ran_by: 'test', runner: 'test' });
  await benchmarks.approve('DET-SAFE', sec, { as: 'security', reason: 'ok', target: 'challenger' });
  const g = await benchmarks.approve('DET-SAFE', risk, { as: 'ai_assurance', reason: 'ok', target: 'challenger' });
  assert.equal(g.version, core.GRANITE_SAFE.version);
  assert.equal(g.ok, true, JSON.stringify(g.checks));
  assert.equal((await benchmarks.gate('DET-SAFE')).ok, false, 'sign-offs for the challenger do not count for the champion');

  await detectors.promoteChallenger('DET-SAFE', admin, { reason: 'beats the cloud prompt' });
  const after = await row('DET-SAFE');
  assert.deepEqual([after.version, after.mode, after.challenger_version], [core.GRANITE_SAFE.version, 'active', null]);
  const events = ((await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin'").all()) as { data: string }[]).map((x) => JSON.parse(x.data).event);
  assert.ok(events.includes('detector.challenger_started') && events.includes('detector.challenger_promoted'));
});

test('an install from before this release moves to the new models; an active one gets a challenger instead', async () => {
  await db.prepare("UPDATE detector SET version = 'deberta-v3-base-injection-v2-fp32', model_sha256 = ?, mode = 'shadow' WHERE id = 'DET-INJ'").run(core.DET_INJ_MODEL_SHA256);
  await db.prepare("INSERT INTO detector_pin (detector_id, version, sha256, pinned_by, pinned_at) VALUES ('DET-INJ', 'deberta-v3-base-injection-v2-fp32', ?, 'system', ?)").run(core.DET_INJ_MODEL_SHA256, new Date().toISOString());
  await db.prepare("UPDATE detector SET version = 'older-jb-v0', model_sha256 = ?, mode = 'active' WHERE id = 'DET-JB'").run('e'.repeat(64));
  const again: string = '../src/detectors.ts?restart=1';
  await import(again); // the start-up migration runs again
  const inj = await row('DET-INJ');
  const jb = await row('DET-JB');
  assert.deepEqual([inj.version, inj.mode, inj.model_sha256], [core.MODEL_DETECTORS['DET-INJ'].version, 'shadow', core.MODEL_DETECTORS['DET-INJ'].sha256]);
  assert.deepEqual([jb.version, jb.mode, jb.challenger_version], ['older-jb-v0', 'active', core.MODEL_DETECTORS['DET-JB'].version], 'active: keeps running, new model beside it');
  assert.ok((await detectors.pinsOf('DET-INJ')).has(core.DET_INJ_MODEL_SHA256), 'old decisions still replay against the old pin');
});

test('a challenger can be stopped', async () => {
  await detectors.startChallenger('DET-SAFE', 'gpt-oss-120b-safety-prompt-v1', admin, 'compare again');
  await detectors.stopChallenger('DET-SAFE', admin, 'not needed');
  assert.equal((await row('DET-SAFE')).challenger_version, null);
});

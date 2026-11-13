import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Detector pins and Replay (DA 3 "pinned and hashed", DA 6 mechanism 3, SGC-SELF-001 / 007).
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-replay-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const core = await import('@signet/core');
const detectors = await import('../src/detectors');
const replay = await import('../src/replay');
const registry = await import('../src/registry');
const ledger = await import('../src/ledger');
const { permissionsFor } = await import('../src/rbac');
const owner = { id: 'o@x.example', name: 'o', kind: 'human' as const, roles: ['agent_owner' as const], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };
after(dropTestDatabase);

test('every detector version Signet knows from code is pinned at start-up', async () => {
  const rows = (await detectors.list()) as { id: string; model_sha256: string | null }[];
  const pin = (id: string) => rows.find((r) => r.id === id)!.model_sha256;
  assert.equal(pin('DET-INJ'), core.MODEL_DETECTORS['DET-INJ'].sha256);
  assert.equal(pin('DET-JB'), core.MODEL_DETECTORS['DET-JB'].sha256);
  assert.equal(pin('DET-SAFE'), core.specHash(core.DETECTOR_SPECS['DET-SAFE']!.spec));
  assert.equal(pin('DET-ANOM'), core.knownPin('DET-ANOM', core.ANOM_VERSION));
  assert.ok(pin('DET-GROUND') && pin('DET-PII'));
  assert.ok((await detectors.pinsOf('DET-SAFE')).has(pin('DET-SAFE')!));
});

test('replay reproduces recorded decisions and catches a changed outcome or an unreleased hash', async () => {
  const agent = await registry.registerAgent({ handle: 'replay-agent', name: 'replay-agent', purpose: 'Answers order questions', sponsor: 's@x.example', autonomy_level: 'L2' } as never, owner);
  const anomPin = core.knownPin('DET-ANOM', core.ANOM_VERSION)!;
  const injPin = core.MODEL_DETECTORS['DET-INJ'].sha256;
  const anom = { id: 'DET-ANOM', version: core.ANOM_VERSION, status: 'ok', score: core.zToScore(3.2), band: 'elevated', sha256: anomPin, thresholds: core.ANOM_THRESHOLDS.T2, features: { volume: 3.2, cost: 1.1 } };
  const inj = { id: 'DET-INJ', version: core.MODEL_DETECTORS['DET-INJ'].version, status: 'ok', score: 0.91, band: 'high', sha256: injPin, thresholds: core.INJ_THRESHOLDS.prompt.T2 };
  const write = async (inputs: unknown, detectors: unknown[] = []) => (await ledger.append({ kind: 'transaction', agent_id: agent.id, data: { action_type: 'llm_call', bundle_version: 7, decision_inputs: inputs, detectors } })).record_id;

  // Allow + DET-ANOM elevated on T2 -> hold for approval (DA 4 matrix).
  const good = await write({ tier: 'T2', rule_outcome: 'allow', combiner: 'strict', combined: 'require_approval', detectors: [anom] }, [inj]);
  const r = await replay.replay(good, 'auditor@x.example');
  assert.equal(r.status, 'reproduced', JSON.stringify(r.checks));
  assert.equal(r.replayed, 'require_approval');
  assert.ok(r.checks.some((c) => c.what === 'DET-ANOM score' && c.ok));
  assert.ok(r.checks.some((c) => c.what === 'DET-INJ band' && c.ok));

  // The record claims the action was allowed: the combiner says otherwise.
  const changed = await write({ tier: 'T2', rule_outcome: 'allow', combiner: 'strict', combined: 'allow', detectors: [anom] });
  const c = await replay.replay(changed, 'auditor@x.example');
  assert.equal(c.status, 'mismatch');
  assert.equal(c.replayed, 'require_approval');

  // Scored by a version that was never pinned.
  const rogue = await write({ tier: 'T3', rule_outcome: 'allow', combiner: 'strict', combined: 'allow', detectors: [{ ...anom, sha256: 'f'.repeat(64), score: 0, band: 'low', features: { volume: 0 } }] });
  const g = await replay.replay(rogue, 'auditor@x.example');
  assert.equal(g.status, 'mismatch');
  assert.ok(g.checks.some((x) => x.what === 'DET-ANOM version' && !x.ok));

  const none = await write(undefined);
  assert.equal((await replay.replay(none, 'auditor@x.example')).status, 'not_replayable');

  // The daily sample covers records with decision inputs and is written as evidence.
  const s = await replay.sample(100, 'test');
  assert.equal(s.sampled, 3);
  assert.equal(s.mismatched, 2);
  const runs = await replay.runs();
  assert.equal(runs[0]!.mismatched, 2);
});

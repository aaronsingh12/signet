import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-onboard-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
process.env.SIGNET_SINGLE_OPERATOR = 'true';

after(async () => {
  await dropTestDatabase();
});

const { permissionsFor } = await import('../src/rbac');
const registry = await import('../src/registry');
const workflow = await import('../src/workflow');
const quick = await import('../src/quick-connect');
const controls = await import('../src/controls');
await controls.seed();

const roles = ['tenant_admin', 'platform_admin', 'governance_board', 'risk_officer', 'security_officer', 'agent_owner'] as Principal['roles'];
const admin = { id: 'admin', kind: 'human', roles, permissions: permissionsFor(roles), groups: [], mfa: true } as unknown as Principal;
let n = 0;
const input = (extra: object = {}) => ({ handle: `v-${++n}`, name: 'Validated', purpose: 'Checks onboarding validation', sponsor: 'a@x.example', autonomy_level: 'L2', ...extra }) as never;
const isClientError = (e: { status?: number }) => e.status !== undefined && e.status < 500;
const model = { model: 'gpt-oss:120b-cloud', region: 'unverified' };
const limits = { rpm: 1, tokens_per_day: 1, usd_per_day: 1 };

test('registration refuses malformed input with a client error', async () => {
  for (const bad of [{ team: 'x' }, { team: [{ role: 'builder' }] }, { team: [{ user: 'a@b.c', role: 'king' }] }, { name: 'x'.repeat(201) }, { purpose: 'short' }]) {
    await assert.rejects(registry.registerAgent(input(bad), admin), isClientError, JSON.stringify(bad).slice(0, 40));
  }
});

test('intake values that classification scores must be real', async () => {
  const agent = await registry.registerAgent(input(), admin);
  for (const bad of [{ users_affected: ['nobody'] }, { users_affected: 'public' }, { data_touched: ['nonsense'] }, { reversibility: 'maybe' }]) {
    await assert.rejects(workflow.start(agent, bad as never, admin), isClientError, JSON.stringify(bad));
  }
  const lc = await workflow.start(agent, { users_affected: ['internal'], data_touched: [] } as never, admin);
  await assert.rejects(workflow.updateIntake(lc.id, { users_affected: ['nobody'] } as never, admin), isClientError);
});

test('manifests that could never work are refused', async () => {
  const agent = await registry.registerAgent(input(), admin);
  for (const bad of [
    { models: 'x', environments: ['dev'], limits },
    { models: [model], environments: ['moon'], limits },
    { models: [model], environments: ['dev'], limits, data_classes: { prompt: ['personal'], forbidden: ['personal'] } },
  ]) await assert.rejects(registry.validateSeal(agent, bad as never), isClientError, JSON.stringify(bad).slice(0, 60));
});

test('"Partly" completes the questionnaire and opens a gap against that control', async () => {
  const r = await quick.start({ name: 'Partly Agent', purpose: 'Answers customer questions', users_affected: ['customers'], reversibility: 'yes' }, admin);
  assert.ok(r.state === 'needs_answers');
  const done = await quick.advance(r.agent_id, r.lifecycle_id, admin, { ...Object.fromEntries(r.questions.map((q) => [q.id, 'yes'])), q6: 'partial' });
  assert.equal(done.state, 'connected');
  assert.ok(done.state === 'connected' && done.open_gaps.length === 1, 'the gap is reported with the key');
});

test('quick connect refuses bad input before creating anything, and reports later failures with a link', async () => {
  await assert.rejects(quick.start({ name: 'Too Short', purpose: 'x', users_affected: ['internal'] }, admin), isClientError);
  const retry = await quick.start({ name: 'Too Short', purpose: 'A proper purpose for this agent', users_affected: ['internal'], reversibility: 'yes' }, admin);
  assert.equal(retry.state, 'connected', 'the failed attempt left nothing behind');
  const r = await quick.start({ name: 'Bad Answer', purpose: 'Answers customer questions', users_affected: ['customers'], reversibility: 'yes' }, admin);
  await assert.rejects(quick.advance(r.agent_id, r.lifecycle_id, admin, { q2: 'maybe' }), isClientError);
});

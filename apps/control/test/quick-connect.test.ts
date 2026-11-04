import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-quick-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
process.env.SIGNET_SINGLE_OPERATOR = 'true';

after(async () => {
  await dropTestDatabase();
});

const { permissionsFor } = await import('../src/rbac');
const quick = await import('../src/quick-connect');
const registry = await import('../src/registry');
const controls = await import('../src/controls');
await controls.seed();

const roles = ['tenant_admin', 'platform_admin', 'governance_board', 'risk_officer', 'security_officer', 'agent_owner'] as Principal['roles'];
const admin = { id: 'admin', kind: 'human', roles, permissions: permissionsFor(roles), groups: [], mfa: true } as unknown as Principal;
const base = { purpose: 'Answers internal questions about policy', reversibility: 'yes', data_touched: [] as string[] };

test('a low-risk internal agent gets a working key straight away (T4)', async () => {
  const r = await quick.start({ ...base, name: 'Quick Internal', users_affected: ['internal'] }, admin);
  assert.equal(r.state, 'connected');
  assert.equal(r.tier, 'T4');
  assert.ok(r.state === 'connected' && r.deployment_credential.startsWith('sdc_'));
  assert.ok(await registry.activeCertificate(r.agent_id));
});

test('T3 stops for the admin\'s own answers; nothing is answered on their behalf, then approval is recorded', async () => {
  const first = await quick.start({ ...base, name: 'Quick Customer', users_affected: ['customers'] }, admin);
  assert.equal(first.state, 'needs_answers');
  assert.equal(first.tier, 'T3');
  assert.equal(await registry.activeCertificate(first.agent_id), null);
  assert.ok(first.state === 'needs_answers');
  const partial = await quick.advance(first.agent_id, first.lifecycle_id, admin, { [first.questions[0]!.id]: 'yes' });
  assert.equal(partial.state, 'needs_answers');
  const done = await quick.advance(first.agent_id, first.lifecycle_id, admin, Object.fromEntries(first.questions.map((q) => [q.id, 'yes'])));
  assert.equal(done.state, 'connected');
  assert.ok(await registry.activeCertificate(first.agent_id));
});

test('a "no" on a high-severity question opens a gap and sends the agent to the full lifecycle', async () => {
  const first = await quick.start({ ...base, name: 'Quick Gap', users_affected: ['customers'] }, admin);
  assert.ok(first.state === 'needs_answers');
  const done = await quick.advance(first.agent_id, first.lifecycle_id, admin, { ...Object.fromEntries(first.questions.map((q) => [q.id, 'yes'])), q7: 'no' });
  assert.equal(done.state, 'needs_review');
  assert.equal(await registry.activeCertificate(first.agent_id), null);
});

test('high-risk agents cannot take the shortcut', async () => {
  const r = await quick.start({ purpose: base.purpose, reversibility: 'no', data_touched: ['personal'], name: 'Quick Risky', users_affected: ['public'], decisions_about_individuals: true }, admin);
  assert.equal(r.state, 'needs_review');
  assert.ok(r.tier === 'T1' || r.tier === 'T2');
  assert.equal(await registry.activeCertificate(r.agent_id), null);
});

test('a test call explains an unreachable gateway and refuses anything that is not a key', async () => {
  process.env.SIGNET_GATEWAY_PUBLIC_URL = 'http://127.0.0.1:9';
  const r = await quick.testCall('sdc_abc123');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'gateway_unreachable');
  await assert.rejects(quick.testCall('not-a-key'));
});

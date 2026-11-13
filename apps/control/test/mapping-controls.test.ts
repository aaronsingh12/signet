import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Controls added to cover the remaining framework requirements: encryption in transit and at rest
// (SC-8, SC-28), lawful basis (GDPR Art. 6), transfers (Art. 44), appeal routes (contestability),
// unsafe content (DET-SAFE) and injection / jailbreak detection (DET-INJ, DET-JB).
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-mapping-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const controls = await import('../src/controls');
const registry = await import('../src/registry');
const workflow = await import('../src/workflow');
await import('../src/detectors');
await controls.seed();
const { permissionsFor } = await import('../src/rbac');
const owner = { id: 'o@x.example', name: 'o', kind: 'human' as const, roles: ['agent_owner' as const], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };
after(dropTestDatabase);
const statusOf = async (id: string) => (await controls.evaluate()).find((r) => r.control_id === id)!;

test('intake: appeal route and lawful basis are validated and pre-fill the assessment', async () => {
  const agent = await registry.registerAgent({ handle: 'loans-agent', name: 'loans-agent', purpose: 'Pre-screens loan applications', sponsor: 's@x.example', autonomy_level: 'L2' } as never, owner);
  await assert.rejects(workflow.start(agent, { users_affected: ['customers'], data_touched: ['personal'], decisions_about_individuals: true, lawful_basis: 'because' } as never, owner), /lawful_basis must be one of/);
  const lc = await workflow.start(agent, { users_affected: ['customers'], data_touched: ['personal'], decisions_about_individuals: true, individual_domains: ['credit'] } as never, owner);
  assert.equal((await statusOf('SGC-HUMAN-005')).status, 'ineffective', 'decides about people, no appeal route');
  assert.equal((await statusOf('SGC-DATA-005')).status, 'ineffective', 'personal data, no lawful basis');
  await workflow.updateIntake(lc.id, { appeal_route: 'https://bank.example/appeal or appeals@bank.example', lawful_basis: 'contract' }, owner);
  assert.equal((await statusOf('SGC-HUMAN-005')).status, 'effective');
  assert.equal((await statusOf('SGC-DATA-005')).status, 'effective');
});

test('encryption in transit: a remote database without sslmode=require or a plain-http LLM is ineffective', async () => {
  const saved = { db: process.env.DATABASE_URL, llm: process.env.SIGNET_LLM_BASE_URL, pub: process.env.SIGNET_PUBLIC_URL };
  try {
    process.env.SIGNET_PUBLIC_URL = 'https://signet.example';
    process.env.SIGNET_LLM_BASE_URL = 'https://ollama.com/v1';
    assert.equal((await statusOf('SGC-DATA-003')).status, 'effective', 'local database, TLS elsewhere');
    process.env.SIGNET_LLM_BASE_URL = 'http://llm.internal.example/v1';
    const r = await statusOf('SGC-DATA-003');
    assert.equal(r.status, 'ineffective');
    assert.match(r.detail, /cloud LLM uses http/);
  } finally {
    process.env.SIGNET_LLM_BASE_URL = saved.llm;
    process.env.SIGNET_PUBLIC_URL = saved.pub;
  }
});

test('at rest, transfers, unsafe content and injection detection report honestly', async () => {
  assert.equal((await statusOf('SGC-DATA-004')).status, 'partially_effective', 'the local key is not enough for production');
  assert.notEqual((await statusOf('SGC-DATA-006')).status, 'ineffective');
  assert.notEqual((await statusOf('SGC-SEC-003')).status, 'ineffective', 'DET-SAFE is active');
  const inj = await statusOf('SGC-SEC-004');
  assert.equal(inj.status, 'partially_effective');
  assert.match(inj.detail, /DET-INJ, DET-JB in shadow/);
});

test('after Propose only the appeal route and lawful basis can change, and the change is in the ledger', async () => {
  const { db } = await import('../src/db');
  const agent = await registry.registerAgent({ handle: 'sealed-agent', name: 'sealed-agent', purpose: 'Screens job applications', sponsor: 's@x.example', autonomy_level: 'L2' } as never, owner);
  const lc = await workflow.start(agent, { users_affected: ['public'], data_touched: ['personal'], decisions_about_individuals: true, individual_domains: ['employment'] } as never, owner);
  await db.prepare("UPDATE lifecycle SET stage = 'monitor' WHERE id = ?").run(lc.id);
  await assert.rejects(workflow.updateIntake(lc.id, { users_affected: ['internal'] }, owner), /stage|propose/i);
  await workflow.updateIntake(lc.id, { appeal_route: 'hr-appeals@x.example', lawful_basis: 'legitimate_interests' }, owner);
  const v = await workflow.get(lc.id);
  assert.equal(v.data.intake.appeal_route, 'hr-appeals@x.example');
  const ev = ((await db.prepare("SELECT data FROM ledger_record WHERE kind = 'lifecycle'").all()) as { data: string }[]).map((r) => JSON.parse(r.data)).find((d) => d.event === 'intake.records_updated');
  assert.deepEqual(ev?.fields, ['appeal_route', 'lawful_basis']);
});

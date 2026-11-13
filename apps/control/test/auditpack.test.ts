import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Audit packs (BP 9.6): signed per-framework exports with requirements, controls, inventory,
// independence statement, activity, ledger roots and a framework-specific section.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-auditpack-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const controls = await import('../src/controls');
const registry = await import('../src/registry');
const workflow = await import('../src/workflow');
const ledger = await import('../src/ledger');
const auditpack = await import('../src/auditpack');
const { db } = await import('../src/db');
await import('../src/detectors');
await controls.seed();
const { permissionsFor } = await import('../src/rbac');
const owner = { id: 'o@x.example', name: 'o', kind: 'human' as const, roles: ['agent_owner' as const], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };
const auditor = { ...owner, id: 'auditor@x.example', roles: ['auditor' as const], permissions: permissionsFor(['auditor']) };
after(dropTestDatabase);

const agent = await registry.registerAgent({ handle: 'claims-agent', name: 'claims-agent', purpose: 'Triages insurance claims', sponsor: 's@x.example', autonomy_level: 'L2', vendor: 'ServiceNow' } as never, owner);
await db.prepare("UPDATE agent SET tier = 'T2', vendor = 'ServiceNow' WHERE id = ?").run(agent.id);
await workflow.start(agent, { users_affected: ['customers'], data_touched: ['personal'], decisions_about_individuals: true, individual_domains: ['insurance'], appeal_route: 'claims-appeals@x.example', lawful_basis: 'contract' } as never, owner);
await ledger.append({ kind: 'transaction', agent_id: agent.id, data: { action_type: 'llm_call', policy_decision: 'allow', cost_usd: 0.25 } });
await ledger.append({ kind: 'transaction', agent_id: agent.id, data: { action_type: 'tool_call', policy_decision: 'deny', cost_usd: 0 } });
await controls.evaluate();

test('NIST AI RMF pack: every requirement with its controls, profile by function, gaps; signed and verifiable', async () => {
  const g = await auditpack.generate({ framework_id: 'nist-ai-rmf' }, auditor);
  assert.equal(g.summary!.requirements, 72);
  assert.equal(g.summary!.no_control, 0);
  const file = await auditpack.get(g.id, auditor);
  const p = file.pack;
  assert.equal(p.format, 'signet-audit-pack/1');
  assert.ok(p.requirements.every((r: { controls: unknown[] }) => r.controls.length > 0));
  assert.equal(Object.keys(p.nist_ai_rmf.profile).join(), 'GOVERN,MAP,MEASURE,MANAGE');
  assert.deepEqual(p.activity.transactions, { allow: 1, deny: 1 });
  assert.equal(p.activity.spend_usd, 0.25);
  assert.match(p.independence.statement, /same rulebook/);
  assert.deepEqual(p.independence.governed_vendors, ['ServiceNow']);
  assert.equal(auditpack.verify(file).ok, true);
  // An auditor edits one value: the hash no longer matches the signature.
  const tampered = JSON.parse(JSON.stringify(file));
  tampered.pack.requirements[0].status = 'effective';
  tampered.pack.summary.ineffective = 0;
  tampered.pack.activity.spend_usd = 0;
  assert.equal(auditpack.verify(tampered).ok, false);
  const csv = auditpack.requirementsCsv(p);
  assert.match(csv.split('\n')[0]!, /^requirement,summary,status,controls$/);
  assert.equal(csv.split('\n').length, 73);
});

test('EU AI Act pack has the Annex IV outline for high-risk agents; 800-53 has statements and an OSCAL fragment', async () => {
  const eu = (await auditpack.get((await auditpack.generate({ framework_id: 'eu-ai-act', agents: ['claims-agent'] }, auditor)).id, auditor)).pack;
  const a = eu.eu_ai_act.high_risk_agents[0];
  assert.equal(a.agent, 'claims-agent');
  assert.equal(a.annex_iv['2 development and design'].intake.appeal_route, 'claims-appeals@x.example');
  assert.ok('Art. 14 human oversight' in eu.eu_ai_act.articles);
  const sp = (await auditpack.get((await auditpack.generate({ framework_id: 'nist-800-53' }, auditor)).id, auditor)).pack;
  const sc8 = sp.sp800_53.implementation_statements.find((s: { control: string }) => s.control === 'SC-8');
  assert.match(sc8.implementation, /SGC-DATA-003/);
  const impl = sp.sp800_53.oscal_ssp_fragment['system-security-plan']['control-implementation']['implemented-requirements'];
  assert.ok(impl.some((r: { 'control-id': string }) => r['control-id'] === 'sc-8'));
});

test('board pack: inventory by tier, seals, incidents, open gaps, spend; licence-required frameworks are refused', async () => {
  const b = (await auditpack.get((await auditpack.generate({ framework_id: 'board' }, auditor)).id, auditor)).pack;
  assert.equal(b.board.inventory_by_tier.T2, 1);
  assert.deepEqual(b.board.agents_without_active_seal, ['claims-agent']);
  assert.equal(b.board.spend_usd, 0.25);
  assert.ok(Array.isArray(b.board.open_gaps));
  await assert.rejects(auditpack.generate({ framework_id: 'iso-42001' }, auditor), /licensed copy/);
  await assert.rejects(auditpack.generate({ framework_id: 'nist-ai-rmf', from: '2026-12-01', to: '2026-01-01' }, auditor), /from must not be after to/);
  const events = ((await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin'").all()) as { data: string }[]).map((r) => JSON.parse(r.data).event);
  assert.ok(events.includes('audit_pack.generated') && events.includes('audit_pack.downloaded'), 'exports are logged (BP 12)');
});

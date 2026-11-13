import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Compliance framework catalogue (BP 9): built-in pack, licence rules, per-tenant enable, scores with
// coverage gaps, and the OSCAL importer for NIST SP 800-53 catalogs and FedRAMP profiles.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-fw-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const { db } = await import('../src/db');
const fw = await import('../src/frameworks');
const controls = await import('../src/controls');
const oscal = await import('../src/oscal');
const { permissionsFor } = await import('../src/rbac');
after(dropTestDatabase);

const admin = { id: 'risk@x.example', name: 'risk', kind: 'human' as const, roles: ['risk_officer' as const], permissions: permissionsFor(['risk_officer']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };

test('catalogue: unique ids, every framework has requirements, every mapping names a real Signet Control', () => {
  const ids = fw.REQUIREMENTS.map((r) => `${r.framework_id}:${r.external_id}`);
  assert.equal(new Set(ids).size, ids.length, 'requirement ids are unique');
  for (const f of fw.FRAMEWORKS) assert.ok(fw.REQUIREMENTS.some((r) => r.framework_id === f.id), `${f.id} has requirements`);
  for (const r of fw.REQUIREMENTS) {
    assert.ok(fw.FRAMEWORKS.some((f) => f.id === r.framework_id), `${r.framework_id} is a known framework`);
    for (const m of r.maps) assert.ok(controls.CONTROL_IDS.has(m.control), `${r.framework_id} ${r.external_id} maps to unknown control ${m.control}`);
  }
  assert.equal(fw.REQUIREMENTS.filter((r) => r.framework_id === 'nist-ai-rmf').length, 72, 'all 72 NIST AI RMF subcategories');
  assert.equal(fw.REQUIREMENTS.filter((r) => r.framework_id === 'owasp-llm').length, 10, 'all 10 OWASP LLM risks');
  assert.ok(!fw.REQUIREMENTS.some((r) => r.framework_id === 'fedramp-moderate' && r.external_id === 'AU-10'), 'AU-10 is a High-only control');
});

test('licence rule: paid or restricted standards ship only as empty locked entries', () => {
  for (const f of fw.FRAMEWORKS) assert.doesNotMatch(f.name, /ISO\/IEC|SOC 2|CIS |AI Controls Matrix|Secure Controls Framework/);
  const ids = fw.PLACEHOLDERS.map((x) => x.id);
  for (const id of ['iso-42001', 'iso-27001', 'iso-27701', 'iso-23894', 'soc2-tsc', 'cis-controls', 'csa-aicm', 'scf']) assert.ok(ids.includes(id), id);
  assert.ok(!fw.REQUIREMENTS.some((r) => ids.includes(r.framework_id)), 'no requirement text for licence-needed frameworks');
});

test('framework selection follows the agent profile and the tenant switches', () => {
  const on = ['nist-ai-rmf', 'eu-ai-act', 'gdpr', 'dora'].map((id) => ({ id, name: id }));
  assert.deepEqual(fw.applicableFrameworks(on, { eu_ai_act: false, personal_data: false }), ['NIST AI RMF 1.0', 'DORA (Regulation (EU) 2022/2554)']);
  const both = fw.applicableFrameworks(on, { eu_ai_act: true, personal_data: true });
  assert.ok(both.includes('EU AI Act (Regulation (EU) 2024/1689)') && both.includes('GDPR (Regulation (EU) 2016/679)'));
});

test('seed loads the pack, replaces old ISO 42001 content with a locked entry, keeps tenant switches, and scores show coverage gaps', async () => {
  await db.prepare("INSERT INTO framework (id, name, version, licence, namespace) VALUES ('iso-42001', 'ISO/IEC 42001', '2023', 'x', 'signet') ON CONFLICT DO NOTHING").run();
  await db.prepare("INSERT INTO framework_requirement (id, framework_id, external_id, summary) VALUES ('iso-42001:A.2.2', 'iso-42001', 'A.2.2', 'x') ON CONFLICT DO NOTHING").run();
  await controls.seed();

  await controls.setFrameworkEnabled('dora', true, admin, 'EU bank customer');
  await controls.seed(); // unchanged catalogue: skipped
  await db.prepare("DELETE FROM library_state WHERE key = 'catalogue_sha256'").run();
  await controls.seed(); // a later release reseeds but must not undo the tenant's choice
  const enabled = (await controls.enabledFrameworks()).map((f) => f.id);
  assert.ok(enabled.includes('dora'));
  assert.ok(!enabled.includes('us-nyc-ll144'), 'regional frameworks start switched off');
  const iso = (await db.prepare("SELECT namespace, enabled FROM framework WHERE id = 'iso-42001'").get()) as { namespace: string; enabled: number };
  assert.deepEqual(iso, { namespace: 'licence_required', enabled: 0 }, 'old ISO content is replaced by a locked entry');
  assert.equal(await db.prepare("SELECT id FROM framework_requirement WHERE id = 'iso-42001:A.2.2'").get(), undefined);
  await assert.rejects(controls.setFrameworkEnabled('iso-42001', true, admin, 'try'), /needs a licence/);
  await assert.rejects(controls.setFrameworkEnabled('dora', false, admin, ' '), /reason/);

  const scores = await controls.scores();
  const rmf = scores.find((s) => s.framework_id === 'nist-ai-rmf')!;
  assert.equal(rmf.requirements.length, 72);
  assert.ok(rmf.coverage! > 50 && rmf.coverage! < 100, 'some subcategories have no Signet Control yet');
  assert.ok(rmf.requirements.some((r) => r.status === 'no_control'));
  const lib = await controls.library();
  const tool = lib.controls.find((c) => c.id === 'SGC-TOOL-004') as unknown as { mappings: { relationship: string }[] };
  assert.ok(tool.mappings.length > 5 && tool.mappings.every((m) => ['equivalent', 'subset_of', 'superset_of', 'intersects'].includes(m.relationship)));
});

test('new SELF and RISK controls evaluate', async () => {
  const out = await controls.evaluate();
  assert.equal(out.find((r) => r.control_id === 'SGC-SELF-010')?.status, 'effective');
  assert.equal(out.find((r) => r.control_id === 'SGC-RISK-003')?.status, 'effective');
});

test('OSCAL catalog import keeps every control but scores only the AI subset; built-in text wins', async () => {
  assert.equal(oscal.displayId('ac-2.1'), 'AC-2(1)');
  const catalog = {
    catalog: {
      metadata: { title: 'NIST Special Publication 800-53 Revision 5', version: '5.1.1' },
      groups: [{ id: 'ac', title: 'Access Control', controls: [
        { id: 'ac-2', title: 'Account Management', parts: [{ name: 'statement', prose: 'Define {{ insert: param, ac-02_odp.01 }} account types.' }], controls: [{ id: 'ac-2.1', title: 'Automated System Account Management' }] },
      ] }, { id: 'pm', title: 'Program Management', controls: [{ id: 'pm-1', title: 'Information Security Program Plan' }] }],
    },
  };
  const r = await oscal.importOscal({ document: catalog }, admin);
  assert.deepEqual([r.framework_id, r.controls, r.in_scope], ['nist-800-53', 3, 1]);
  const row = (id: string) => db.prepare('SELECT summary, in_scope, source FROM framework_requirement WHERE id = ?').get(id) as Promise<{ summary: string; in_scope: number; source: string }>;
  assert.deepEqual(await row('nist-800-53:AC-2'), { summary: 'Account Management', in_scope: 1, source: 'signet' });
  assert.equal((await row('nist-800-53:PM-1')).in_scope, 0);
  assert.equal((await row('nist-800-53:AC-2(1)')).source, 'oscal');
  const all = await oscal.importOscal({ document: catalog, subset: 'all' }, admin);
  assert.equal(all.in_scope, 3);
  await assert.rejects(oscal.importOscal({ document: {} as never }, admin), /catalog/);
});

test('OSCAL profile import (FedRAMP) reports built-in controls the official baseline does not select', async () => {
  const profile = { profile: { metadata: { title: 'FedRAMP Rev 5 Moderate Baseline' }, imports: [{ href: '#cat', 'include-controls': [{ 'with-ids': ['ac-2', 'ac-3', 'pm-1'] }] }] } };
  const r = await oscal.importOscal({ document: profile }, admin);
  assert.equal(r.framework_id, 'fedramp-moderate');
  assert.equal(r.in_scope, 2);
  assert.ok((r as { built_in_not_in_profile: string[] }).built_in_not_in_profile.includes('AC-6'));
  const events = (await db.prepare("SELECT COUNT(*) n FROM ledger_record WHERE jsonb_extract_path_text(data::jsonb, 'event') = 'library.oscal_import'").get()) as { n: number };
  assert.ok(Number(events.n) >= 3, 'every import is in the ledger');
});

const other = { ...admin, id: 'board@x.example', roles: ['governance_board' as const], permissions: permissionsFor(['governance_board']) };
const libraryImport = await import('../src/library-import');

test('spreadsheet import fills a licence-needed framework only with a recorded licence, then it can be switched on', async () => {
  const rows = [{ external_id: 'A.5.1', title: 'Policies for information security', description: 'Licensed text' }, { external_id: 'A.5.15', title: 'Access control' }];
  await assert.rejects(libraryImport.importSheet({ framework_id: 'iso-27001', rows }, admin), /licence_confirmation/);
  await assert.rejects(libraryImport.importSheet({ framework_id: 'iso-27001', rows: [rows[0]!, rows[0]!], licence_confirmation: 'x' }, admin), /more than once/);
  await assert.rejects(libraryImport.importSheet({ framework_id: 'nist-ai-rmf', rows }, admin), /built in/);
  const r = await libraryImport.importSheet({ framework_id: 'iso-27001', rows, licence_confirmation: 'ISO order 12345' }, admin);
  assert.deepEqual([r.rows, r.created, r.licensed], [2, 2, true]);
  await controls.setFrameworkEnabled('iso-27001', true, admin, 'licence bought');
  const iso = (await controls.scores()).find((x) => x.framework_id === 'iso-27001')!;
  assert.equal(iso.coverage, 0, 'imported requirements start with no linked control');
  await db.prepare('DELETE FROM library_state').run();
  await controls.seed(); // a Signet release keeps the organisation's licensed copy
  assert.deepEqual(await db.prepare("SELECT namespace, enabled FROM framework WHERE id = 'iso-27001'").get(), { namespace: 'customer_licensed', enabled: 1 });
  assert.ok(await db.prepare("SELECT id FROM framework_requirement WHERE id = 'iso-27001:A.5.15'").get());

  const own = await libraryImport.importSheet({ name: 'Our AI usage policy', version: 'v3', rows: [{ external_id: 'P-1', title: 'Every agent has a named owner' }] }, admin);
  assert.equal(own.framework_id, 'custom-our-ai-usage-policy');
  const again = await libraryImport.importSheet({ framework_id: own.framework_id, rows: [{ external_id: 'P-2', title: 'Agents log every action' }], replace: true }, admin);
  assert.deepEqual([again.created, again.removed], [1, 1]);
});

test('links need two people; suggestions are hints; built-in links cannot be removed', async () => {
  const id = 'iso-27001:A.5.15';
  const hints = await libraryImport.suggestMappings(id);
  assert.ok(hints.some((h) => h.control_id === 'SGC-TOOL-004'), 'access control suggests the tool manifest control');
  process.env.SIGNET_SINGLE_OPERATOR = 'false';
  const proposed = await libraryImport.proposeMapping({ requirement_id: id, control_id: 'SGC-TOOL-004' }, admin);
  assert.equal(proposed.status, 'proposed');
  const before = (await controls.scores()).find((x) => x.framework_id === 'iso-27001')!;
  assert.equal(before.requirements.find((r) => r.id === id)!.status, 'no_control', 'an unconfirmed link does not count');
  await assert.rejects(libraryImport.confirmMapping({ requirement_id: id, control_id: 'SGC-TOOL-004' }, admin), /second person/);
  await libraryImport.confirmMapping({ requirement_id: id, control_id: 'SGC-TOOL-004' }, other);
  const after = (await controls.scores()).find((x) => x.framework_id === 'iso-27001')!;
  assert.notEqual(after.requirements.find((r) => r.id === id)!.status, 'no_control');
  assert.equal(after.coverage, 50);
  await assert.rejects(libraryImport.proposeMapping({ requirement_id: id, control_id: 'SGC-TOOL-004' }, admin), /already linked/);
  await assert.rejects(libraryImport.removeMapping({ requirement_id: 'nist-ai-rmf:GOVERN 1.1', control_id: 'SGC-GOV-002', reason: 'x' }, admin), /built-in/);
  await libraryImport.removeMapping({ requirement_id: id, control_id: 'SGC-TOOL-004', reason: 'wrong link' }, other);
  process.env.SIGNET_SINGLE_OPERATOR = 'true';
  assert.equal((await libraryImport.proposeMapping({ requirement_id: id, control_id: 'SGC-TOOL-004' }, admin)).status, 'confirmed', 'single administrator mode: confirmed and marked');
});

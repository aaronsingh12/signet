import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Library packs (BP 9.1, 9.4): versioned library, adopted automatically or after review, signed packs
// imported offline only from trusted keys, every step in the ledger.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-library-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const core = await import('@signet/core');
const controls = await import('../src/controls');
const library = await import('../src/library');
const { db } = await import('../src/db');
const { permissionsFor } = await import('../src/rbac');
const admin = { id: 'lib@x.example', name: 'lib', kind: 'human' as const, roles: ['tenant_admin' as const], permissions: permissionsFor(['tenant_admin']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };
after(dropTestDatabase);
const techsnitch = core.loadSigningKey(core.generateSigningKey('pack-test'));
const stranger = core.loadSigningKey(core.generateSigningKey('pack-other'));
process.env.SIGNET_LIBRARY_TRUSTED_KEYS = JSON.stringify({ keys: [core.toJwk(techsnitch)] });
const events = async () => ((await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin'").all()) as { data: string }[]).map((r) => JSON.parse(r.data));

/** A newer pack: one framework added, one requirement reworded. */
function nextPack(): ReturnType<typeof library.builtInPack> {
  const base = library.builtInPack();
  const content = structuredClone(base.content);
  content.frameworks.push({ id: 'zz-test-fw', name: 'Test framework', version: '1', licence: 'test', ships: 'summaries', category: 'regional', source_url: 'https://example.com', default_enabled: false, applies: 'tenant' });
  content.requirements.push({ framework_id: 'zz-test-fw', external_id: 'T1', summary: 'Test requirement', maps: [{ control: 'SGC-GOV-001', rel: 'intersects' }] });
  content.requirements[0]!.summary += ' (reworded)';
  return { ...base, version: '1.1.0', content, sha256: core.sha256(core.canonicalize(content)) };
}

test('a fresh install adopts the built-in pack automatically and records it', async () => {
  await controls.seed();
  const l = await library.list();
  assert.equal(l.mode, 'auto');
  const adopted = (l.items as { status: string; source: string; version: string }[]).find((p) => p.status === 'adopted');
  assert.deepEqual([adopted?.source, adopted?.version], ['built_in', l.built_in.version]);
  const ev = (await events()).find((e) => e.event === 'library.pack_adopted');
  assert.equal(ev.automatic, true);
  assert.ok(ev.changes.requirements.added > 400, 'first adoption: everything is new');
  assert.equal(await controls.appliedSha(), l.built_in.sha256);
});

test('signed pack import: untrusted signers and tampered packs are refused; a trusted pack shows its diff and is adopted', async () => {
  const pack = nextPack();
  await assert.rejects(library.importPack(library.signPack(pack, stranger), admin), /not valid for a trusted key/);
  const tampered = library.signPack(pack, techsnitch);
  tampered.pack = { ...tampered.pack, content: { ...tampered.pack.content, requirements: tampered.pack.content.requirements.slice(1) } };
  await assert.rejects(library.importPack(tampered, admin), /does not match its signature/);

  const r = await library.importPack(library.signPack(pack, techsnitch), admin);
  assert.equal(r.signer, 'pack-test');
  assert.deepEqual(r.diff.frameworks.added, ['zz-test-fw']);
  assert.equal(r.diff.requirements.added, 1);
  assert.equal(r.diff.requirements.changed, 1);
  assert.equal(r.diff.mappings.added, 1);
  assert.equal(r.diff.previous, '1.0.0');
  assert.equal(Number(((await db.prepare("SELECT COUNT(*) AS n FROM framework WHERE id = 'zz-test-fw'").get()) as { n: number }).n), 0, 'not applied before adoption');

  await library.adopt(r.id, admin);
  assert.equal(Number(((await db.prepare("SELECT COUNT(*) AS n FROM framework_requirement WHERE framework_id = 'zz-test-fw'").get()) as { n: number }).n), 1);
  const statuses = (await library.list()).items as { version: string; status: string }[];
  assert.deepEqual(statuses.filter((p) => p.status === 'adopted').map((p) => p.version), ['1.1.0']);
  assert.ok((await events()).some((e) => e.event === 'library.pack_imported' && e.signer === 'pack-test'));
});

test('review mode: a new built-in pack waits for a person, and admins are told', async () => {
  await library.setMode('review', admin);
  // The adopted library (1.1.0 above) differs from the built-in one, as after a deploy.
  await library.syncBuiltIn();
  assert.notEqual(await controls.appliedSha(), library.builtInPack().sha256, 'not applied automatically');
  const waiting = ((await library.list()).items as { id: string; source: string; status: string }[]).find((p) => p.source === 'built_in' && p.status !== 'adopted');
  assert.ok(waiting, 'listed as available');
  const note = (await db.prepare("SELECT title FROM notification WHERE kind = 'library'").get()) as { title: string } | undefined;
  assert.match(note?.title ?? '', /ready to review/);
  const d = await library.diffOf(waiting!.id);
  assert.deepEqual(d.frameworks.removed, ['zz-test-fw'], 'the diff shows what adopting would remove');
  await library.adopt(waiting!.id, admin);
  assert.equal(await controls.appliedSha(), library.builtInPack().sha256);
  await assert.rejects(library.importPack(library.signPack(nextPack(), techsnitch), { ...admin, kind: 'service' as const }), /by people/);
});

import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// Official sources (BP 9.3): Signet downloads the NIST SP 800-53 catalog itself, pinned to one commit,
// and imports it only when the SHA-256 matches.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-official-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const controls = await import('../src/controls');
const oscal = await import('../src/oscal');
const { db } = await import('../src/db');
await controls.seed();
const { permissionsFor } = await import('../src/rbac');
const admin = { id: 'lib@x.example', name: 'lib', kind: 'human' as const, roles: ['tenant_admin' as const], permissions: permissionsFor(['tenant_admin']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };

const catalog = JSON.stringify({ catalog: { metadata: { title: 'NIST SP 800-53 Rev 5 (test copy)', version: '5.2.0' }, groups: [{ id: 'pm', title: 'Program Management', controls: [{ id: 'pm-1', title: 'Information Security Program Plan' }, { id: 'pm-2', title: 'Information Security Program Leadership Role' }] }] } });
const server = createServer((_req, res) => res.writeHead(200, { 'content-type': 'application/json' }).end(catalog));
await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/catalog.json`;
after(async () => { server.close(); await dropTestDatabase(); });

test('the pinned source is a fixed commit with a hash', () => {
  const s = oscal.OFFICIAL_SOURCES['nist-800-53'];
  assert.match(s.url, /usnistgov\/oscal-content\/[0-9a-f]{40}\//);
  assert.match(s.sha256, /^[0-9a-f]{64}$/);
});

test('a file that does not match the pin is refused; a matching one is imported and written to the ledger', async () => {
  await assert.rejects(oscal.loadOfficial('nist-800-53', admin, { url, sha256: 'a'.repeat(64) }), /does not match the pinned SHA-256/);
  assert.equal(Number(((await db.prepare("SELECT COUNT(*) AS n FROM framework_requirement WHERE framework_id = 'nist-800-53' AND external_id LIKE 'PM-%'").get()) as { n: number }).n), 0, 'nothing imported');
  const sha = createHash('sha256').update(catalog).digest('hex');
  const r = await oscal.loadOfficial('nist-800-53', admin, { url, sha256: sha });
  assert.equal(r.framework_id, 'nist-800-53');
  assert.equal(Number(((await db.prepare("SELECT COUNT(*) AS n FROM framework_requirement WHERE framework_id = 'nist-800-53' AND external_id LIKE 'PM-%'").get()) as { n: number }).n), 2);
  const ev = ((await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin'").all()) as { data: string }[]).map((x) => JSON.parse(x.data)).find((d) => d.event === 'library.official_source_loaded');
  assert.equal(ev?.sha256, sha);
  await assert.rejects(oscal.loadOfficial('iso-27001', admin), /unknown official source/);
});

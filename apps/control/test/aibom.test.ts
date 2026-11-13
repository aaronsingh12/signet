import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// AIBOM (CycloneDX 1.6) and vulnerability scanning (OSV.dev + CISA KEV), BP 6 Stage 3 and 7.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-aibom-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const live = process.env.SIGNET_TEST_OSV_LIVE === '1';

// Stand-in OSV and KEV unless the live run is asked for.
let advisories: Record<string, { id: string; aliases: string[]; severity: string }[]> = {
  'pkg:npm/lodash@4.17.15': [{ id: 'GHSA-p6mc-m468-83gw', aliases: ['CVE-2020-8203'], severity: 'HIGH' }],
  'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1': [{ id: 'GHSA-jfh8-c2jp-5v3q', aliases: ['CVE-2021-44228'], severity: 'CRITICAL' }],
};
const fake = createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/kev.json') return void res.end(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2021-44228' }] }));
    if (req.url === '/v1/querybatch') {
      const q = JSON.parse(raw).queries as { package: { purl: string } }[];
      return void res.end(JSON.stringify({ results: q.map((x) => ({ vulns: (advisories[x.package.purl] ?? []).map((v) => ({ id: v.id })) })) }));
    }
    const id = decodeURIComponent(String(req.url).replace('/v1/vulns/', ''));
    const v = Object.values(advisories).flat().find((a) => a.id === id);
    res.end(JSON.stringify({ id, aliases: v?.aliases, summary: `advisory ${id}`, database_specific: { severity: v?.severity } }));
  });
});
if (!live) {
  await new Promise<void>((r) => fake.listen(0, '127.0.0.1', r));
  const port = (fake.address() as AddressInfo).port;
  process.env.SIGNET_OSV_URL = `http://127.0.0.1:${port}`;
  process.env.SIGNET_KEV_URL = `http://127.0.0.1:${port}/kev.json`;
}
const aibom = await import('../src/aibom');
const registry = await import('../src/registry');
const { db } = await import('../src/db');
const { permissionsFor } = await import('../src/rbac');
after(async () => { fake.close(); await dropTestDatabase(); });
const owner = { id: 'owner@x.example', name: 'o', kind: 'human' as const, roles: ['agent_owner' as const], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };

const sbom = {
  bomFormat: 'CycloneDX', specVersion: '1.5',
  components: [
    { type: 'library', name: 'lodash', version: '4.17.15', purl: 'pkg:npm/lodash@4.17.15' },
    { type: 'library', name: 'log4j-core', group: 'org.apache.logging.log4j', version: '2.14.1', purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' },
    { type: 'library', name: 'express', version: '4.22.3', purl: 'pkg:npm/express@4.22.3' },
  ],
};

test('AIBOM: CycloneDX 1.6 from the registry plus the uploaded SBOM; vulnerabilities found; KEV raised to critical', async () => {
  const agent = await registry.registerAgent({ handle: 'aibom-agent', name: 'AIBOM agent', purpose: 'Answers order questions', sponsor: 's@x.example', autonomy_level: 'L2', framework: 'langgraph', runtime: 'python' } as never, owner);
  const r = await aibom.generate(agent.id, { sbom }, owner);
  assert.equal(r.scanned, 3);
  assert.ok(r.findings >= 2, 'lodash and log4j are vulnerable');
  assert.ok(r.kev >= 1, 'Log4Shell is on the CISA KEV list');
  const l = await aibom.latest(agent.id);
  assert.equal(l.cyclonedx!.specVersion, '1.6');
  assert.ok(l.cyclonedx!.components.some((c) => c.type === 'framework' && c.name === 'langgraph'));
  const top = l.findings[0]!;
  assert.equal(top.kev, true);
  assert.equal(top.severity, 'critical');
  assert.ok(l.findings.some((f) => f.kev && f.aliases.includes('CVE-2021-44228')), 'Log4Shell is listed as known-exploited');

  // A later scan where the package is fixed closes the finding; a rebuild keeps the uploaded SBOM.
  if (!live) {
    advisories = { 'pkg:npm/lodash@4.17.15': advisories['pkg:npm/lodash@4.17.15']! };
    await aibom.generate(agent.id, {}, owner);
    const after = await aibom.latest(agent.id);
    assert.ok(after.cyclonedx!.components.some((c) => c.name === 'log4j-core'), 'uploaded components are kept');
    assert.ok(!after.findings.some((f) => f.kev), 'the Log4Shell finding is closed once no longer reported');
    const fixed = (await db.prepare("SELECT status FROM vulnerability_finding WHERE vuln_id = 'GHSA-jfh8-c2jp-5v3q'").get()) as { status: string };
    assert.equal(fixed.status, 'fixed');
  }
});

test('SPDX uploads are read; other formats are refused', async () => {
  const agent = await registry.registerAgent({ handle: 'spdx-agent', name: 'SPDX agent', purpose: 'Answers order questions', sponsor: 's@x.example', autonomy_level: 'L2' } as never, owner);
  const spdx = { spdxVersion: 'SPDX-2.3', packages: [{ name: 'lodash', versionInfo: '4.17.15', externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.15' }] }] };
  const r = await aibom.generate(agent.id, { sbom: spdx }, owner);
  assert.equal(r.scanned, 1);
  await assert.rejects(aibom.generate(agent.id, { sbom: { hello: 'world' } }, owner), /CycloneDX or SPDX/);
});

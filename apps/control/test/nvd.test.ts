import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// NVD CVE API 2.0 (BP 9.3 feeds): official CVSS for CVEs that OSV.dev gives no severity for, cached for
// 7 days and rate-limited.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-nvd-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
let calls = 0;
let limited = false;
const nvd = createServer((req, res) => {
  calls++;
  if (limited) return void res.writeHead(403).end();
  const cve = new URL(String(req.url), 'http://x').searchParams.get('cveId');
  const metric = cve === 'CVE-2099-0001'
    ? { cvssMetricV31: [{ cvssData: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } }] }
    : { cvssMetricV2: [{ cvssData: { version: '2.0', baseScore: 5.0, vectorString: 'AV:N/AC:L/Au:N/C:N/I:N/A:P' }, baseSeverity: 'MEDIUM' }] };
  res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ vulnerabilities: [{ cve: { id: cve, metrics: metric } }] }));
});
await new Promise<void>((r) => nvd.listen(0, '127.0.0.1', r));
process.env.SIGNET_NVD_URL = `http://127.0.0.1:${(nvd.address() as AddressInfo).port}/rest/json/cves/2.0`;
process.env.SIGNET_NVD_DELAY_MS = '0';
const aibom = await import('../src/aibom');
after(async () => { nvd.close(); await dropTestDatabase(); });

test('NVD: newest CVSS version wins, results are cached, and a rate limit stops the lookups politely', async () => {
  const s = await aibom.nvdScores(['CVE-2099-0001', 'CVE-2099-0002', 'CVE-2099-0001']);
  assert.deepEqual(s.get('CVE-2099-0001'), { score: 9.8, severity: 'critical', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', version: '3.1' });
  assert.equal(s.get('CVE-2099-0002')!.severity, 'medium', 'CVSS v2 keeps its severity on the metric');
  assert.equal(calls, 2, 'duplicates asked once');
  await aibom.nvdScores(['CVE-2099-0001', 'CVE-2099-0002']);
  assert.equal(calls, 2, 'answered from the 7-day cache');
  limited = true;
  const r = await aibom.nvdScores(['CVE-2099-0003', 'CVE-2099-0004', 'CVE-2099-0005']);
  assert.equal(r.size, 0);
  assert.equal(calls, 3, 'stops at the first rate-limit answer and tries again next scan');
});

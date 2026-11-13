import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { gunzipSync } from 'node:zlib';
import { after, test } from 'node:test';
import { signAws } from '@signet/core';
import { dropTestDatabase } from './database';

// End to end (BP 8.3): a sealed daily root is copied to S3 with Object Lock and timestamped by an RFC 3161
// authority; the evidence package carries the token. Needs a real S3 API with Object Lock and a TSA:
//   SIGNET_TEST_S3_ENDPOINT / SIGNET_TEST_S3_KEY / SIGNET_TEST_S3_SECRET, and SIGNET_TEST_TSA_URL.
const endpoint = process.env.SIGNET_TEST_S3_ENDPOINT;
const tsaUrl = process.env.SIGNET_TEST_TSA_URL;
const skip = !(endpoint && tsaUrl) && 'set SIGNET_TEST_S3_* and SIGNET_TEST_TSA_URL to run';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-anchor-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);

test('a sealed day is stored write-once in S3 and timestamped; the package carries the token', { skip }, async () => {
  const bucket = `signet-anchor-${Date.now()}`;
  Object.assign(process.env, {
    SIGNET_EVIDENCE_S3_ENDPOINT: endpoint, SIGNET_EVIDENCE_S3_BUCKET: bucket, SIGNET_EVIDENCE_S3_ACCESS_KEY_ID: process.env.SIGNET_TEST_S3_KEY,
    SIGNET_EVIDENCE_S3_SECRET_ACCESS_KEY: process.env.SIGNET_TEST_S3_SECRET, SIGNET_EVIDENCE_RETENTION_DAYS: '1', SIGNET_TSA_URL: tsaUrl,
  });
  const url = new URL(`${endpoint}/${bucket}`);
  const h = signAws({ method: 'PUT', url, region: 'us-east-1', service: 's3', headers: { 'x-amz-bucket-object-lock-enabled': 'true', 'x-amz-content-sha256': createHash('sha256').update('').digest('hex') }, credentials: { access_key_id: process.env.SIGNET_TEST_S3_KEY!, secret_access_key: process.env.SIGNET_TEST_S3_SECRET! } });
  delete h.host;
  assert.equal((await fetch(url, { method: 'PUT', headers: h })).status, 200);

  const ledger = await import('../src/ledger');
  const evidence = await import('../src/evidence');
  after(dropTestDatabase);
  for (let i = 0; i < 3; i++) await ledger.append({ kind: 'admin', data: { event: 'test.anchor', i } });
  const day = new Date().toISOString().slice(0, 10);
  await evidence.sealDay(day);

  const first = await evidence.anchorPending();
  assert.deepEqual([first.stored, first.timestamped, first.errors], [[day], [day], []]);
  const again = await evidence.anchorPending();
  assert.deepEqual([again.stored, again.timestamped], [[], []], 'each day is anchored once');

  const status = await evidence.storageStatus();
  assert.equal(status.s3.configured && 'object_lock' in status.s3 && status.s3.object_lock, true);
  assert.deepEqual([status.roots, status.s3.stored, status.tsa.timestamped], [1, 1, 1]);
  const root = (await evidence.roots()).find((r) => r.day === day)!;
  assert.ok(root.s3 && root.timestamp?.time);

  const chunks: Buffer[] = [];
  await new Promise<void>((resolve) => evidence.writePackage(new Writable({ write(c, _e, cb) { chunks.push(c); cb(); }, final(cb) { resolve(); cb(); } }), { actor: 'test' }));
  const lines = gunzipSync(Buffer.concat(chunks)).toString().trim().split('\n').map((l) => JSON.parse(l));
  const rootLine = lines.find((l) => l.type === 'root' && l.day === day);
  assert.equal(rootLine.timestamp.digest, createHash('sha256').update(rootLine.jws).digest('hex'), 'the token covers the root JWS');
  assert.ok(Buffer.from(rootLine.timestamp.token, 'base64').length > 1000);
});

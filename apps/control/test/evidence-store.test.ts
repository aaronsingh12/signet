import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { signAws } from '@signet/core';
import { checkBucket, getObject, putOnce, s3Config } from '../src/evidence-store';
import { checkResponse, timestampRequest } from '../src/tsa';

// Write-once evidence copies (S3 Object Lock) and RFC 3161 timestamps (BP 8.3).

test('S3 settings: off unless configured; incomplete or invalid settings are refused', () => {
  assert.equal(s3Config({}), null);
  assert.throws(() => s3Config({ SIGNET_EVIDENCE_S3_ENDPOINT: 'http://x', SIGNET_EVIDENCE_S3_BUCKET: 'b' }), /ACCESS_KEY_ID/);
  assert.throws(() => s3Config({ SIGNET_EVIDENCE_S3_ENDPOINT: 'http://x', SIGNET_EVIDENCE_S3_BUCKET: 'b', SIGNET_EVIDENCE_S3_ACCESS_KEY_ID: 'a', SIGNET_EVIDENCE_S3_SECRET_ACCESS_KEY: 's', SIGNET_EVIDENCE_LOCK_MODE: 'off' }), /LOCK_MODE/);
  const c = s3Config({ SIGNET_EVIDENCE_S3_ENDPOINT: 'http://x/', SIGNET_EVIDENCE_S3_BUCKET: 'b', SIGNET_EVIDENCE_S3_ACCESS_KEY_ID: 'a', SIGNET_EVIDENCE_S3_SECRET_ACCESS_KEY: 's' })!;
  assert.deepEqual([c.endpoint, c.mode, c.retentionDays], ['http://x', 'COMPLIANCE', 2555]);
});

test('RFC 3161: request encoding and response checks (granted, our digest and nonce, time)', () => {
  const digest = createHash('sha256').update('root').digest();
  const nonce = Buffer.from([0x12, 0x34]);
  const req = timestampRequest(digest, nonce);
  assert.equal(req[0], 0x30);
  assert.ok(req.includes(digest) && req.includes(Buffer.from([0x02, 0x02, 0x12, 0x34])));
  // A minimal granted TimeStampResp: status 0, then a token holding digest, nonce and genTime.
  const der = (tag: number, body: Buffer) => Buffer.concat([Buffer.from([tag, body.length]), body]);
  const token = der(0x30, Buffer.concat([der(0x04, digest), der(0x02, Buffer.from([0x05])), der(0x18, Buffer.from('20261113092337Z')), der(0x02, nonce)]));
  const resp = der(0x30, Buffer.concat([der(0x30, der(0x02, Buffer.from([0]))), token]));
  assert.deepEqual(checkResponse(resp, digest, nonce), { time: '2026-11-13T09:23:37Z' });
  assert.throws(() => checkResponse(resp, createHash('sha256').update('other').digest(), nonce), /digest/);
  assert.throws(() => checkResponse(resp, digest, Buffer.from([0x77])), /nonce/);
  const refused = der(0x30, der(0x30, der(0x02, Buffer.from([2]))));
  assert.throws(() => checkResponse(refused, digest, nonce), /refused/);
});

// Runs against a real S3 API with Object Lock when SIGNET_TEST_S3_ENDPOINT is set (for example a local
// Zenko CloudServer); skipped otherwise.
const endpoint = process.env.SIGNET_TEST_S3_ENDPOINT;
test('S3 Object Lock: write once, retries are idempotent, changes and deletes are refused', { skip: !endpoint && 'set SIGNET_TEST_S3_ENDPOINT to run' }, async () => {
  const bucket = `signet-test-${Date.now()}`;
  const env = { SIGNET_EVIDENCE_S3_ENDPOINT: endpoint, SIGNET_EVIDENCE_S3_BUCKET: bucket, SIGNET_EVIDENCE_S3_ACCESS_KEY_ID: process.env.SIGNET_TEST_S3_KEY, SIGNET_EVIDENCE_S3_SECRET_ACCESS_KEY: process.env.SIGNET_TEST_S3_SECRET, SIGNET_EVIDENCE_RETENTION_DAYS: '1' };
  const cfg = s3Config(env)!;
  const call = async (method: string, path: string, headers: Record<string, string> = {}, body = '') => {
    const url = new URL(`${cfg.endpoint}/${bucket}${path}`);
    const h = signAws({ method, url, region: cfg.region, service: 's3', body, headers: { ...headers, 'x-amz-content-sha256': createHash('sha256').update(body).digest('hex') }, credentials: { access_key_id: cfg.accessKeyId, secret_access_key: cfg.secretAccessKey } });
    delete h.host;
    return fetch(url, { method, headers: h, body: body || undefined });
  };
  // A bucket without Object Lock is reported as unusable.
  assert.equal((await call('PUT', '')).status, 200);
  assert.equal((await checkBucket(cfg)).object_lock, false);
  // A bucket created with Object Lock.
  const locked = { ...cfg, bucket: `${bucket}-locked` };
  const url = new URL(`${cfg.endpoint}/${locked.bucket}`);
  const h = signAws({ method: 'PUT', url, region: cfg.region, service: 's3', headers: { 'x-amz-bucket-object-lock-enabled': 'true', 'x-amz-content-sha256': createHash('sha256').update('').digest('hex') }, credentials: { access_key_id: cfg.accessKeyId, secret_access_key: cfg.secretAccessKey } });
  delete h.host;
  assert.equal((await fetch(url, { method: 'PUT', headers: h })).status, 200);
  assert.equal((await checkBucket(locked)).object_lock, true);

  const stored = await putOnce(locked, 'tnt/roots/2026-11-12.jws', 'root-jws');
  assert.equal(stored.mode, 'COMPLIANCE');
  assert.equal(await getObject(locked, 'tnt/roots/2026-11-12.jws'), 'root-jws');
  assert.equal((await putOnce(locked, 'tnt/roots/2026-11-12.jws', 'root-jws')).url, stored.url, 'a retry with the same content is fine');
  await assert.rejects(putOnce(locked, 'tnt/roots/2026-11-12.jws', 'edited'), /different content|could not store/);
  assert.equal(await getObject(locked, 'tnt/roots/2026-11-12.jws'), 'root-jws', 'the original is unchanged');
  // Deleting the locked version is refused.
  const lockedCall = async (method: string, path: string) => {
    const u = new URL(`${cfg.endpoint}/${locked.bucket}${path}`);
    const hh = signAws({ method, url: u, region: cfg.region, service: 's3', headers: { 'x-amz-content-sha256': createHash('sha256').update('').digest('hex') }, credentials: { access_key_id: cfg.accessKeyId, secret_access_key: cfg.secretAccessKey } });
    delete hh.host;
    return fetch(u, { method, headers: hh });
  };
  if (stored.version_id) assert.notEqual((await lockedCall('DELETE', `/tnt/roots/2026-11-12.jws?versionId=${encodeURIComponent(stored.version_id)}`)).status, 204);
  assert.equal(await getObject(locked, 'tnt/roots/2026-11-12.jws'), 'root-jws');
});

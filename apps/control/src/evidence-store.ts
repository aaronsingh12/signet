import { createHash } from 'node:crypto';
import { signAws } from '@signet/core';

// Write-once evidence storage in S3 with Object Lock (BP 8.3, 3: "Any S3 API ... with Object Lock").
// Daily roots and ledger segments are stored with a retention date in COMPLIANCE mode, so nobody,
// including a Signet or cloud administrator, can change or delete them before the date passes. Works with
// AWS S3 and S3-compatible stores that implement Object Lock (MinIO, Wasabi, Backblaze B2, NetApp, Dell
// ECS). Cloudflare R2 has bucket-level locks only and is not supported here.
//
// Configuration (all optional; without it Signet keeps its existing local or database copy):
//   SIGNET_EVIDENCE_S3_ENDPOINT   https://s3.<region>.amazonaws.com or http://localhost:9000 (MinIO)
//   SIGNET_EVIDENCE_S3_BUCKET     a bucket created with Object Lock enabled
//   SIGNET_EVIDENCE_S3_REGION     default us-east-1
//   SIGNET_EVIDENCE_S3_ACCESS_KEY_ID / SIGNET_EVIDENCE_S3_SECRET_ACCESS_KEY
//   SIGNET_EVIDENCE_RETENTION_DAYS  default 2555 (7 years, BP 8.1)
//   SIGNET_EVIDENCE_LOCK_MODE     COMPLIANCE (default) or GOVERNANCE (can be lifted by privileged users)

export interface S3Config { endpoint: string; bucket: string; region: string; accessKeyId: string; secretAccessKey: string; retentionDays: number; mode: 'COMPLIANCE' | 'GOVERNANCE' }

export function s3Config(env = process.env): S3Config | null {
  const endpoint = env.SIGNET_EVIDENCE_S3_ENDPOINT?.trim();
  const bucket = env.SIGNET_EVIDENCE_S3_BUCKET?.trim();
  if (!endpoint || !bucket) return null;
  const accessKeyId = env.SIGNET_EVIDENCE_S3_ACCESS_KEY_ID ?? '';
  const secretAccessKey = env.SIGNET_EVIDENCE_S3_SECRET_ACCESS_KEY ?? '';
  if (!accessKeyId || !secretAccessKey) throw new Error('SIGNET_EVIDENCE_S3_ACCESS_KEY_ID and SIGNET_EVIDENCE_S3_SECRET_ACCESS_KEY are required with SIGNET_EVIDENCE_S3_BUCKET');
  const mode = (env.SIGNET_EVIDENCE_LOCK_MODE ?? 'COMPLIANCE').toUpperCase();
  if (mode !== 'COMPLIANCE' && mode !== 'GOVERNANCE') throw new Error('SIGNET_EVIDENCE_LOCK_MODE must be COMPLIANCE or GOVERNANCE');
  const retentionDays = Number(env.SIGNET_EVIDENCE_RETENTION_DAYS ?? 2555);
  if (!Number.isInteger(retentionDays) || retentionDays < 1) throw new Error('SIGNET_EVIDENCE_RETENTION_DAYS must be a whole number of days');
  return { endpoint: endpoint.replace(/\/$/, ''), bucket, region: env.SIGNET_EVIDENCE_S3_REGION ?? 'us-east-1', accessKeyId, secretAccessKey, retentionDays, mode };
}

const sha256hex = (s: string) => createHash('sha256').update(s).digest('hex');

async function s3(cfg: S3Config, method: string, key: string, opts: { query?: string; body?: string; headers?: Record<string, string> } = {}) {
  const url = new URL(`${cfg.endpoint}/${encodeURIComponent(cfg.bucket)}${key ? `/${key.split('/').map(encodeURIComponent).join('/')}` : ''}${opts.query ? `?${opts.query}` : ''}`);
  const body = opts.body ?? '';
  const headers = signAws({
    method, url, region: cfg.region, service: 's3', body,
    headers: { ...(opts.headers ?? {}), 'x-amz-content-sha256': sha256hex(body) },
    credentials: { access_key_id: cfg.accessKeyId, secret_access_key: cfg.secretAccessKey },
  });
  delete headers.host;
  return fetch(url, { method, headers, body: method === 'PUT' ? body : undefined, signal: AbortSignal.timeout(20_000) });
}

export interface StoredObject { url: string; version_id: string | null; retain_until: string; mode: string }

/**
 * Store an object once, locked until its retention date. If the key already exists the stored content
 * must be identical (a retry), otherwise this is reported as tampering or a conflict.
 */
export async function putOnce(cfg: S3Config, key: string, content: string): Promise<StoredObject> {
  const retainUntil = new Date(Date.now() + cfg.retentionDays * 86_400_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  // Read first: not every S3 implementation honours If-None-Match, and on a versioned (Object Lock) bucket a
  // second PUT would quietly add a newer version. Sealing runs under a lock, so there is no race here.
  const before = await s3(cfg, 'GET', key);
  if (before.ok) return existingCopy(cfg, key, content, before, retainUntil);
  if (before.status !== 404) throw new Error(`could not check evidence object ${key} in S3 (${before.status})`);
  const r = await s3(cfg, 'PUT', key, {
    body: content,
    headers: {
      'content-type': key.endsWith('.jsonl') ? 'application/x-ndjson' : 'application/jose',
      'content-md5': createHash('md5').update(content).digest('base64'), // Object Lock requires an integrity header
      'if-none-match': '*',
      'x-amz-object-lock-mode': cfg.mode,
      'x-amz-object-lock-retain-until-date': retainUntil,
    },
  });
  if (r.status === 412 || r.status === 409) {
    const existing = await s3(cfg, 'GET', key);
    if (!existing.ok) throw new Error(`evidence object ${key} exists but could not be read back (${existing.status})`);
    return existingCopy(cfg, key, content, existing, retainUntil);
  }
  if (!r.ok) throw new Error(`could not store evidence object ${key} in S3 (${r.status}: ${(await r.text()).slice(0, 200)})`);
  return { url: `s3://${cfg.bucket}/${key}`, version_id: r.headers.get('x-amz-version-id'), retain_until: retainUntil, mode: cfg.mode };
}

async function existingCopy(cfg: S3Config, key: string, content: string, existing: Response, retainUntil: string): Promise<StoredObject> {
  if ((await existing.text()) !== content) throw new Error(`evidence object ${key} already exists with different content`);
  return { url: `s3://${cfg.bucket}/${key}`, version_id: existing.headers.get('x-amz-version-id'), retain_until: existing.headers.get('x-amz-object-lock-retain-until-date') ?? retainUntil, mode: existing.headers.get('x-amz-object-lock-mode') ?? cfg.mode };
}

export async function getObject(cfg: S3Config, key: string): Promise<string | null> {
  const r = await s3(cfg, 'GET', key);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`could not read evidence object ${key} (${r.status})`);
  return r.text();
}

/** Checks that the bucket is reachable and has Object Lock switched on. */
export async function checkBucket(cfg: S3Config): Promise<{ ok: boolean; object_lock: boolean; detail: string }> {
  try {
    const r = await s3(cfg, 'GET', '', { query: 'object-lock=' });
    const text = await r.text();
    if (r.status === 404 && /ObjectLockConfigurationNotFound/.test(text)) return { ok: false, object_lock: false, detail: 'bucket has no Object Lock; create a new bucket with Object Lock enabled' };
    if (!r.ok) return { ok: false, object_lock: false, detail: `bucket check failed (${r.status}: ${text.slice(0, 160)})` };
    const enabled = /<ObjectLockEnabled>\s*Enabled\s*<\/ObjectLockEnabled>/.test(text);
    return { ok: enabled, object_lock: enabled, detail: enabled ? `Object Lock on; new objects locked in ${cfg.mode} mode for ${cfg.retentionDays} days` : 'Object Lock is not enabled on this bucket' };
  } catch (e) {
    return { ok: false, object_lock: false, detail: `bucket unreachable: ${(e as Error).message}` };
  }
}

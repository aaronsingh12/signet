import { createHash, createHmac } from 'node:crypto';

// AWS Signature Version 4 (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html), for
// the AWS platform connector. Only what Signet needs: signed JSON/REST requests with static keys.

export interface AwsCredentials { access_key_id: string; secret_access_key: string; session_token?: string }

const sha256hex = (v: string | Buffer) => createHash('sha256').update(v).digest('hex');
const hmac = (key: Buffer | string, v: string) => createHmac('sha256', key).update(v).digest();
// RFC 3986 encoding as SigV4 requires (encodeURIComponent leaves !'()* alone).
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

export function signAws(input: {
  method: string;
  url: URL;
  region: string;
  service: string;
  headers?: Record<string, string>;
  body?: string;
  credentials: AwsCredentials;
  now?: Date;
}): Record<string, string> {
  const now = input.now ?? new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const day = amzDate.slice(0, 8);
  const body = input.body ?? '';
  const headers: Record<string, string> = { ...(input.headers ?? {}), host: input.url.host, 'x-amz-date': amzDate };
  if (input.credentials.session_token) headers['x-amz-security-token'] = input.credentials.session_token;
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v).trim().replace(/\s+/g, ' ')]));
  const names = Object.keys(lower).sort();
  const canonicalHeaders = names.map((n) => `${n}:${lower[n]}\n`).join('');
  const signedHeaders = names.join(';');
  const path = input.url.pathname.split('/').map((seg) => enc(decodeURIComponent(seg))).join('/') || '/';
  const query = [...input.url.searchParams.entries()].map(([k, v]) => [enc(k), enc(v)]).sort(([a, x], [b, y]) => (a === b ? (x! < y! ? -1 : 1) : a! < b! ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join('&');
  const canonical = [input.method.toUpperCase(), path, query, canonicalHeaders, signedHeaders, sha256hex(body)].join('\n');
  const scope = `${day}/${input.region}/${input.service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonical)].join('\n');
  const kDate = hmac(`AWS4${input.credentials.secret_access_key}`, day);
  const kSigning = hmac(hmac(hmac(kDate, input.region), input.service), 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(toSign).digest('hex');
  return { ...headers, authorization: `AWS4-HMAC-SHA256 Credential=${input.credentials.access_key_id}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
}

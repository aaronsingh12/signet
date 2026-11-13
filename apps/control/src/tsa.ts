import { createHash, randomBytes } from 'node:crypto';

// RFC 3161 trusted timestamps for the signed daily roots (BP 8.3 "external anchoring"). A Time-Stamp
// Authority chosen by the tenant signs "this hash existed at this time", so even an operator who controls
// Signet and its keys cannot back-date or rewrite a day's evidence afterwards.
//
//   SIGNET_TSA_URL   for example https://freetsa.org/tsr or http://timestamp.digicert.com
//
// Signet checks the answer here (status granted, our hash and nonce inside, the time) and keeps the full
// token. Auditors verify the TSA's signature offline with standard tools:
//   openssl ts -verify -digest <sha256 of the root JWS> -in <token>.tsr -CAfile <tsa-ca.pem>

const SHA256_OID = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

function der(tag: number, body: Buffer): Buffer {
  const n = body.length;
  const len = n < 0x80 ? Buffer.from([n]) : (() => { const b: number[] = []; let x = n; while (x) { b.unshift(x & 0xff); x >>= 8; } return Buffer.from([0x80 | b.length, ...b]); })();
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
const derInt = (v: Buffer) => der(0x02, v[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), v]) : v);

/** DER TimeStampReq for a SHA-256 digest, asking the TSA to include its certificate. */
export function timestampRequest(digest: Buffer, nonce: Buffer): Buffer {
  const algorithm = der(0x30, Buffer.concat([Buffer.from(SHA256_OID), Buffer.from([0x05, 0x00])]));
  const imprint = der(0x30, Buffer.concat([algorithm, der(0x04, digest)]));
  return der(0x30, Buffer.concat([derInt(Buffer.from([1])), imprint, derInt(nonce), Buffer.from([0x01, 0x01, 0xff])]));
}

// Minimal DER reader: tag, header length and content length at an offset.
function read(buf: Buffer, at: number): { tag: number; start: number; end: number } {
  const tag = buf[at]!;
  let len = buf[at + 1]!;
  let start = at + 2;
  if (len & 0x80) {
    const k = len & 0x7f;
    len = 0;
    for (let i = 0; i < k; i++) len = len * 256 + buf[start + i]!;
    start += k;
  }
  if (start + len > buf.length) throw new Error('truncated DER');
  return { tag, start, end: start + len };
}

export interface TimestampResult { token: string; time: string; tsa_url: string; digest: string }

/**
 * Check a TimeStampResp: status granted (0 or 1), our exact digest and nonce inside the signed TSTInfo,
 * and read its generation time. Returns the token (the whole response, base64) for offline verification.
 */
export function checkResponse(resp: Buffer, digest: Buffer, nonce: Buffer): { time: string } {
  const outer = read(resp, 0);
  if (outer.tag !== 0x30) throw new Error('not a TimeStampResp');
  const statusInfo = read(resp, outer.start);
  const status = read(resp, statusInfo.start);
  const code = resp.subarray(status.start, status.end).reduce((a, b) => a * 256 + b, 0);
  if (status.tag !== 0x02 || code > 1) throw new Error(`the TSA refused the request (status ${code})`);
  if (statusInfo.end >= outer.end) throw new Error('the TSA granted the request but returned no token');
  const token = resp.subarray(statusInfo.end, outer.end);
  const at = token.indexOf(digest);
  if (at < 0) throw new Error('the token does not contain our digest');
  const nonceDer = derInt(nonce);
  if (token.indexOf(nonceDer, at) < 0) throw new Error('the token does not contain our nonce (possible replay)');
  // TSTInfo: ... messageImprint, serialNumber, genTime (GeneralizedTime). The first GeneralizedTime after
  // the imprint is genTime; certificates and signed attributes come after TSTInfo.
  const g = token.indexOf(0x18, at + digest.length);
  if (g < 0) throw new Error('no time in the token');
  const t = read(token, g);
  const s = token.subarray(t.start, t.end).toString('latin1'); // YYYYMMDDhhmmss[.fff]Z
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s);
  if (!m) throw new Error(`unexpected time format ${s}`);
  return { time: `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ''}Z` };
}

export const tsaUrl = (env = process.env) => env.SIGNET_TSA_URL?.trim() || null;

/** Ask the configured TSA to timestamp `content` (SHA-256). */
export async function timestamp(url: string, content: string): Promise<TimestampResult> {
  const digest = createHash('sha256').update(content).digest();
  const nonce = randomBytes(8);
  nonce[0] = (nonce[0]! & 0x7f) || 1; // positive and minimally encoded
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' }, body: timestampRequest(digest, nonce), signal: AbortSignal.timeout(20_000) });
  if (!r.ok) throw new Error(`TSA answered ${r.status}`);
  const resp = Buffer.from(await r.arrayBuffer());
  const { time } = checkResponse(resp, digest, nonce);
  return { token: resp.toString('base64'), time, tsa_url: url, digest: digest.toString('hex') };
}

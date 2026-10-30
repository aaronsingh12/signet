import { createPublicKey, verify as cryptoVerify, type JsonWebKey, type KeyObject } from 'node:crypto';

// Verifies JWTs issued by an external OIDC provider (RS256 / ES256 / EdDSA) against its JWKS.
// Used for human sign-in and machine clients (BP 13: OAuth 2.0 bearer tokens).

export interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

const ALGS: Record<string, { hash: string | null; dsa?: 'ieee-p1363' }> = {
  RS256: { hash: 'sha256' },
  ES256: { hash: 'sha256', dsa: 'ieee-p1363' },
  EdDSA: { hash: null },
};

export function decodeJwt<T>(token: string): { header: JwtHeader; payload: T; signingInput: string; signature: Buffer } {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) throw new Error('malformed JWT');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url').toString()) as JwtHeader,
    payload: JSON.parse(Buffer.from(p, 'base64url').toString()) as T,
    signingInput: `${h}.${p}`,
    signature: Buffer.from(s, 'base64url'),
  };
}

export const keyFromJwk = (jwk: JsonWebKey): KeyObject => createPublicKey({ key: jwk, format: 'jwk' });

export function verifyJwtSignature(token: string, key: KeyObject): { header: JwtHeader; payload: Record<string, unknown> } {
  const d = decodeJwt<Record<string, unknown>>(token);
  const alg = ALGS[d.header.alg];
  if (!alg) throw new Error(`unsupported JWT alg ${d.header.alg}`);
  const ok = cryptoVerify(alg.hash, Buffer.from(d.signingInput), alg.dsa ? { key, dsaEncoding: alg.dsa } : key, d.signature);
  if (!ok) throw new Error('bad JWT signature');
  return { header: d.header, payload: d.payload };
}

export function checkTimes(payload: Record<string, unknown>, skewSeconds = 60) {
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && payload.exp + skewSeconds < now) throw new Error('JWT expired');
  if (typeof payload.nbf === 'number' && payload.nbf - skewSeconds > now) throw new Error('JWT not yet valid');
}

import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, generateKeyPairSync,
  randomBytes, sign, verify, type JsonWebKey, type KeyObject,
} from 'node:crypto';
import { canonicalize } from './canonical';

export const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
export const b64url = (data: string | Buffer) => Buffer.from(data).toString('base64url');

// Ed25519 signing keys (BP 4.2, 4.3). Dev keeps PEMs on disk; production keeps them in a KMS or HSM.
export interface SigningKey {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export interface StoredKey {
  kid: string;
  privatePem: string;
}

export function generateSigningKey(kid: string): StoredKey {
  const { privateKey } = generateKeyPairSync('ed25519');
  return { kid, privatePem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString() };
}

export function loadSigningKey(stored: StoredKey): SigningKey {
  const privateKey = createPrivateKey(stored.privatePem);
  return { kid: stored.kid, privateKey, publicKey: createPublicKey(privateKey) };
}

export type PublicJwk = JsonWebKey & { kid: string };

export const toJwk = (key: SigningKey): PublicJwk => ({ ...key.publicKey.export({ format: 'jwk' }), kid: key.kid, alg: 'EdDSA', use: 'sig' });
export const fromJwk = (jwk: PublicJwk): KeyObject => createPublicKey({ key: jwk, format: 'jwk' });

// Compact JWS with EdDSA over the canonical JSON payload.
export function signJws(payload: object, key: SigningKey, typ = 'JWT'): string {
  const header = b64url(JSON.stringify({ alg: 'EdDSA', kid: key.kid, typ }));
  const body = b64url(canonicalize(payload));
  const sig = sign(null, Buffer.from(`${header}.${body}`), key.privateKey);
  return `${header}.${body}.${b64url(sig)}`;
}

export interface VerifiedJws<T> {
  header: { alg: string; kid: string; typ: string };
  payload: T;
}

export function verifyJws<T>(jws: string, keys: ReadonlyMap<string, KeyObject>, expectTyp?: string): VerifiedJws<T> {
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('malformed JWS');
  const [h, p, s] = parts as [string, string, string];
  const header = JSON.parse(Buffer.from(h, 'base64url').toString()) as VerifiedJws<T>['header'];
  if (header.alg !== 'EdDSA') throw new Error('unsupported JWS alg');
  if (expectTyp && header.typ !== expectTyp) throw new Error(`unexpected JWS typ ${header.typ}`);
  const key = keys.get(header.kid);
  if (!key) throw new Error(`unknown signing key ${header.kid}`);
  if (!verify(null, Buffer.from(`${h}.${p}`), key, Buffer.from(s, 'base64url'))) throw new Error('bad JWS signature');
  return { header, payload: JSON.parse(Buffer.from(p, 'base64url').toString()) as T };
}

// AES-256-GCM for the tokenisation vault (BP 5.3).
export function seal(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map((b) => b.toString('base64url')).join('.');
}

export function unseal(sealed: string, key: Buffer): string {
  const [iv, tag, ct] = sealed.split('.').map((s) => Buffer.from(s, 'base64url')) as [Buffer, Buffer, Buffer];
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

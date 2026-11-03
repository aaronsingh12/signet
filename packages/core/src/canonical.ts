// JSON canonicalisation (RFC 8785 JCS): keys sorted by UTF-16 code units, no whitespace,
// numbers in ECMAScript form. Used for everything that is signed or hashed.
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (value === undefined) throw new Error('canonicalize: undefined is not JSON');
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('canonicalize: non-finite number');
    if (typeof value === 'bigint' || typeof value === 'function' || typeof value === 'symbol') throw new Error(`canonicalize: ${typeof value} is not JSON`);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

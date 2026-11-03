import { createHash } from 'node:crypto';

// Merkle trees in the RFC 6962 / RFC 9162 style (as used by Certificate Transparency):
// leaf = SHA-256(0x00 || leaf bytes), node = SHA-256(0x01 || left || right).
// Daily ledger roots (BP 8.3) are built over the record hashes of one UTC day.

const h = (...parts: Buffer[]) => createHash('sha256').update(Buffer.concat(parts)).digest();
const LEAF = Buffer.from([0]);
const NODE = Buffer.from([1]);

export const leafHash = (hex: string) => h(LEAF, Buffer.from(hex, 'hex'));

function largestPowerOfTwoBelow(n: number) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function rootOf(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return h();
  if (leaves.length === 1) return leaves[0]!;
  const k = largestPowerOfTwoBelow(leaves.length);
  return h(NODE, rootOf(leaves.slice(0, k)), rootOf(leaves.slice(k)));
}

export function merkleRoot(recordHashes: string[]): string {
  return rootOf(recordHashes.map(leafHash)).toString('hex');
}

// Audit path for leaf `index` (RFC 9162 section 2.1.3).
function path(index: number, leaves: Buffer[]): Buffer[] {
  if (leaves.length <= 1) return [];
  const k = largestPowerOfTwoBelow(leaves.length);
  return index < k
    ? [...path(index, leaves.slice(0, k)), rootOf(leaves.slice(k))]
    : [...path(index - k, leaves.slice(k)), rootOf(leaves.slice(0, k))];
}

export function inclusionProof(recordHashes: string[], index: number): string[] {
  return path(index, recordHashes.map(leafHash)).map((b) => b.toString('hex'));
}

export function verifyInclusion(recordHash: string, index: number, size: number, proof: string[], root: string): boolean {
  if (index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leafHash(recordHash);
  for (const p of proof.map((x) => Buffer.from(x, 'hex'))) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = h(NODE, p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = h(NODE, r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.toString('hex') === root;
}

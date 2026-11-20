import { GUARDRAIL_PARAMS } from '@signet/core';

/** Bounded Guardian review input, below the gateway's existing 2 MiB JSON transport limit. */
export const GUARDIAN_MAX_BYTES = GUARDRAIL_PARAMS.guardian_max_bytes;
export const GUARDIAN_CHUNK_BYTES = 32768;
export const GUARDIAN_OVERLAP_BYTES = 2048;

/** Covers all text with overlapping UTF-8 windows; never splits a multibyte character or drops a tail. */
export function guardianChunks(content: string): string[] {
  const encoded = Buffer.from(content, 'utf8');
  const chunks: string[] = [];
  let start = 0;
  while (start < encoded.length) {
    let end = Math.min(start + GUARDIAN_CHUNK_BYTES, encoded.length);
    while (end < encoded.length && (encoded[end]! & 0xc0) === 0x80) end--;
    chunks.push(encoded.subarray(start, end).toString('utf8'));
    if (end === encoded.length) break;
    start = end - GUARDIAN_OVERLAP_BYTES;
    while ((encoded[start]! & 0xc0) === 0x80) start++;
  }
  return chunks;
}

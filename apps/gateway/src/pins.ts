import { DETECTOR_SPECS, specHash } from '@signet/core';
import * as state from './state';

// Detector pins (DA 3, DA 6 mechanism 3): the hash of what this gateway actually runs is compared with
// the pin in the signed policy bundle. A mismatch makes the detector unavailable (fail safe).
const running = new Map<string, string>();
for (const [id, s] of Object.entries(DETECTOR_SPECS)) if (s) running.set(id, specHash(s.spec));

/** Model detectors report the hash of the weights they loaded. */
export const setRunningHash = (id: string, sha256: string) => running.set(id, sha256);
export const runningHashes = () => Object.fromEntries(running);

export function pinCheck(id: string): { sha256?: string; ok: boolean; reason?: string } {
  const have = running.get(id);
  const pinned = state.detectors.get(id)?.sha256 ?? null;
  if (!pinned) return { sha256: have, ok: true }; // not pinned yet: SGC-SELF-001 reports it
  if (!have) return { ok: false, reason: `pinned ${pinned.slice(0, 12)}, but this gateway cannot hash what it runs` };
  if (have !== pinned) return { sha256: have, ok: false, reason: `running ${have.slice(0, 12)} does not match the pinned ${pinned.slice(0, 12)}` };
  return { sha256: have, ok: true };
}

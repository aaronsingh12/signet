import { PII_ENTITIES, type DetectorResult, type Finding } from '@signet/core';
import { pinCheck } from './pins';
import * as state from './state';

// DET-PII, personal data in free text (DA 3): Microsoft Presidio (MIT) finds names and addresses that
// patterns cannot. It is a registered detector, so it follows the Decision Architecture:
//   off     - not called.
//   shadow  - called and counted in the record, never changes the prompt (RB-MOD-03).
//   active  - names and addresses it finds are handled like any other personal data: tokenised (or
//             blocked) by the seal's DLP rules before the prompt reaches the model.
//   failure - unavailable: the pattern DLP still runs and T1/T2 allows are held (RB-INV-06).
// Only ever adds caution: it can mask more text, never less.
//
//   SIGNET_PRESIDIO_URL       Presidio analyzer, for example http://localhost:5002 (docker image
//                             mcr.microsoft.com/presidio-analyzer)
//   SIGNET_PRESIDIO_MIN_SCORE default 0.6

const ENTITIES: Record<string, Finding['tag']> = PII_ENTITIES; // shared with the control plane, which pins its hash
const CAP_MS = Number(process.env.SIGNET_PRESIDIO_CAP_MS ?? 1500);
const MAX_CHARS = 20_000;

interface PresidioHit { entity_type: string; start: number; end: number; score: number }

export const presidioUrl = (env = process.env) => env.SIGNET_PRESIDIO_URL?.trim().replace(/\/$/, '') || null;

export async function analyze(url: string, text: string, signal?: AbortSignal): Promise<Finding[]> {
  const minScore = Number(process.env.SIGNET_PRESIDIO_MIN_SCORE ?? 0.6);
  const r = await fetch(`${url}/analyze`, {
    method: 'POST', signal,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text, language: 'en', entities: Object.keys(ENTITIES), score_threshold: minScore }),
  });
  if (!r.ok) throw new Error(`Presidio answered ${r.status}`);
  const hits = (await r.json()) as PresidioHit[];
  return hits
    .filter((h) => ENTITIES[h.entity_type] && h.score >= minScore && h.end > h.start)
    .map((h) => ({ recogniser: `presidio_${h.entity_type.toLowerCase()}`, tag: ENTITIES[h.entity_type]!, start: h.start, end: h.end, value: text.slice(h.start, h.end) }));
}

/** Score every text segment of the prompt. Returns the detector result and findings per segment. */
export async function detectPii(texts: string[]): Promise<{ result: DetectorResult & { reason?: string; found?: number }; findings: Map<string, Finding[]> }> {
  const cfg = state.detectors.get('DET-PII');
  const pin = pinCheck('DET-PII');
  const base = { id: 'DET-PII', version: cfg?.version ?? 'not-deployed', ...(pin.sha256 ? { sha256: pin.sha256 } : {}) };
  const findings = new Map<string, Finding[]>();
  const url = presidioUrl();
  if (!cfg || cfg.mode === 'off' || !url) return { result: { ...base, status: 'unavailable', reason: !url ? 'SIGNET_PRESIDIO_URL not set' : 'off' }, findings };
  if (!pin.ok) return { result: { ...base, status: 'unavailable', reason: `pin mismatch: ${pin.reason}` }, findings };
  const unique = [...new Set(texts.filter((t) => /\p{L}{2,}/u.test(t)))];
  if (unique.reduce((n, t) => n + t.length, 0) > MAX_CHARS) return { result: { ...base, status: 'unavailable', reason: `prompt over ${MAX_CHARS} characters` }, findings };
  try {
    const signal = AbortSignal.timeout(CAP_MS);
    const all = await Promise.all(unique.map(async (t) => [t, await analyze(url, t, signal)] as const));
    let found = 0;
    for (const [t, f] of all) if (f.length) { findings.set(t, f); found += f.length; }
    return { result: { ...base, status: cfg.mode === 'active' ? 'ok' : 'shadow', score: found ? 1 : 0, band: 'low', found }, findings };
  } catch (e) {
    return { result: { ...base, status: 'unavailable', reason: (e as Error).message }, findings };
  }
}

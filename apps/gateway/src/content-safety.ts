import { SAFETY_CATEGORIES, SAFETY_POLICY, env, type DetectorResult, type Tier } from '@signet/core';
import { pinCheck } from './pins';
import { safetyChallenger } from './challenger';
import { type Ctx, halt, wouldBlock } from './ctx';
import * as state from './state';
import { chatCompletion, UpstreamRejected, UpstreamUnavailable } from './provider';
import { recordSafetyUsage, safetyModelUsage, type SafetyModelUsage } from './safety-usage';

const CATEGORIES = SAFETY_CATEGORIES;
type SafetyCategory = typeof CATEGORIES[number];
export interface SafetyVerdict { category: SafetyCategory; model: string; tokens: number; usage: SafetyModelUsage[] }
export class SafetyUnavailable extends Error {
  constructor(message: string, readonly usage: SafetyModelUsage[]) { super(message); }
}

const POLICY = SAFETY_POLICY; // shared with the control plane, which pins its hash (DA 3)

export interface Classified<L extends string> { label: L; model: string; tokens: number; usage: SafetyModelUsage[] }

/**
 * Asks the cloud LLM for exactly one label from `labels` under `policy`. Fails closed: a timeout, an
 * unreachable provider or any answer that is not one of the labels is SafetyUnavailable after 3 attempts.
 */
export async function classifyWith<L extends string>(policy: string, labels: readonly L[], conversation: string, name = 'Safety classifier'): Promise<Classified<L>> {
  const model = env('SIGNET_LLM_MODEL', 'gpt-oss:120b-cloud');
  const usage: SafetyModelUsage[] = [];
  let lastError: Error = new SafetyUnavailable(`${name} did not run`, []);
  for (let attempt = 1; attempt <= 3; attempt++) {
    const signal = AbortSignal.timeout(15_000);
    try {
      const response = await chatCompletion({ model, temperature: 0, max_tokens: 1024, messages: [
        { role: 'system', content: policy },
        { role: 'user', content: conversation },
      ] }, signal, undefined);
      usage.push(safetyModelUsage(model, response.usage, state.bundle?.catalogue ?? []));
      const content = response && Array.isArray(response.choices) ? response.choices[0]?.message?.content : null;
      const text = typeof content === 'string' ? content.trim() : null;
      const label = labels.find((value) => value === text);
      if (!label) throw new SafetyUnavailable(`${name} ${model} returned an invalid label: ${JSON.stringify(text)}`, [...usage]);
      return { label, model, tokens: usage.reduce((sum, record) => sum + (record.tokens_in ?? 0) + (record.tokens_out ?? 0), 0), usage };
    } catch (error) {
      if (signal.aborted && error instanceof Error) lastError = new SafetyUnavailable(`${name} ${model} timed out: ${error.message}`, [...usage]);
      else if (error instanceof UpstreamUnavailable || error instanceof UpstreamRejected || error instanceof SafetyUnavailable || error instanceof SyntaxError) lastError = error;
      else throw error;
      if (attempt < 3) console.warn(`Signet ${name.toLowerCase()} failed; retrying`, { attempt, model, error: lastError.message });
    }
  }
  throw new SafetyUnavailable(`${name} failed after 3 attempts for ${model}: ${lastError.message}`, usage);
}

/** Fail closed when the independent cloud safety review cannot return a valid verdict. */
export async function reviewContent(conversation: string): Promise<SafetyVerdict> {
  const { label, ...rest } = await classifyWith(POLICY, CATEGORIES, conversation, 'Safety classifier');
  return { category: label, ...rest };
}

// DET-SAFE, unsafe content by policy category (DA 3). It is a registered detector, so it follows the
// Decision Architecture like every other detector:
//   off      - not run.
//   shadow   - scored and logged, never blocks (RB-MOD-03).
//   active   - unsafe content is blocked; in a shadow deployment it is recorded as would_block.
//   failure  - the check is unavailable: the rules still decide, T1/T2 allows are held for approval and
//              T3/T4 continue (DA 2 fail safe, RB-INV-06), instead of blocking every chat.
// The verdict is applied here, so the combiner only sees the detector's availability (band stays low).
export async function contentSafety(ctx: Ctx, conversation: string, stage: 8 | 13, review: (conversation: string) => Promise<SafetyVerdict> = reviewContent): Promise<DetectorResult | null> {
  const cfg = state.detectors.get('DET-SAFE');
  const mode = cfg?.mode ?? 'active'; // a control plane from before DET-SAFE was registered: keep blocking
  if (mode === 'off') return null;
  const pin = pinCheck('DET-SAFE');
  const base = { id: 'DET-SAFE', version: cfg?.version ?? 'unregistered', ...(pin.sha256 ? { sha256: pin.sha256 } : {}) };
  const where = stage === 8 ? 'input' : 'output';
  let verdict: SafetyVerdict;
  try {
    verdict = await review(conversation);
  } catch (error) {
    if (!(error instanceof SafetyUnavailable)) throw error;
    recordSafetyUsage(ctx, error.usage);
    console.error('Signet content safety unavailable', { request_id: ctx.requestId, stage, error: error.message });
    ctx.reasons.push(`DET-SAFE unavailable on the ${where} (${error.message}); rules decide, T1/T2 held (RB-INV-06)`);
    safetyChallenger(ctx, conversation, where, { status: 'unavailable' });
    return { ...base, status: 'unavailable' };
  }
  recordSafetyUsage(ctx, verdict.usage);
  ctx.extra[`${where}_safety`] = verdict;
  safetyChallenger(ctx, conversation, where, { category: verdict.category, status: mode });
  const unsafe = verdict.category !== 'allow';
  if (unsafe && mode === 'shadow') ctx.reasons.push(`DET-SAFE (shadow) would block the ${where}: ${verdict.category}`);
  if (unsafe && mode === 'active' && !wouldBlock(ctx, stage, ['DET-SAFE'], `unsafe content (${verdict.category}) in the ${where}`)) {
    halt(ctx, stage, 403, 'unsafe_content', `Chat blocked by Signet: ${stage === 8 ? 'this request' : 'the AI response'} violates the ${verdict.category.replaceAll('_', ' ')} safety policy. Please ask for safe, lawful information.`, 'deny', ['DET-SAFE'], 'blocked', { blocked_by: 'signet', category: verdict.category, stage: where });
  }
  // A version that does not match its pin still blocks unsafe content (that only adds caution), but it
  // does not count as a working check, so T1/T2 allows are held (DA 2 fail safe).
  if (!pin.ok) {
    ctx.reasons.push(`DET-SAFE pin mismatch: ${pin.reason}; treated as unavailable (DA 3)`);
    return { ...base, status: 'unavailable', score: unsafe ? 1 : 0 };
  }
  return { ...base, status: mode === 'active' ? 'ok' : 'shadow', score: unsafe ? 1 : 0, band: 'low' };
}

// The answer could not be safety-checked: T1/T2 answers are withheld for approval (DA 2 fail safe);
// T3/T4 answers are released on the rules alone.
export function withholdIfHighRisk(ctx: Ctx, tier: Tier) {
  if (tier !== 'T1' && tier !== 'T2') return;
  if (wouldBlock(ctx, 13, ['RB-INV-06', 'DET-SAFE'], 'answer not safety-checked; needs approval')) return;
  halt(ctx, 13, 403, 'response_withheld', 'The safety check on this answer is unavailable, so the answer is withheld until a person approves it.', 'require_approval', ['RB-INV-06', 'DET-SAFE']);
}

import type { IncomingHttpHeaders } from 'node:http';
import { scan, sha256 } from '@signet/core';
import { finish, Halt, halt, maskArgs, newCtx, preflight, step, type Ctx, type Done } from './ctx';
import { reviewContent, SafetyUnavailable } from './content-safety';
import { pinCheck } from './pins';

interface GuardianRequest { content: string }
interface Flag { flagged: boolean; categories: string[] }
interface GuardianVerdict {
  security: Flag; safety: Flag;
  review: { status: 'complete' | 'unavailable'; decision: 'clear' | 'flagged'; enforcement: 'servicenow_guardian'; scope: 'submitted_content' };
}

/** Recognizes direct credential-disclosure requests, not password-reset/help keywords alone. */
export function requestsCredentials(content: string): boolean {
  const text = content.normalize('NFKC').toLowerCase().replace(/[\u200B-\u200D\uFEFF]/g, '').replace(/\s+/g, ' ');
  const request = /\b(?:give|show|reveal|display|dump|export|list|retrieve|extract|disclose|send|print|batao|dikhao|nikalo)\b/;
  const credential = /\b(?:(?:all|every|stored|saved|actual|plaintext|users?|admin|database|production)\s+){0,3}(?:passwords?|passwds?|credentials|api[ _-]?keys?|private[ _-]?keys?|access[ _-]?tokens?|client[ _-]?secrets?)\b/;
  const segments = text.split(/[.!?;\n]/);
  return segments.some(segment => {
    const action = request.exec(segment);
    const secret = credential.exec(segment);
    if (!action || !secret || Math.abs(action.index - secret.index) > 160) return false;
    const prefix = segment.slice(0, action.index);
    if (/\b(?:do not|don't|never|cannot|can't|won't|refuse to|avoid)\s*$/.test(prefix)) return false;
    const suffix = segment.slice(secret.index + secret[0].length);
    if (/^\s+(?:policy|policies|requirements|strength|reset|rotation|manager|managers|management|help)\b/.test(suffix)) return false;
    const between = segment.slice(Math.min(action.index, secret.index), Math.max(action.index, secret.index));
    if (/\b(?:reset|change|rotate|protect|secure|policy|requirements|strength|manager|management|example|examples)\b/.test(between)) return false;
    return true;
  });
}

function verdict(security: string[], safety: string[], status: GuardianVerdict['review']['status']): GuardianVerdict {
  return {
    security: { flagged: security.length > 0, categories: security }, safety: { flagged: safety.length > 0, categories: safety },
    review: { status, decision: security.length || safety.length ? 'flagged' : 'clear', enforcement: 'servicenow_guardian', scope: 'submitted_content' },
  };
}

/** Independent BYOG review; it returns a verdict and never forwards a model or tool operation. */
export async function handleServiceNowGuardian(headers: IncomingHttpHeaders, input: GuardianRequest): Promise<Done> {
  const ctx = newCtx('guardrail_check', 'servicenow://guardian', headers);
  try {
    const checked = await inspect(ctx, headers, input);
    ctx.extra.guardrail_review = checked.review;
    ctx.extra.guardrail_categories = [...checked.security.categories, ...checked.safety.categories];
    ctx.extra.coverage = 'submitted_content_only';
    const result = await finish(ctx, null, checked);
    if (result.status !== 200) return result;
    return { ...result, body: { ...checked, request_id: ctx.requestId, record_id: result.recordId } };
  } catch (error) {
    if (error instanceof Halt) return finish(ctx, error, null);
    throw error;
  }
}

async function inspect(ctx: Ctx, headers: IncomingHttpHeaders, input: GuardianRequest): Promise<GuardianVerdict> {
  await preflight(ctx, headers);
  const bytes = typeof input?.content === 'string' ? Buffer.byteLength(input.content, 'utf8') : null;
  ctx.extra.guardrail_input = { type: typeof input?.content, bytes };
  if (typeof input?.content !== 'string' || !input.content.trim() || (bytes !== null && bytes > 65536)) {
    const detail = typeof input?.content !== 'string' ? 'Expected a JSON object with a content string; check the ServiceNow request transformer and Content-Type'
      : !input.content.trim() ? 'Guardian content is empty; check the ServiceNow request transformer'
      : `Guardian content is ${bytes} UTF-8 bytes; maximum is 65536. Reduce the ServiceNow Custom Guardian Token limit so each chunk fits; content is never truncated`;
    ctx.extra.guardrail_input_error = detail;
    halt(ctx, 6, 400, 'invalid_guardian_content', detail, 'deny', ['SN-GUARD-INPUT']);
  }
  ctx.promptHash = sha256(input.content);
  ctx.extra.content_bytes = Buffer.byteLength(input.content, 'utf8');
  step(ctx, 6, 'pass', 'Validated Guardian submission; original text is not retained in the ledger');
  const secrets = scan(input.content).filter(finding => finding.tag === 'secrets');
  if (secrets.length) {
    ctx.rules.push('SN-GUARD-SECRET');
    ctx.dlp.push(...secrets.map(finding => ({ direction: 'in' as const, tag: finding.tag, recogniser: finding.recogniser, action: 'flag' })));
    return verdict(['secret_disclosure'], [], 'complete');
  }
  if (requestsCredentials(input.content)) {
    ctx.rules.push('SN-GUARD-CREDENTIAL-REQUEST');
    return verdict(['credential_disclosure_request'], [], 'complete');
  }
  const pin = pinCheck('DET-SAFE');
  if (!pin.ok) {
    ctx.rules.push('SN-GUARD-UNAVAILABLE');
    ctx.reasons.push('Safety classifier pin mismatch; Guardian must withhold content');
    return verdict(['inspection_unavailable'], [], 'unavailable');
  }
  try {
    const review = await reviewContent(String(maskArgs(input.content)));
    ctx.tokensIn = review.tokens;
    ctx.extra.guardrail_classifier = { model: review.model, category: review.category, tokens: review.tokens };
    if (review.category === 'allow') return verdict([], [], 'complete');
    ctx.rules.push('SN-GUARD-SAFETY');
    return ['cyber_abuse', 'fraud'].includes(review.category) ? verdict([review.category], [], 'complete') : verdict([], [review.category], 'complete');
  } catch (error) {
    if (!(error instanceof SafetyUnavailable)) throw error;
    console.warn('ServiceNow Guardian safety review unavailable', { request_id: ctx.requestId, error: maskArgs(error.message) });
    ctx.rules.push('SN-GUARD-UNAVAILABLE');
    return verdict(['inspection_unavailable'], [], 'unavailable');
  }
}

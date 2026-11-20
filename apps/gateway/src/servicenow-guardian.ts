import type { IncomingHttpHeaders } from 'node:http';
import {
  ATTACK_LABELS, ATTACK_POLICY, GUARDIAN_ATTACK_JUDGE, GUARDRAIL_PARAMS, SIGNET_BLOCKED_PREFIX, SIGNET_REF, promptDecision, scan, sha256, specHash,
  type CatalogueModel, type CompiledPolicy, type DataTag, type DetectorResult, type Tier,
} from '@signet/core';
import { finish, Halt, halt, maskArgs, newCtx, preflight, step, type Ctx, type Done } from './ctx';
import { classifyWith, reviewContent, SafetyUnavailable, type Classified, type SafetyVerdict } from './content-safety';
import { detectInjection, detectJailbreak } from './detectors';
import { pinCheck } from './pins';
import { guardianChunks, GUARDIAN_CHUNK_BYTES, GUARDIAN_OVERLAP_BYTES } from './guardian-content';
import { recordSafetyUsage } from './safety-usage';
import type { SafetyModelUsage } from './safety-usage';
import * as state from './state';

// ServiceNow Guardian (bring your own guardrail). ServiceNow sends the text it is about to give its own LLM, or
// the answer it is about to show, and Signet returns a verdict. ServiceNow's Block action withholds flagged
// content, so Signet makes the decision and ServiceNow carries it out; this endpoint never forwards a model or
// tool call. Checks run fastest first and stop at the first finding:
//   1. secrets, credential requests and the agent's seal data rules (pattern rules, milliseconds)
//   2. the safety judge (DET-SAFE) and the prompt-attack judge, in parallel, beside DET-INJ / DET-JB
// Any check that cannot run fails closed: the verdict is flagged "inspection_unavailable".

type AttackLabel = typeof ATTACK_LABELS[number];
interface GuardianRequest { content: string }
interface Flag { flagged: boolean; categories: string[] }
export interface GuardianVerdict {
  security: Flag; safety: Flag;
  review: { status: 'complete' | 'unavailable'; decision: 'clear' | 'flagged'; enforcement: 'servicenow_guardian'; scope: 'submitted_content' };
}

/** One reason to withhold the content: a category ServiceNow receives, the rule, and plain words for people. */
export interface GuardianFinding { category: string; kind: 'security' | 'safety'; rule: string; reason: string }

/** The checks that need a model; replaced in tests. */
export interface GuardianChecks {
  safety: (chunk: string) => Promise<SafetyVerdict>;
  attack: (chunk: string) => Promise<Classified<AttackLabel>>;
  injection: (text: string, tier: Tier) => Promise<DetectorResult>;
  jailbreak: (text: string, tier: Tier) => Promise<DetectorResult>;
}

const LIVE_CHECKS: GuardianChecks = {
  safety: reviewContent,
  attack: (chunk) => classifyWith(ATTACK_POLICY, ATTACK_LABELS, chunk, 'Prompt-attack classifier'),
  injection: (text, tier) => detectInjection(text, tier, 'prompt'),
  jailbreak: detectJailbreak,
};

const ATTACK_JUDGE_SHA256 = specHash(GUARDIAN_ATTACK_JUDGE.spec);
const SECURITY_SAFETY = new Set(['cyber_abuse', 'fraud']); // DET-SAFE categories ServiceNow treats as security
const DETECTOR_WINDOW = 4000; // the model detectors read at most this many characters per call
const DETECTOR_MAX_WINDOWS = 8;
const CATEGORY_MAX = 200; // ServiceNow categories and Signet's block sync accept strings up to this length

/** Recognizes direct credential-disclosure requests, not password-reset/help keywords alone. */
export function requestsCredentials(content: string): boolean {
  const text = content.normalize('NFKC').toLowerCase().replace(/[​-‍﻿]/g, '').replace(/\s+/g, ' ');
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

/** The message people see in ServiceNow's Guardian log (and in chat, where ServiceNow shows categories). */
export const blockedMessage = (findings: GuardianFinding[]): string =>
  `${SIGNET_BLOCKED_PREFIX}${[...new Set(findings.map((f) => f.reason))].join('; ')}`.slice(0, CATEGORY_MAX);

/**
 * Builds the verdict ServiceNow's response transformer expects. ServiceNow reads each field for a different
 * check: Prompt Injection acts on `security`, Offensiveness on `safety`. A Signet block must hold whichever check
 * asked (an answer reviewed only by Offensiveness can still leak a secret), so a block flags both fields with the
 * same categories, the blocked message and the Signet reference; ServiceNow keeps them in its Guardian metrics.
 * `kind` stays on each finding for the ledger and the Guardrails page.
 */
export function guardianVerdict(findings: GuardianFinding[], status: GuardianVerdict['review']['status'], requestId: string): GuardianVerdict {
  const categories = findings.length ? [...new Set(findings.map((f) => f.category)), blockedMessage(findings), `${SIGNET_REF}${requestId}`] : [];
  return {
    security: { flagged: categories.length > 0, categories: [...categories] }, safety: { flagged: categories.length > 0, categories: [...categories] },
    review: { status, decision: findings.length ? 'flagged' : 'clear', enforcement: 'servicenow_guardian', scope: 'submitted_content' },
  };
}

const plainTag = (tag: DataTag) => tag.replaceAll('_', ' ');
const unavailable = (reason: string): GuardianFinding => ({ category: 'inspection_unavailable', kind: 'security', rule: 'SN-GUARD-UNAVAILABLE', reason: `Signet could not complete its checks (${reason})` });

/** Step 1: pattern rules. Secrets, direct credential requests, and data classes the agent's seal does not allow. */
export function fastFindings(ctx: Ctx, content: string, policy: Pick<CompiledPolicy, 'prompt_tags' | 'forbidden_tags'>, model: Pick<CatalogueModel, 'code_approved'>): GuardianFinding[] {
  const findings: GuardianFinding[] = [];
  const found = scan(content);
  const secrets = found.filter((f) => f.tag === 'secrets');
  if (secrets.length) {
    ctx.dlp.push(...secrets.map((f) => ({ direction: 'in' as const, tag: f.tag, recogniser: f.recogniser, action: 'flag' })));
    findings.push({ category: 'secret_disclosure', kind: 'security', rule: 'SN-GUARD-SECRET', reason: 'the content contains a secret' });
  }
  if (requestsCredentials(content)) findings.push({ category: 'credential_disclosure_request', kind: 'security', rule: 'SN-GUARD-CREDENTIAL-REQUEST', reason: 'it asks for passwords or other credentials' });
  // The same data-class matrix the gateway applies to prompts (RB-DATA). Guardian only flags: it does not
  // tokenise, and it does not kill the agent, because ServiceNow's own model produced or received the text.
  for (const f of found.filter((x) => x.tag !== 'secrets')) {
    const d = promptDecision(f.tag, policy, model as CatalogueModel);
    if (d.action !== 'block') continue;
    ctx.dlp.push({ direction: 'in', tag: f.tag, recogniser: f.recogniser, action: 'flag' });
    findings.push({ category: `restricted_data:${f.tag}`, kind: 'security', rule: 'SN-GUARD-DATA', reason: `it contains ${plainTag(f.tag)} data this agent may not handle` });
  }
  return findings;
}

const usageTotals = (ctx: Ctx, usage: SafetyModelUsage[]) => {
  recordSafetyUsage(ctx, usage);
  ctx.tokensIn += usage.reduce((sum, u) => sum + (u.tokens_in ?? 0), 0);
  ctx.tokensOut += usage.reduce((sum, u) => sum + (u.tokens_out ?? 0), 0);
};

/** Scores the content in windows and keeps the highest score; a window that fails makes the result unavailable. */
async function scoreWindows(run: (text: string) => Promise<DetectorResult>, content: string): Promise<DetectorResult & { windows: number }> {
  const windows: string[] = [];
  for (let i = 0; i < content.length && windows.length < DETECTOR_MAX_WINDOWS; i += DETECTOR_WINDOW) windows.push(content.slice(i, i + DETECTOR_WINDOW));
  let best: DetectorResult | null = null;
  for (const w of windows) {
    const r = await run(w);
    if (r.status === 'unavailable') return { ...r, windows: windows.length };
    if (!best || (r.score ?? 0) > (best.score ?? 0)) best = r;
  }
  return { ...(best ?? { id: 'unknown', version: 'unknown', status: 'unavailable' as const }), windows: windows.length };
}

/**
 * Step 2: the model checks. The safety judge and the prompt-attack judge decide; DET-INJ and DET-JB score the
 * same content and only decide once a person has promoted them to active (DA 3: shadow never blocks).
 */
export async function modelFindings(ctx: Ctx, content: string, tier: Tier, checks: GuardianChecks = LIVE_CHECKS): Promise<GuardianFinding[]> {
  const pin = pinCheck('DET-SAFE');
  if (!pin.ok) {
    ctx.reasons.push(`DET-SAFE pin mismatch (${pin.reason}); Guardian withholds the content`);
    return [unavailable('safety classifier version does not match its pin')];
  }
  const masked = String(maskArgs(content));
  const chunks = guardianChunks(masked);
  const safety: SafetyVerdict[] = [];
  const attack: Classified<AttackLabel>[] = [];
  const classifier = () => ({
    chunk_count: chunks.length, completed_chunks: Math.min(safety.length, attack.length),
    chunk_max_bytes: GUARDIAN_CHUNK_BYTES, overlap_bytes: GUARDIAN_OVERLAP_BYTES, results: [...safety],
  });
  ctx.extra.guardrail_classifier = classifier();
  const detectors = Promise.all([scoreWindows((t) => checks.injection(t, tier), masked), scoreWindows((t) => checks.jailbreak(t, tier), masked)]);
  let failure: SafetyUnavailable | null = null;
  // Bound provider concurrency; settle each batch before recording a final verdict.
  for (let index = 0; index < chunks.length && !failure; index += 3) {
    const batch = chunks.slice(index, index + 3);
    const results = await Promise.allSettled([...batch.map((c) => checks.safety(c)), ...batch.map((c) => checks.attack(c))]);
    for (const [i, result] of results.entries()) {
      if (result.status === 'fulfilled') {
        usageTotals(ctx, result.value.usage);
        if (i < batch.length) safety.push(result.value as SafetyVerdict);
        else attack.push(result.value as Classified<AttackLabel>);
      } else if (result.reason instanceof SafetyUnavailable) {
        usageTotals(ctx, result.reason.usage);
        failure ??= result.reason;
      } else throw result.reason;
    }
  }
  ctx.extra.guardrail_classifier = classifier();
  ctx.extra.guardrail_attack = { version: GUARDIAN_ATTACK_JUDGE.version, sha256: ATTACK_JUDGE_SHA256, labels: attack.map((a) => a.label), tokens: attack.reduce((sum, a) => sum + a.tokens, 0) };
  const [inj, jb] = await detectors;
  ctx.detectors.push(inj, jb);

  const findings: GuardianFinding[] = [];
  for (const d of [inj, jb]) {
    const what = d.id === 'DET-JB' ? 'jailbreak attempt' : 'prompt injection';
    if (d.status === 'shadow' && d.band && d.band !== 'low') ctx.reasons.push(`${d.id} (shadow) ${d.band} (${d.score}) on Guardian content: would flag ${what}`);
    // Active: High flags in every tier; Elevated flags T1/T2 (DA 4 holds those for a person, which Guardian cannot).
    const flags = d.status === 'ok' && (d.band === 'high' || (d.band === 'elevated' && (tier === 'T1' || tier === 'T2')));
    if (flags) findings.push({ category: d.id === 'DET-JB' ? 'jailbreak' : 'prompt_injection', kind: 'security', rule: d.id, reason: `${what} detected` });
  }
  if (failure) {
    console.warn('ServiceNow Guardian review unavailable', { request_id: ctx.requestId, error: maskArgs(failure.message) });
    return [...findings, unavailable(failure.message.includes('Prompt-attack') ? 'prompt-attack classifier unavailable' : 'safety classifier unavailable')];
  }
  for (const label of new Set(attack.map((a) => a.label).filter((l) => l !== 'allow'))) {
    findings.push({ category: label, kind: 'security', rule: 'SN-GUARD-ATTACK', reason: label === 'jailbreak' ? 'jailbreak attempt detected' : 'prompt injection detected' });
  }
  for (const category of new Set(safety.map((s) => s.category).filter((c) => c !== 'allow'))) {
    findings.push({ category, kind: SECURITY_SAFETY.has(category) ? 'security' : 'safety', rule: 'SN-GUARD-SAFETY', reason: `unsafe content (${category.replaceAll('_', ' ')})` });
  }
  return findings;
}

/** Independent BYOG review; it returns a verdict and never forwards a model or tool operation. */
export async function handleServiceNowGuardian(headers: IncomingHttpHeaders, input: GuardianRequest, checks: GuardianChecks = LIVE_CHECKS): Promise<Done> {
  const ctx = newCtx('guardrail_check', 'servicenow://guardian', headers);
  try {
    const { findings, status } = await inspect(ctx, headers, input, checks);
    const checked = guardianVerdict(findings, status, ctx.requestId);
    ctx.extra.guardrail_review = checked.review;
    ctx.extra.guardrail_categories = [...new Set(findings.map((f) => f.category))];
    ctx.extra.coverage = 'submitted_content_only';
    ctx.rules.push(...new Set(findings.map((f) => f.rule)));
    if (findings.length) {
      // Signet's decision is a block even though ServiceNow carries it out: the ledger records it as one, while
      // ServiceNow still receives HTTP 200 with the flagged verdict its Block action needs.
      const message = blockedMessage(findings);
      ctx.extra.guardrail_reason = message;
      ctx.extra.blocked_by = 'signet';
      ctx.decision = 'deny';
      ctx.softBlock = new Halt(200, 'blocked_by_signet', message, 'deny', 'blocked');
      step(ctx, 9, 'fail', message);
    } else step(ctx, 9, 'pass', 'clear');
    const result = await finish(ctx, null, checked);
    if (result.status !== 200) return result;
    return { ...result, body: { ...checked, request_id: ctx.requestId, record_id: result.recordId } };
  } catch (error) {
    if (error instanceof Halt) return finish(ctx, error, null);
    throw error;
  }
}

async function inspect(ctx: Ctx, headers: IncomingHttpHeaders, input: GuardianRequest, checks: GuardianChecks): Promise<{ findings: GuardianFinding[]; status: GuardianVerdict['review']['status'] }> {
  const { cert, policy } = await preflight(ctx, headers);
  const bytes = typeof input?.content === 'string' ? Buffer.byteLength(input.content, 'utf8') : null;
  ctx.extra.guardrail_input = { type: typeof input?.content, bytes };
  if (typeof input?.content !== 'string' || !input.content.trim() || (bytes !== null && bytes > GUARDRAIL_PARAMS.guardian_max_bytes)) {
    const detail = typeof input?.content !== 'string' ? 'Expected a JSON object with a content string; check the ServiceNow request transformer and Content-Type'
      : !input.content.trim() ? 'Guardian content is empty; check the ServiceNow request transformer'
      : `Guardian content is ${bytes} UTF-8 bytes; maximum is ${GUARDRAIL_PARAMS.guardian_max_bytes}. Submit smaller Guardian inputs; accepted content is reviewed in overlapping chunks and is never truncated`;
    ctx.extra.guardrail_input_error = detail;
    halt(ctx, 6, 400, 'invalid_guardian_content', detail, 'deny', ['SN-GUARD-INPUT']);
  }
  ctx.promptHash = sha256(input.content);
  ctx.extra.content_bytes = Buffer.byteLength(input.content, 'utf8');
  step(ctx, 6, 'pass', 'Validated Guardian submission; original text is not retained in the ledger');
  const model = state.bundle?.catalogue.find((c) => !c.upstream) ?? { code_approved: false };
  const fast = fastFindings(ctx, input.content, policy, model);
  if (fast.length) {
    step(ctx, 8, 'fail', `pattern rules: ${fast.map((f) => f.category).join(', ')}`);
    return { findings: fast, status: 'complete' };
  }
  const findings = await modelFindings(ctx, input.content, cert.tier, checks);
  step(ctx, 8, findings.length ? 'fail' : 'pass', findings.length ? findings.map((f) => f.category).join(', ') : 'no findings');
  return { findings, status: findings.some((f) => f.rule === 'SN-GUARD-UNAVAILABLE') ? 'unavailable' : 'complete' };
}

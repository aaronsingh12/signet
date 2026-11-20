import { mkdirSync, writeFileSync } from 'node:fs';
import type { IncomingHttpHeaders } from 'node:http';
import { join } from 'node:path';
import {
  ATTACK_LABELS, GUARDIAN_ATTACK_JUDGE, GUARDRAIL_PARAMS, SIGNET_BLOCKED_PREFIX, SIGNET_REF, attackClassificationMessages, devOverridesAllowed, promptDecision, scan, sha256, specHash,
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
  attack: (chunk) => classifyWith(attackClassificationMessages, ATTACK_LABELS, chunk, 'Prompt-attack classifier'),
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

/**
 * What the judges review. ServiceNow's AI agent engine sends its whole working prompt as JSON: the user's question,
 * conversation memory and tool results, but also tens of kilobytes of its own orchestration text (worked examples,
 * tool definitions, engine rules, the configured persona). That orchestration text is written as instructions to a
 * model, so a prompt-attack judge reading it flags ServiceNow itself. For this envelope the judges review only the
 * fields that carry outside input, each labelled; pattern rules (secrets, data classes) still scan everything. Any
 * other shape, including text that is not this envelope, is reviewed whole.
 */
export interface ReviewScope { kind: 'servicenow_reviewed_field' | 'servicenow_agent_inputs' | 'full_content'; text: string; fields: string[] }
const OUTSIDE_INPUT_FIELDS = [
  ['question', 'User request'],
  ['short_term_memory', 'Conversation and context memory'],
  ['agent_scratchpad', 'Tool results and agent steps so far'],
  ['previous_scratchpad', 'Earlier agent steps'],
  ['long_term_memory', 'Long-term memory'],
  ['episodic_memory', 'Memory from earlier runs'],
] as const;

export function reviewScope(content: string): ReviewScope {
  const whole: ReviewScope = { kind: 'full_content', text: content, fields: [] };
  let parsed: unknown;
  try { parsed = JSON.parse(content); } catch { return whole; }
  const metadata = (parsed as { request_metadata?: { input?: unknown; chunkedAttributeName?: unknown } } | null)?.request_metadata;
  const input = metadata?.input;
  if (!input || typeof input !== 'object' || Array.isArray(input)) return whole;
  // ServiceNow names the field it is asking about (for example guardianChunkInput, a slice of the conversation and
  // the agent's reply). The rest of such a request is its own metadata, including full copies of the engine prompt
  // (originalPayload, aia_framework_request), so only the named field is judged.
  const reviewed = metadata.chunkedAttributeName;
  if (typeof reviewed === 'string') {
    const value = (input as Record<string, unknown>)[reviewed];
    if (typeof value === 'string' && value.trim()) return { kind: 'servicenow_reviewed_field', text: value, fields: [reviewed] };
  }
  const parts: string[] = [];
  const fields: string[] = [];
  for (const [field, label] of OUTSIDE_INPUT_FIELDS) {
    const value = (input as Record<string, unknown>)[field];
    const text = typeof value === 'string' ? value : value === undefined || value === null ? '' : JSON.stringify(value);
    if (!text.trim() || text.trim() === '[]' || text.trim() === '{}') continue;
    parts.push(`### ${label} (${field})\n${text}`);
    fields.push(field);
  }
  // An envelope with none of these fields is a shape we do not know yet: review all of it.
  return parts.length ? { kind: 'servicenow_agent_inputs', text: parts.join('\n\n'), fields } : whole;
}

/**
 * Which AI agent a review belongs to. A custom guardian set to "All" receives every Now Assist feature and AI agent
 * on the ServiceNow instance, all under this one credential. Signet governs only the ServiceNow agents linked to the
 * credential's Signet agent (bundle guardian_agents); other agents' reviews pass and are logged, so this identity
 * never blocks another team's agent. The agent engine's request names the agent (request_metadata.input.agent_name);
 * the chunked follow-up reviews of the same run carry only its conversation and execution IDs, so those IDs are
 * remembered from the named review. A review that names no agent and matches no remembered run is not attributed to
 * this agent. With no linked ServiceNow agent, everything is governed as before.
 */
export interface Attribution { governed: boolean; reason: 'no_linked_agents' | 'agent_name' | 'same_run' | 'unattributed'; agent_name: string | null; run_id: string | null }
const RUN_TTL_MS = 2 * 3_600_000;
const RUN_MEMORY_MAX = 10_000;
const runs = new Map<string, { governed: boolean; at: number }>();
const SYS_ID = /^[a-f0-9]{32}$/i;

export function attributeReview(content: string, linkedNames: readonly string[] | undefined, memory = runs, now = Date.now()): Attribution {
  if (!linkedNames?.length) return { governed: true, reason: 'no_linked_agents', agent_name: null, run_id: null };
  let parsed: { request_metadata?: { _meta?: Record<string, unknown>; input?: { agent_name?: unknown; _meta?: Record<string, unknown> } } } | null = null;
  try { parsed = JSON.parse(content); } catch { parsed = null; }
  const metas = [parsed?.request_metadata?._meta, parsed?.request_metadata?.input?._meta];
  const runIds = [...new Set(metas.flatMap((m) => ['conversationId', 'aiaExecutionId', 'documentId'].map((k) => m?.[k])).filter((v): v is string => typeof v === 'string' && SYS_ID.test(v)))];
  for (const [id, entry] of memory) if (now - entry.at > RUN_TTL_MS) memory.delete(id);
  const name = parsed?.request_metadata?.input?.agent_name;
  if (typeof name === 'string' && name.trim()) {
    const governed = linkedNames.some((n) => n.trim().toLowerCase() === name.trim().toLowerCase());
    for (const id of runIds) memory.set(id, { governed, at: now });
    while (memory.size > RUN_MEMORY_MAX) memory.delete(memory.keys().next().value!);
    return { governed, reason: 'agent_name', agent_name: name.trim(), run_id: runIds[0] ?? null };
  }
  for (const id of runIds) {
    const known = memory.get(id);
    if (known) { known.at = now; return { governed: known.governed, reason: 'same_run', agent_name: null, run_id: id }; }
  }
  return { governed: false, reason: 'unattributed', agent_name: null, run_id: runIds[0] ?? null };
}

/** Step 1: pattern rules. Secrets, direct credential requests, and data classes the agent's seal does not allow. */
// `requestText` is what a person or tool asked (the review scope); the credential-request rule reads only that, so
// ServiceNow's own rules ("Do NOT expose identifiers") never look like a request. Secrets and data classes are
// scanned in the whole content.
export function fastFindings(ctx: Ctx, content: string, policy: Pick<CompiledPolicy, 'prompt_tags' | 'forbidden_tags'>, model: Pick<CatalogueModel, 'code_approved'>, requestText = content): GuardianFinding[] {
  const findings: GuardianFinding[] = [];
  const found = scan(content);
  const secrets = found.filter((f) => f.tag === 'secrets');
  if (secrets.length) {
    ctx.dlp.push(...secrets.map((f) => ({ direction: 'in' as const, tag: f.tag, recogniser: f.recogniser, action: 'flag' })));
    findings.push({ category: 'secret_disclosure', kind: 'security', rule: 'SN-GUARD-SECRET', reason: 'the content contains a secret' });
  }
  if (requestsCredentials(requestText)) findings.push({ category: 'credential_disclosure_request', kind: 'security', rule: 'SN-GUARD-CREDENTIAL-REQUEST', reason: 'it asks for passwords or other credentials' });
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

/**
 * Temporary judge-tuning aid, off unless SIGNET_GUARDIAN_DEBUG_DIR is set, and only on a developer laptop
 * (devOverridesAllowed: SIGNET_ENV=dev, not Vercel, not production). For a flagged review it writes the submitted
 * content and the chunks the judges saw (secrets already masked) with each chunk's verdict to a local file, so false
 * blocks can be studied. Nothing goes to the ledger, which keeps only hashes.
 * Remove the variable and delete the folder when tuning is done.
 */
export function guardianDebugCapture(ctx: Ctx, content: string, findings: GuardianFinding[], dir = process.env.SIGNET_GUARDIAN_DEBUG_DIR): string | null {
  // Flagged reviews only: a guardian set to "All" receives every AI feature on the instance, including other
  // teams' agents, so clear traffic is not collected.
  if (!dir || !findings.length || !devOverridesAllowed()) return null;
  const scope = reviewScope(content);
  const chunks = guardianChunks(String(maskArgs(scope.text)));
  const safety = (ctx.extra.guardrail_classifier as { results?: { category: string }[] } | undefined)?.results ?? [];
  const attack = (ctx.extra.guardrail_attack as { labels?: string[] } | undefined)?.labels ?? [];
  const file = join(dir, `guardian-${findings.length ? 'flagged' : 'clear'}-${ctx.requestId}.json`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(file, JSON.stringify({
    request_id: ctx.requestId, captured_at: new Date().toISOString(), agent_id: ctx.claims?.agent_id ?? null,
    decision: findings.length ? 'flagged' : 'clear', findings, scope: { kind: scope.kind, fields: scope.fields },
    judged_chunks: chunks.map((text, index) => ({ index, safety: safety[index]?.category ?? null, attack: attack[index] ?? null, text })),
    submitted_content: String(maskArgs(content)),
  }, null, 2), { mode: 0o600 });
  console.warn(`[gateway] Guardian debug capture written to ${file} (SIGNET_GUARDIAN_DEBUG_DIR is set; remove it when tuning is done)`);
  return file;
}

/** Independent BYOG review; it returns a verdict and never forwards a model or tool operation. */
export async function handleServiceNowGuardian(headers: IncomingHttpHeaders, input: GuardianRequest, checks: GuardianChecks = LIVE_CHECKS): Promise<Done> {
  const ctx = newCtx('guardrail_check', 'servicenow://guardian', headers);
  try {
    const { findings, status, passthrough } = await inspect(ctx, headers, input, checks);
    const checked = guardianVerdict(findings, status, ctx.requestId);
    if (passthrough) {
      // Another agent's review: recorded under its own action type, so it never counts as this agent's reviews or blocks.
      ctx.actionType = 'guardrail_passthrough';
      ctx.extra.guardrail_review = checked.review;
      ctx.rules.push('SN-GUARD-NOT-GOVERNED');
      step(ctx, 9, 'pass', 'not governed by this agent');
      const result = await finish(ctx, null, checked);
      return result.status === 200 ? { ...result, body: { ...checked, request_id: ctx.requestId, record_id: result.recordId } } : result;
    }
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
    try { guardianDebugCapture(ctx, input.content, findings); } catch (error) { console.warn('[gateway] Guardian debug capture failed', (error as Error).message); }
    const result = await finish(ctx, null, checked);
    if (result.status !== 200) return result;
    return { ...result, body: { ...checked, request_id: ctx.requestId, record_id: result.recordId } };
  } catch (error) {
    if (error instanceof Halt) return finish(ctx, error, null);
    throw error;
  }
}

async function inspect(ctx: Ctx, headers: IncomingHttpHeaders, input: GuardianRequest, checks: GuardianChecks): Promise<{ findings: GuardianFinding[]; status: GuardianVerdict['review']['status']; passthrough?: true }> {
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
  const attribution = attributeReview(input.content, state.bundle?.guardian_agents?.[ctx.claims!.agent_id]);
  ctx.extra.guardrail_attribution = attribution;
  if (!attribution.governed) {
    step(ctx, 7, 'note', `not governed here (${attribution.reason}${attribution.agent_name ? `: ${attribution.agent_name}` : ''}); passed through and logged`);
    return { findings: [], status: 'complete', passthrough: true };
  }
  const model = state.bundle?.catalogue.find((c) => !c.upstream) ?? { code_approved: false };
  const scope = reviewScope(input.content);
  ctx.extra.guardrail_scope = { kind: scope.kind, fields: scope.fields, reviewed_bytes: Buffer.byteLength(scope.text, 'utf8') };
  const fast = fastFindings(ctx, input.content, policy, model, scope.text);
  if (fast.length) {
    step(ctx, 8, 'fail', `pattern rules: ${fast.map((f) => f.category).join(', ')}`);
    return { findings: fast, status: 'complete' };
  }
  const findings = await modelFindings(ctx, scope.text, cert.tier, checks);
  step(ctx, 8, findings.length ? 'fail' : 'pass', findings.length ? findings.map((f) => f.category).join(', ') : 'no findings');
  return { findings, status: findings.some((f) => f.rule === 'SN-GUARD-UNAVAILABLE') ? 'unavailable' : 'complete' };
}

import type { IncomingHttpHeaders } from 'node:http';
import {
  newId, verifyJws,
  type CertificateBody, type CompiledPolicy, type DetectorResult, type Outcome, type WorkloadClaims,
} from '@signet/core';
import { appendRecord } from './ledgerclient';
import * as limits from './limits';
import type { DlpEvent } from './policy';
import * as state from './state';

// Shared request context and steps 1-5 and 14 of the gateway pipeline (BP 5.2). Steps 6-13 differ for
// model calls (chat.ts) and tool calls (toolcall.ts). Every request, allowed or not, ends with a ledger
// record written before the agent gets an answer (RB-INV-15).

export const ENV_NAME = process.env.SIGNET_ENV ?? 'dev';
export const STEP_NAMES = ['', 'authenticate', 'resolve seal', 'kill and quarantine', 'seal validity', 'limits', 'normalise', 'manifest', 'DLP inbound', 'policy', 'human approval', 'credential injection', 'forward', 'DLP and guardrails outbound', 'log and score'];
const LADDER_LEVEL: Partial<Record<Outcome, number>> = { deny: 1, require_approval: 1, step_up: 2, throttle: 3, quarantine: 4, kill: 5 };

export interface Step {
  n: number;
  name: string;
  result: 'pass' | 'fail' | 'note';
  detail?: string;
  ms: number;
}

export interface Ctx {
  requestId: string;
  started: number;
  lastMark: number;
  actionType: 'llm_call' | 'tool_call';
  steps: Step[];
  rules: string[];
  reasons: string[];
  claims?: WorkloadClaims;
  cert?: CertificateBody;
  policy?: CompiledPolicy;
  sessionId: string;
  callerUserId: string | null;
  dlp: DlpEvent[];
  detectors: DetectorResult[];
  decision: Outcome;
  tokensIn: number;
  tokensOut: number;
  costUsd: number;
  upstreamMs: number;
  target: string;
  argsDigest?: string;
  promptHash?: string;
  responseHash?: string;
  approverGroups: string[];
  extra: Record<string, unknown>;
}

export class Halt extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly outcome: Outcome,
    readonly ledgerOutcome: 'blocked' | 'upstream_error' | 'timeout',
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export function newCtx(actionType: Ctx['actionType'], target: string, headers: IncomingHttpHeaders): Ctx {
  const now = performance.now();
  return {
    requestId: newId('req'), started: now, lastMark: now, actionType, steps: [], rules: [], reasons: [], sessionId: '',
    callerUserId: typeof headers['x-signet-user'] === 'string' ? headers['x-signet-user'] : null,
    dlp: [], detectors: [], decision: 'allow', tokensIn: 0, tokensOut: 0, costUsd: 0, upstreamMs: 0, target, approverGroups: [], extra: {},
  };
}

export function step(ctx: Ctx, n: number, result: Step['result'], detail?: string) {
  const now = performance.now();
  ctx.steps.push({ n, name: STEP_NAMES[n]!, result, detail, ms: Math.round((now - ctx.lastMark) * 100) / 100 });
  ctx.lastMark = now;
}

export function halt(ctx: Ctx, n: number, status: number, code: string, message: string, outcome: Outcome, rules: string[], ledgerOutcome: Halt['ledgerOutcome'] = 'blocked', extra: Record<string, unknown> = {}): never {
  step(ctx, n, 'fail', `${code}: ${message}`);
  ctx.rules.push(...rules);
  ctx.decision = outcome;
  throw new Halt(status, code, message, outcome, ledgerOutcome, extra);
}

// Automatic ladder action from a gateway rule (RB-INV-05: always cites the rule).
export async function ladder(ctx: Ctx, action: 'kill' | 'quarantine', ruleId: string, reason: string, evidence: Record<string, unknown> = {}) {
  const c = ctx.claims!;
  state.applyScope(`agent:${c.agent_id}`, { level: action === 'kill' ? 'killed' : 'quarantined' }); // effective on this node at once
  ctx.extra.ladder = { action, rule_id: ruleId };
  try {
    await state.internal('/internal/enforce', {
      method: 'POST',
      body: JSON.stringify({ agent_id: c.agent_id, action, rule_id: ruleId, reason, evidence: { request_id: ctx.requestId, ...evidence }, node_id: state.NODE_ID }),
    });
  } catch (e) {
    console.error(`[gateway] could not report ${action} of ${c.agent_id}: ${(e as Error).message}`);
  }
}

export async function recordOutOfManifest(ctx: Ctx, what: string, rules: string[]): Promise<never> {
  const n = limits.recordOutOfManifest(ctx.claims!.agent_id);
  if (n >= 3) {
    await ladder(ctx, 'kill', 'RB-KILL-04', `${n} out-of-manifest attempts in 10 minutes`, { last: what });
    halt(ctx, 7, 403, 'out_of_manifest', `${what}; ${n} out-of-manifest attempts in 10 minutes, the agent has been killed`, 'kill', [...rules, 'RB-KILL-04'], 'blocked', { attempts_in_window: n });
  }
  halt(ctx, 7, 403, 'out_of_manifest', what, 'deny', rules, 'blocked', { attempts_in_window: n });
}

// Steps 1-5: identity, seal, ladder state, validity, limits.
export function preflight(ctx: Ctx, headers: IncomingHttpHeaders) {
  // 1. Authenticate the workload token.
  const token = String(headers.authorization ?? '').replace(/^Bearer\s+/i, '');
  if (!token) halt(ctx, 1, 401, 'unauthenticated', 'a workload token is required', 'deny', ['BP-5.2-1']);
  let claims: WorkloadClaims;
  try {
    claims = verifyJws<WorkloadClaims>(token, state.tokenKeys, 'JWT').payload;
  } catch {
    halt(ctx, 1, 401, 'invalid_token', 'workload token signature is not valid', 'deny', ['BP-5.2-1']);
  }
  if (claims.exp * 1000 < Date.now()) halt(ctx, 1, 401, 'token_expired', 'workload token has expired; refresh it', 'deny', ['BP-5.2-1']);
  if (state.isRevoked(claims.jti)) halt(ctx, 1, 401, 'token_revoked', 'workload token has been revoked', 'deny', ['BP-5.2-1']);
  ctx.claims = claims;
  ctx.sessionId = typeof headers['x-signet-session'] === 'string' ? headers['x-signet-session'].slice(0, 80) : claims.jti;
  step(ctx, 1, 'pass', claims.sub);

  // 2. Resolve the seal and its compiled policy from the signed bundle.
  if (state.bundleExpired()) halt(ctx, 2, 503, 'policy_bundle_expired', 'no current policy bundle; failing closed', 'deny', ['BP-3']);
  const eff = state.effective(claims.agent_id, claims.ver, claims.ins);
  const cert = state.certs.get(claims.cert_id);
  const policy = state.policies.get(claims.cert_id);
  if ((!cert || !policy) && !eff.blocked) halt(ctx, 2, 403, 'no_active_seal', 'the seal in this token is not active', 'deny', ['RB-INV-01']);

  // 3. Kill and quarantine state (agent, version or instance).
  if (eff.blocked === 'killed') halt(ctx, 3, 403, 'agent_killed', 'this agent has been killed', 'deny', ['RB-INV-08']);
  if (eff.blocked === 'quarantined') halt(ctx, 3, 403, 'agent_quarantined', 'this agent is quarantined', 'deny', ['BP-5.4']);
  ctx.cert = cert!;
  ctx.policy = policy!;
  step(ctx, 2, 'pass', `${cert!.cert_id} ${cert!.version}`);
  step(ctx, 3, 'pass', eff.stepUp || eff.throttleFactor < 1 ? `step-up ${eff.stepUp}, throttle ${eff.throttleFactor}` : 'active');

  // 4. Seal validity window, identity match and environment.
  const now = Date.now();
  if (cert!.agent_id !== claims.agent_id) halt(ctx, 4, 403, 'seal_mismatch', 'token and seal name different agents', 'deny', ['RB-INV-01']);
  if (now < Date.parse(cert!.valid_from) || now > Date.parse(cert!.valid_to)) halt(ctx, 4, 403, 'seal_expired', 'the seal is outside its validity window', 'deny', ['RB-KILL-11', 'RB-BL-16']);
  if (!cert!.environments.includes(ENV_NAME)) halt(ctx, 4, 403, 'wrong_environment', `the seal does not cover environment ${ENV_NAME}`, 'deny', ['BP-5.2-4']);
  step(ctx, 4, 'pass', `valid to ${cert!.valid_to.slice(0, 10)}`);

  // 5. Rate, volume and cost limits; a throttle scales them down (ladder level 3).
  const rpm = cert!.limits.rpm * eff.throttleFactor;
  if (!limits.takeRequest(claims.agent_id, rpm)) halt(ctx, 5, 429, 'rate_limited', `over ${Math.floor(rpm)} requests per minute${eff.throttleFactor < 1 ? ' (throttled)' : ''}`, 'throttle', ['BP-5.2-5']);
  const used = limits.usage(claims.agent_id);
  if (used.tokens >= cert!.limits.tokens_per_day * eff.throttleFactor) halt(ctx, 5, 429, 'token_budget_exhausted', 'daily token limit reached', 'throttle', ['BP-5.2-5']);
  if (cert!.limits.usd_per_day > 0 && used.usd >= cert!.limits.usd_per_day * eff.throttleFactor) halt(ctx, 5, 429, 'cost_budget_exhausted', 'daily cost limit reached', 'throttle', ['BP-5.2-5']);
  step(ctx, 5, 'pass', `${used.tokens} tokens today`);
  return { claims, cert: cert!, policy: policy!, eff };
}

export interface Done {
  status: number;
  body: unknown;
  headers: Record<string, string>;
  recordId: string | null;
}

// 14. Log: the record is written before any answer leaves the gateway (RB-INV-15).
export async function finish(ctx: Ctx, err: Halt | null, okBody: unknown): Promise<Done> {
  step(ctx, 14, 'pass');
  const total = performance.now() - ctx.started;
  const counts: Record<string, number> = {};
  for (const d of ctx.dlp) counts[`${d.direction}:${d.tag}:${d.action}`] = (counts[`${d.direction}:${d.tag}:${d.action}`] ?? 0) + 1;
  const tags = (dir: 'in' | 'out') => [...new Set(ctx.dlp.filter((d) => d.direction === dir).map((d) => d.tag))];
  const data = {
    request_id: ctx.requestId,
    node_id: state.NODE_ID,
    bundle_version: state.bundle?.version ?? null,
    action_type: ctx.actionType,
    target: ctx.target,
    agent_version: ctx.cert?.version ?? ctx.claims?.ver ?? null,
    instance_id: ctx.claims?.ins ?? null,
    session_id: ctx.sessionId || null,
    caller_user_id: ctx.callerUserId,
    args_digest: ctx.argsDigest ?? null,
    prompt_hash: ctx.promptHash ?? null,
    response_hash: ctx.responseHash ?? null,
    data_classes_in: tags('in'),
    data_classes_out: tags('out'),
    dlp_actions: counts,
    policy_decision: ctx.decision,
    policy_rule_ids: [...new Set(ctx.rules)],
    approver_groups: ctx.approverGroups,
    reasons: ctx.reasons,
    detectors: ctx.detectors,
    ladder_level: LADDER_LEVEL[ctx.decision] ?? 0,
    tokens_in: ctx.tokensIn,
    tokens_out: ctx.tokensOut,
    cost_usd: ctx.costUsd,
    latency_ms_gateway: Math.round((total - ctx.upstreamMs) * 10) / 10,
    latency_ms_upstream: ctx.upstreamMs,
    outcome: err ? err.ledgerOutcome : 'success',
    error_code: err?.code ?? null,
    steps: ctx.steps,
    ...ctx.extra,
  };
  let recordId: string;
  try {
    const record = await appendRecord({ kind: 'transaction', agent_id: ctx.claims?.agent_id ?? null, cert_id: ctx.cert?.cert_id ?? null, data });
    recordId = record.record_id;
  } catch (e) {
    // No evidence, no answer: fail closed rather than return an unlogged response.
    console.error(`[gateway] ledger write failed: ${(e as Error).message}`);
    return errorDone(ctx, new Halt(503, 'ledger_unavailable', 'the evidence ledger is unreachable; request not completed', 'deny', 'blocked'), null);
  }
  const headers: Record<string, string> = {
    'x-signet-request-id': ctx.requestId,
    'x-signet-record-id': recordId,
    'x-signet-decision': err ? err.outcome : ctx.decision,
    'x-signet-gateway-ms': String(data.latency_ms_gateway),
  };
  if (err) return errorDone(ctx, err, recordId, headers);
  return { status: 200, body: okBody, headers, recordId };
}

export function errorDone(ctx: Ctx, err: Halt, recordId: string | null, headers: Record<string, string> = {}): Done {
  if (typeof err.extra.retry_after === 'number') headers['retry-after'] = String(err.extra.retry_after);
  return {
    status: err.status,
    recordId,
    headers,
    body: {
      error: {
        type: 'signet_policy',
        code: err.code,
        message: err.message,
        decision: err.outcome,
        rule_ids: [...new Set(ctx.rules)],
        request_id: ctx.requestId,
        record_id: recordId,
        ...err.extra,
      },
    },
  };
}

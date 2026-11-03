import type { IncomingHttpHeaders } from 'node:http';
import {
  TOKEN_AUDIENCE, newId, rewrite, scan, sha256, tokenIssuer, verifyJws,
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
  // Deploy-stage rollout (BP 6 Stage 6): in shadow, non-fatal decisions are logged as would_block.
  shadow: boolean;
  rollout: string | null;
  wouldBlock: { step: number; rules: string[]; reason: string }[];
}

export class Halt extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly outcome: Outcome,
    readonly ledgerOutcome: 'blocked' | 'upstream_error' | 'timeout' | 'pending',
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
    shadow: false, rollout: null, wouldBlock: [],
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

// In shadow mode only kill, circuit-breaker and secrets-exfiltration blocks are enforced (RB-INV-18);
// every other refusal is recorded as would_block and the request continues.
export function wouldBlock(ctx: Ctx, n: number, rules: string[], reason: string): boolean {
  if (!ctx.shadow) return false;
  ctx.wouldBlock.push({ step: n, rules, reason });
  step(ctx, n, 'note', `would_block (${ctx.rollout}): ${reason}`);
  return true;
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

export async function recordOutOfManifest(ctx: Ctx, what: string, rules: string[], shadowOk = false): Promise<void> {
  const n = limits.recordOutOfManifest(ctx.claims!.agent_id);
  if (n >= 3) {
    await ladder(ctx, 'kill', 'RB-KILL-04', `${n} out-of-manifest attempts in 10 minutes`, { last: what });
    halt(ctx, 7, 403, 'out_of_manifest', `${what}; ${n} out-of-manifest attempts in 10 minutes, the agent has been killed`, 'kill', [...rules, 'RB-KILL-04'], 'blocked', { attempts_in_window: n });
  }
  // The repeat-violation kill is enforced even in shadow; a single attempt is only would_block there.
  if (shadowOk && wouldBlock(ctx, 7, rules, what)) return;
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
  // The signature proves who the agent is, so even a refused stale token is attributed to it in the ledger.
  if (state.agentErased(claims.agent_id)) halt(ctx, 1, 403, 'agent_removed', 'this agent was permanently removed from Signet', 'deny', ['BP-5.2-1']);
  ctx.claims = claims;
  const tenant = state.bundle?.tenant;
  if (claims.aud !== TOKEN_AUDIENCE || !tenant || claims.tenant !== tenant || claims.iss !== tokenIssuer(tenant)) {
    halt(ctx, 1, 401, 'invalid_token', 'workload token was not issued for this gateway', 'deny', ['BP-5.2-1']);
  }
  if (claims.exp * 1000 < Date.now()) halt(ctx, 1, 401, 'token_expired', 'workload token has expired; refresh it', 'deny', ['BP-5.2-1']);
  if (state.isRevoked(claims.jti)) halt(ctx, 1, 401, 'token_revoked', 'workload token has been revoked', 'deny', ['BP-5.2-1']);
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
  const rollout = state.rollouts.get(cert!.cert_id);
  if (rollout && rollout.mode !== 'enforce') {
    // Canary: a stable share of sessions is fully enforced, the rest run in shadow.
    const bucket = parseInt(sha256(ctx.sessionId).slice(0, 8), 16) % 100;
    ctx.shadow = rollout.mode === 'shadow' || bucket >= rollout.canary_pct;
    ctx.rollout = rollout.mode === 'shadow' ? 'shadow' : `canary:${ctx.shadow ? 'shadow' : 'enforced'}`;
  }
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
    auth_kind: ctx.claims?.kind ?? null, // bootstrap (self-hosted runtime) or client_credentials (vendor platform)
    session_id: ctx.sessionId || null,
    caller_user_id: ctx.callerUserId,
    args_digest: ctx.argsDigest ?? null,
    rollout: ctx.rollout,
    prompt_hash: ctx.promptHash ?? null,
    response_hash: ctx.responseHash ?? null,
    data_classes_in: tags('in'),
    data_classes_out: tags('out'),
    dlp_actions: counts,
    policy_decision: !err && ctx.wouldBlock.length ? 'would_block' : ctx.decision,
    shadow_rule_ids: ctx.wouldBlock.length ? [...new Set(ctx.wouldBlock.flatMap((w) => w.rules))] : undefined,
    would_block: ctx.wouldBlock.length ? ctx.wouldBlock : undefined,
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
    'x-signet-decision': err ? err.outcome : data.policy_decision,
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

// Session state (taint, pending detector verdicts) belongs to one agent's session: another agent
// reusing the same session id must not inherit it.
export const sessionKey = (ctx: Ctx) => `${ctx.claims?.agent_id ?? '-'}:${ctx.sessionId}`;

// Arguments as shown to an approver: sensitive values replaced by their data class (BP 7.4).
export function maskArgs(v: unknown): unknown {
  if (typeof v === 'string') return rewrite(v, scan(v), (f) => `[${f.tag}]`);
  if (Array.isArray(v)) return v.map(maskArgs);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, maskArgs(x)]));
  return v;
}

// 10. Human in the loop (BP 5.2 step 10, 7.4). The gateway parks the action and waits for a person, up
// to the tenant's hold time. With x-signet-hitl: async the agent gets 202 and resubmits the same call
// with x-signet-approval: <approval_id>, which is single-use. A timeout is a rejection (RB-INV-11).
export async function humanApproval(ctx: Ctx, headers: IncomingHttpHeaders, input: { actionKey: string; args: unknown; rules: string[]; groups: string[] }) {
  const c = ctx.claims!;
  const resubmitted = headers['x-signet-approval'];
  if (typeof resubmitted === 'string') {
    let approvers: string[] = [];
    try {
      const r = await state.internal<{ approvers: string[] }>(`/internal/hitl/${encodeURIComponent(resubmitted)}/consume`, { method: 'POST', body: JSON.stringify({ agent_id: c.agent_id, action_key: input.actionKey, session_id: ctx.sessionId }) });
      approvers = r.approvers;
    } catch (e) {
      halt(ctx, 10, 403, 'approval_invalid', `approval ${resubmitted} cannot be used: ${(e as Error).message}`, 'deny', input.rules);
    }
    ctx.extra.approval_id = resubmitted;
    ctx.extra.approved_by = approvers;
    ctx.decision = 'allow';
    step(ctx, 10, 'pass', `approved by ${approvers.join(', ')} (${resubmitted})`);
    return;
  }
  const opened = await state.internal<{ status: string; approval_id: string; expires_at?: string; grant?: boolean }>('/internal/hitl', {
    method: 'POST',
    body: JSON.stringify({ agent_id: c.agent_id, cert_id: c.cert_id, session_id: ctx.sessionId, action_key: input.actionKey, args_masked: input.args, rule_ids: input.rules, approver_groups: input.groups, reasons: ctx.reasons, request_id: ctx.requestId, node_id: state.NODE_ID, caller_user_id: ctx.callerUserId }),
  });
  ctx.extra.approval_id = opened.approval_id;
  if (opened.status === 'approved') {
    ctx.decision = 'allow';
    step(ctx, 10, 'pass', `session grant from ${opened.approval_id}`);
    return;
  }
  if (headers['x-signet-hitl'] === 'async') {
    halt(ctx, 10, 202, 'approval_pending', `waiting for ${input.groups.join(', ') || 'an approver'}; resubmit with x-signet-approval: ${opened.approval_id}`, 'require_approval', input.rules, 'pending', { approval_id: opened.approval_id, expires_at: opened.expires_at });
  }
  const hold = new AbortController();
  const untrack = state.track(c.agent_id, c.ver, c.ins, hold);
  let out: Awaited<ReturnType<typeof waitForDecision>>;
  try {
    out = await waitForDecision(opened.approval_id, Date.parse(opened.expires_at ?? '') || Date.now() + state.hitlWaitMs(), hold.signal);
  } catch (error) {
    if (hold.signal.aborted) halt(ctx, 10, 403, 'agent_stopped', 'approval wait was cancelled because this agent was stopped', 'deny', ['BP-5.4']);
    throw error;
  } finally { untrack(); }
  if (out.status === 'approved') {
    ctx.decision = 'allow';
    ctx.extra.approved_by = out.approvers;
    step(ctx, 10, 'pass', `approved by ${out.approvers.join(', ')} (${opened.approval_id})`);
    return;
  }
  if (out.status === 'expired' || out.status === 'pending') halt(ctx, 10, 403, 'approval_timeout', 'no decision within the hold time; rejected as on timeout', 'require_approval', [...input.rules, 'RB-INV-11']);
  halt(ctx, 10, 403, 'approval_rejected', `rejected by ${out.approvers.join(', ') || 'an approver'}`, out.decision === 'reject_quarantine' ? 'quarantine' : 'deny', input.rules);
}

const waiters = new Map<string, () => void>();
export const hitlDecided = (approvalId: string) => waiters.get(approvalId)?.();

async function waitForDecision(id: string, until: number, signal: AbortSignal): Promise<{ status: string; decision: string | null; approvers: string[] }> {
  const fetchStatus = () => state.internal<{ status: string; outcome: string | null; approvers: { approver: string; decision: string }[] }>(`/internal/hitl/${encodeURIComponent(id)}`);
  for (;;) {
    signal.throwIfAborted();
    const s = await fetchStatus().catch(() => null);
    if (s && s.status !== 'pending') return { status: s.status, decision: s.outcome, approvers: s.approvers.map((a) => a.approver) };
    if (Date.now() > until + 3_000) return { status: s?.status ?? 'pending', decision: null, approvers: [] };
    // Woken by the decision push from the control plane; polls every 2 s as a fallback.
    await new Promise<void>((r) => {
      const t = setTimeout(r, 2_000);
      waiters.set(id, () => (clearTimeout(t), r()));
    });
    waiters.delete(id);
  }
}

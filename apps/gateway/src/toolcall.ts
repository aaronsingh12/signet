import type { IncomingHttpHeaders } from 'node:http';
import { canonicalize, combine, sha256, type Outcome, type ToolAlias } from '@signet/core';
import { type Ctx, type Done, Halt, finish, halt, ladder, newCtx, preflight, recordOutOfManifest, step } from './ctx';
import { detectInjection, notDeployed } from './detectors';
import { evaluate } from './engine';
import { appendRecord } from './ledgerclient';
import * as limits from './limits';
import { cleanJson, inspectArgs, stringsOf } from './policy';
import * as state from './state';
import { settle, taint, taintOf, trackPending } from './taint';

// Tool calls through the MCP proxy and the HTTP tool proxy (BP 5.1, 5.2 steps 6-13 for tool_call).
// The agent names an alias; the real address and credential are added here (keyless agents, E32).

export interface ToolRequest {
  kind: 'mcp' | 'http';
  alias: string;
  action: string;
  args: Record<string, unknown>;
  // How to reach the tool once the call is allowed; returns the tool's result.
  forward: (tool: ToolAlias, credential: string | null, signal: AbortSignal) => Promise<unknown>;
}

const TOOL_TIMEOUT_MS = 30_000;

export async function handleTool(headers: IncomingHttpHeaders, req: ToolRequest): Promise<Done> {
  const ctx = newCtx('tool_call', `${req.kind}://${req.alias}.${req.action}`, headers);
  try {
    return await finish(ctx, null, await run(ctx, headers, req));
  } catch (e) {
    if (e instanceof Halt) return finish(ctx, e, null);
    throw e;
  }
}

async function run(ctx: Ctx, headers: IncomingHttpHeaders, req: ToolRequest): Promise<unknown> {
  const { claims, cert, policy, eff } = preflight(ctx, headers);

  // 6. Normalise.
  const key = ctx.target;
  ctx.argsDigest = sha256(canonicalize(req.args ?? {}));
  if (!req.args || typeof req.args !== 'object' || Array.isArray(req.args)) halt(ctx, 6, 400, 'unparseable_request', 'tool arguments must be a JSON object', 'deny', ['RB-PREC-08']);
  step(ctx, 6, 'pass', `tool_call ${key}`);

  // 7. Manifest: the alias must exist and the action must be in the seal (default deny).
  const tool = state.tools.get(req.alias);
  if (!tool || tool.kind !== req.kind) await recordOutOfManifest(ctx, `tool ${req.kind}://${req.alias} is not registered`, ['BP-5.1']);
  const action = policy.actions[key];
  if (!action) await recordOutOfManifest(ctx, `${key} is not in this agent's seal`, ['RB-PREC-01', 'SGC-TOOL-004']);
  step(ctx, 7, 'pass', `${action!.impact}`);

  // Hijack (RB-KILL-01): a privileged or critical attempt after DET-INJ scored High on a tool response
  // in this session. The deterministic part is the attempt itself; the signal is the taint. A
  // high-impact action first waits for any verdict still being computed for this session.
  if (action!.impact === 'privileged' || action!.impact === 'critical') {
    const settled = await settle(ctx.sessionId, 5_000);
    if (!settled) ctx.reasons.push('a DET-INJ verdict for this session was still pending after 5 s');
  }
  const t = taintOf(ctx.sessionId);
  if (t?.band === 'high' && (action!.impact === 'privileged' || action!.impact === 'critical')) {
    const act = cert.tier === 'T1' || cert.tier === 'T2' ? 'kill' : 'quarantine';
    await ladder(ctx, act, 'RB-KILL-01', `privileged ${key} attempted after injection in a tool response`, { taint_source: t.source });
    halt(ctx, 7, 403, 'hijack_detected', `privileged action after injected content in this session; agent ${act === 'kill' ? 'killed' : 'quarantined'}`, act, ['RB-KILL-01']);
  }

  // 8. DLP on the arguments: a tool receives only the data classes in its scope.
  const di = inspectArgs(req.args, action, policy);
  ctx.dlp.push(...di.events);
  if (di.exfiltration) {
    await ladder(ctx, 'kill', 'RB-KILL-02', `${di.exfiltration.tag} sent to ${key}, outside the tool's data scope`, { tag: di.exfiltration.tag });
    halt(ctx, 8, 403, 'data_exfiltration', `${di.exfiltration.tag} data may not be sent to ${key}; the agent has been killed`, 'kill', [di.exfiltration.rule, 'RB-KILL-02']);
  }
  if (di.blocked) halt(ctx, 8, 403, 'data_blocked', `${di.blocked.tag} data is outside the data scope of ${key}`, 'deny', [di.blocked.rule]);
  step(ctx, 8, 'pass', di.events.length ? `${di.events.length} finding(s) within scope` : 'no sensitive data');

  // 9. Policy engine: manifest constraints, privileged-action rules, taint, step-up, seal HITL rules.
  const r = evaluate({
    kind: 'tool',
    policy,
    action: { key, args: req.args },
    context: { tainted: !!t, step_up: eff.stepUp, tool_calls_in_session: limits.toolCallsIn(ctx.sessionId), tool_calls_limit: cert.limits.tool_calls_per_session ?? null },
  });
  ctx.detectors = notDeployed();
  let outcome = r.decision as Outcome;
  if (di.approval && outcome !== 'deny') outcome = 'require_approval';
  const combined = combine(outcome, [], cert.tier); // detectors score tool responses (step 13), not arguments
  ctx.decision = combined.outcome;
  ctx.rules.push(...r.rule_ids, ...(di.approval ? [di.approval.rule] : []));
  ctx.approverGroups = r.approver_groups;
  if (r.decision === 'deny') {
    if (r.rule_ids.includes('BP-4.3-constraint')) ctx.reasons.push(...r.details);
    halt(ctx, 9, 403, 'policy_denied', r.details.join('; ') || 'denied by policy', 'deny', r.rule_ids);
  }
  step(ctx, 9, 'pass', `${r.decision}${r.rule_ids.length ? ` (${r.rule_ids.join(', ')})` : ''}`);

  // 10. Human in the loop: rejected until the approvals engine ships (Phase 2), as on timeout (RB-INV-11).
  if (combined.outcome === 'require_approval') {
    halt(ctx, 10, 403, 'approval_required', `${key} needs approval by ${r.approver_groups.join(', ') || 'an approver'}; the approvals engine is not deployed yet, so it is rejected as on timeout`, 'require_approval', ['RB-INV-11']);
  }
  step(ctx, 10, 'pass', 'not required');

  // 11. Credential injection from the Secrets Broker; the agent never sees it.
  let credential: string | null = null;
  if (tool!.secret_id) {
    try {
      credential = await state.secret(tool!.secret_id);
    } catch {
      halt(ctx, 11, 503, 'credential_unavailable', 'the brokered credential for this tool is unavailable', 'deny', ['BP-5.2-11']);
    }
  }
  step(ctx, 11, 'pass', credential ? `brokered credential ${tool!.secret_id} attached` : 'tool needs no credential');

  // 12. Forward. A kill cuts the call before or during forwarding.
  limits.countToolCall(ctx.sessionId);
  const ctrl = new AbortController();
  const untrack = state.track(claims.agent_id, claims.ver, claims.ins, ctrl);
  const t0 = performance.now();
  let result: unknown;
  try {
    result = await req.forward(tool!, credential, AbortSignal.any([ctrl.signal, AbortSignal.timeout(TOOL_TIMEOUT_MS)]));
  } catch (e) {
    if (ctrl.signal.aborted) halt(ctx, 12, 403, 'agent_stopped', 'call cut in flight by enforcement', 'kill', ['BP-5.4']);
    halt(ctx, 12, 502, 'tool_unavailable', `tool error: ${(e as Error).message}`, ctx.decision, ['BP-5.2-12'], 'upstream_error');
  } finally {
    untrack();
    ctx.upstreamMs = Math.round(performance.now() - t0);
    ctx.lastMark = performance.now();
  }
  step(ctx, 12, 'pass', `${req.kind} ${req.alias} in ${ctx.upstreamMs} ms`);

  // 13. Outbound: DLP now; DET-INJ on the tool response (indirect injection, OWASP LLM01) runs right
  //     after the response returns. Its verdict taints the session for the agent's next actions and
  //     is written to a linked ledger record (RB-DET-04).
  const text = stringsOf(result);
  const cfg = state.detectors.get('DET-INJ');
  if (cfg && cfg.mode !== 'off' && text.trim()) {
    const requestId = ctx.requestId;
    const scoring = detectInjection(text, cert.tier, 'tool').then(async (inj) => {
      let applied: string | null = null;
      if (inj.status === 'ok' && inj.band && inj.band !== 'low') {
        taint(ctx.sessionId, inj.band, `${key} response (${requestId})`);
        applied = `session tainted ${inj.band} for 60 minutes (RB-BL-12)`;
      }
      await appendRecord({ kind: 'transaction', agent_id: claims.agent_id, cert_id: cert.cert_id, data: { action_type: 'detector_score', request_id: requestId, target: key, session_id: ctx.sessionId, node_id: state.NODE_ID, detector: inj, applied, policy_decision: applied ? 'taint' : inj.status === 'shadow' ? 'would_taint' : 'none' } }).catch(() => {});
    });
    trackPending(ctx.sessionId, scoring);
    ctx.detectors = [{ id: 'DET-INJ', version: cfg.version, status: 'pending' }, ...notDeployed()];
  } else ctx.detectors = [{ id: 'DET-INJ', version: cfg?.version ?? 'unknown', status: 'unavailable' }, ...notDeployed()];
  const cleaned = cleanJson(result, ctx.dlp);
  ctx.responseHash = sha256(canonicalize(cleaned ?? null));
  if (ctx.decision === 'allow' && ctx.dlp.some((d) => d.direction === 'out' && d.action !== 'allow')) ctx.decision = 'allow_with_obligations';
  step(ctx, 13, 'pass', `DLP ${ctx.dlp.filter((d) => d.direction === 'out').length} finding(s); DET-INJ ${ctx.detectors[0]!.status}`);
  return cleaned;
}

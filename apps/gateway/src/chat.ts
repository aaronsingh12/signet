import type { IncomingHttpHeaders } from 'node:http';
import { canonicalize, combine, sha256, strictest, type Outcome } from '@signet/core';
import { type Ctx, type Done, Halt, finish, halt, ladder, newCtx, preflight, recordOutOfManifest, step } from './ctx';
import { detectInjection, notDeployed } from './detectors';
import { evaluate } from './engine';
import * as limits from './limits';
import * as outage from './outage';
import { cleanResponseText, inspectPrompt, newTextOf, textOf } from './policy';
import { chatCompletion, credentialAttached, UpstreamRejected, UpstreamUnavailable, type ChatResponse } from './provider';
import * as state from './state';
import { taint, trackPending } from './taint';
import { detokenise, tokenise } from './vault';

// Model calls to the one cloud LLM (BP 5.2 steps 6-13 for llm_call).

const OUTAGE_RETRY_AFTER_S = 30;
type Msg = { role: string; content?: unknown };

export async function handleChat(headers: IncomingHttpHeaders, body: Record<string, unknown> | undefined, foreignProvider?: string): Promise<Done> {
  const ctx = newCtx('llm_call', String(body?.model ?? 'unknown'), headers);
  try {
    return await finish(ctx, null, await run(ctx, headers, body ?? {}, foreignProvider));
  } catch (e) {
    if (e instanceof Halt) return finish(ctx, e, null);
    throw e;
  }
}

async function run(ctx: Ctx, headers: IncomingHttpHeaders, body: Record<string, unknown>, foreignProvider?: string): Promise<ChatResponse> {
  const { claims, cert, policy } = preflight(ctx, headers);

  // Only the cloud LLM may be called (RB-INV-19); other providers' API shapes count as out-of-manifest.
  if (foreignProvider) {
    ctx.target = `${foreignProvider}/${ctx.target}`;
    await recordOutOfManifest(ctx, `provider ${foreignProvider} is not the tenant's cloud LLM`, ['RB-INV-19']);
  }

  // 6. Normalise.
  const messages = body.messages as Msg[];
  if (typeof body.model !== 'string' || !Array.isArray(messages) || messages.length === 0) {
    halt(ctx, 6, 400, 'unparseable_request', 'expected an OpenAI-style chat request with model and messages', 'deny', ['RB-PREC-08']);
  }
  const estTokens = Math.ceil(textOf(messages).length / 4);
  step(ctx, 6, 'pass', `llm_call ${body.model}, ${messages.length} messages, ~${estTokens} tokens`);

  // 7. Manifest: the model must be in the tenant catalogue and in the seal.
  const model = state.bundle!.catalogue.find((c) => c.model === body.model);
  const grant = cert.models.find((g) => new RegExp(`^${g.model.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`).test(String(body.model)));
  if (!model || !grant) await recordOutOfManifest(ctx, `model ${body.model} is not in this agent's seal`, [model ? 'RB-PREC-01' : 'RB-INV-19']);
  const upstreamBody: Record<string, unknown> = { ...body };
  delete upstreamBody.stream;
  let capped = false;
  if (grant!.max_tokens && (typeof body.max_tokens !== 'number' || body.max_tokens > grant!.max_tokens)) {
    upstreamBody.max_tokens = grant!.max_tokens;
    capped = true;
  }
  step(ctx, 7, 'pass', `${model!.model} (${model!.family})`);

  // 8. DLP inbound on prompt, context and tool results; detectors on new text only (RB-DET-05).
  const inspection = inspectPrompt(messages, policy, model!, (value, tag) => tokenise(value, tag, claims.agent_id, ctx.sessionId));
  ctx.dlp.push(...inspection.events);
  ctx.promptHash = sha256(canonicalize(inspection.messages));
  if (inspection.exfiltration) {
    const x = inspection.exfiltration;
    await ladder(ctx, 'kill', 'RB-KILL-02', `${x.tag} sent towards the cloud LLM, which this seal does not allow`, { tag: x.tag, recogniser: x.recogniser });
    halt(ctx, 8, 403, 'data_exfiltration', `${x.tag} data may not be sent to the model; the agent has been killed`, 'kill', [x.rule, 'RB-KILL-02']);
  }
  if (inspection.blocked) halt(ctx, 8, 403, 'data_blocked', `${inspection.blocked.tag} data may not be sent to the model`, 'deny', [inspection.blocked.rule]);
  upstreamBody.messages = inspection.messages;
  // DET-INJ scores the new text while the model call is in flight; its verdict is applied before the
  // answer is released (see after step 12). Tool results inside the conversation can taint the session.
  const fresh = newTextOf(messages);
  const injCfg = state.detectors.get('DET-INJ');
  const scoring = injCfg && injCfg.mode !== 'off' ? Promise.all([detectInjection(fresh.user, cert.tier, 'prompt'), fresh.tool ? detectInjection(fresh.tool, cert.tier, 'tool') : null]) : null;
  if (scoring) trackPending(ctx.sessionId, scoring);
  ctx.detectors = [{ id: 'DET-INJ', version: injCfg?.version ?? 'unknown', status: scoring ? 'pending' : 'unavailable' }, ...notDeployed()];
  step(ctx, 8, 'pass', `${inspection.tokenised ? `${inspection.tokenised} value(s) tokenised` : 'no sensitive data'}; DET-INJ ${scoring ? 'scoring in parallel' : 'off'}`);

  // 9. Policy: the Tier 0 rules (policy engine) combined with the detectors; stricter wins (DA 2).
  const r = evaluate({
    kind: 'llm',
    policy,
    action: { key: 'llm', est_input_tokens: estTokens, est_cost_usd: (estTokens * model!.price_per_1k_usd.in) / 1000 },
    context: { dlp_tokenised: inspection.tokenised, max_tokens_capped: capped },
  });
  const combined = combine(r.decision as Outcome, ctx.detectors, cert.tier);
  ctx.decision = combined.outcome;
  ctx.rules.push(...r.rule_ids);
  ctx.reasons.push(...r.details, ...combined.reasons, ...r.obligations.map((o) => `obligation: ${o}`));
  if (combined.outcome === 'deny') halt(ctx, 9, 403, 'policy_denied', r.details.join('; ') || 'denied by policy', 'deny', r.rule_ids);
  step(ctx, 9, 'pass', `${r.decision} -> ${combined.outcome}`);

  // 10. Human in the loop. The approvals engine ships in Phase 2; until then a hold is rejected,
  //     which is what a timeout does (RB-INV-11).
  if (combined.outcome === 'require_approval' || combined.outcome === 'quarantine') {
    if (combined.outcome === 'quarantine') await ladder(ctx, 'quarantine', 'DA-4', combined.reasons.join('; '));
    ctx.approverGroups = r.approver_groups;
    halt(ctx, 10, 403, 'approval_required', 'this action needs human approval and the approvals engine is not deployed yet; rejected as on timeout', strictest(combined.outcome), ['RB-INV-11', ...(combined.reasons.some((x) => x.includes('RB-INV-06')) ? ['RB-INV-06'] : [])]);
  }
  step(ctx, 10, 'pass', 'not required');

  // 11. Credential injection happens inside the provider adapter.
  step(ctx, 11, 'pass', credentialAttached() ? 'brokered credential attached' : 'no provider credential configured');

  // 12. Forward to the cloud LLM. A kill cuts the call mid-flight.
  const ctrl = new AbortController();
  const untrack = state.track(claims.agent_id, claims.ver, claims.ins, ctrl);
  const t0 = performance.now();
  let resp: ChatResponse;
  try {
    resp = await chatCompletion({ ...upstreamBody, model: model!.model }, ctrl.signal);
    outage.record(claims.agent_id, true);
  } catch (e) {
    if (e instanceof UpstreamUnavailable) {
      outage.record(claims.agent_id, false);
      ctx.extra.provider_outage_declared = outage.isDeclared();
      halt(ctx, 12, 503, 'upstream_unavailable', 'the cloud LLM is unavailable; retry later', ctx.decision, ['RB-PROV-05'], 'upstream_error', { retry_after: OUTAGE_RETRY_AFTER_S });
    }
    if (e instanceof UpstreamRejected) halt(ctx, 12, 400, 'upstream_rejected', e.body.slice(0, 500), ctx.decision, ['BP-5.2-12'], 'upstream_error');
    if (ctrl.signal.aborted) halt(ctx, 12, 403, `agent_${state.effective(claims.agent_id, claims.ver, claims.ins).blocked ?? 'stopped'}`, 'call cut in flight by enforcement', 'kill', ['BP-5.4']);
    throw e;
  } finally {
    untrack();
    ctx.upstreamMs = Math.round(performance.now() - t0);
    ctx.lastMark = performance.now();
  }
  if (!String(resp.model ?? '').startsWith(model!.upstream_model)) {
    halt(ctx, 12, 502, 'model_family_drift', `provider answered with ${resp.model}, expected ${model!.upstream_model}`, 'deny', ['RB-BL-02']);
  }
  step(ctx, 12, 'pass', `${resp.model} in ${ctx.upstreamMs} ms`);

  // Detector verdict, applied before anything reaches the agent (DA 4 decision matrix; stricter wins).
  if (scoring) {
    const [injUser, injTool] = await scoring;
    ctx.detectors = [injUser, ...(injTool ? [{ ...injTool, id: 'DET-INJ.tool' }] : []), ...notDeployed()];
    if (injTool?.status === 'ok' && injTool.band && injTool.band !== 'low') {
      taint(ctx.sessionId, injTool.band, `tool result in llm_call ${ctx.requestId}`);
      ctx.reasons.push(`DET-INJ ${injTool.band} on tool content in the conversation: session tainted (RB-BL-12)`);
    }
    const high = cert.tier === 'T1' || cert.tier === 'T2';
    if (injUser.status === 'ok' && injUser.band === 'high') {
      if (high) await ladder(ctx, 'quarantine', 'DA-4', `DET-INJ high (${injUser.score}) on the prompt`, { score: injUser.score });
      halt(ctx, 13, 403, 'response_withheld', `prompt injection detected (DET-INJ ${injUser.score}); the answer is withheld${high ? ' and the agent quarantined' : ' and needs approval'}`, high ? 'quarantine' : 'require_approval', ['DA-4', ...(high ? [] : ['RB-INV-11'])]);
    }
    if (injUser.status === 'ok' && injUser.band === 'elevated') {
      if (high) halt(ctx, 13, 403, 'response_withheld', `DET-INJ elevated (${injUser.score}); the answer needs approval and is withheld`, 'require_approval', ['DA-4', 'RB-INV-11']);
      ctx.reasons.push(`DET-INJ elevated (${injUser.score}) on the prompt (DA 4: step-up)`);
      ctx.decision = strictest(ctx.decision, 'step_up');
    }
  }

  // 13. DLP outbound: restore tokens for this caller, redact secrets, mask cards.
  const restore = (s: string) => detokenise(s, claims.agent_id, ctx.sessionId).text;
  const allowedActions = new Set(Object.keys(policy.actions).map((k) => k.split('.').pop()));
  for (const choice of resp.choices ?? []) {
    const msg = choice.message;
    if (typeof msg.content === 'string') msg.content = cleanResponseText(msg.content, restore, ctx.dlp);
    if (typeof msg.reasoning === 'string') msg.reasoning = cleanResponseText(msg.reasoning, restore, ctx.dlp);
    for (const tc of msg.tool_calls ?? []) tc.function.arguments = cleanResponseText(tc.function.arguments, restore, ctx.dlp);
    const unknown = (msg.tool_calls ?? []).map((tc) => tc.function.name).filter((n) => !allowedActions.has(n));
    if (unknown.length) ctx.reasons.push(`model proposed tools outside the seal: ${unknown.join(', ')} (the tool proxy will refuse them)`);
  }
  ctx.responseHash = sha256(canonicalize(resp.choices ?? []));
  const outActions = ctx.dlp.filter((d) => d.direction === 'out' && d.action !== 'allow').length;
  step(ctx, 13, 'pass', outActions ? `${outActions} value(s) redacted or masked` : 'clean');

  ctx.tokensIn = resp.usage?.prompt_tokens ?? estTokens;
  ctx.tokensOut = resp.usage?.completion_tokens ?? 0;
  ctx.costUsd = (ctx.tokensIn * model!.price_per_1k_usd.in + ctx.tokensOut * model!.price_per_1k_usd.out) / 1000;
  limits.addUsage(claims.agent_id, ctx.tokensIn + ctx.tokensOut, ctx.costUsd);
  return resp;
}

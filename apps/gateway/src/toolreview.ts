import type { IncomingHttpHeaders } from 'node:http';
import type { CompiledPolicy } from '@signet/core';
import { type Ctx, halt, humanApproval, ladder, maskArgs, sessionKey, step, wouldBlock } from './ctx';
import { evaluate } from './engine';
import * as limits from './limits';
import { inspectArgs } from './policy';
import type { ChatResponse } from './provider';
import { settle, taintOf } from './taint';

// Agents on their own LLM often run tools inside their own code, so no tool call crosses the network.
// Their LLM still has to name each tool in its answer, and that answer passes through here: a call the
// seal does not allow never reaches the agent, so it never runs. The rules are the tool proxy's rules.
// A proposal is not an attempt by the agent, so it does not count towards the out-of-manifest kill.

const REVIEW_STEP = 12;

export function proposedCalls(resp: ChatResponse): { name: string; args: string }[] {
  return (resp.choices ?? []).flatMap((c) => c.message.tool_calls ?? []).map((tc) => ({ name: tc.function.name, args: tc.function.arguments }));
}

export const actionKeysFor = (policy: CompiledPolicy, name: string) => Object.keys(policy.actions).filter((k) => k.endsWith(`.${name}`));

function parseArgs(text: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// The agent carries on normally: it gets an answer with the reason in it and no tool to run.
export function blockedAnswer(resp: ChatResponse, reason: string): void {
  for (const choice of resp.choices ?? []) {
    choice.finish_reason = 'stop';
    choice.message = { role: 'assistant', content: `Chat blocked by Signet. This action was blocked by company policy. Reason: ${reason}.` };
  }
}

export async function reviewProposedCalls(ctx: Ctx, headers: IncomingHttpHeaders, resp: ChatResponse, policy: CompiledPolicy, stepUp: boolean, restore: (s: string) => string): Promise<void> {
  const cert = ctx.cert!;
  const claims = ctx.claims!;
  for (const call of proposedCalls(resp)) {
    const keys = actionKeysFor(policy, call.name);
    if (!keys.length) {
      const what = `the LLM proposed ${call.name}, which is not in this agent's seal`;
      if (!wouldBlock(ctx, REVIEW_STEP, ['RB-PREC-01', 'SGC-TOOL-004'], what)) halt(ctx, REVIEW_STEP, 403, 'tool_call_blocked', what, 'deny', ['RB-PREC-01', 'SGC-TOOL-004']);
      continue;
    }
    const args = parseArgs(restore(call.args));
    if (!args) {
      // Unreadable arguments cannot be checked against the seal's limits, so they do not pass.
      const what = `the LLM proposed ${call.name} with arguments that are not a JSON object`;
      if (!wouldBlock(ctx, REVIEW_STEP, ['RB-PREC-08'], what)) halt(ctx, REVIEW_STEP, 403, 'tool_call_blocked', what, 'deny', ['RB-PREC-08']);
      continue;
    }
    for (const key of keys) {
      const action = policy.actions[key]!;
      if (action.impact === 'privileged' || action.impact === 'critical') await settle(sessionKey(ctx), 5_000);
      const t = await taintOf(sessionKey(ctx));
      if (t?.band === 'high' && (action.impact === 'privileged' || action.impact === 'critical')) {
        const act = cert.tier === 'T1' || cert.tier === 'T2' ? 'kill' : 'quarantine';
        await ladder(ctx, act, 'RB-KILL-01', `privileged ${key} proposed after injection in this session`, { taint_source: t.source });
        halt(ctx, REVIEW_STEP, 403, 'hijack_detected', `privileged action after injected content in this session; agent ${act === 'kill' ? 'killed' : 'quarantined'}`, act, ['RB-KILL-01']);
      }
      const di = inspectArgs(args, action, policy);
      ctx.dlp.push(...di.events);
      if (di.exfiltration) {
        await ladder(ctx, 'kill', 'RB-KILL-02', `${di.exfiltration.tag} proposed for ${key}, outside the tool's data scope`, { tag: di.exfiltration.tag });
        halt(ctx, REVIEW_STEP, 403, 'data_exfiltration', `${di.exfiltration.tag} data may not be sent to ${key}; the agent has been killed`, 'kill', [di.exfiltration.rule, 'RB-KILL-02']);
      }
      if (di.blocked && !wouldBlock(ctx, REVIEW_STEP, [di.blocked.rule], `${di.blocked.tag} outside the data scope of ${key}`)) halt(ctx, REVIEW_STEP, 403, 'data_blocked', `${di.blocked.tag} data is outside the data scope of ${key}`, 'deny', [di.blocked.rule]);
      const r = evaluate({ kind: 'tool', policy, action: { key, args }, context: { tainted: !!t, step_up: stepUp, tool_calls_in_session: await limits.toolCallsIn(sessionKey(ctx)), tool_calls_limit: cert.limits.tool_calls_per_session ?? null } });
      const rules = [...r.rule_ids, ...(di.approval ? [di.approval.rule] : [])];
      ctx.rules.push(...rules);
      if (r.decision === 'deny') {
        const what = r.details.join('; ') || 'denied by policy';
        if (!wouldBlock(ctx, REVIEW_STEP, r.rule_ids, what)) halt(ctx, REVIEW_STEP, 403, 'policy_denied', what, 'deny', r.rule_ids);
      } else if (r.decision === 'require_approval' || di.approval) {
        if (!wouldBlock(ctx, 10, rules, `needs approval by ${r.approver_groups.join(', ') || 'an approver'}`)) await humanApproval(ctx, headers, { actionKey: key, args: maskArgs(args), rules, groups: r.approver_groups });
      }
      step(ctx, REVIEW_STEP, 'pass', `proposed ${key} reviewed for agent ${claims.agent_id}`);
    }
    await limits.countToolCall(sessionKey(ctx));
  }
}

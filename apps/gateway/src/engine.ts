import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT, type CompiledPolicy } from '@signet/core';

// Policy evaluation (BP 5.2 step 9). The source of truth is policy/signet.rego. When CI has compiled
// it to policy/dist/policy.wasm, the gateway evaluates it in-process with OPA's WebAssembly runtime.
// Otherwise this TypeScript evaluator runs; it implements the same rules one for one, and
// test/engine.test.ts checks them against the cases in policy/conformance.json, which OPA also runs.

export interface PolicyInput {
  kind: 'llm' | 'tool';
  policy: CompiledPolicy;
  action: { key: string; args?: Record<string, unknown>; est_input_tokens?: number; est_cost_usd?: number };
  context: { tainted?: boolean; step_up?: boolean; tool_calls_in_session?: number; tool_calls_limit?: number | null; dlp_tokenised?: number; max_tokens_capped?: boolean };
}

export interface PolicyResult {
  decision: 'allow' | 'allow_with_obligations' | 'require_approval' | 'deny';
  rule_ids: string[];
  details: string[];
  obligations: string[];
  approver_groups: string[];
}

const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const sorted = (xs: Iterable<string>) => [...new Set(xs)].sort();

export function evaluateTs(input: PolicyInput): PolicyResult {
  const p = input.policy;
  const act = p.actions[input.action.key];
  const args = input.action.args ?? {};
  const tool = input.kind === 'tool';
  const highTier = p.tier === 'T1' || p.tier === 'T2';
  const impact = act?.impact;
  const money = act?.value_arg ? args[act.value_arg] : undefined;
  const ctx = input.context;

  const deny: { rule: string; detail: string }[] = [];
  if (tool && !act) deny.push({ rule: 'RB-PREC-01', detail: `${input.action.key} is not in the seal` });
  if (tool && act) {
    for (const [name, c] of Object.entries(act.constraints)) {
      const v = args[name];
      if (isNum(c.max) && isNum(v) && v > c.max) deny.push({ rule: 'BP-4.3-constraint', detail: `${name} above maximum ${c.max}` });
      if (isNum(c.min) && isNum(v) && v < c.min) deny.push({ rule: 'BP-4.3-constraint', detail: `${name} below minimum ${c.min}` });
      if (Array.isArray(c.enum) && v !== undefined && v !== null && v !== false && !c.enum.includes(v as never)) deny.push({ rule: 'BP-4.3-constraint', detail: `${name} is not an allowed value` });
      if (typeof c.pattern === 'string' && typeof v === 'string' && !new RegExp(c.pattern).test(v)) deny.push({ rule: 'BP-4.3-constraint', detail: `${name} does not match the allowed pattern` });
      if (isNum(c.max_length) && typeof v === 'string' && [...v].length > c.max_length) deny.push({ rule: 'BP-4.3-constraint', detail: `${name} longer than ${c.max_length} characters` });
    }
  }
  if (input.kind === 'llm' && (input.action.est_input_tokens ?? 0) > p.max_input_tokens) {
    deny.push({ rule: 'RB-BL-03', detail: `about ${input.action.est_input_tokens} input tokens; cap ${p.max_input_tokens}` });
  }
  if (tool && isNum(ctx.tool_calls_limit) && (ctx.tool_calls_in_session ?? 0) >= ctx.tool_calls_limit) deny.push({ rule: 'BP-4.3-limits', detail: 'tool calls per session exhausted' });
  if (deny.length) return { decision: 'deny', rule_ids: sorted(deny.map((d) => d.rule)), details: sorted(deny.map((d) => d.detail)), obligations: [], approver_groups: [] };

  const approval: { rule: string; group: string }[] = [];
  if (tool && act) {
    const waived = isNum(act.value_threshold_usd) && isNum(money) && money <= act.value_threshold_usd;
    if (impact === 'critical' && ['T1', 'T2', 'T3'].includes(p.tier)) approval.push({ rule: 'RB-PRIV-03', group: 'security-approvers' });
    if (impact === 'privileged' && highTier && !waived) approval.push({ rule: 'RB-PRIV-04', group: 'owner-approvers' });
    if (impact === 'critical' && isNum(money) && money > 10_000) approval.push({ rule: 'RB-PRIV-08', group: 'dual-control' });
    if ((p.autonomy_level === 'L0' || p.autonomy_level === 'L1') && impact !== 'read') approval.push({ rule: 'RB-PRIV-07', group: 'owner-approvers' });
    if (ctx.tainted && (impact === 'privileged' || impact === 'critical')) approval.push({ rule: 'RB-BL-12', group: 'security-approvers' });
    const stepUpScope = highTier ? impact !== 'read' : impact === 'privileged' || impact === 'critical';
    if (ctx.step_up && stepUpScope) approval.push({ rule: 'BP-5.4-L2', group: 'security-approvers' });
    for (const h of act.hitl) {
      if (h.arg === null) approval.push({ rule: 'cert.hitl', group: h.approver_group });
      else if (isNum(args[h.arg]) && isNum(h.gt) && (args[h.arg] as number) > h.gt) approval.push({ rule: 'cert.hitl', group: h.approver_group });
    }
  }
  if (input.kind === 'llm' && (input.action.est_cost_usd ?? 0) > p.max_cost_per_request_usd) approval.push({ rule: 'RB-BL-04', group: 'owner-approvers' });

  const obligations: string[] = [];
  if ((ctx.dlp_tokenised ?? 0) > 0) obligations.push('tokenise');
  if (ctx.max_tokens_capped) obligations.push('max_tokens_cap');

  if (approval.length) return { decision: 'require_approval', rule_ids: sorted(approval.map((a) => a.rule)), details: [], obligations: sorted(obligations), approver_groups: sorted(approval.map((a) => a.group)) };
  if (obligations.length) return { decision: 'allow_with_obligations', rule_ids: [], details: [], obligations: sorted(obligations), approver_groups: [] };
  return { decision: 'allow', rule_ids: [], details: [], obligations: [], approver_groups: [] };
}

type Wasm = { evaluate: (input: unknown) => { result: PolicyResult }[] };
let wasm: Wasm | null = null;
export let engineName = 'typescript (mirrors policy/signet.rego)';

export async function initEngine() {
  const file = join(REPO_ROOT, 'policy', 'dist', 'policy.wasm');
  if (!existsSync(file)) return engineName;
  const { loadPolicy } = (await import('@open-policy-agent/opa-wasm')) as unknown as { loadPolicy: (b: Buffer) => Promise<Wasm & { setData: (d: unknown) => void }> };
  const p = await loadPolicy(readFileSync(file));
  p.setData({});
  wasm = p;
  engineName = 'opa-wasm (policy/dist/policy.wasm)';
  return engineName;
}

export function evaluate(input: PolicyInput): PolicyResult {
  if (wasm) {
    const out = wasm.evaluate(input);
    if (out[0]?.result) return out[0].result;
  }
  return evaluateTs(input);
}

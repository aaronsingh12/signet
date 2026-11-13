import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT, evaluateTs, strictest, type PolicyInput, type PolicyResult } from '@signet/core';

export { evaluateTs, type PolicyInput, type PolicyResult };

// Policy evaluation (BP 5.2 step 9). The source of truth is policy/signet.rego. When CI has compiled
// it to policy/dist/policy.wasm, the gateway evaluates it in-process with OPA's WebAssembly runtime.
// Otherwise this TypeScript evaluator runs; it implements the same rules one for one, and
// test/engine.test.ts checks them against the cases in policy/conformance.json, which OPA also runs.

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
  const ts = evaluateTs(input);
  if (!wasm) return ts;
  const opa = wasm.evaluate(input)[0]?.result;
  if (!opa) return ts;
  // Both engines must agree (they share policy/conformance.json). If they ever differ on live traffic, the
  // difference is logged and the stricter answer is used, so a gap in either copy can never loosen a decision.
  if (opa.decision !== ts.decision || opa.rule_ids.join() !== ts.rule_ids.join()) {
    mismatches++;
    console.warn('[gateway] policy engines disagree; using the stricter result', { opa: opa.decision, opa_rules: opa.rule_ids, typescript: ts.decision, ts_rules: ts.rule_ids });
    return strictest(opa.decision, ts.decision) === opa.decision ? opa : ts;
  }
  return opa;
}

/** Live disagreements between the OPA and TypeScript engines since start (should stay 0). */
export let mismatches = 0;

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT, evaluateTs, type PolicyInput, type PolicyResult } from '@signet/core';

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
  if (wasm) {
    const out = wasm.evaluate(input);
    if (out[0]?.result) return out[0].result;
  }
  return evaluateTs(input);
}

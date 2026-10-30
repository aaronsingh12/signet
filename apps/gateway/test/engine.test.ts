import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { REPO_ROOT } from '@signet/core';
import { evaluateTs, type PolicyInput } from '../src/engine';

// The same cases run against policy/signet.rego under `opa test policy/` (CI), so the TypeScript
// evaluator and the Rego policy cannot drift apart unnoticed.
const { conformance } = JSON.parse(readFileSync(join(REPO_ROOT, 'policy', 'conformance.json'), 'utf8')) as {
  conformance: { cases: { name: string; input: PolicyInput; expect: { decision: string; rule_ids: string[] } }[] };
};

for (const c of conformance.cases) {
  test(`policy conformance: ${c.name}`, () => {
    const r = evaluateTs(c.input);
    assert.equal(r.decision, c.expect.decision);
    assert.deepEqual(r.rule_ids, c.expect.rule_ids);
  });
}

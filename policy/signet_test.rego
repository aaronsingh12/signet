package signet.decision_test

import rego.v1

import data.signet.decision

# Runs every case in policy/conformance.json; the TypeScript evaluator runs the same file
# (apps/gateway/test/engine.test.ts), so the two cannot drift apart unnoticed.
test_conformance if {
	every c in data.conformance.cases {
		r := decision.result with input as c.input
		r.decision == c.expect.decision
		r.rule_ids == c.expect.rule_ids
	}
}

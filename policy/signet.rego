# Signet gateway decision policy (BP 5.2 step 9; Rulebook baseline and privileged-action rules).
# Input: the compiled seal (input.policy), the normalised action and request context.
# Output: data.signet.decision.result = {decision, rule_ids, details, obligations, approver_groups}.
# Deny overrides approval, approval overrides obligations (RB-PREC-03, RB-PREC-04).
# The gateway's TypeScript evaluator (apps/gateway/src/engine.ts) implements the same rules and the
# conformance test keeps the two identical; CI compiles this file to policy.wasm for in-process OPA.
package signet.decision

import rego.v1

act := input.policy.actions[input.action.key]

args := object.get(input.action, "args", {})

high_tier if input.policy.tier in {"T1", "T2"}

impact := act.impact

money := args[act.value_arg] if is_string(act.value_arg)

# --- deny ---------------------------------------------------------------------------------------

deny contains {"rule": "RB-PREC-01", "detail": sprintf("%s is not in the seal", [input.action.key])} if {
	input.kind == "tool"
	not input.policy.actions[input.action.key]
}

deny contains {"rule": "BP-4.3-constraint", "detail": sprintf("%s above maximum %v", [name, c.max])} if {
	input.kind == "tool"
	some name, c in act.constraints
	is_number(c.max)
	is_number(args[name])
	args[name] > c.max
}

deny contains {"rule": "BP-4.3-constraint", "detail": sprintf("%s below minimum %v", [name, c.min])} if {
	input.kind == "tool"
	some name, c in act.constraints
	is_number(c.min)
	is_number(args[name])
	args[name] < c.min
}

deny contains {"rule": "BP-4.3-constraint", "detail": sprintf("%s is not an allowed value", [name])} if {
	input.kind == "tool"
	some name, c in act.constraints
	is_array(c.enum)
	args[name]
	not args[name] in c.enum
}

deny contains {"rule": "BP-4.3-constraint", "detail": sprintf("%s does not match the allowed pattern", [name])} if {
	input.kind == "tool"
	some name, c in act.constraints
	is_string(c.pattern)
	is_string(args[name])
	not regex.match(c.pattern, args[name])
}

deny contains {"rule": "BP-4.3-constraint", "detail": sprintf("%s longer than %v characters", [name, c.max_length])} if {
	input.kind == "tool"
	some name, c in act.constraints
	is_number(c.max_length)
	is_string(args[name])
	count(args[name]) > c.max_length
}

deny contains {"rule": "RB-BL-03", "detail": sprintf("about %v input tokens; cap %v", [input.action.est_input_tokens, input.policy.max_input_tokens])} if {
	input.kind == "llm"
	input.action.est_input_tokens > input.policy.max_input_tokens
}

deny contains {"rule": "BP-4.3-limits", "detail": "tool calls per session exhausted"} if {
	input.kind == "tool"
	is_number(input.context.tool_calls_limit)
	input.context.tool_calls_in_session >= input.context.tool_calls_limit
}

# --- human approval -----------------------------------------------------------------------------

waived if {
	is_number(act.value_threshold_usd)
	is_number(money)
	money <= act.value_threshold_usd
}

approval contains {"rule": "RB-PRIV-03", "group": "security-approvers"} if {
	input.kind == "tool"
	impact == "critical"
	input.policy.tier in {"T1", "T2", "T3"}
}

approval contains {"rule": "RB-PRIV-04", "group": "owner-approvers"} if {
	input.kind == "tool"
	impact == "privileged"
	high_tier
	not waived
}

approval contains {"rule": "RB-PRIV-08", "group": "dual-control"} if {
	input.kind == "tool"
	impact == "critical"
	is_number(money)
	money > 10000
}

approval contains {"rule": "RB-PRIV-07", "group": "owner-approvers"} if {
	input.kind == "tool"
	input.policy.autonomy_level in {"L0", "L1"}
	impact in {"write", "privileged", "critical"}
}

approval contains {"rule": "RB-BL-12", "group": "security-approvers"} if {
	input.kind == "tool"
	input.context.tainted
	impact in {"privileged", "critical"}
}

step_up_scope if {
	high_tier
	impact in {"write", "privileged", "critical"}
}

step_up_scope if {
	not high_tier
	impact in {"privileged", "critical"}
}

approval contains {"rule": "BP-5.4-L2", "group": "security-approvers"} if {
	input.kind == "tool"
	input.context.step_up
	step_up_scope
}

approval contains {"rule": "cert.hitl", "group": h.approver_group} if {
	input.kind == "tool"
	some h in act.hitl
	h.arg == null
}

approval contains {"rule": "cert.hitl", "group": h.approver_group} if {
	input.kind == "tool"
	some h in act.hitl
	is_string(h.arg)
	is_number(args[h.arg])
	args[h.arg] > h.gt
}

approval contains {"rule": "RB-BL-04", "group": "owner-approvers"} if {
	input.kind == "llm"
	input.action.est_cost_usd > input.policy.max_cost_per_request_usd
}

# --- obligations --------------------------------------------------------------------------------

obligations contains "tokenise" if input.context.dlp_tokenised > 0

obligations contains "max_tokens_cap" if input.context.max_tokens_capped

# --- result -------------------------------------------------------------------------------------

rules(set) := sort({r | some x in set; r := x.rule})

result := {
	"decision": "deny",
	"rule_ids": rules(deny),
	"details": sort({d | some x in deny; d := x.detail}),
	"obligations": [],
	"approver_groups": [],
} if count(deny) > 0

result := {
	"decision": "require_approval",
	"rule_ids": rules(approval),
	"details": [],
	"obligations": sort(obligations),
	"approver_groups": sort({g | some x in approval; g := x.group}),
} if {
	count(deny) == 0
	count(approval) > 0
}

result := {
	"decision": "allow_with_obligations",
	"rule_ids": [],
	"details": [],
	"obligations": sort(obligations),
	"approver_groups": [],
} if {
	count(deny) == 0
	count(approval) == 0
	count(obligations) > 0
}

default result := {"decision": "allow", "rule_ids": [], "details": [], "obligations": [], "approver_groups": []}

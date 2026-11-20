import type { Tier } from './types';
import { BASELINE_DAYS, MIN_BASELINE_DAYS, MIN_BASELINE_RECORDS } from './anomaly';
import { GUARDRAIL_PARAMS, formatBytes, pct } from './guardrail-params';

// The guardrail catalogue: every check Signet enforces, in one place. Rule IDs are the ones the code
// writes into ledger records and error responses (policy_rule_ids, rule_ids), so a refusal in Activity
// can be looked up here. Sources: Product & Engineering Blueprint (BP), Decision Architecture and
// Self-Governance (DA) and the Rulebook (RB, v0.1 in rulebook.ts; the v0.2 additions the code cites,
// such as RB-INV-19 and RB-PROV-*, exist only here). test/guardrails.test.ts fails when enforcement code
// cites a rule ID missing here, or when this catalogue and the Rulebook coverage disagree.

export type GuardrailGroup =
  | 'identity' | 'limits' | 'scope' | 'data' | 'approval' | 'detectors'
  | 'stops' | 'rollout' | 'provider' | 'evidence' | 'seal' | 'lifecycle' | 'servicenow';

/** What happens when the guardrail is triggered. */
export type GuardrailEffect =
  | 'block' | 'hold' | 'step_up' | 'throttle' | 'quarantine' | 'kill'
  | 'redact' | 'tokenise' | 'modify' | 'detect' | 'record' | 'refuse' | 'combine' | 'flag';

export interface Guardrail {
  key: string; // stable id for the console
  rule_ids: string[]; // IDs written to the ledger; empty when the code cites none
  rulebook?: string[]; // Rulebook v0.1 rules this guardrail implements, when they differ from rule_ids
  group: GuardrailGroup;
  name: string;
  what: string; // plain-English description of what it checks and does
  effect: GuardrailEffect;
  where: 'gateway' | 'control_plane';
  step?: number; // gateway pipeline step (1-14), when enforced inline
  tiers?: Tier[]; // only these risk tiers; absent means every tier
  detector?: string; // its status follows this detector's mode
  source: string; // document section
  code: string[]; // files that enforce it
}

export interface GuardrailGroupInfo { id: GuardrailGroup; title: string; summary: string }

export const GUARDRAIL_GROUPS: readonly GuardrailGroupInfo[] = [
  { id: 'identity', title: 'Who is calling', summary: 'Every request must prove which agent sent it and that the agent holds a valid, active seal.' },
  { id: 'limits', title: 'How much', summary: 'Rate, size and cost limits from the seal and the tenant baseline.' },
  { id: 'scope', title: 'What the agent may use', summary: 'Default deny: only the models, tools and actions listed in the seal.' },
  { id: 'data', title: 'What data may leave', summary: 'Pattern DLP and the data-class matrix decide what reaches a model or tool, and what comes back.' },
  { id: 'approval', title: 'When a person must decide', summary: 'Rules that hold an action for human approval, and how a held action waits.' },
  { id: 'detectors', title: 'AI detectors', summary: 'Small detectors can only add caution. Only rules can allow an action.' },
  { id: 'stops', title: 'Automatic stops and the response ladder', summary: 'Block, step-up, throttle, quarantine and kill. Every automatic stop needs a rule.' },
  { id: 'rollout', title: 'Rollout', summary: 'New seals start in shadow, then canary, then full enforcement.' },
  { id: 'provider', title: 'The cloud LLM and credentials', summary: 'One approved cloud LLM; agents never hold real keys.' },
  { id: 'evidence', title: 'Proof of every decision', summary: 'Every decision is recorded before the agent gets an answer, in a ledger that shows any change.' },
  { id: 'seal', title: 'Checks before an agent is approved', summary: 'Rules the control plane applies when a seal is written and approved.' },
  { id: 'lifecycle', title: 'Onboarding gates', summary: 'Each of the eight lifecycle stages has an exit gate an agent must meet before it moves on.' },
  { id: 'servicenow', title: 'ServiceNow Guardian', summary: 'Checks on content that ServiceNow sends to Signet for review.' },
];

const byTier = (values: Record<Tier, number>, unit: 'day' | 'minute') => (['T1', 'T2', 'T3', 'T4'] as const).map((t) => `${t} ${values[t]} ${unit}${values[t] === 1 ? '' : 's'}`).join(', ');

// The 14 gateway steps (BP 5.2). Names are the ones written into each ledger record's steps[].
export const PIPELINE_STEPS: readonly { n: number; name: string; what: string }[] = [
  { n: 1, name: 'authenticate', what: 'Check the workload token: signature, issuer, audience, expiry, revocation.' },
  { n: 2, name: 'resolve seal', what: 'Find the seal and compiled policy in the signed policy bundle.' },
  { n: 3, name: 'kill and quarantine', what: 'Refuse agents, versions or instances that are stopped or paused.' },
  { n: 4, name: 'seal validity', what: 'Check the seal dates and that it covers this environment.' },
  { n: 5, name: 'limits', what: 'Requests per minute, tokens and cost per day; behaviour anomaly scoring.' },
  { n: 6, name: 'normalise', what: 'Parse the request into one standard shape; refuse what cannot be read.' },
  { n: 7, name: 'manifest', what: 'Is this model, tool and action in the seal? Out-of-seal attempts are counted.' },
  { n: 8, name: 'DLP inbound', what: 'Scan prompts and tool arguments; tokenise, block or stop per the data-class matrix; start detectors.' },
  { n: 9, name: 'policy', what: 'Run the rules (policy/signet.rego) and combine them with detector results; strictest wins.' },
  { n: 10, name: 'human approval', what: 'Hold the action for a person when a rule requires it.' },
  { n: 11, name: 'credential injection', what: 'Attach the real credential from the Secrets Broker; the agent never sees it.' },
  { n: 12, name: 'forward', what: 'Send to the cloud LLM or tool; enforcement can cut the call mid-flight.' },
  { n: 13, name: 'DLP and guardrails outbound', what: 'Apply detector verdicts, redact secrets, mask cards, restore tokens for the caller.' },
  { n: 14, name: 'log and score', what: 'Write the ledger record before the answer leaves the gateway.' },
];

const CTX = 'apps/gateway/src/ctx.ts';
const CHAT = 'apps/gateway/src/chat.ts';
const TOOL = 'apps/gateway/src/toolcall.ts';
const POLICY = 'policy/signet.rego';
const EVAL = 'packages/core/src/policyeval.ts';
const MATRIX = 'packages/core/src/datamatrix.ts';
const COMBINE = 'packages/core/src/decision.ts';
const LADDER = 'apps/control/src/enforcement.ts';
const REGISTRY = 'apps/control/src/registry.ts';
const WORKFLOW = 'apps/control/src/workflow.ts';

export const GUARDRAILS: readonly Guardrail[] = [
  // --- Who is calling ---------------------------------------------------------------------------
  {
    key: 'workload-token', rulebook: ['RB-BL-06', 'RB-A2A-10'], rule_ids: ['BP-5.2-1'], group: 'identity', name: 'Valid workload token',
    what: 'Every request must carry a short-lived token signed by Signet for this gateway and tenant. Missing, forged, expired or revoked tokens are refused, and so is any token of an agent that was permanently removed.',
    effect: 'block', where: 'gateway', step: 1, source: 'BP 4.2, BP 5.2 step 1', code: [CTX],
  },
  {
    key: 'deployment-credential', rule_ids: ['BP-4.2'], group: 'identity', name: 'Deployment credential swap',
    what: 'An agent may use its deployment credential (sdc_…) as an API key. The gateway swaps it for that agent\'s own workload token; it can never be used to get any other agent\'s token.',
    effect: 'block', where: 'gateway', step: 1, source: 'BP 4.2', code: ['apps/gateway/src/apikey.ts', 'apps/gateway/src/index.ts'],
  },
  {
    key: 'unsigned-flood', rule_ids: [], group: 'identity', name: 'Flood protection for calls without a token',
    what: `Calls without a valid token are recorded for the first ${GUARDRAIL_PARAMS.unsigned_recorded_per_minute} per address each minute. After that they get 429 without a ledger record, so floods cannot fill the ledger.`,
    effect: 'block', where: 'gateway', step: 14, source: 'Signet hardening', code: [CTX, 'apps/gateway/src/limits.ts'],
  },
  {
    key: 'active-seal', rule_ids: ['RB-INV-01'], group: 'identity', name: 'Active seal required',
    what: 'No seal, no action. The token must point to an active seal in the current policy bundle, and tokens are only issued to agents with an active, unexpired seal.',
    effect: 'block', where: 'gateway', step: 2, source: 'Rulebook', code: [CTX, 'apps/control/src/identity.ts'],
  },
  {
    key: 'signed-bundle', rule_ids: ['BP-3'], group: 'identity', name: 'Fail closed without a current policy bundle',
    what: `Gateways enforce from a signed policy bundle, refreshed by push and every ${GUARDRAIL_PARAMS.bundle_poll_seconds} seconds. Each seal in it is signature-checked and must match the hash of its compiled policy, or it is ignored. If the bundle expires (${GUARDRAIL_PARAMS.bundle_ttl_hours} hours without contact) every request is refused.`,
    effect: 'block', where: 'gateway', step: 2, source: 'BP 3', code: ['apps/gateway/src/state.ts', CTX],
  },
  {
    key: 'stopped-agents', rule_ids: ['RB-INV-08', 'BP-5.4'], group: 'identity', name: 'Stopped and paused agents are refused',
    what: 'If the agent, its version or this running instance is killed or quarantined, the request is refused straight away.',
    effect: 'block', where: 'gateway', step: 3, source: 'BP 5.2 step 3, BP 5.4', code: [CTX, 'apps/gateway/src/state.ts'],
  },
  {
    key: 'seal-validity', rule_ids: ['RB-KILL-11', 'RB-BL-16'], group: 'identity', name: 'Seal inside its validity window',
    what: 'Requests outside the seal\'s valid-from and valid-to dates are refused. A seal that expires without re-attestation also pauses (quarantines) the agent.',
    effect: 'block', where: 'gateway', step: 4, source: 'BP 4.3, BP 5.4 kill conditions', code: [CTX, 'apps/control/src/workflow.ts', 'apps/control/src/identity.ts'],
  },
  {
    key: 'environment', rule_ids: ['BP-5.2-4'], group: 'identity', name: 'Right environment',
    what: 'The seal must list the environment this gateway runs in (for example dev or prod).',
    effect: 'block', where: 'gateway', step: 4, source: 'BP 5.2 step 4', code: [CTX],
  },

  // --- How much --------------------------------------------------------------------------------
  {
    key: 'seal-limits', rulebook: ['RB-PREC-06'], rule_ids: ['BP-5.2-5'], group: 'limits', name: 'Seal rate, token and cost limits',
    what: 'Requests per minute, tokens per day and US dollars per day, as set in each seal. Over the limit the agent gets 429. A throttle (ladder level 3) scales these limits down.',
    effect: 'throttle', where: 'gateway', step: 5, source: 'BP 4.3 limits, BP 5.2 step 5', code: [CTX, 'apps/gateway/src/limits.ts'],
  },
  {
    key: 'input-cap', rule_ids: ['RB-BL-03'], group: 'limits', name: 'Input size cap per request',
    what: 'A prompt estimated above the tenant cap is refused.',
    effect: 'block', where: 'gateway', step: 9, source: 'Rulebook baseline', code: [POLICY, EVAL],
  },
  {
    key: 'cost-cap', rule_ids: ['RB-BL-04'], group: 'limits', name: 'Cost cap per request',
    what: 'A single model call estimated above the tenant cost cap is held for the owner to approve.',
    effect: 'hold', where: 'gateway', step: 9, source: 'Rulebook baseline', code: [POLICY, EVAL],
  },
  {
    key: 'answer-length', rule_ids: [], group: 'limits', name: 'Answer length cap',
    what: 'If the seal sets max_tokens for the model, a request asking for more is cut down to that cap. This is recorded as an obligation on the decision.',
    effect: 'modify', where: 'gateway', step: 7, source: 'BP 4.3 models[]', code: [CHAT],
  },
  {
    key: 'tool-calls-per-session', rule_ids: ['BP-4.3-limits'], group: 'limits', name: 'Tool calls per session',
    what: 'When the seal limits tool calls per session, calls beyond that number are refused.',
    effect: 'block', where: 'gateway', step: 9, source: 'BP 4.3 limits', code: [POLICY, EVAL, TOOL],
  },

  // --- What the agent may use -------------------------------------------------------------------
  {
    key: 'one-llm', rulebook: ['RB-BL-01'], rule_ids: ['RB-INV-19'], group: 'scope', name: 'Only the approved cloud LLM',
    what: 'Agents may call only models in the tenant catalogue. Calls shaped for another provider\'s API, or for a model outside the catalogue, are refused and counted as out-of-seal attempts. This is enforced even in shadow.',
    effect: 'block', where: 'gateway', step: 7, source: 'Rulebook v0.2 D-17', code: [CHAT, 'apps/gateway/src/index.ts'],
  },
  {
    key: 'in-seal', rule_ids: ['RB-PREC-01', 'SGC-TOOL-004'], group: 'scope', name: 'Model, tool and action must be in the seal',
    what: 'Default deny. Every model and tool action must be listed in the seal; anything else is refused and counts towards the repeat-violation stop. An unknown action is treated as critical impact.',
    effect: 'block', where: 'gateway', step: 7, source: 'BP 5.2 step 7', code: [CHAT, TOOL, POLICY],
  },
  {
    key: 'tool-registered', rulebook: ['RB-BL-05'], rule_ids: ['BP-5.1'], group: 'scope', name: 'Tool must be registered',
    what: 'Agents name a tool by its alias. The alias must be registered in Signet, and seals can only list registered aliases. The real address and credential are added by the gateway.',
    effect: 'block', where: 'gateway', step: 7, source: 'BP 5.1', code: [TOOL, REGISTRY],
  },
  {
    key: 'tool-list-filter', rule_ids: [], group: 'scope', name: 'Agents only see their own tools',
    what: 'When an agent asks an MCP server for its tool list, the answer is cut down to the actions in its seal. MCP methods Signet does not govern yet are not passed through.',
    effect: 'modify', where: 'gateway', step: 7, source: 'BP 5.1 (least privilege)', code: ['apps/gateway/src/index.ts'],
  },
  {
    key: 'arg-constraints', rule_ids: ['BP-4.3-constraint'], group: 'scope', name: 'Argument limits',
    what: 'Tool arguments must meet the seal\'s limits: maximum, minimum, allowed values, pattern and maximum length. A call that breaks one is refused.',
    effect: 'block', where: 'gateway', step: 9, source: 'BP 4.3 tools[].constraints', code: [POLICY, EVAL],
  },
  {
    key: 'readable-requests', rule_ids: ['RB-PREC-08'], group: 'scope', name: 'Requests must be readable',
    what: 'A request Signet cannot parse (no model or messages, tool arguments that are not a JSON object, a malformed tool call) is refused, never guessed at.',
    effect: 'block', where: 'gateway', step: 6, source: 'Rulebook precedence', code: [CHAT, TOOL, 'apps/gateway/src/toolreview.ts'],
  },
  {
    key: 'own-llm-tool-review', rule_ids: ['RB-PREC-01', 'RB-PREC-08'], group: 'scope', name: 'Tool calls proposed by an agent\'s own LLM',
    what: 'Agents on their own LLM may run tools inside their code. The tool calls in the model\'s answer are checked with the tool proxy\'s rules; a refused call is removed from the answer, with the reason.',
    effect: 'block', where: 'gateway', step: 13, source: 'BP 5.2 step 13', code: ['apps/gateway/src/toolreview.ts'],
  },
  {
    key: 'safe-destinations', rule_ids: [], group: 'scope', name: 'Safe tool destinations',
    what: `Tool addresses are checked when registered and on every connection. Cloud metadata and link-local addresses are never reachable, private addresses only when allowed, and path escapes are refused. Responses are capped at ${formatBytes(GUARDRAIL_PARAMS.tool_response_max_bytes)} and tool calls time out after ${GUARDRAIL_PARAMS.tool_timeout_ms / 1000} seconds.`,
    effect: 'block', where: 'gateway', step: 12, source: 'Signet hardening (SSRF)', code: ['packages/core/src/netguard.ts', 'apps/gateway/src/index.ts'],
  },
  {
    key: 'model-drift', rule_ids: ['RB-BL-02'], group: 'scope', name: 'Model family drift',
    what: 'If the provider answers with a different model than the catalogue expects, the answer is refused.',
    effect: 'block', where: 'gateway', step: 12, source: 'Rulebook baseline', code: [CHAT],
  },

  // --- What data may leave ----------------------------------------------------------------------
  {
    key: 'dlp-patterns', rule_ids: [], group: 'data', name: 'Pattern DLP',
    what: 'Every prompt, tool argument and answer is scanned in well under a millisecond for keys and tokens, passwords, private keys, connection strings, card numbers (Luhn-checked), IBANs (mod-97), email, phone and the national ID formats of the country packs switched on. What happens to each find is set by the data-class matrix.',
    effect: 'detect', where: 'gateway', step: 8, source: 'BP 5.3', code: ['packages/core/src/dlp.ts', 'packages/core/src/dlp-packs.ts'],
  },
  {
    key: 'no-secrets', rule_ids: ['RB-INV-16'], group: 'data', name: 'Secrets never reach a model or tool',
    what: 'Credentials and secrets in a prompt or tool argument are blocked and treated as exfiltration. No seal can allow secrets; the gateway adds real credentials itself.',
    effect: 'kill', where: 'gateway', step: 8, source: 'Rulebook invariants', code: [MATRIX, REGISTRY],
  },
  {
    key: 'data-matrix', rulebook: ['RB-BL-08', 'RB-PREC-05'], rule_ids: ['RB-DATA-matrix'], group: 'data', name: 'Data-class matrix',
    what: 'Each data class gets a fixed action. Card numbers and special-category data are tokenised if the seal allows them and blocked if not. Legal-privileged data is blocked to models and held for approval to tools. Source code goes only to code-approved models. Confidential documents go only where allowed. Tools receive only the classes in their data scope. A seal can only tighten these defaults.',
    effect: 'block', where: 'gateway', step: 8, source: 'Rulebook data-class matrix', code: [MATRIX, 'apps/gateway/src/policy.ts'],
  },
  {
    key: 'personal-tokenised', rule_ids: ['RB-DATA-01'], group: 'data', name: 'Personal and financial data tokenised',
    what: 'Email, phone numbers, IBANs, national IDs and similar values are replaced by tokens before the prompt reaches the cloud LLM, which is always treated as outside the tenant boundary.',
    effect: 'tokenise', where: 'gateway', step: 8, source: 'Rulebook data-class matrix', code: [MATRIX, 'apps/gateway/src/vault.ts'],
  },
  {
    key: 'token-scope', rule_ids: ['RB-DATA-06'], group: 'data', name: 'Tokens restored only for the same agent and session',
    what: 'Tokenised values are put back into the answer only for the agent and session that sent them. Any other caller sees the token.',
    effect: 'tokenise', where: 'gateway', step: 13, source: 'BP 5.3 tokenisation vault', code: ['apps/gateway/src/vault.ts'],
  },
  {
    key: 'response-redaction', rule_ids: ['RB-BL-10'], group: 'data', name: 'Answers scanned before release',
    what: 'Secrets in answers, reasoning text and proposed tool arguments become [REDACTED:secret]; card numbers are masked to the last four digits.',
    effect: 'redact', where: 'gateway', step: 13, source: 'Rulebook baseline, BP 5.2 step 13', code: ['apps/gateway/src/policy.ts'],
  },

  // --- When a person must decide ----------------------------------------------------------------
  {
    key: 'precedence', rulebook: ['RB-PREC-02', 'RB-PREC-07', 'RB-BL-09'], rule_ids: ['RB-PREC-03', 'RB-PREC-04'], group: 'approval', name: 'Strictest outcome wins',
    what: 'Deny overrides approval, approval overrides obligations. Across rules and detectors the order is: kill, quarantine, deny, hold for approval, step-up, throttle, allow with safeguards, allow.',
    effect: 'combine', where: 'gateway', step: 9, source: 'Rulebook precedence', code: [POLICY, COMBINE],
  },
  {
    key: 'critical-actions', rulebook: ['RB-BL-09'], rule_ids: ['RB-PRIV-03'], group: 'approval', name: 'Critical actions need Security',
    what: 'A tool action labelled critical is held for the security approvers.',
    effect: 'hold', where: 'gateway', step: 9, tiers: ['T1', 'T2', 'T3'], source: 'Rulebook privileged actions', code: [POLICY, EVAL],
  },
  {
    key: 'privileged-actions', rulebook: ['RB-BL-09', 'RB-PRIV-05'], rule_ids: ['RB-PRIV-04'], group: 'approval', name: 'Privileged actions need the owner',
    what: 'A tool action labelled privileged is held for the owner\'s approvers, unless the amount is at or below the waiver threshold in the seal.',
    effect: 'hold', where: 'gateway', step: 9, tiers: ['T1', 'T2'], source: 'Rulebook privileged actions', code: [POLICY, EVAL],
  },
  {
    key: 'dual-control', rule_ids: ['RB-PRIV-08'], group: 'approval', name: 'Two people for large critical amounts',
    what: `A critical action moving more than ${GUARDRAIL_PARAMS.dual_control_usd.toLocaleString('en-US')} needs two approvers (the dual-control group).`,
    effect: 'hold', where: 'gateway', step: 9, source: 'Rulebook privileged actions', code: [POLICY, EVAL],
  },
  {
    key: 'low-autonomy', rule_ids: ['RB-PRIV-07'], group: 'approval', name: 'Low-autonomy agents ask first',
    what: 'Agents at autonomy level L0 or L1 need approval for every action that is not read-only.',
    effect: 'hold', where: 'gateway', step: 9, source: 'Rulebook, BP 6 autonomy levels', code: [POLICY, EVAL],
  },
  {
    key: 'seal-hitl', rule_ids: ['cert.hitl'], group: 'approval', name: 'The seal\'s own approval rules',
    what: 'Approval checkpoints written into the seal at approval, for example "refunds over 5,000 go to ops supervisors".',
    effect: 'hold', where: 'gateway', step: 9, source: 'BP 4.3 hitl[]', code: [POLICY, EVAL, 'apps/control/src/compile.ts'],
  },
  {
    key: 'step-up', rule_ids: ['BP-5.4-L2'], group: 'approval', name: 'Extra checks (step-up)',
    what: 'While an agent is on step-up (ladder level 2), T1/T2 agents need Security approval for every action that is not read-only, and T3/T4 agents for privileged and critical actions.',
    effect: 'hold', where: 'gateway', step: 9, source: 'BP 5.4 level 2', code: [POLICY, EVAL],
  },
  {
    key: 'session-taint', rule_ids: ['RB-BL-12'], group: 'approval', name: 'Session taint',
    what: `Once a tool response or retrieved document scores Elevated or High on DET-INJ, the session is tainted for ${GUARDRAIL_PARAMS.session_taint_minutes} minutes: privileged and critical actions need Security approval. The taint is shared by every gateway node.`,
    effect: 'hold', where: 'gateway', step: 9, source: 'Rulebook baseline, DA 4', code: ['apps/gateway/src/taint.ts', POLICY],
  },
  {
    key: 'hitl-wait', rule_ids: ['BP-7.4'], group: 'approval', name: 'How a held action waits',
    what: `The gateway parks the action and shows approvers the action with sensitive values masked. It holds the connection for up to the tenant hold time, or answers 202 with an approval ID to resubmit. An approval is used once, by the same agent, for the same action. "Approve for this session" lasts ${GUARDRAIL_PARAMS.session_grant_hours} hours; "reject and quarantine" also pauses the agent.`,
    effect: 'hold', where: 'gateway', step: 10, source: 'BP 5.2 step 10, BP 7.4', code: [CTX, 'apps/control/src/hitl.ts'],
  },
  {
    key: 'timeout-reject', rule_ids: ['RB-INV-11'], group: 'approval', name: 'No answer means no',
    what: 'A held action with no decision within the hold time is rejected.',
    effect: 'block', where: 'gateway', step: 10, source: 'Rulebook invariants, BP 7.4', code: [CTX, 'apps/control/src/approvals.ts'],
  },

  // --- AI detectors -----------------------------------------------------------------------------
  {
    key: 'only-rules-allow', rulebook: ['RB-INV-04'], rule_ids: ['DA-4'], group: 'detectors', name: 'Detectors can only add caution',
    what: 'Only rules can allow. Elevated scores make an allowed action wait for a person (T1/T2) or need step-up (T3/T4). High scores pause the agent (T1/T2) or wait for a person (T3/T4). A detector score alone never kills an agent.',
    effect: 'combine', where: 'gateway', step: 9, source: 'DA 2, DA 4', code: [COMBINE],
  },
  {
    key: 'fail-safe', rulebook: ['RB-DET-03', 'RB-LAT-07', 'RB-LAT-01'], rule_ids: ['RB-INV-06'], group: 'detectors', name: 'Fail safe when a detector is missing',
    what: 'If a detector is off, in shadow, down, too slow or running an unpinned version, the rules decide alone and T1/T2 allows are held for a person. A seal can choose to record the gap instead (detector_unavailability: audit).',
    effect: 'hold', where: 'gateway', step: 9, tiers: ['T1', 'T2'], source: 'DA 2 fail safe', code: [COMBINE, 'apps/gateway/src/content-safety.ts'],
  },
  {
    key: 'det-inj', rulebook: ['RB-LAT-02'], rule_ids: ['DET-INJ'], group: 'detectors', name: 'Prompt-injection detector (DET-INJ)', detector: 'DET-INJ',
    what: 'Scores the new user text and any tool results, with stricter thresholds for tool results. It runs while the LLM call is in flight and its verdict applies before the answer is released. High on the prompt: answer withheld and agent paused (T1/T2) or held (T3/T4). Elevated: held (T1/T2) or step-up. On tool results it taints the session.',
    effect: 'hold', where: 'gateway', step: 13, source: 'DA 3, DA 4', code: ['apps/gateway/src/detectors.ts', CHAT, TOOL],
  },
  {
    key: 'det-jb', rule_ids: ['DET-JB'], group: 'detectors', name: 'Jailbreak detector (DET-JB)', detector: 'DET-JB',
    what: 'Scores the new user text. High: the answer is withheld. Elevated: held for a person (T1/T2) or step-up (T3/T4). A jailbreak score alone never pauses the agent.',
    effect: 'block', where: 'gateway', step: 13, source: 'DA 3', code: ['apps/gateway/src/detectors.ts', CHAT],
  },
  {
    key: 'det-safe', rulebook: ['RB-BL-11', 'RB-LAT-05'], rule_ids: ['DET-SAFE'], group: 'detectors', name: 'Unsafe content detector (DET-SAFE)', detector: 'DET-SAFE',
    what: 'Checks the prompt and the answer for violence, weapons, sexual exploitation, self-harm, fraud, cyber abuse and illicit drugs, in English, Hindi and Hinglish. Unsafe content is blocked. If the check is unavailable, T1/T2 answers are withheld for approval. It currently uses the cloud LLM as the classifier.',
    effect: 'block', where: 'gateway', step: 8, source: 'DA 3', code: ['apps/gateway/src/content-safety.ts'],
  },
  {
    key: 'det-pii', rulebook: ['RB-LAT-04'], rule_ids: ['DET-PII'], group: 'detectors', name: 'Names and addresses detector (DET-PII)', detector: 'DET-PII',
    what: 'Finds people\'s names and places in free text (Microsoft Presidio) in prompts and tool arguments. When active they are tokenised like other personal data; in shadow they are only recorded.',
    effect: 'tokenise', where: 'gateway', step: 8, source: 'DA 3', code: ['apps/gateway/src/pii.ts'],
  },
  {
    key: 'det-anom', rulebook: ['RB-ANOM-01', 'RB-ANOM-02', 'RB-ANOM-03', 'RB-ANOM-04', 'RB-ANOM-05', 'RB-ANOM-08', 'RB-ANOM-09', 'RB-LAT-06'], rule_ids: ['DET-ANOM'], group: 'detectors', name: 'Behaviour anomaly detector (DET-ANOM)', detector: 'DET-ANOM',
    what: `Compares each agent with its own ${BASELINE_DAYS}-day baseline of volume, cost, errors, time of day and tool mix. It needs ${MIN_BASELINE_DAYS} days and ${MIN_BASELINE_RECORDS} records before it counts. A High cost anomaly throttles T3/T4 agents, and it is the signal behind the runaway stop.`,
    effect: 'throttle', where: 'gateway', step: 5, source: 'DA 3', code: ['apps/gateway/src/anomaly.ts', 'packages/core/src/anomaly.ts'],
  },
  {
    key: 'det-ground', rulebook: ['RB-MOD-06'], rule_ids: ['DET-GROUND'], group: 'detectors', name: 'Groundedness review (DET-GROUND, offline)', detector: 'DET-GROUND',
    what: `A sample of answers that cite sources (${pct(Math.min(...Object.values(GUARDRAIL_PARAMS.grounding_sample_rates)))} to ${pct(Math.max(...Object.values(GUARDRAIL_PARAMS.grounding_sample_rates)))} by tier) is checked later by the cloud LLM acting as a judge. It produces findings for people and never changes a decision.`,
    effect: 'record', where: 'control_plane', source: 'DA 3, DA 5', code: ['apps/gateway/src/grounding.ts', 'apps/control/src/grounding.ts'],
  },
  {
    key: 'new-text-only', rulebook: ['RB-LAT-03'], rule_ids: ['RB-DET-05'], group: 'detectors', name: 'Detectors read new text only',
    what: 'Only the latest user message and the tool results after it are scored, so earlier turns are not scored again.',
    effect: 'detect', where: 'gateway', step: 8, source: 'Rulebook detectors', code: ['apps/gateway/src/policy.ts'],
  },
  {
    key: 'detector-pinning', rulebook: ['RB-MOD-01', 'RB-MOD-02', 'RB-MOD-07', 'RB-DET-04'], rule_ids: ['DA-6'], group: 'detectors', name: 'Detectors pinned, isolated and replayable',
    what: 'Each detector version is pinned by hash; a gateway running anything else treats the detector as unavailable. Detectors run in a separate process with no network, tools or memory. Every record keeps the version hash, score and thresholds, so Replay can reproduce the decision.',
    effect: 'record', where: 'gateway', source: 'DA 3, DA 6', code: ['apps/gateway/src/pins.ts', 'apps/gateway/src/detectors.ts', 'apps/control/src/replay.ts'],
  },
  {
    key: 'detector-promotion', rulebook: ['RB-DET-02'], rule_ids: ['RB-MOD-03', 'RB-INV-10', 'SGC-SELF-004'], group: 'detectors', name: 'New detector versions must earn their place',
    what: `A new detector version runs in shadow for ${GUARDRAIL_PARAMS.detector_shadow_days} days, must pass its benchmark and beat the current version, and needs Security and AI Assurance sign-off. Only a person can promote it.`,
    effect: 'refuse', where: 'control_plane', source: 'DA 6 mechanism 4', code: ['apps/control/src/detectors.ts', 'apps/control/src/benchmarks.ts'],
  },

  // --- Automatic stops and the response ladder --------------------------------------------------
  {
    key: 'kill-hijack', rule_ids: ['RB-KILL-01'], group: 'stops', name: 'Hijack stop',
    what: 'A privileged or critical action attempted after DET-INJ scored High on a tool response in the same session. The agent is killed (T1/T2) or paused (T3/T4).',
    effect: 'kill', where: 'gateway', step: 7, source: 'DA 4 kill conditions, BP 5.4', code: [TOOL, 'apps/gateway/src/toolreview.ts'],
  },
  {
    key: 'kill-exfiltration', rule_ids: ['RB-KILL-02'], group: 'stops', name: 'Exfiltration stop',
    what: 'Restricted data (secrets, card numbers, special-category or legal-privileged data) sent towards a model or tool the seal does not allow. The agent is killed. This is enforced even in shadow.',
    effect: 'kill', where: 'gateway', step: 8, source: 'DA 4 kill conditions', code: [CHAT, TOOL, MATRIX],
  },
  {
    key: 'kill-runaway', rule_ids: ['RB-KILL-03'], group: 'stops', name: 'Runaway stop',
    what: `Cost or volume above ${GUARDRAIL_PARAMS.runaway.limit_multiple * 100}% of a seal limit while DET-ANOM has been High for ${GUARDRAIL_PARAMS.runaway.anomaly_high_minutes} minutes. The agent is killed.`,
    effect: 'kill', where: 'gateway', step: 5, source: 'DA 4 kill conditions', code: [CTX, 'apps/gateway/src/anomaly.ts'],
  },
  {
    key: 'kill-repeat', rule_ids: ['RB-KILL-04'], group: 'stops', name: 'Repeat-violation stop',
    what: `${GUARDRAIL_PARAMS.out_of_manifest.attempts} out-of-seal attempts within ${GUARDRAIL_PARAMS.out_of_manifest.window_minutes} minutes. The agent is killed, even in shadow.`,
    effect: 'kill', where: 'gateway', step: 7, source: 'DA 4 kill conditions', code: [CTX, 'apps/gateway/src/limits.ts'],
  },
  {
    key: 'ladder', rulebook: ['RB-LAD-05'], rule_ids: [], group: 'stops', name: 'Response ladder',
    what: 'Six levels: block one request, step-up (extra checks for a time), throttle (lower limits for a time), quarantine (paused, tokens revoked), kill, and circuit breaker. Step-up and throttle end on their own; quarantine and kill do not.',
    effect: 'combine', where: 'control_plane', source: 'BP 5.4', code: [LADDER],
  },
  {
    key: 'stop-needs-rule', rule_ids: ['RB-INV-05'], group: 'stops', name: 'Every automatic stop cites a rule',
    what: 'An automatic step-up, throttle, quarantine or kill must name the rule that caused it, or it is refused.',
    effect: 'refuse', where: 'control_plane', source: 'Rulebook invariants, DA 2', code: [LADDER],
  },
  {
    key: 'kill-final', rule_ids: ['RB-INV-08'], group: 'stops', name: 'A kill is never lifted',
    what: 'A killed agent can come back only with a new seal, through the lifecycle again.',
    effect: 'refuse', where: 'control_plane', source: 'Rulebook invariants, BP 5.4', code: [LADDER, 'apps/gateway/src/state.ts'],
  },
  {
    key: 'human-release', rule_ids: ['RB-INV-10'], group: 'stops', name: 'Only people lift a pause',
    what: 'Releasing a quarantine goes through the approvals matrix (T1 needs Owner, Security and Risk). Machines cannot release agents or promote detectors.',
    effect: 'refuse', where: 'control_plane', source: 'Rulebook invariants, BP 7.2', code: ['apps/control/src/workflow.ts', 'apps/control/src/detectors.ts'],
  },
  {
    key: 'stop-everywhere', rule_ids: ['BP-5.4'], group: 'stops', name: 'Stops reach every gateway at once',
    what: `A kill or quarantine is pushed to every gateway node, which confirms it. Calls in flight and approval waits are cut, tokens are revoked, and gateways also re-read the bundle every ${GUARDRAIL_PARAMS.bundle_poll_seconds} seconds. Workloads linked on hosting platforms are stopped there too.`,
    effect: 'kill', where: 'control_plane', source: 'BP 5.4 kill mechanics', code: [LADDER, 'apps/control/src/hub.ts', 'apps/gateway/src/state.ts', 'apps/control/src/platforms.ts'],
  },
  {
    key: 'circuit-breaker', rule_ids: ['RB-KILL-13', 'BP-5.4-L6'], group: 'stops', name: 'Circuit breaker (people only)',
    what: 'Quarantine or kill every agent matching a selector (a tool, model version or tag) at once. Only a person can arm it, never a detector. There is no provider selector, because the one cloud LLM would match every agent.',
    effect: 'kill', where: 'control_plane', source: 'BP 5.4 level 6', code: [LADDER],
  },
  {
    key: 'ownerless', rulebook: ['RB-KILL-12'], rule_ids: ['BP-6-S7-OWNER'], group: 'stops', name: 'Agents without an owner are paused',
    what: `When an agent's owner leaves (from SCIM) and no new owner is named within ${GUARDRAIL_PARAMS.owner_grace_days} days, the agent is quarantined.`,
    effect: 'quarantine', where: 'control_plane', source: 'BP 6 Stage 7', code: ['apps/control/src/index.ts', 'apps/control/src/scim.ts'],
  },

  // --- Rollout ----------------------------------------------------------------------------------
  {
    key: 'shadow-canary', rule_ids: ['RB-INV-18'], group: 'rollout', name: 'Shadow and canary rollout',
    what: `A new seal starts in shadow: blocks are recorded as would_block and the call goes through, except kills, the circuit breaker, secrets exfiltration and the one-LLM rule. Canary then fully enforces a stable ${GUARDRAIL_PARAMS.deploy.canary_pct}% of sessions, then enforcement covers all.`,
    effect: 'record', where: 'gateway', step: 2, source: 'BP 6 Stage 6', code: [CTX, 'apps/control/src/workflow.ts'],
  },

  // --- The cloud LLM and credentials ------------------------------------------------------------
  {
    key: 'brokered-credentials', rulebook: ['RB-INV-03'], rule_ids: ['BP-5.2-11'], group: 'provider', name: 'Agents never hold real keys',
    what: 'LLM and tool credentials come from the Secrets Broker at call time and are attached by the gateway. An agent\'s own LLM gets only its own key. If a credential is unavailable, the call is refused.',
    effect: 'block', where: 'gateway', step: 11, source: 'BP 5.2 step 11', code: [TOOL, 'apps/gateway/src/provider.ts'],
  },
  {
    key: 'upstream-errors', rule_ids: ['BP-5.2-12'], group: 'provider', name: 'Errors from the LLM or a tool are passed back clearly',
    what: 'If the cloud LLM rejects a request, or a tool fails or returns an error, the agent gets a structured error with the reason. The ledger records it as an upstream error, not as a policy refusal.',
    effect: 'record', where: 'gateway', step: 12, source: 'BP 5.2 step 12', code: [CHAT, TOOL],
  },
  {
    key: 'provider-outage', rule_ids: ['RB-PROV-05', 'RB-PROV-04'], group: 'provider', name: 'Provider outages are not the agent\'s fault',
    what: `When the cloud LLM is down the agent gets 503 with retry-after ${GUARDRAIL_PARAMS.outage.retry_after_seconds} seconds, and it never counts against the agent. An outage is declared and recorded when over ${pct(GUARDRAIL_PARAMS.outage.agent_error_share)} of calls fail for at least ${pct(GUARDRAIL_PARAMS.outage.failing_agent_share)} of active agents (minimum ${GUARDRAIL_PARAMS.outage.min_failing_agents}) in ${GUARDRAIL_PARAMS.outage.bucket_minutes} minutes.`,
    effect: 'record', where: 'gateway', step: 12, source: 'Rulebook v0.2 provider rules', code: [CHAT, 'apps/gateway/src/outage.ts'],
  },
  {
    key: 'provider-terms', rule_ids: ['RB-PROV-03'], group: 'provider', name: 'Provider region and terms',
    what: 'The cloud LLM\'s region is shown as unverified until the provider terms record is checked; until then personal data stays tokenised.',
    effect: 'record', where: 'control_plane', source: 'Rulebook v0.2 provider rules', code: ['apps/control/src/tenant.ts'],
  },

  // --- Proof of every decision ------------------------------------------------------------------
  {
    key: 'no-record-no-answer', rule_ids: ['RB-INV-15'], group: 'evidence', name: 'No record, no answer',
    what: 'Every request, allowed or refused, is written to the ledger before the agent gets a reply. If the ledger cannot be reached, the agent gets 503 instead of an unrecorded answer.',
    effect: 'block', where: 'gateway', step: 14, source: 'Rulebook invariants, BP 8', code: [CTX, 'apps/gateway/src/ledgerclient.ts'],
  },
  {
    key: 'tamper-evident', rule_ids: [], group: 'evidence', name: 'Tamper-evident ledger',
    what: 'Each record\'s hash includes the previous record, so any edit or deletion breaks the chain. Each day is sealed with a signed Merkle root written once, and evidence packages can be verified offline with signet-verify.',
    effect: 'record', where: 'control_plane', source: 'BP 8.3', code: ['packages/core/src/ledger.ts', 'apps/control/src/ledger.ts', 'apps/control/src/evidence.ts'],
  },

  // --- Checks before an agent is approved -------------------------------------------------------
  {
    key: 'seal-model', rule_ids: ['RB-BL-01'], group: 'seal', name: 'A seal names at least one model',
    what: 'A seal with no model grant cannot be saved.',
    effect: 'refuse', where: 'control_plane', source: 'Rulebook baseline', code: [REGISTRY],
  },
  {
    key: 'impact-labels', rule_ids: ['RB-PRIV-01'], group: 'seal', name: 'Every action has an impact label',
    what: 'Each tool action in a seal must be labelled read, write, privileged or critical. The approval rules depend on the label.',
    effect: 'refuse', where: 'control_plane', source: 'Rulebook privileged actions', code: [REGISTRY],
  },
  {
    key: 'tier-ceilings', rulebook: ['RB-PRIV-06', 'RB-DATA-04'], rule_ids: ['RB-INV-17'], group: 'seal', name: 'What lower tiers may hold',
    what: 'T4 seals cannot contain privileged or critical actions, and only T1/T2 seals may allow restricted data classes.',
    effect: 'refuse', where: 'control_plane', source: 'Rulebook invariants', code: [REGISTRY],
  },
  {
    key: 'prohibited-use', rule_ids: ['RB-INV-13'], group: 'seal', name: 'Prohibited uses are rejected',
    what: 'An agent whose use is prohibited under the EU AI Act is rejected at Classify, with the reason recorded.',
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 2', code: ['apps/control/src/workflow.ts'],
  },
  {
    key: 'min-tier', rule_ids: ['RB-INV-14'], group: 'seal', name: 'Decisions about people are at least T2',
    what: 'Agents that make or shape decisions about a person\'s credit, employment, insurance, healthcare, education or access to essential services are classified T2 or higher.',
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 2', code: ['apps/control/src/workflow.ts'],
  },
  {
    key: 'separation-of-duties', rule_ids: ['RB-INV-09'], group: 'seal', name: 'Nobody approves their own agent',
    what: 'The proposer, the owner and the build team can never fill an independent approval slot for that agent.',
    effect: 'refuse', where: 'control_plane', source: 'BP 7.3', code: ['apps/control/src/approvals.ts', REGISTRY],
  },
  {
    key: 'approval-matrix', rule_ids: ['BP-7.2', 'BP-7', 'BP-6'], group: 'seal', name: 'Approval matrix and fresh sign-in',
    what: `Seals are issued only through the lifecycle. T4 is approved automatically when tests pass; T3 needs Owner and Security; T2 also Risk; T1 also a Governance Board quorum of ${GUARDRAIL_PARAMS.board_quorum}. T1/T2 decisions need a sign-in within the last ${GUARDRAIL_PARAMS.approval_reauth_seconds / 60} minutes.`,
    effect: 'refuse', where: 'control_plane', source: 'BP 7.2, BP 7.3', code: ['apps/control/src/approvals.ts', 'apps/control/src/workflow.ts'],
  },

  {
    key: 'ai-disclosure', rule_ids: [], rulebook: ['RB-BL-15'], group: 'seal', name: 'AI disclosure for user-facing agents',
    what: 'Seals carry an AI-disclosure flag, on by default, and a Signet Control checks that user-facing agents have it. The gateway does not yet add the flag to responses.',
    effect: 'record', where: 'control_plane', source: 'Rulebook, EU AI Act Art. 50', code: [REGISTRY, 'apps/control/src/controls.ts'],
  },

  // --- Onboarding gates ------------------------------------------------------------------------
  {
    key: 'gate-propose', rule_ids: ['BP-6-S1'], group: 'lifecycle', name: 'Propose: the basics are filled in',
    what: 'An agent leaves Propose only with a named owner and sponsor, a written purpose, an autonomy level, the users it affects and the data it touches.',
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 1', code: [WORKFLOW],
  },
  {
    key: 'gate-classify', rule_ids: ['BP-6-S2'], group: 'lifecycle', name: 'Classify: the right people set the tier',
    what: 'Only Risk/Compliance can override a classification factor, and must give a reason. T1/T2 classifications are confirmed by the risk team; T3/T4 by the owner or the risk team.',
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 2, BP 7.2', code: [WORKFLOW],
  },
  {
    key: 'gate-assess', rule_ids: ['BP-6-S3'], group: 'lifecycle', name: 'Assess: no open critical gaps',
    what: 'Assess ends only when the assessments required for the tier are complete, the manifest passes seal validation, no critical gap is open, and every high gap is mitigated or risk-accepted. Critical gaps can never be risk-accepted. The manifest can be changed only in Propose or Assess; later changes need a new version.',
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 3', code: [WORKFLOW],
  },
  {
    key: 'gate-test', rule_ids: ['BP-6-S4'], group: 'lifecycle', name: 'Test: the agent proves its behaviour',
    what: `Baseline suites run the agent's compiled policy and DLP against probes: every tool-misuse and argument-limit probe must be blocked, no data may leak and every approval rule must hold. T1/T2 also need a golden-set score of at least ${GUARDRAIL_PARAMS.functional_min_pct}% and must pass the live attack suites; agents that decide about people need a bias ratio within ${GUARDRAIL_PARAMS.bias_ratio.min}-${GUARDRAIL_PARAMS.bias_ratio.max}; T1 needs an independent red-team report.`,
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 4', code: [WORKFLOW, 'apps/control/src/attacklab.ts'],
  },
  {
    key: 'gate-deploy', rule_ids: ['BP-6-S6'], group: 'lifecycle', name: 'Deploy: shadow, then canary, then enforce',
    what: `Shadow runs for ${byTier(GUARDRAIL_PARAMS.deploy.shadow_days, 'day')}. ${GUARDRAIL_PARAMS.deploy.canary_tiers.join('/')} agents then run a canary on ${GUARDRAIL_PARAMS.deploy.canary_pct}% of sessions for at least ${GUARDRAIL_PARAMS.deploy.canary_min_days} ${GUARDRAIL_PARAMS.deploy.canary_min_days === 1 ? 'day' : 'days'} before full enforcement. Only the owner or Security moves a deployment forward, never while the agent is paused or stopped. Critical would-blocks seen in shadow must be explained first, and a canary with more than ${pct(GUARDRAIL_PARAMS.deploy.canary_max_error_share)} upstream errors (after ${GUARDRAIL_PARAMS.deploy.canary_min_transactions} calls) cannot move on.`,
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 6', code: [WORKFLOW],
  },
  {
    key: 'gate-monitor', rule_ids: ['BP-6-S7'], group: 'lifecycle', name: 'Monitor: re-attestation and changes',
    what: `Only the owner re-attests, confirming the purpose, a minimal manifest and accountability; a change in any of these needs a change request instead. Reminders go out ${GUARDRAIL_PARAMS.reattest_reminder_days.join(', ')} days before the seal expires, and inside ${GUARDRAIL_PARAMS.renewal_window_days} days an attestation renews it with the same manifest. An agent runs one lifecycle at a time. Only the sponsor or an approver names a new owner, who must be active in the identity provider.`,
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 7', code: [WORKFLOW, 'apps/control/src/scim.ts'],
  },
  {
    key: 'gate-retire', rule_ids: ['BP-6-S8'], group: 'lifecycle', name: 'Retire: a clean, recorded end',
    what: 'Only the owner or Security requests retirement, and it goes through approval. Retirement revokes the seal and every token, marks the tool credentials for rotation and records a decommission pack in the ledger. The Agent ID is never reused.',
    effect: 'refuse', where: 'control_plane', source: 'BP 6 Stage 8', code: [WORKFLOW],
  },

  // --- ServiceNow Guardian ----------------------------------------------------------------------
  {
    key: 'sn-input', rule_ids: ['SN-GUARD-INPUT'], group: 'servicenow', name: 'Guardian input must be valid',
    what: `ServiceNow must send non-empty text of at most ${formatBytes(GUARDRAIL_PARAMS.guardian_max_bytes)}. Content is never cut short, and the original text is not kept in the ledger.`,
    effect: 'block', where: 'gateway', step: 6, source: 'ServiceNow Guardian setup', code: ['apps/gateway/src/servicenow-guardian.ts'],
  },
  {
    key: 'sn-secrets', rule_ids: ['SN-GUARD-SECRET', 'SN-GUARD-CREDENTIAL-REQUEST'], group: 'servicenow', name: 'Secrets and credential requests',
    what: 'Content that contains a secret, or asks to reveal passwords, API keys or tokens (including Hindi phrasing), is flagged as a security issue.',
    effect: 'flag', where: 'gateway', step: 8, source: 'ServiceNow Guardian setup', code: ['apps/gateway/src/servicenow-guardian.ts'],
  },
  {
    key: 'sn-data', rule_ids: ['SN-GUARD-DATA'], group: 'servicenow', name: 'Data the agent may not handle',
    what: 'The agent\'s seal data rules apply to Guardian content as they do to prompts: card numbers, special-category data, legal privilege and other data classes the seal forbids are flagged. Guardian only flags; it does not tokenise or kill the agent, because ServiceNow\'s own model produced or received the text.',
    effect: 'flag', where: 'gateway', step: 8, source: 'ServiceNow Guardian setup', code: ['apps/gateway/src/servicenow-guardian.ts'],
  },
  {
    key: 'sn-attack', rule_ids: ['SN-GUARD-ATTACK'], group: 'servicenow', name: 'Prompt injection and jailbreak',
    what: 'ServiceNow sends its Prompt Injection checks to Signet. A prompt-attack judge (the cloud model with a fixed, hashed prompt) flags attempts to override the agent\'s instructions or switch off its safety rules. DET-INJ and DET-JB score the same content beside it and flag only once a person promotes them to active.',
    effect: 'flag', where: 'gateway', step: 8, source: 'ServiceNow Guardian setup', code: ['apps/gateway/src/servicenow-guardian.ts'],
  },
  {
    key: 'sn-safety', rule_ids: ['SN-GUARD-SAFETY'], group: 'servicenow', name: 'Unsafe content', detector: 'DET-SAFE',
    what: 'DET-SAFE reviews the content. Fraud and cyber abuse are flagged as security issues; the other unsafe categories as safety issues.',
    effect: 'flag', where: 'gateway', step: 8, source: 'ServiceNow Guardian setup', code: ['apps/gateway/src/servicenow-guardian.ts'],
  },
  {
    key: 'sn-unavailable', rule_ids: ['SN-GUARD-UNAVAILABLE'], group: 'servicenow', name: 'Withhold when the check cannot run',
    what: 'If the safety judge or the prompt-attack judge cannot answer, or the safety judge\'s pinned version does not match, the verdict is "inspection unavailable", so ServiceNow withholds the content (fail closed).',
    effect: 'flag', where: 'gateway', step: 8, source: 'ServiceNow Guardian setup', code: ['apps/gateway/src/servicenow-guardian.ts'],
  },
];

/** Guardrails that cite this rule ID (ledger records carry the IDs in policy_rule_ids). */
export const guardrailsForRule = (ruleId: string): Guardrail[] => {
  const base = ruleId.replace(/\.(tool|output|challenger)$/, '');
  return GUARDRAILS.filter((g) => g.rule_ids.includes(base));
};

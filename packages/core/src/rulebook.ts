// Signet Rulebook v0.1 (2026-10-28), the rule set Signet checks every agent against, with what the code
// enforces today. Text follows the Rulebook; coverage was checked against the code on 2026-11-19.
// The code also cites Rulebook v0.2 additions (RB-INV-19, RB-PROV-*, the D-17 one-LLM decision); the
// v0.2 document is not available, so those rules appear only in the guardrail catalogue.
//
// Coverage:
//   enforced   the code does what the rule says (the note explains any difference in strictness)
//   partial    part of the rule is built; the note says which part is missing
//   not_built  nothing in the code does this yet
//   guidance   describes process or sources, not something the product enforces

import { MIN_BASELINE_DAYS, MIN_BASELINE_RECORDS } from './anomaly';
import { GUARDRAIL_PARAMS } from './guardrail-params';

export type RuleStatus = 'defined' | 'proposed' | 'decision';
export type Coverage = 'enforced' | 'partial' | 'not_built' | 'guidance';

export interface RulebookRule {
  id: string;
  area: string;
  text: string;
  status: RuleStatus; // Rulebook label: Defined in a source doc, Proposed default, or a logged Decision
  coverage: Coverage;
  note?: string;
}

export const RULEBOOK = {
  title: 'Signet Rulebook',
  version: 'v0.1',
  date: '2026-10-28',
  basis: 'Built on the Blueprint (BP) and the Decision Architecture (DA). Where they conflict, DA wins on AI decisions, detectors and kill rules; BP wins everywhere else (D-13).',
} as const;

export const RULEBOOK_AREAS: readonly { id: string; title: string }[] = [
  { id: 'PREC', title: 'Precedence and combining rules' },
  { id: 'INV', title: 'Platform invariants' },
  { id: 'DATA', title: 'Data rules' },
  { id: 'PRIV', title: 'Privileged and critical actions' },
  { id: 'BL', title: 'Tenant baseline' },
  { id: 'DET', title: 'Detector bands and thresholds' },
  { id: 'MOD', title: 'Detector models' },
  { id: 'LAD', title: 'Response ladder and strikes' },
  { id: 'KILL', title: 'Escalation and kill' },
  { id: 'ANOM', title: 'Behaviour anomaly baseline' },
  { id: 'A2A', title: 'Agent-to-agent' },
  { id: 'LAT', title: 'Latency budget' },
];

const A2A_NOTE = 'There is no agent-to-agent endpoint yet.';
const STRIKES = 'There is no strike counter yet.';

const R = (id: string, status: RuleStatus, coverage: Coverage, text: string, note?: string): RulebookRule =>
  ({ id, area: id.split('-')[1]!, text, status, coverage, ...(note ? { note } : {}) });

export const RULEBOOK_RULES: readonly RulebookRule[] = [
  R('RB-PREC-01', 'defined', 'enforced', 'Default deny. Any model, tool, action, data class or environment not listed in the agent\'s seal is denied.'),
  R('RB-PREC-02', 'proposed', 'partial', 'Layer order: platform invariants, then tenant baseline, then business-unit policy, then the seal. A later layer can only narrow an earlier one.', 'There is no business-unit layer, and the input and cost caps always use the tenant value.'),
  R('RB-PREC-03', 'proposed', 'enforced', 'Deny overrides. If any layer or rule returns deny, the result is deny.'),
  R('RB-PREC-04', 'defined', 'enforced', 'Strictest outcome wins: kill, quarantine, deny, hold for approval, step-up, throttle, allow with obligations, allow.'),
  R('RB-PREC-05', 'proposed', 'partial', 'Strictest data action wins across layers: block, redact, tokenise, log_only, allow.', 'One data-class matrix decides each class and a seal can only tighten it; there is no merge across several layers.'),
  R('RB-PREC-06', 'proposed', 'partial', 'Lowest limit wins for any rate, token, cost, session or row limit.', 'Rate and daily limits come from the seal; the per-request input and cost caps come from the tenant only.'),
  R('RB-PREC-07', 'proposed', 'enforced', 'Obligations add up: every obligation from every layer applies.'),
  R('RB-PREC-08', 'proposed', 'enforced', 'Unparseable means deny: a request that cannot be normalised into a known action is denied and logged.'),
  R('RB-PREC-09', 'decision', 'guidance', 'Source precedence: DA wins on AI decisions, detectors and kill rules; the Blueprint wins everywhere else (D-13).'),

  R('RB-INV-01', 'defined', 'enforced', 'No valid, active, unexpired seal: no traffic.'),
  R('RB-INV-02', 'proposed', 'not_built', 'A seal is accepted only if its Seal Transparency Log inclusion proof verifies; until the log ships, only seals on the signed issuance list from the control plane.', 'Gateways accept seals signed by the tenant CA inside the signed policy bundle; there is no transparency log or separate issuance list.'),
  R('RB-INV-03', 'defined', 'enforced', 'Agents never hold real model or tool credentials. Static agent keys are allowed only in Dev and are flagged.', 'Real keys stay in the Secrets Broker; agents authenticate only with Signet credentials, in every environment.'),
  R('RB-INV-04', 'defined', 'enforced', 'Only rules can produce allow. Detector output can only keep or tighten a decision.'),
  R('RB-INV-05', 'defined', 'enforced', 'Every automatic kill references at least one deterministic rule ID. A detector score alone can at most quarantine.'),
  R('RB-INV-06', 'defined', 'enforced', 'Detector down, over budget or below its confidence floor: decide on rules only, and turn any T1/T2 allow into hold for approval.'),
  R('RB-INV-07', 'defined', 'not_built', 'A child agent never holds more permission than its parent\'s seal.', A2A_NOTE),
  R('RB-INV-08', 'defined', 'enforced', 'A kill is never lifted. Re-entry needs a new certificate through Stage 3 onward.'),
  R('RB-INV-09', 'defined', 'enforced', 'The proposer, builder or any build-team member can never approve that agent.', 'Single-operator installs record the waiver in each decision.'),
  R('RB-INV-10', 'defined', 'enforced', 'Lifting a quarantine, reversing a kill, loosening any threshold and promoting a detector version are human-only and ledgered.'),
  R('RB-INV-11', 'defined', 'enforced', 'A runtime HITL request that times out is rejected (configurable only for T4).', 'Timeout always rejects, for T4 as well.'),
  R('RB-INV-12', 'defined', 'not_built', 'T1 and T2 agents must be Enforced (all traffic through the gateway) to receive a seal.', 'Seal issue does not check how the agent is connected.'),
  R('RB-INV-13', 'defined', 'enforced', 'An EU AI Act prohibited use is rejected at Classify.'),
  R('RB-INV-14', 'defined', 'enforced', 'An agent that makes or materially influences decisions on credit, employment, insurance, healthcare, education or essential services is at least T2.'),
  R('RB-INV-15', 'defined', 'enforced', 'Every decision is written to the ledger before the response returns to the agent.'),
  R('RB-INV-16', 'proposed', 'enforced', 'Credentials and secrets never reach a model, in any tier, under any seal.'),
  R('RB-INV-17', 'proposed', 'enforced', 'A T4 seal cannot contain Restricted data classes or privileged tool actions; needing either forces reclassification.'),
  R('RB-INV-18', 'defined', 'enforced', 'Shadow mode never enforces anything except kill, circuit breaker and secrets-exfiltration blocks.', 'v0.2 also keeps the one-LLM rule enforced in shadow.'),

  R('RB-DATA-01', 'proposed', 'partial', 'Data tagged Personal or higher goes only to models whose region is inside the seal\'s regions and the tenant\'s residency setting.', 'The cloud LLM\'s region is unverified, so personal and financial data are always tokenised first (stricter); the region comparison itself is not built.'),
  R('RB-DATA-02', 'proposed', 'not_built', 'Confidential or higher data goes only to external models flagged zero-retention or covered by an approved data processing agreement.', 'Catalogue models have no zero-retention or DPA flag.'),
  R('RB-DATA-03', 'proposed', 'not_built', 'Restricted data from production never enters Dev or Test; detection there is a block.', 'Not found in the code.'),
  R('RB-DATA-04', 'proposed', 'partial', 'If a seal allows any Restricted tag, the Classify data-sensitivity factor must be 4 or 5; a mismatch blocks seal issue.', 'Classify scores sensitivity 5 when Restricted data is planned; no check blocks seal issue on a mismatch.'),
  R('RB-DATA-05', 'proposed', 'not_built', 'Any single response with more than 100 Personal records is held for approval on T1/T2 and logged on T3/T4.', 'Not found in the code.'),
  R('RB-DATA-06', 'defined', 'enforced', 'Detokenisation happens only in responses to the caller the seal authorises, never to other agents.', 'Tokens are restored only for the same agent and session.'),

  R('RB-PRIV-01', 'proposed', 'enforced', 'Every action in a seal must carry an impact label (read, write, privileged, critical); a seal with an unlabelled action cannot be issued.'),
  R('RB-PRIV-02', 'proposed', 'not_built', 'At Assess, Signet pre-labels actions from their names; Security confirms privileged labels, Security and Risk confirm critical labels (D-07).', 'Owners label actions themselves.'),
  R('RB-PRIV-03', 'proposed', 'enforced', 'Critical actions always require HITL on T1, T2 and T3.'),
  R('RB-PRIV-04', 'proposed', 'enforced', 'Privileged actions require HITL on T1 and T2, unless the seal sets a waiver (for example refunds under USD 100).'),
  R('RB-PRIV-05', 'proposed', 'enforced', 'Privileged actions on T3 run without HITL but count toward step-up after a detector Elevated signal in the same session.', 'Stricter: a tainted session holds privileged actions for a person on every tier (RB-BL-12).'),
  R('RB-PRIV-06', 'proposed', 'enforced', 'T4 seals contain read and write actions only.'),
  R('RB-PRIV-07', 'defined', 'enforced', 'Autonomy L0 and L1 agents need HITL for every write, privileged and critical action, whatever the tier.'),
  R('RB-PRIV-08', 'proposed', 'partial', 'Critical actions above USD 10,000 (or the seal\'s stated value) need two different approvers.', `The threshold is fixed at ${GUARDRAIL_PARAMS.dual_control_usd.toLocaleString('en-US')}; a value set in the seal is not used.`),

  R('RB-BL-01', 'proposed', 'enforced', 'The model must be on the tenant\'s approved model catalogue (provider, family, region).', 'The code cites this check as RB-INV-19 (v0.2) and uses RB-BL-01 for "a seal names at least one model".'),
  R('RB-BL-02', 'proposed', 'enforced', 'The model version must match the seal; a provider silently switching family is a deny.'),
  R('RB-BL-03', 'proposed', 'partial', 'Per-request input cap: 32,000 tokens unless the seal sets lower.', 'The tenant cap applies; a lower value in the seal is not read.'),
  R('RB-BL-04', 'proposed', 'partial', 'Per-request cost cap: USD 5 estimated cost unless the seal sets lower; hold for approval.', 'The tenant cap applies; a lower value in the seal is not read.'),
  R('RB-BL-05', 'proposed', 'partial', 'HTTP tools may reach only registered aliases; a raw URL in tool arguments only if its domain is on the tenant egress allow-list.', 'Registered aliases only; raw URLs inside arguments are not checked.'),
  R('RB-BL-06', 'proposed', 'partial', 'A static API key presented in Prod is refused, with a Discovery finding.', 'Anything that is not a Signet credential is refused in every environment; no Discovery finding is raised.'),
  R('RB-BL-07', 'proposed', 'not_built', 'Requests from a network range not listed in the seal\'s environments are refused.', 'Seals list environment names, not network ranges.'),
  R('RB-BL-08', 'proposed', 'partial', 'Data rules RB-DATA-01 to RB-DATA-05 apply to every request.', 'See each RB-DATA rule.'),
  R('RB-BL-09', 'proposed', 'enforced', 'HITL rules RB-PRIV-03, -04, -07 and -08 apply to every request.'),
  R('RB-BL-10', 'proposed', 'enforced', 'Responses are scanned for secrets and redacted, whatever the seal says.'),
  R('RB-BL-11', 'proposed', 'partial', 'Responses a person will see are scanned by DET-SAFE; hard categories (child sexual abuse material, mass-casualty weapons) are blocked at 0.5 or above in every tier.', 'DET-SAFE blocks unsafe categories on prompts and answers in every tier, but returns a label, not a score, so there is no separate hard-category threshold.'),
  R('RB-BL-12', 'proposed', 'enforced', 'Session taint: after a tool response or document scores Elevated or High on DET-INJ, every privileged or critical action in that session (max 60 minutes) needs HITL, on every tier.'),
  R('RB-BL-13', 'proposed', 'not_built', 'Re-sending a denied or rejected action with changed arguments within 5 minutes counts as a strike.', STRIKES),
  R('RB-BL-14', 'proposed', 'not_built', 'Agent-to-agent calls follow the RB-A2A rules.', A2A_NOTE),
  R('RB-BL-15', 'proposed', 'partial', 'Every response carries the AI-disclosure flag the seal requires for user-facing agents (EU AI Act Art. 50).', 'Seals carry the flag and a control checks it; the gateway does not add it to responses.'),
  R('RB-BL-16', 'proposed', 'enforced', 'Calls outside the seal\'s validity window, or after re-attestation is overdue, are refused.'),

  R('RB-DET-01', 'defined', 'not_built', 'Thresholds live in the seal as detector_thresholds, inherited from tier defaults; a seal may only make them stricter.', 'Thresholds are the tier defaults in code; seals have no detector_thresholds field.'),
  R('RB-DET-02', 'proposed', 'partial', 'Calibration: High at most 1% false positives on benign traffic, Elevated at most 3%; recall at High at least 0.90 for DET-INJ and DET-JB, or no promotion.', 'A benchmark gate blocks promotion; see each detector\'s Release panel for its targets.'),
  R('RB-DET-03', 'proposed', 'partial', 'A detector result counts as unavailable when it misses its latency budget, the language is not benchmarked, or the input was truncated.', 'The latency cap applies; language and truncation checks are not built.'),
  R('RB-DET-04', 'defined', 'enforced', 'Every ledger record holds each detector\'s version hash, raw score, band and thresholds.'),
  R('RB-DET-05', 'proposed', 'enforced', 'DET-INJ scores only text that is new in this turn.'),
  R('RB-DET-06', 'defined', 'guidance', 'Thresholds are reviewed after each 14-day shadow and each monthly drift review.'),

  R('RB-MOD-01', 'defined', 'enforced', 'Licence review first: each model\'s licence is checked for commercial use.', 'Each model release records its licence.'),
  R('RB-MOD-02', 'defined', 'enforced', 'Each detector version is pinned by hash in the policy bundle, and the ledger records the version that scored each action.'),
  R('RB-MOD-03', 'defined', 'enforced', 'Benchmark, 14-day shadow and champion/challenger apply before any model goes active, even an unchanged ready-made one.'),
  R('RB-MOD-04', 'decision', 'guidance', 'Fine-tuning on Signet red-team data starts when a ready-made model misses its targets, or in Phase 3; customer signals only with opt-in (D-14).'),
  R('RB-MOD-05', 'defined', 'guidance', 'English at launch; multilingual detectors are added per regional rollout, each with its own benchmark.', 'DET-SAFE already covers Hindi and Hinglish.'),
  R('RB-MOD-06', 'proposed', 'partial', 'The evaluator runs only offline on samples, never feeds the gateway, and goes through the gateway as a sealed agent.', 'Runs offline and never feeds the gateway, but calls the cloud LLM directly, not as a sealed agent.'),
  R('RB-MOD-07', 'defined', 'enforced', 'Detectors have no tool access, no network access, no memory between calls and no ability to act.'),

  R('RB-LAD-01', 'proposed', 'not_built', 'Each agent version has one strike counter over a sliding 10-minute window, also kept per instance.', STRIKES),
  R('RB-LAD-02', 'proposed', 'not_built', 'A strike is added for a rules deny with detector High, a Restricted DLP block not covered by kill rules, or an approval-bypass attempt.', STRIKES),
  R('RB-LAD-03', 'proposed', 'not_built', 'Strike thresholds: T1 step-up at 1, quarantine at 2; T2 at 2 and 3; T3/T4 at 3 and 5.', STRIKES),
  R('RB-LAD-04', 'proposed', 'not_built', 'A second require-approval-plus-High result for the same agent within 24 hours quarantines it.', 'Not found in the code.'),
  R('RB-LAD-05', 'defined', 'partial', 'Strikes and ladder events are written to the enforcement ledger with the rule ID, detector scores and window count.', 'Ladder events are recorded with their rule ID; there are no strikes to record.'),
  R('RB-LAD-06', 'proposed', 'not_built', 'An agent quarantined twice in 30 days for the same trigger must return to Assess before release.', 'Not found in the code.'),
  R('RB-LAD-07', 'decision', 'not_built', 'Cost above 150% of the daily limit: throttle; above 200%: throttle to 10% and alert Security (D-16).', 'Requests stop at the daily cost limit; DET-ANOM can throttle T3/T4 on a cost anomaly.'),

  R('RB-KILL-01', 'defined', 'enforced', 'Hijack: a privileged or critical action, including one already in flight, after DET-INJ High on a tool response in the same session. Kill T1/T2, quarantine T3/T4.', `A privileged action waits up to ${GUARDRAIL_PARAMS.hijack_verdict_wait_ms / 1000} seconds for a pending verdict before it is forwarded.`),
  R('RB-KILL-02', 'defined', 'enforced', 'Exfiltration: a Restricted tag sent to a destination the seal does not allow. Block and kill.'),
  R('RB-KILL-03', 'defined', 'enforced', 'Runaway: cost or volume above 200% of the seal limit while DET-ANOM has been High for 10 minutes. Kill.'),
  R('RB-KILL-04', 'defined', 'enforced', 'Repeat violation: 3 out-of-manifest attempts in 10 minutes. Kill.'),
  R('RB-KILL-05', 'proposed', 'not_built', 'Stolen identity: a token used from a network range outside the seal, or a revoked token replayed more than once. Kill.', 'Revoked tokens are refused, but replays do not trigger a kill.'),
  R('RB-KILL-06', 'proposed', 'not_built', 'A gateway-only key used from another address. Kill and rotate the key.', 'Not found in the code.'),
  R('RB-KILL-07', 'proposed', 'not_built', 'Seal forgery: a signed cert_id not in the Transparency Log. Deny, quarantine and raise a security incident.', 'Depends on RB-INV-02.'),
  R('RB-KILL-08', 'proposed', 'not_built', 'Strike threshold reached: step-up, then quarantine.', STRIKES),
  R('RB-KILL-09', 'decision', 'not_built', 'Cost over 150%: throttle; over 200%: throttle to 10% and alert (D-16).', 'See RB-LAD-07.'),
  R('RB-KILL-10', 'proposed', 'not_built', 'DET-ANOM High for 10 continuous minutes with no rule breach: step-up (T1/T2 quarantine).', 'Sustained High is used only by the runaway kill.'),
  R('RB-KILL-11', 'defined', 'enforced', 'Certificate expired or re-attestation missed: suspension (same effect as quarantine).'),
  R('RB-KILL-12', 'defined', 'enforced', 'Owner left and no reassignment within 10 business days: suspension.', `Cited in the ledger as BP-6-S7-OWNER; the grace period is ${GUARDRAIL_PARAMS.owner_grace_days} calendar days.`),
  R('RB-KILL-13', 'defined', 'enforced', 'Circuit breaker on a selector: quarantine or kill as chosen by a person; never automatic from a detector.', 'No provider selector, because the one cloud LLM would match every agent (v0.2 D-20).'),

  R('RB-ANOM-01', 'proposed', 'partial', 'Deviation = (value − median) / (1.4826 × MAD) for the same hour of week over 14 days.', 'Uses mean and standard deviation per hour of day.'),
  R('RB-ANOM-02', 'proposed', 'partial', 'Tool mix compared with the baseline using Jensen-Shannon divergence.', 'A rarely or never used tool raises the score; Jensen-Shannon is not used.'),
  R('RB-ANOM-03', 'proposed', 'enforced', 'Combined score = the highest feature deviation.'),
  R('RB-ANOM-04', 'proposed', 'partial', 'First-seen actions, destinations or data tags score Elevated at once; a first-seen privileged action on T1 scores High.', 'A never-used tool raises the score; destinations, data tags and the T1 rule are not built.'),
  R('RB-ANOM-05', 'proposed', 'partial', 'Warm-up: until 7 days or 1,000 actions in production, DET-ANOM is capped at Elevated.', `Needs ${MIN_BASELINE_DAYS} days and ${MIN_BASELINE_RECORDS} records; until then it reports unavailable.`),
  R('RB-ANOM-06', 'proposed', 'not_built', 'A minor version keeps its parent\'s baseline; a major version starts a new warm-up.', 'Not found in the code.'),
  R('RB-ANOM-07', 'decision', 'not_built', 'Poisoning guard: periods with strikes, blocks or ladder events are excluded; the baseline may move at most 10% a week on T1, 20% elsewhere (D-11).', 'Not found in the code.'),
  R('RB-ANOM-08', 'proposed', 'partial', 'Sustained High = High in at least 2 of every 3 five-minute buckets for 10 minutes.', `The runaway kill uses ${GUARDRAIL_PARAMS.runaway.anomaly_high_minutes} minutes of High.`),
  R('RB-ANOM-09', 'proposed', 'partial', 'DET-ANOM runs after the decision and changes state for the next request; it never delays the current one.', 'It is scored at step 5 of the current request.'),

  R('RB-A2A-01', 'defined', 'not_built', 'Both agents need an active seal and pass the full pipeline on their own side.', A2A_NOTE),
  R('RB-A2A-02', 'proposed', 'not_built', 'The caller\'s seal lists the callee as a tool; the callee\'s seal lists the caller in accepts_from.', A2A_NOTE),
  R('RB-A2A-03', 'proposed', 'not_built', 'The callee uses only data tags both seals allow and only its own tool actions.', A2A_NOTE),
  R('RB-A2A-04', 'proposed', 'not_built', 'A tainted caller session makes the callee\'s session start tainted.', A2A_NOTE),
  R('RB-A2A-05', 'proposed', 'not_built', 'At most 3 hops per trace (2 with a T1 agent); an agent appearing more than twice is a loop and denied.', A2A_NOTE),
  R('RB-A2A-06', 'defined', 'not_built', 'Only L4 agents may spawn or direct other agents; L3 may call but not spawn.', A2A_NOTE),
  R('RB-A2A-07', 'defined', 'not_built', 'A spawned child\'s seal is capped by its parent\'s and revoked with it.', A2A_NOTE),
  R('RB-A2A-08', 'proposed', 'not_built', 'caller_user_id passes down the chain; an approval for one agent does not carry to another.', A2A_NOTE),
  R('RB-A2A-09', 'proposed', 'not_built', 'Cost counts against both the callee and the originating agent.', A2A_NOTE),
  R('RB-A2A-10', 'defined', 'enforced', 'Calls to agents in another tenant are denied in v1.', 'Workload tokens are bound to this tenant, so another tenant\'s agent cannot call in.'),

  R('RB-LAT-01', 'proposed', 'enforced', 'Detectors run only after steps 1–7 pass; a request rules already denied is never scored.'),
  R('RB-LAT-02', 'proposed', 'partial', 'Inbound detectors run in parallel; DET-INJ and DET-JB share one model pass.', 'They run in parallel with the LLM call, as separate models.'),
  R('RB-LAT-03', 'proposed', 'enforced', 'DET-INJ scores only new text in the turn.'),
  R('RB-LAT-04', 'proposed', 'partial', 'DET-PII runs on every free-text payload for T1/T2; for T3/T4 only when pattern DLP finds nothing and the text is over 2 KB.', 'When deployed it runs on every prompt for every tier (stricter, slower).'),
  R('RB-LAT-05', 'proposed', 'partial', 'DET-SAFE runs on responses to people and all T1 responses, within 40 ms p95 on the outbound path, on a GPU pool if CPU cannot meet it.', 'DET-SAFE uses the cloud LLM, so it runs on every prompt and answer and does not meet this latency budget.'),
  R('RB-LAT-06', 'proposed', 'partial', 'DET-ANOM runs after the decision.', 'See RB-ANOM-09.'),
  R('RB-LAT-07', 'proposed', 'enforced', 'A detector that misses its budget is cut off and treated as unavailable; the request does not wait.'),
];

export const RULEBOOK_DECISIONS: readonly { id: string; question: string; decided: string }[] = [
  { id: 'D-01', question: 'Which kill rules apply', decided: 'DA 4\'s four kill rules, plus three identity and seal kill rules (RB-KILL-05 to -07)' },
  { id: 'D-02', question: 'Hijack kill rarely reachable for T1/T2', decided: 'Keep quarantine on tool-response High; RB-KILL-01 also fires on a privileged call already in flight' },
  { id: 'D-03', question: 'Non-English traffic', decided: 'English at launch; non-English T1/T2 traffic held for approval until multilingual detectors ship' },
  { id: 'D-04', question: 'Outbound DET-SAFE latency', decided: 'Its own 40 ms p95 budget on the outbound path; GPU pool if CPU cannot meet it' },
  { id: 'D-05', question: 'Strike thresholds', decided: 'As in RB-LAD-03; out-of-manifest attempts go to RB-KILL-04 instead' },
  { id: 'D-06', question: 'Money thresholds in templates', decided: 'USD 100 / 1,000 / 10,000; tune with the first design partners' },
  { id: 'D-07', question: 'Who confirms impact labels', decided: 'Security for privileged; Security and Risk/Compliance for critical' },
  { id: 'D-08', question: 'Seal trust before the Transparency Log ships', decided: 'Signed issuance list from the control plane' },
  { id: 'D-09', question: 'Layer precedence', decided: 'Deny overrides; later layers only narrow' },
  { id: 'D-10', question: 'Controls catalogue', decided: 'The Rulebook catalogue is the base; merge if a fuller list is found' },
  { id: 'D-11', question: 'Baseline poisoning guard', decided: '10% per week on T1, 20% on other tiers' },
  { id: 'D-12', question: 'Secrets to models', decided: 'Fixed invariant (RB-INV-16), not configurable' },
  { id: 'D-13', question: 'Which doc wins in a conflict', decided: 'DA for AI decisions, detectors and kill rules; the Blueprint for everything else' },
  { id: 'D-14', question: 'Detector models', decided: 'Ready-made models at launch; fine-tuning (E39) later' },
  { id: 'D-15', question: 'Evaluator model', decided: 'The customer\'s approved model through Signet' },
  { id: 'D-16', question: 'Cost over 200%', decided: 'Throttle to 10% and alert, not quarantine' },
];

export const rulebookRule = (id: string): RulebookRule | undefined => RULEBOOK_RULES.find((r) => r.id === id);

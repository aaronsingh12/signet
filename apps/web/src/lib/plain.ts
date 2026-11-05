// Plain-language wording for what the backend records. Rule IDs stay in the technical details.

export const RISK_LABEL: Record<string, string> = { T1: 'Critical risk', T2: 'High risk', T3: 'Moderate risk', T4: 'Low risk' };
export const isHighRisk = (tier: string | null | undefined) => tier === 'T1' || tier === 'T2';

// Shown wherever a T1/T2 hold can surprise someone (DA 2 fail safe, RB-INV-06).
export const DETECTOR_HOLD_NOTE = 'Some of Signet\'s automatic safety detectors are not running yet. Until they are, high and critical risk agents wait for a person on each new conversation. Choosing "Allow for 8 hours in this conversation" keeps a conversation moving.';

const OUTCOME: Record<string, string> = {
  out_of_manifest: 'This action is not on the list you approved. Nothing was carried out.',
  policy_denied: 'A safety rule refused this action. Nothing was carried out.',
  data_blocked: 'It contained information this agent may not send, so it was stopped.',
  data_exfiltration: 'It tried to send restricted information, so Signet stopped the agent.',
  hijack_detected: 'It tried an important action right after receiving a suspicious instruction, so Signet stopped it.',
  response_withheld: 'The request looked like an attempt to manipulate the agent, so the answer was withheld.',
  agent_killed: 'This agent has been killed.',
  agent_quarantined: 'This agent is quarantined and needs a review.',
  rate_limited: 'The agent went over its requests-per-minute limit.',
  token_budget_exhausted: 'The agent has used its daily usage limit.',
  cost_budget_exhausted: 'The agent has used its daily spending limit.',
  approval_timeout: 'Nobody decided in time, so the request was refused.',
  approval_rejected: 'A person refused this request.',
  approval_pending: 'This is waiting for a person to decide.',
  no_active_seal: 'This agent has no active seal.',
  seal_expired: 'This agent\'s seal has expired.',
  invalid_token: 'The request did not come with a valid key.',
  token_expired: 'The key used for this request has expired.',
  token_revoked: 'The key used for this request has been cancelled.',
  unauthenticated: 'The request did not include a key.',
  upstream_unavailable: 'The AI service was unavailable. This is not a safety problem.',
  tool_unavailable: 'The connected app did not respond. This is not a safety problem.',
};

export function explainRecord(d: { error_code?: string | null; policy_decision?: string; reasons?: string[]; would_block?: unknown[] }): string {
  if (d.error_code && OUTCOME[d.error_code]) return OUTCOME[d.error_code]!;
  if (d.error_code) return 'Signet did not complete this request. Technical details are below.';
  if (d.policy_decision === 'would_block') return 'In shadow mode this went through, but it would be blocked or held once enforcing.';
  if (d.policy_decision === 'allow_with_obligations') return 'Allowed, with sensitive details hidden or a limit applied.';
  if (d.policy_decision === 'allow') return 'Allowed. Every check passed.';
  return 'Recorded by Signet.';
}

export function riskReasons(intake: { users_affected?: string[]; data_touched?: string[]; decisions_about_individuals?: boolean; reversibility?: string; planned_tools?: string[] }, autonomy: string): string[] {
  const out: string[] = [];
  const users = intake.users_affected ?? [];
  if (users.includes('public')) out.push('It reaches the public');
  else if (users.includes('customers')) out.push('It talks to your customers');
  else if (users.length) out.push('It is used by your own employees');
  const data = intake.data_touched ?? [];
  if (data.some((t) => t === 'payment_card' || t === 'special_category')) out.push('It can see highly sensitive information');
  else if (data.some((t) => t === 'personal' || t === 'financial_account')) out.push('It can see personal or account details');
  else if (data.length) out.push('It can see confidential material');
  if (intake.decisions_about_individuals) out.push('It makes or shapes decisions about people');
  if (/critical|payment|refund|payout|delete|grant|deploy/i.test((intake.planned_tools ?? []).join(' '))) out.push('It can take high-impact actions in other apps');
  if (intake.reversibility === 'no') out.push('Its mistakes cannot be undone');
  else if (intake.reversibility === 'partly') out.push('Its mistakes can only be partly undone');
  if (autonomy === 'L3' || autonomy === 'L4') out.push('It acts without asking first');
  return out;
}

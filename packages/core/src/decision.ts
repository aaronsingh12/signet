// Strictest outcome wins (RB-PREC-04). Index 0 is strictest.
export const STRICTNESS = [
  'kill',
  'quarantine',
  'deny',
  'require_approval',
  'step_up',
  'throttle',
  'allow_with_obligations',
  'allow',
] as const;

export type Outcome = (typeof STRICTNESS)[number];

export const strictest = (...outcomes: Outcome[]): Outcome =>
  outcomes.reduce((a, b) => (STRICTNESS.indexOf(a) <= STRICTNESS.indexOf(b) ? a : b), 'allow');

// shadow: the detector scored, but it is not yet promoted, so it cannot change the decision.
// pending: scoring runs alongside the request and its verdict applies to the session afterwards.
export type DetectorStatus = 'ok' | 'shadow' | 'unavailable' | 'pending';

export interface DetectorResult {
  id: string;
  version: string;
  status: DetectorStatus;
  score?: number;
  band?: 'low' | 'elevated' | 'high';
}

// Decision combiner (DA 2, E37). Only the rule result can allow; detectors only tighten it.
// Fail safe (RB-INV-06): a detector that is unavailable leaves the rule result in force, and
// turns an allow on a T1/T2 agent into hold for approval.
export function combine(rule: Outcome, detectors: DetectorResult[], tier: 'T1' | 'T2' | 'T3' | 'T4'): { outcome: Outcome; reasons: string[] } {
  const reasons: string[] = [];
  let outcome = rule;
  const highRisk = tier === 'T1' || tier === 'T2';
  const allows = (o: Outcome) => o === 'allow' || o === 'allow_with_obligations';
  for (const d of detectors) {
    if (d.status !== 'ok') {
      if (highRisk && allows(rule)) {
        outcome = strictest(outcome, 'require_approval');
        reasons.push(`${d.id} ${d.status === 'shadow' ? 'in shadow' : 'unavailable'}: ${tier} allow held for approval (RB-INV-06)`);
      }
      continue;
    }
    if (d.band === 'elevated' && allows(rule)) {
      outcome = strictest(outcome, highRisk ? 'require_approval' : 'step_up');
      reasons.push(`${d.id} elevated (DA 4)`);
    }
    if (d.band === 'high') {
      if (allows(rule)) outcome = strictest(outcome, highRisk ? 'quarantine' : 'require_approval');
      reasons.push(`${d.id} high (DA 4)`);
    }
  }
  return { outcome, reasons };
}

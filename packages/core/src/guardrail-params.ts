import type { Tier } from './types';

// The fixed numbers behind Signet's guardrails, in one place. Enforcement code reads them from here and
// the guardrail catalogue (guardrails.ts) quotes them, so the Guardrails page can never show a different
// number from the one enforced. Tenant-tunable values (input and cost caps, hold time) live in tenant
// settings instead and are shown live. policy/signet.rego cannot import this file; the guardrail test
// checks that its copy of dual_control_usd matches.

export const GUARDRAIL_PARAMS = {
  // Identity and policy bundle
  bundle_ttl_hours: 24, // gateways keep enforcing the last bundle this long without contact (BP 3)
  bundle_poll_seconds: 5, // fallback re-read of the bundle (BP 5.4)
  unsigned_recorded_per_minute: 20, // ledger records per address per minute for calls without a valid token

  // Scope and tools
  out_of_manifest: { attempts: 3, window_minutes: 10 }, // RB-KILL-04
  tool_response_max_bytes: 5 * 1024 * 1024,
  tool_timeout_ms: 30_000,

  // Approvals
  dual_control_usd: 10_000, // RB-PRIV-08; also in policy/signet.rego
  session_grant_hours: 8, // "approve for this session" (BP 7.4)
  approval_reauth_seconds: 300, // T1/T2 decisions need a sign-in this recent (BP 7.3)
  board_quorum: 2, // AI Governance Board approvers needed for a T1 seal (BP 7.2)
  session_taint_minutes: 60, // RB-BL-12
  hijack_verdict_wait_ms: 5_000, // a privileged action waits this long for a pending DET-INJ verdict (RB-KILL-01)

  // Stops and the ladder
  runaway: { limit_multiple: 2, anomaly_high_minutes: 10 }, // RB-KILL-03: over 200% of a seal limit, DET-ANOM High 10 min
  ladder: {
    step_up_minutes: { T1: 60, T2: 60, T3: 30, T4: 30 } as Record<Tier, number>,
    throttle: { T1: { factor: 0.25, minutes: 60 }, T2: { factor: 0.25, minutes: 60 }, T3: { factor: 0.5, minutes: 30 }, T4: { factor: 0.5, minutes: 30 } } as Record<Tier, { factor: number; minutes: number }>,
  },
  owner_grace_days: 14, // RB-KILL-12: 10 business days

  // Provider outage (RB-PROV-04, RB-PROV-05)
  outage: { bucket_minutes: 5, agent_error_share: 0.2, failing_agent_share: 0.3, min_failing_agents: 3, retry_after_seconds: 30 },

  // Detectors
  detector_shadow_days: 14, // RB-MOD-03
  grounding_sample_rates: { T1: 0.05, T2: 0.02, T3: 0.01, T4: 0.01 } as Record<Tier, number>, // DET-GROUND

  // Onboarding lifecycle (BP 6)
  deploy: {
    shadow_days: { T1: 14, T2: 7, T3: 3, T4: 1 } as Record<Tier, number>,
    canary_tiers: ['T1', 'T2'] as Tier[],
    canary_pct: 10,
    canary_min_days: 1,
    canary_max_error_share: 0.05,
    canary_min_transactions: 20,
  },
  functional_min_pct: 85, // golden-set accuracy for T1/T2 (BP 6 Stage 4)
  bias_ratio: { min: 0.8, max: 1.25 },
  reattest_reminder_days: [30, 14, 7],
  renewal_window_days: 30,

  // ServiceNow Guardian
  guardian_max_bytes: 65_536,
} as const;

/** "5 MB", "64 KB": for messages and the catalogue. */
export const formatBytes = (n: number): string => (n >= 1024 * 1024 && n % (1024 * 1024) === 0 ? `${n / (1024 * 1024)} MB` : n % 1024 === 0 ? `${n / 1024} KB` : `${n} bytes`);
/** 0.05 -> "5%" */
export const pct = (share: number): string => `${Math.round(share * 1000) / 10}%`;

import { canonicalize, sha256, type CertificateBody, type CompiledAction, type CompiledPolicy } from '@signet/core';
import type { TenantSettings } from './tenant';

// Policy compiler (BP 3 C7, E07): turns an approved seal into the decision data the gateway's
// policy engine evaluates. The seal carries the hash of this output, so a gateway can prove it is
// enforcing exactly what was approved.
export function compilePolicy(cert: Omit<CertificateBody, 'policy_sha256'>, baseline: TenantSettings['baseline']): CompiledPolicy {
  const actions: Record<string, CompiledAction> = {};
  for (const t of cert.tools) {
    for (const a of t.actions) {
      const key = `${t.server}.${a.name}`;
      actions[key] = {
        key,
        impact: a.impact,
        value_threshold_usd: a.value_threshold_usd ?? null,
        value_arg: a.value_arg ?? null,
        constraints: a.constraints ?? {},
        data_scopes: t.data_scopes ?? [],
        hitl: cert.hitl.filter((h) => h.action === key).map((h) => ({ arg: h.arg ?? null, gt: h.gt ?? null, approver_group: h.approver_group })),
      };
    }
  }
  return {
    cert_id: cert.cert_id,
    agent_id: cert.agent_id,
    version: cert.version,
    tier: cert.tier,
    autonomy_level: cert.autonomy_level,
    models: cert.models.map((m) => m.model),
    actions,
    prompt_tags: cert.data_classes.prompt,
    forbidden_tags: cert.data_classes.forbidden,
    max_input_tokens: baseline.max_input_tokens,
    max_cost_per_request_usd: baseline.max_cost_per_request_usd,
  };
}

export const policyHash = (p: CompiledPolicy) => sha256(canonicalize(p));

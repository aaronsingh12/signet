export type Tier = 'T1' | 'T2' | 'T3' | 'T4';
export type Autonomy = 'L0' | 'L1' | 'L2' | 'L3' | 'L4';
export type Impact = 'read' | 'write' | 'privileged' | 'critical';

// Data tags (BP 6 Stage 2; Rulebook data-class matrix).
export type DataTag =
  | 'secrets' | 'payment_card' | 'special_category' | 'legal_privileged'
  | 'financial_account' | 'personal' | 'source_code' | 'confidential_doc';

export const DATA_TAGS: readonly DataTag[] = ['secrets', 'payment_card', 'special_category', 'legal_privileged', 'financial_account', 'personal', 'source_code', 'confidential_doc'];
export const RESTRICTED_TAGS: readonly DataTag[] = ['secrets', 'payment_card', 'special_category', 'legal_privileged'];

// The one cloud LLM (Rulebook v0.2, D-17). Every seal's models[] must point into this catalogue.
export interface CatalogueModel {
  model: string; // name agents send, e.g. gpt-oss:120b-cloud
  upstream_model: string; // name the provider reports back; anything else is family drift (RB-BL-02)
  family: string;
  region: string; // 'unverified' until the provider terms record is checked (RB-PROV-03)
  code_approved: boolean;
  price_per_1k_usd: { in: number; out: number };
}

export interface ModelGrant {
  model: string; // glob over catalogue names
  region: string;
  max_tokens?: number;
}

// Argument constraints on a tool action (BP 4.3 tools[].constraints).
export interface ArgConstraint {
  max?: number;
  min?: number;
  enum?: (string | number)[];
  pattern?: string;
  max_length?: number;
}

export interface ToolAction {
  name: string;
  impact: Impact; // RB-PRIV-01
  value_threshold_usd?: number; // RB-PRIV-04 waiver / RB-PRIV-08 dual control
  value_arg?: string; // which argument carries the money amount
  constraints?: Record<string, ArgConstraint>;
}

export interface ToolGrant {
  server: string; // mcp://<alias> or http://<alias>
  actions: ToolAction[];
  data_scopes?: DataTag[]; // tags this tool may receive in arguments
}

// Machine HITL rule compiled into the seal (BP 4.3 hitl[]).
export interface HitlRule {
  action: string; // server.action, e.g. mcp://orders.issue_refund
  arg?: string;
  gt?: number;
  approver_group: string;
}

export interface Limits {
  rpm: number;
  tokens_per_day: number;
  usd_per_day: number;
  tool_calls_per_session?: number;
}

// Agent Certificate, the seal (BP 4.3 + Rulebook v0.2 seal schema). models[] carries no provider.
export interface CertificateBody {
  cert_id: string;
  agent_id: string;
  version: string;
  tenant: string;
  owner: string;
  approvers: { user: string; at: string }[];
  tier: Tier;
  autonomy_level: Autonomy;
  models: ModelGrant[];
  tools: ToolGrant[];
  data_classes: { prompt: DataTag[]; forbidden: DataTag[] };
  hitl: HitlRule[];
  limits: Limits;
  environments: string[];
  tags: string[];
  ai_disclosure: boolean;
  policy_sha256: string; // hash of the compiled policy the gateway enforces
  valid_from: string;
  valid_to: string;
  issued_at: string;
}

// Seal compiled for the gateway's policy engine (E07 policy compiler).
export interface CompiledAction {
  key: string; // <server>.<action>
  impact: Impact;
  value_threshold_usd: number | null;
  value_arg: string | null;
  constraints: Record<string, ArgConstraint>;
  data_scopes: DataTag[];
  hitl: { arg: string | null; gt: number | null; approver_group: string }[];
}

export interface CompiledPolicy {
  cert_id: string;
  agent_id: string;
  version: string;
  tier: Tier;
  autonomy_level: Autonomy;
  models: string[];
  actions: Record<string, CompiledAction>;
  prompt_tags: DataTag[];
  forbidden_tags: DataTag[];
  max_input_tokens: number;
  max_cost_per_request_usd: number;
}

// Workload token claims (BP 4.2).
export interface WorkloadClaims {
  sub: string;
  agent_id: string;
  ver: string;
  cert_id: string;
  ins: string;
  tier: Tier;
  tenant: string;
  iat: number;
  exp: number;
  jti: string;
}

export type EnforcementLevel = 'active' | 'step_up' | 'throttled' | 'quarantined' | 'killed';

export interface ScopeState {
  level: EnforcementLevel;
  until_ms?: number | null;
  factor?: number; // throttle: share of seal limits still allowed
}

export interface ToolAlias {
  alias: string;
  kind: 'mcp' | 'http';
  url: string;
  secret_id: string | null;
  auth_header: string;
  actions: Record<string, { method: string; path: string }>; // http tools only
}

export type DetectorMode = 'off' | 'shadow' | 'active';

export interface DetectorConfig {
  id: string;
  version: string;
  mode: DetectorMode;
}

// Signed policy bundle the control plane pushes to every gateway node.
export interface PolicyBundle {
  bundle_id: string;
  version: number;
  tenant: string;
  issued_at: string;
  expires_at: string;
  certificates: string[]; // JWS seals, each verified again by the gateway
  policies: Record<string, CompiledPolicy>; // by cert_id
  enforcement: Record<string, ScopeState>; // by scope key
  revoked_jti: string[];
  catalogue: CatalogueModel[];
  tools: ToolAlias[];
  detectors: DetectorConfig[];
}

export const scopeKey = {
  agent: (agentId: string) => `agent:${agentId}`,
  version: (agentId: string, version: string) => `version:${agentId}@${version}`,
  instance: (instanceId: string) => `instance:${instanceId}`,
};

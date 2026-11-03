/** PostgreSQL application schema, including append-only evidence constraints. */
export const SCHEMA_SQL = `

CREATE TABLE IF NOT EXISTS tenant (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  settings TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS session (
  id_hash TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  principal TEXT NOT NULL,
  id_token TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vercel_connection (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenant(id),
  principal_id TEXT NOT NULL,
  vercel_user_id TEXT NOT NULL,
  email TEXT,
  name TEXT,
  access_token_sealed TEXT NOT NULL,
  refresh_token_sealed TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, principal_id)
);

CREATE TABLE IF NOT EXISTS idempotency_key (
  key TEXT NOT NULL,
  principal TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status BIGINT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (key, principal)
);

CREATE TABLE IF NOT EXISTS agent (
  connection_method TEXT,
  vendor_details TEXT NOT NULL DEFAULT '{}',
  vendor TEXT,
  model_provider TEXT,
  framework TEXT,
  runtime TEXT,
  kind TEXT NOT NULL DEFAULT 'self_hosted',
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenant(id),
  handle TEXT NOT NULL,
  name TEXT NOT NULL,
  purpose TEXT NOT NULL,
  owner TEXT NOT NULL,
  sponsor TEXT NOT NULL,
  tier TEXT NOT NULL,
  autonomy_level TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  UNIQUE (tenant_id, handle)
);

CREATE TABLE IF NOT EXISTS agent_team_member (
  agent_id TEXT NOT NULL REFERENCES agent(id),
  "user" TEXT NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (agent_id, "user")
);

CREATE TABLE IF NOT EXISTS certificate (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agent(id),
  version TEXT NOT NULL,
  body TEXT NOT NULL,
  jws TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_to TEXT NOT NULL,
  issued_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bootstrap_credential (
  environment TEXT NOT NULL DEFAULT 'dev',
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL UNIQUE,
  agent_id TEXT NOT NULL REFERENCES agent(id),
  cert_id TEXT NOT NULL REFERENCES certificate(id),
  issued_by TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS agent_instance (
  revoked_at TEXT,
  auth_kind TEXT NOT NULL DEFAULT 'bootstrap',
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agent(id),
  cert_id TEXT NOT NULL,
  version TEXT NOT NULL,
  env TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  state TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issued_token (
  jti TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  exp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_jti (
  jti TEXT PRIMARY KEY,
  exp BIGINT NOT NULL
);

-- Ladder state per scope (BP 4.1: a kill targets an instance, a version or the whole agent).
-- scope_key: agent:<agent_id> | version:<agent_id>@<version> | instance:<instance_id>
CREATE TABLE IF NOT EXISTS enforcement_state (
  scope_key TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  level TEXT NOT NULL,
  rule_id TEXT,
  reason TEXT,
  until_ms BIGINT,
  params TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enforcement_event (
  id TEXT PRIMARY KEY,
  agent_id TEXT,
  scope_key TEXT NOT NULL,
  level TEXT NOT NULL,
  rule_id TEXT,
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  published_at TEXT NOT NULL,
  published_ms BIGINT NOT NULL,
  nodes_expected BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS kill_ack (
  event_id TEXT NOT NULL REFERENCES enforcement_event(id),
  gateway_node_id TEXT NOT NULL,
  acked_at TEXT NOT NULL,
  latency_ms BIGINT NOT NULL,
  PRIMARY KEY (event_id, gateway_node_id)
);

CREATE TABLE IF NOT EXISTS circuit_breaker (
  id TEXT PRIMARY KEY,
  selector TEXT NOT NULL,
  action TEXT NOT NULL,
  armed_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  matched TEXT NOT NULL,
  armed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_node (
  llm_status TEXT,
  id TEXT PRIMARY KEY,
  url TEXT,
  last_seen TEXT NOT NULL,
  bundle_version BIGINT
);

-- Secrets Broker (BP 3 C9): values sealed with AES-256-GCM; never returned by any API.
CREATE TABLE IF NOT EXISTS secret (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  sealed TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  version BIGINT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  rotated_at TEXT,
  rotation_due TEXT,
  UNIQUE (tenant_id, name)
);

-- Tool aliases (BP 5.1): agents call /v1/mcp/<alias> or /v1/tools/http/<alias>; the real address
-- and its credential live here.
CREATE TABLE IF NOT EXISTS tool (
  runner_id TEXT,
  alias TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  url TEXT NOT NULL,
  secret_id TEXT REFERENCES secret(id),
  auth_header TEXT NOT NULL,
  actions TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS discovered_asset (
  agent_id TEXT,
  owner_hint TEXT,
  evidence TEXT NOT NULL DEFAULT '{}',
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source TEXT NOT NULL,
  type TEXT NOT NULL,
  summary TEXT NOT NULL,
  location TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  status TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  resolved_by TEXT,
  UNIQUE (tenant_id, fingerprint, location)
);

CREATE TABLE IF NOT EXISTS detector (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  model_sha256 TEXT,
  mode TEXT NOT NULL,
  shadow_since TEXT,
  promoted_by TEXT,
  promoted_at TEXT,
  notes TEXT
);

-- Append-only ledger (BP 12): application code only ever inserts; triggers refuse edits.
CREATE TABLE IF NOT EXISTS ledger_record (
  erasure_proof TEXT,
  seq BIGINT PRIMARY KEY,
  record_id TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  ts TEXT NOT NULL,
  agent_id TEXT,
  cert_id TEXT,
  data TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  record_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ledger_agent ON ledger_record(agent_id, seq);
CREATE INDEX IF NOT EXISTS ledger_kind ON ledger_record(kind, seq);
CREATE INDEX IF NOT EXISTS ledger_ts ON ledger_record(ts);

CREATE OR REPLACE FUNCTION signet_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END;
$$;
CREATE OR REPLACE TRIGGER ledger_no_update BEFORE UPDATE ON ledger_record FOR EACH ROW EXECUTE FUNCTION signet_append_only();
CREATE OR REPLACE TRIGGER ledger_no_delete BEFORE DELETE ON ledger_record FOR EACH ROW EXECUTE FUNCTION signet_append_only();
CREATE OR REPLACE TRIGGER ledger_no_truncate BEFORE TRUNCATE ON ledger_record FOR EACH STATEMENT EXECUTE FUNCTION signet_append_only();

-- Signed daily Merkle roots (BP 8.3), also written to the WORM evidence store.
CREATE TABLE IF NOT EXISTS daily_root (
  day TEXT PRIMARY KEY,
  first_seq BIGINT NOT NULL,
  last_seq BIGINT NOT NULL,
  count BIGINT NOT NULL,
  merkle_root TEXT NOT NULL,
  jws TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE OR REPLACE TRIGGER root_no_update BEFORE UPDATE ON daily_root FOR EACH ROW EXECUTE FUNCTION signet_append_only();
CREATE OR REPLACE TRIGGER root_no_delete BEFORE DELETE ON daily_root FOR EACH ROW EXECUTE FUNCTION signet_append_only();
CREATE OR REPLACE TRIGGER root_no_truncate BEFORE TRUNCATE ON daily_root FOR EACH STATEMENT EXECUTE FUNCTION signet_append_only();

CREATE TABLE IF NOT EXISTS evidence_object (
  tenant_id TEXT NOT NULL,
  path TEXT NOT NULL,
  content TEXT NOT NULL,
  PRIMARY KEY (tenant_id, path)
);
CREATE OR REPLACE FUNCTION signet_evidence_root_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.path LIKE 'roots/%' THEN RAISE EXCEPTION 'evidence roots are append-only'; END IF;
  RETURN NEW;
END;
$$;
CREATE OR REPLACE TRIGGER evidence_no_root_update BEFORE UPDATE ON evidence_object FOR EACH ROW EXECUTE FUNCTION signet_evidence_root_immutable();
CREATE OR REPLACE TRIGGER evidence_no_delete BEFORE DELETE ON evidence_object FOR EACH ROW EXECUTE FUNCTION signet_append_only();
CREATE OR REPLACE TRIGGER evidence_no_truncate BEFORE TRUNCATE ON evidence_object FOR EACH STATEMENT EXECUTE FUNCTION signet_append_only();


-- One lifecycle per agent version being onboarded (BP 6). data holds intake, manifest draft and deploy plan.
CREATE TABLE IF NOT EXISTS lifecycle (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agent(id),
  kind TEXT NOT NULL,                 -- initial | major | minor
  stage TEXT NOT NULL,
  status TEXT NOT NULL,               -- in_progress | complete | rejected | retired
  data TEXT NOT NULL,
  started_at TEXT NOT NULL,
  stage_entered_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS lifecycle_agent ON lifecycle(agent_id);

CREATE TABLE IF NOT EXISTS stage_record (
  id TEXT PRIMARY KEY,
  lifecycle_id TEXT NOT NULL REFERENCES lifecycle(id),
  stage TEXT NOT NULL,
  outcome TEXT NOT NULL,              -- passed | returned | rejected | skipped
  actor TEXT NOT NULL,
  gate TEXT NOT NULL,
  entered_at TEXT NOT NULL,
  exited_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS classification (
  lifecycle_id TEXT PRIMARY KEY REFERENCES lifecycle(id),
  factors TEXT NOT NULL,
  score DOUBLE PRECISION NOT NULL,
  tier TEXT NOT NULL,
  regulatory_category TEXT NOT NULL,
  frameworks TEXT NOT NULL,
  reasons TEXT NOT NULL,
  overrides TEXT NOT NULL,
  confirmed_by TEXT,
  confirmed_at TEXT
);

CREATE TABLE IF NOT EXISTS assessment (
  id TEXT PRIMARY KEY,
  lifecycle_id TEXT NOT NULL REFERENCES lifecycle(id),
  type TEXT NOT NULL,                 -- questionnaire | threat_model | impact | dpia | vendor_risk
  status TEXT NOT NULL,               -- draft | complete
  content TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (lifecycle_id, type)
);

CREATE TABLE IF NOT EXISTS gap (
  id TEXT PRIMARY KEY,
  lifecycle_id TEXT NOT NULL REFERENCES lifecycle(id),
  agent_id TEXT NOT NULL,
  control_id TEXT,
  severity TEXT NOT NULL,             -- critical | high | medium | low
  title TEXT NOT NULL,
  mitigation TEXT,
  status TEXT NOT NULL,               -- open | mitigated | accepted | closed
  acceptance_request_id TEXT,
  accepted_until TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS test_run (
  id TEXT PRIMARY KEY,
  lifecycle_id TEXT NOT NULL REFERENCES lifecycle(id),
  status TEXT NOT NULL,               -- passed | failed
  suites TEXT NOT NULL,
  report_sha256 TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Approvals engine (BP 7): one table for every decision type.
CREATE TABLE IF NOT EXISTS approval_request (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,                 -- certificate | risk_acceptance | runtime_hitl | quarantine_release | retirement
  agent_id TEXT,
  subject_ref TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  pack TEXT NOT NULL,
  pack_hash TEXT NOT NULL,
  slots TEXT NOT NULL,                -- [{slot, label, roles[], count, owner_only, sod}]
  tier TEXT,
  status TEXT NOT NULL,               -- pending | approved | rejected | sent_back | expired | cancelled
  outcome TEXT,
  sla_due TEXT NOT NULL,
  escalation BIGINT NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS approval_status ON approval_request(status, type);

CREATE TABLE IF NOT EXISTS approval_decision (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL REFERENCES approval_request(id),
  approver TEXT NOT NULL,
  slot TEXT NOT NULL,
  delegate_of TEXT,
  decision TEXT NOT NULL,
  comment TEXT,
  conditions TEXT,
  auth_strength TEXT NOT NULL,
  pack_hash TEXT NOT NULL,
  ts TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delegation (
  id TEXT PRIMARY KEY,
  from_user TEXT NOT NULL,
  to_user TEXT NOT NULL,
  from_date TEXT NOT NULL,
  to_date TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Runtime HITL "approve for this session" grants (BP 7.4).
CREATE TABLE IF NOT EXISTS hitl_grant (
  session_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  action_key TEXT NOT NULL,
  request_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (session_id, agent_id, action_key)
);

CREATE TABLE IF NOT EXISTS attestation (
  id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  type TEXT NOT NULL,                 -- re_attestation | decommission
  signer TEXT NOT NULL,
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  signed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification (
  id TEXT PRIMARY KEY,
  recipient TEXT NOT NULL,            -- "user" id, or role:<role>
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  link TEXT,
  created_at TEXT NOT NULL,
  read_at TEXT
);
CREATE INDEX IF NOT EXISTS notification_recipient ON notification(recipient, read_at);

-- Control library (BP 9): Signet Controls are the hub; framework requirements map to them.
CREATE TABLE IF NOT EXISTS framework (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  licence TEXT NOT NULL,
  namespace TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS framework_requirement (
  id TEXT PRIMARY KEY,
  framework_id TEXT NOT NULL REFERENCES framework(id),
  external_id TEXT NOT NULL,
  summary TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS control (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  objective TEXT NOT NULL,
  test TEXT NOT NULL,
  test_type TEXT NOT NULL,            -- automated | semi_automated | manual
  applies_to TEXT NOT NULL,
  namespace TEXT NOT NULL,
  severity TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS control_mapping (
  requirement_id TEXT NOT NULL REFERENCES framework_requirement(id),
  control_id TEXT NOT NULL REFERENCES control(id),
  relationship TEXT NOT NULL,
  PRIMARY KEY (requirement_id, control_id)
);
CREATE TABLE IF NOT EXISTS control_result (
  control_id TEXT NOT NULL REFERENCES control(id),
  scope TEXT NOT NULL,                -- tenant | agent:<id>
  status TEXT NOT NULL,               -- effective | partially_effective | ineffective | not_tested
  detail TEXT NOT NULL,
  evaluated_at TEXT NOT NULL,
  PRIMARY KEY (control_id, scope)
);

-- Connectors (BP 10, 11): outbound events go through an outbox with retry and dead letters.
CREATE TABLE IF NOT EXISTS connector (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,                 -- servicenow
  name TEXT NOT NULL,
  config TEXT NOT NULL,
  secret_id TEXT,
  status TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_sync_at TEXT,
  watermark TEXT
);
CREATE TABLE IF NOT EXISTS connector_outbox (
  id TEXT PRIMARY KEY,
  connector_id TEXT NOT NULL REFERENCES connector(id),
  event TEXT NOT NULL,
  object_key TEXT NOT NULL,           -- correlation: signet:<tenant>:<object>:<id>
  payload TEXT NOT NULL,
  status TEXT NOT NULL,               -- pending | sent | dead
  attempts BIGINT NOT NULL DEFAULT 0,
  next_at BIGINT NOT NULL,
  last_error TEXT,
  external_ref TEXT,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE INDEX IF NOT EXISTS outbox_due ON connector_outbox(status, next_at);
CREATE TABLE IF NOT EXISTS connector_mapping (
  connector_id TEXT NOT NULL,
  object_key TEXT NOT NULL,
  table_name TEXT NOT NULL,
  sys_id TEXT NOT NULL,
  PRIMARY KEY (connector_id, object_key)
);


-- Third-party agents (vendor-hosted) cannot hold a bootstrap credential: the vendor platform calls
-- Signet tools with OAuth client credentials. Only the secret's hash is stored.
CREATE TABLE IF NOT EXISTS agent_client (
  environment TEXT,
  client_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agent(id),
  secret_hash TEXT NOT NULL,
  label TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT
);
-- What the SDK or sidecar saw in the agent's runtime at start-up (names only, never values).
CREATE TABLE IF NOT EXISTS agent_diagnostic (
  instance_id TEXT PRIMARY KEY REFERENCES agent_instance(id),
  agent_id TEXT NOT NULL,
  client TEXT NOT NULL,               -- e.g. signet-python/0.1.0, signet-sidecar/0.1.0
  report TEXT NOT NULL,
  bypass_risk BIGINT NOT NULL,
  reported_at TEXT NOT NULL
);
-- Discovery sources and when each last delivered data (Key Sweep, network logs, SaaS audit logs, SDK).
CREATE TABLE IF NOT EXISTS discovery_source (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  last_ingest_at TEXT,
  last_count BIGINT NOT NULL DEFAULT 0,
  total BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS deployment_credential (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenant(id),
  secret_hash TEXT NOT NULL UNIQUE,
  agent_id TEXT NOT NULL REFERENCES agent(id),
  cert_id TEXT NOT NULL REFERENCES certificate(id),
  instance_id TEXT NOT NULL REFERENCES agent_instance(id),
  environment TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS edge_runner (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenant(id), name TEXT NOT NULL,
  secret_hash TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  last_seen_at TEXT, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS edge_job (
  id TEXT PRIMARY KEY, runner_id TEXT NOT NULL REFERENCES edge_runner(id),
  agent_id TEXT NOT NULL REFERENCES agent(id) ON DELETE CASCADE,
  cert_id TEXT NOT NULL, instance_id TEXT NOT NULL, jti TEXT NOT NULL, token_exp BIGINT NOT NULL,
  alias TEXT NOT NULL, action TEXT NOT NULL, args_json TEXT NOT NULL,
  state TEXT NOT NULL, result_json TEXT, error TEXT, expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS edge_job_queue ON edge_job(runner_id, state, expires_at);
-- Platform connectors (Vercel, AWS, Azure, Google ...): the API credential lives in the Secrets Broker.
CREATE TABLE IF NOT EXISTS platform_connection (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenant(id), platform TEXT NOT NULL,
  label TEXT NOT NULL, secret_id TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL, status_detail TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
  last_scan_at TEXT, last_scan_count INTEGER NOT NULL DEFAULT 0, revoked_at TEXT
);
-- A workload on a platform (a Vercel project, a Lambda function) linked to a Signet agent.
CREATE TABLE IF NOT EXISTS platform_link (
  id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenant(id),
  connection_id TEXT NOT NULL REFERENCES platform_connection(id) ON DELETE CASCADE,
  workload_id TEXT NOT NULL, workload_name TEXT NOT NULL,
  agent_id TEXT NOT NULL REFERENCES agent(id) ON DELETE CASCADE,
  credential_id TEXT, settings TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL, detail TEXT, deployment_id TEXT, created_by TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (connection_id, workload_id)
);
-- Usage reported by a platform (OpenAI and Anthropic usage APIs): AI use outside Signet, per day.
CREATE TABLE IF NOT EXISTS platform_usage (
  connection_id TEXT NOT NULL REFERENCES platform_connection(id) ON DELETE CASCADE,
  workload_id TEXT NOT NULL, day TEXT NOT NULL, requests BIGINT NOT NULL DEFAULT 0,
  input_tokens BIGINT NOT NULL DEFAULT 0, output_tokens BIGINT NOT NULL DEFAULT 0, cost_usd DOUBLE PRECISION,
  PRIMARY KEY (connection_id, workload_id, day)
);
`;

export const SCHEMA_TABLES: ReadonlySet<string> = new Set([...SCHEMA_SQL.matchAll(/CREATE TABLE IF NOT EXISTS ([a-z_]+)/g)].map((match) => match[1]!));

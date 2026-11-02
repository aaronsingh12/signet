import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DATA_DIR } from '@signet/core';

// Dev profile: embedded SQLite (BP 2, 15.1). Production profiles use Postgres 16 with the same schema.
// Every table that holds tenant data carries tenant_id (BP 12); Phase 1 runs one tenant per install.
mkdirSync(DATA_DIR, { recursive: true });
export const db = new DatabaseSync(process.env.SIGNET_DB ?? join(DATA_DIR, 'signet.db'));

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

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

CREATE TABLE IF NOT EXISTS idempotency_key (
  key TEXT NOT NULL,
  principal TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (key, principal)
);

CREATE TABLE IF NOT EXISTS agent (
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
  user TEXT NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (agent_id, user)
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
  id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL UNIQUE,
  agent_id TEXT NOT NULL REFERENCES agent(id),
  cert_id TEXT NOT NULL REFERENCES certificate(id),
  issued_by TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS agent_instance (
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
  exp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_jti (
  jti TEXT PRIMARY KEY,
  exp INTEGER NOT NULL
);

-- Ladder state per scope (BP 4.1: a kill targets an instance, a version or the whole agent).
-- scope_key: agent:<agent_id> | version:<agent_id>@<version> | instance:<instance_id>
CREATE TABLE IF NOT EXISTS enforcement_state (
  scope_key TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  level TEXT NOT NULL,
  rule_id TEXT,
  reason TEXT,
  until_ms INTEGER,
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
  published_ms INTEGER NOT NULL,
  nodes_expected INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kill_ack (
  event_id TEXT NOT NULL REFERENCES enforcement_event(id),
  gateway_node_id TEXT NOT NULL,
  acked_at TEXT NOT NULL,
  latency_ms INTEGER NOT NULL,
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
  id TEXT PRIMARY KEY,
  url TEXT,
  last_seen TEXT NOT NULL,
  bundle_version INTEGER
);

-- Secrets Broker (BP 3 C9): values sealed with AES-256-GCM; never returned by any API.
CREATE TABLE IF NOT EXISTS secret (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  sealed TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  version INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  rotated_at TEXT,
  rotation_due TEXT,
  UNIQUE (tenant_id, name)
);

-- Tool aliases (BP 5.1): agents call /v1/mcp/<alias> or /v1/tools/http/<alias>; the real address
-- and its credential live here.
CREATE TABLE IF NOT EXISTS tool (
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
  seq INTEGER PRIMARY KEY,
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

CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger_record
BEGIN SELECT RAISE(ABORT, 'ledger_record is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger_record
BEGIN SELECT RAISE(ABORT, 'ledger_record is append-only'); END;

-- Signed daily Merkle roots (BP 8.3), also written to the WORM evidence store.
CREATE TABLE IF NOT EXISTS daily_root (
  day TEXT PRIMARY KEY,
  first_seq INTEGER NOT NULL,
  last_seq INTEGER NOT NULL,
  count INTEGER NOT NULL,
  merkle_root TEXT NOT NULL,
  jws TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS root_no_update BEFORE UPDATE ON daily_root
BEGIN SELECT RAISE(ABORT, 'daily_root is append-only'); END;
CREATE TRIGGER IF NOT EXISTS root_no_delete BEFORE DELETE ON daily_root
BEGIN SELECT RAISE(ABORT, 'daily_root is append-only'); END;
`);

// --- Phase 2: lifecycle, approvals, control library, connectors ---
db.exec(`
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
  score REAL NOT NULL,
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
  escalation INTEGER NOT NULL DEFAULT 0,
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
  recipient TEXT NOT NULL,            -- user id, or role:<role>
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
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL,
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
`);

// Columns added after a table first shipped. SQLite has no ADD COLUMN IF NOT EXISTS, so each is
// added once, checked against the live schema; existing rows take the default.
function addColumn(table: string, column: string, ddl: string) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  if (!cols.some((c) => c.name === column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`);
}

// --- Agent connectivity: agent kind and runtime, third-party clients, connection diagnostics ---
addColumn('agent', 'kind', "TEXT NOT NULL DEFAULT 'self_hosted'"); // self_hosted | framework | no_code | third_party
addColumn('agent', 'runtime', 'TEXT'); // where it runs: runpod, aws_ec2, docker, kubernetes, on_prem, vendor ...
addColumn('agent', 'framework', 'TEXT'); // langchain, langgraph, crewai, n8n, flowise, dify, custom ...
addColumn('agent', 'model_provider', 'TEXT'); // the provider the agent was built against before Signet
addColumn('agent', 'vendor', 'TEXT'); // third-party agents: Amazon, OpenAI, Microsoft, Salesforce ...
addColumn('agent', 'vendor_details', "TEXT NOT NULL DEFAULT '{}'"); // contract, contact, data residency, documentation links
addColumn('bootstrap_credential', 'environment', "TEXT NOT NULL DEFAULT 'dev'");
addColumn('agent_instance', 'auth_kind', "TEXT NOT NULL DEFAULT 'bootstrap'"); // bootstrap | client_credentials
addColumn('agent_instance', 'revoked_at', 'TEXT');
addColumn('gateway_node', 'llm_status', 'TEXT'); // the node's last check of the cloud LLM (JSON)
addColumn('discovered_asset', 'evidence', "TEXT NOT NULL DEFAULT '{}'"); // what was seen, where, by which source
addColumn('discovered_asset', 'owner_hint', 'TEXT'); // user or host the activity came from
addColumn('discovered_asset', 'agent_id', 'TEXT'); // a registered agent the finding concerns, if any
db.exec(`
-- Third-party agents (vendor-hosted) cannot hold a bootstrap credential: the vendor platform calls
-- Signet tools with OAuth client credentials. Only the secret's hash is stored.
CREATE TABLE IF NOT EXISTS agent_client (
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
  bypass_risk INTEGER NOT NULL,
  reported_at TEXT NOT NULL
);
-- Discovery sources and when each last delivered data (Key Sweep, network logs, SaaS audit logs, SDK).
CREATE TABLE IF NOT EXISTS discovery_source (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  last_ingest_at TEXT,
  last_count INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL DEFAULT 0
);
`);

// WAL with synchronous=NORMAL syncs at checkpoints; a checkpoint every 2 s keeps committed records
// durable within the 2 s the Blueprint allows (BP 2 NFR "durable within 2 s"). A failed checkpoint is
// retried on the next tick; it never stops the writer.
let checkpointErrors = 0;
setInterval(() => {
  try {
    db.exec('PRAGMA wal_checkpoint(PASSIVE)');
  } catch (e) {
    if (++checkpointErrors % 10 === 1) console.error(`[control] WAL checkpoint failed (${checkpointErrors}): ${(e as Error).message}`);
  }
}, 2_000).unref();

export const nowIso = () => new Date().toISOString();

let depth = 0;
export function tx<T>(fn: () => T): T {
  if (depth > 0) return fn(); // nested calls join the outer transaction
  db.exec('BEGIN IMMEDIATE');
  depth++;
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  } finally {
    depth--;
  }
}

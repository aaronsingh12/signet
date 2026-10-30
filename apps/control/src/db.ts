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

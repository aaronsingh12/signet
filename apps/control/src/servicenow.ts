import { newId, request } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, invalid, notFound } from './errors';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { putSecret, revealForGateway } from './secrets';
import { tenant } from './tenant';

// ServiceNow connector, Standard mode (BP 10.1-10.4, 10.9, E14). Runs inside Signet and calls the
// customer instance over the Table API and the Identification and Reconciliation API. ServiceNow is
// never a dependency: a failing connector never blocks enforcement, lifecycle or kills.

interface Config {
  instance_url: string;
  auth: 'oauth_client_credentials' | 'basic';
  client_id?: string;
  username?: string;
  // AI Control Tower installed on the instance (found by the self-test): agents go into its AI tables.
  aict?: boolean;
}

interface ConnectorRow {
  id: string;
  type: string;
  name: string;
  config: string;
  secret_id: string | null;
  status: string;
  last_sync_at: string | null;
  watermark: string | null;
}

// AI Control Tower's inventory tables (AI system digital asset, AI function CI, asset-CI relationship).
const AICT_TABLES = ['alm_ai_system_digital_asset', 'cmdb_ci_function_ai', 'cmdb_rel_asset_ci'];
const REQUIRED_TABLES = ['sn_risk_risk', 'sn_grc_issue', 'incident', 'cmdb_ci_appl', 'sn_grc_indicator_result', 'sn_compliance_control_test', 'sn_compliance_authority_document', 'sn_compliance_citation'];
const MAX_ATTEMPTS = 10;

const getRow = async (id: string) => {
  const r = (await db.prepare('SELECT * FROM connector WHERE id = ?').get(id)) as ConnectorRow | undefined;
  if (!r) throw notFound(`connector ${id}`);
  return { ...r, config: JSON.parse(r.config) as Config };
};

export async function create(input: Config & { name?: string; secret: string }, p: Principal) {
  let url: URL;
  try {
    url = new URL(input.instance_url);
  } catch {
    throw invalid('instance_url is not a valid URL');
  }
  if (!['oauth_client_credentials', 'basic'].includes(input.auth)) throw invalid('auth must be oauth_client_credentials or basic');
  if (input.auth === 'oauth_client_credentials' && !input.client_id) throw invalid('client_id is required');
  if (input.auth === 'basic' && !input.username) throw invalid('username is required');
  const id = newId('evt').replace('evt_', 'con_');
  // The client secret or password lives only in the Secrets Broker (BP 10.2).
  const secret = (await putSecret({ name: `servicenow-${id.slice(-8).toLowerCase()}`, kind: 'tool', value: input.secret }, p));
  const config: Config = { instance_url: url.toString().replace(/\/$/, ''), auth: input.auth, client_id: input.client_id, username: input.username };
  (await db.prepare('INSERT INTO connector (id, type, name, config, secret_id, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, 'servicenow', input.name ?? url.hostname, JSON.stringify(config), secret.id, 'configured', p.id, nowIso()));
  (await ledger.append({ kind: 'admin', data: { event: 'connector.created', connector_id: id, type: 'servicenow', instance: url.origin, auth: input.auth, basic_auth_warning: input.auth === 'basic' ? 'Basic auth is for proof of concept only (BP 10.2)' : null, actor: p.id } }));
  return (await view(id));
}

const tokens = new Map<string, { token: string; exp: number }>();

async function authHeader(c: Awaited<ReturnType<typeof getRow>>): Promise<string> {
  const secret = (await revealForGateway(c.secret_id!)).value;
  if (c.config.auth === 'basic') return `Basic ${Buffer.from(`${c.config.username}:${secret}`).toString('base64')}`;
  const cached = tokens.get(c.id);
  if (cached && cached.exp > Date.now() + 30_000) return `Bearer ${cached.token}`;
  const r = await request(`${c.config.instance_url}/oauth_token.do`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: c.config.client_id!, client_secret: secret }).toString(),
    timeoutMs: 10_000,
  });
  if (!r.ok) throw new Error(`OAuth token request failed (${r.status})`);
  const j = r.json<{ access_token: string; expires_in?: number }>();
  tokens.set(c.id, { token: j.access_token, exp: Date.now() + (j.expires_in ?? 1800) * 1000 });
  return `Bearer ${j.access_token}`;
}

async function call(c: Awaited<ReturnType<typeof getRow>>, method: string, path: string, body?: unknown) {
  const r = await request(`${c.config.instance_url}${path}`, {
    method,
    headers: { authorization: await authHeader(c), accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    timeoutMs: 15_000,
  });
  if (r.status === 429) throw new Error('rate limited by the instance (429)');
  if (!r.ok) throw new Error(`${method} ${path.split('?')[0]} returned ${r.status}`);
  return r.status === 204 ? {} : r.json<Record<string, unknown>>();
}

// Self-test (BP 10.2): confirms authentication and every table the connector writes or reads.
export async function selfTest(id: string, p: Principal) {
  const c = (await getRow(id));
  const checks: { check: string; ok: boolean; detail: string }[] = [];
  try {
    await authHeader(c);
    checks.push({ check: 'authentication', ok: true, detail: c.config.auth });
    const res = (await call(c, 'GET', `/api/now/table/sys_db_object?sysparm_query=nameIN${[...REQUIRED_TABLES, ...AICT_TABLES].join(',')}&sysparm_fields=name&sysparm_limit=100`)) as { result: { name: string }[] };
    const found = new Set(res.result.map((t) => t.name));
    for (const t of REQUIRED_TABLES) checks.push({ check: `table ${t}`, ok: found.has(t), detail: found.has(t) ? 'present' : 'missing on this instance' });
    // Optional: with AI Control Tower, agents are written to its AI inventory instead of generic applications.
    const aict = AICT_TABLES.every((t) => found.has(t));
    checks.push({ check: 'AI Control Tower inventory', ok: true, detail: aict ? 'present: agents sync as AI systems' : 'not installed: agents sync as applications (cmdb_ci_appl)' });
    (await db.prepare('UPDATE connector SET config = ? WHERE id = ?').run(JSON.stringify({ ...c.config, aict }), id));
  } catch (e) {
    checks.push({ check: 'authentication', ok: false, detail: (e as Error).message });
  }
  const ok = checks.every((x) => x.ok);
  (await db.prepare('UPDATE connector SET status = ? WHERE id = ?').run(ok ? 'active' : 'error', id));
  (await ledger.append({ kind: 'admin', data: { event: 'connector.self_test', connector_id: id, ok, checks, actor: p.id } }));
  return { ok, checks, connector: (await view(id)) };
}

// --- outbound (BP 10.4) ---

interface OutboxRow {
  id: string;
  connector_id: string;
  event: string;
  object_key: string;
  payload: string;
  attempts: number;
}

const mapping = async (connectorId: string, key: string) => (await db.prepare('SELECT table_name, sys_id FROM connector_mapping WHERE connector_id = ? AND object_key = ?').get(connectorId, key)) as { table_name: string; sys_id: string } | undefined;
const remember = async (connectorId: string, key: string, table: string, sysId: string) =>
  (await db.prepare('INSERT INTO connector_mapping (connector_id, object_key, table_name, sys_id) VALUES (?, ?, ?, ?) ON CONFLICT (connector_id, object_key) DO UPDATE SET table_name = EXCLUDED.table_name, sys_id = EXCLUDED.sys_id').run(connectorId, key, table, sysId));

async function upsert(c: Awaited<ReturnType<typeof getRow>>, table: string, key: string, values: Record<string, unknown>) {
  // Idempotency: the correlation key maps to the record created first; retries update it (BP 10.4).
  const m = (await mapping(c.id, key));
  if (m) {
    await call(c, 'PATCH', `/api/now/table/${table}/${m.sys_id}`, values);
    return m.sys_id;
  }
  const r = (await call(c, 'POST', `/api/now/table/${table}`, { ...values, correlation_id: key })) as { result: { sys_id: string } };
  (await remember(c.id, key, table, r.result.sys_id));
  return r.result.sys_id;
}

async function send(c: Awaited<ReturnType<typeof getRow>>, row: OutboxRow): Promise<string> {
  const p = JSON.parse(row.payload) as Record<string, string | number | boolean | null | string[]>;
  const priority = (sev: unknown) => ({ critical: '1', high: '2', medium: '3', low: '4' })[String(sev)] ?? '3';
  switch (row.event) {
    case 'risk.upsert':
      return (await upsert(c, 'sn_risk_risk', row.object_key, { name: `AI agent ${p.handle}`, statement: p.statement, description: `Signet tier ${p.tier}, score ${p.score}, ${p.regulatory_category}`, owner: p.owner, inherent_rating: { T1: 'Very High', T2: 'High', T3: 'Moderate' }[String(p.tier)] ?? 'Low' }));
    case 'issue.upsert':
      return (await upsert(c, 'sn_grc_issue', row.object_key, { short_description: `[Signet] ${String(p.title).slice(0, 150)}`, description: JSON.stringify(p), priority: priority(p.severity), state: p.state === 'open' ? 'open' : p.state === 'accepted' ? 'risk_accepted' : 'closed' }));
    case 'incident.create': {
      const existing = (await mapping(c.id, row.object_key));
      if (existing) return existing.sys_id;
      const urgency = p.tier === 'T1' || p.tier === 'T2' ? '1' : '2';
      const r = (await call(c, 'POST', '/api/now/table/incident', { short_description: `[Signet] Agent ${p.level} (${p.rule_id ?? 'manual'})`, description: `${p.reason}\nActor: ${p.actor}\nLadder event: ${p.event_id}\nEvidence: Signet ledger`, urgency, impact: urgency, category: 'AI Agent', correlation_id: row.object_key })) as { result: { sys_id: string } };
      (await remember(c.id, row.object_key, 'incident', r.result.sys_id));
      return r.result.sys_id;
    }
    case 'ci.upsert': {
      if (c.config.aict) {
        // AI Control Tower: the agent is an AI function CI plus an AI system digital asset, related.
        const ci = (await call(c, 'POST', '/api/now/identifyreconcile?sysparm_data_source=Signet', {
          items: [{ className: 'cmdb_ci_function_ai', values: { name: p.handle, short_description: p.name, correlation_id: row.object_key, install_status: p.install_status, u_signet_agent_id: p.agent_id, u_signet_tier: p.tier, u_signet_certificate_status: p.certificate_status, u_signet_certificate_expiry: p.certificate_expiry } }],
        })) as { items: { sysId: string }[] };
        const ciId = ci.items[0]!.sysId;
        (await remember(c.id, row.object_key, 'cmdb_ci_function_ai', ciId));
        const assetKey = `${row.object_key}:asset`;
        const isNew = !(await mapping(c.id, assetKey));
        const assetId = (await upsert(c, 'alm_ai_system_digital_asset', assetKey, { display_name: p.name, short_description: `Signet agent ${p.handle} (tier ${p.tier}); governed by Signet`, u_signet_agent_id: p.agent_id, u_signet_tier: p.tier }));
        if (isNew) (await call(c, 'POST', '/api/now/table/cmdb_rel_asset_ci', { asset: assetId, ci: ciId }));
        return ciId;
      }
      const r = (await call(c, 'POST', '/api/now/identifyreconcile?sysparm_data_source=Signet', {
        items: [{ className: 'cmdb_ci_appl', values: { name: p.handle, short_description: p.name, category: 'AI Agent', correlation_id: row.object_key, install_status: p.install_status, u_signet_agent_id: p.agent_id, u_signet_tier: p.tier, u_signet_certificate_status: p.certificate_status, u_signet_certificate_expiry: p.certificate_expiry } }],
      })) as { items: { sysId: string }[] };
      const sysId = r.items[0]!.sysId;
      (await remember(c.id, row.object_key, 'cmdb_ci_appl', sysId));
      return sysId;
    }
    case 'indicator.result':
      return (((await call(c, 'POST', '/api/now/table/sn_grc_indicator_result', { u_signet_control: p.control_id, passed: p.passed, value: p.status, explanation: p.detail })) as { result: { sys_id: string } }).result.sys_id);
    case 'control_test.create':
      return (await upsert(c, 'sn_compliance_control_test', row.object_key, { short_description: `[Signet] Test stage ${p.handle}`, result: p.result, u_report_sha256: p.report_sha256 }));
    default:
      throw new Error(`unknown event ${row.event}`);
  }
}

let running = false;
export async function work() {
  if (running) return;
  running = true;
  try {
    const due = (await db.prepare("SELECT o.* FROM connector_outbox o JOIN connector c ON c.id = o.connector_id WHERE o.status = 'pending' AND o.next_at <= ? AND c.status = 'active' ORDER BY o.created_at LIMIT 25").all(Date.now())) as unknown as OutboxRow[];
    for (const row of due) {
      const c = (await getRow(row.connector_id));
      try {
        const ref = await send(c, row);
        (await db.prepare("UPDATE connector_outbox SET status = 'sent', external_ref = ?, sent_at = ?, attempts = attempts + 1 WHERE id = ?").run(ref, nowIso(), row.id));
        (await db.prepare('UPDATE connector SET last_sync_at = ? WHERE id = ?').run(nowIso(), c.id));
      } catch (e) {
        // Exponential back-off 1 s .. 15 min, then the dead-letter queue (BP 10.9).
        const attempts = row.attempts + 1;
        const dead = attempts >= MAX_ATTEMPTS;
        const delay = Math.min(15 * 60_000, 1000 * 2 ** (attempts - 1));
        (await db.prepare('UPDATE connector_outbox SET status = ?, attempts = ?, next_at = ?, last_error = ? WHERE id = ?').run(dead ? 'dead' : 'pending', attempts, Date.now() + delay, (e as Error).message.slice(0, 300), row.id));
        if (dead) (await ledger.append({ kind: 'admin', data: { event: 'connector.dead_letter', connector_id: c.id, outbox_id: row.id, event_type: row.event, error: (e as Error).message } }));
      }
    }
  } finally {
    running = false;
  }
}

export async function retry(outboxId: string, p: Principal) {
  const r = (await db.prepare("UPDATE connector_outbox SET status = 'pending', next_at = ?, attempts = 0 WHERE id = ? AND status = 'dead'").run(Date.now(), outboxId));
  if (!r.changes) throw new PolicyError('BP-10.9', 'only dead letters can be retried', 409);
  (await ledger.append({ kind: 'admin', data: { event: 'connector.retry', outbox_id: outboxId, actor: p.id } }));
  return { ok: true };
}

// --- inbound (BP 10.3): authority documents and citations become frameworks in the library ---

export async function pullLibrary(id: string, p: Principal) {
  const c = (await getRow(id));
  if (c.status !== 'active') throw new PolicyError('BP-10', 'run a successful self-test first', 409);
  const since = c.watermark ?? '1970-01-01 00:00:00';
  const q = (t: string, fields: string) => `/api/now/table/${t}?sysparm_query=sys_updated_on>${encodeURIComponent(since)}^ORDERBYsys_updated_on&sysparm_fields=${fields}&sysparm_limit=1000&sysparm_exclude_reference_link=true`;
  const docs = ((await call(c, 'GET', q('sn_compliance_authority_document', 'sys_id,name,version,sys_updated_on'))) as { result: { sys_id: string; name: string; version?: string; sys_updated_on: string }[] }).result;
  const cits = ((await call(c, 'GET', q('sn_compliance_citation', 'sys_id,name,reference,description,authority_document,sys_updated_on'))) as { result: { sys_id: string; name: string; reference?: string; description?: string; authority_document: string; sys_updated_on: string }[] }).result;
  let watermark = since;
  (await tx(async () => {
    for (const d of docs) {
      (await db.prepare('INSERT INTO framework (id, name, version, licence, namespace) VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, version = EXCLUDED.version, licence = EXCLUDED.licence, namespace = EXCLUDED.namespace').run(`sn:${d.sys_id}`, d.name, d.version ?? '', 'customer library (ServiceNow is master for text)', 'servicenow'));
      if (d.sys_updated_on > watermark) watermark = d.sys_updated_on;
    }
    for (const ct of cits) {
      (await db.prepare('INSERT INTO framework_requirement (id, framework_id, external_id, summary) VALUES (?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET framework_id = EXCLUDED.framework_id, external_id = EXCLUDED.external_id, summary = EXCLUDED.summary').run(`sn:${ct.sys_id}`, `sn:${ct.authority_document}`, ct.reference ?? ct.name, ct.description ?? ct.name));
      if (ct.sys_updated_on > watermark) watermark = ct.sys_updated_on;
    }
    (await db.prepare('UPDATE connector SET watermark = ?, last_sync_at = ? WHERE id = ?').run(watermark, nowIso(), id));
    (await ledger.append({ kind: 'admin', data: { event: 'connector.library_pull', connector_id: id, authority_documents: docs.length, citations: cits.length, watermark, actor: p.id } }));
  }));
  return { authority_documents: docs.length, citations: cits.length, watermark };
}

export async function view(id: string) {
  const c = (await getRow(id));
  const counts = (await db.prepare('SELECT status, COUNT(*) n FROM connector_outbox WHERE connector_id = ? GROUP BY status').all(id)) as { status: string; n: number }[];
  return { id: c.id, type: c.type, name: c.name, config: c.config, status: c.status, last_sync_at: c.last_sync_at, watermark: c.watermark, queue: Object.fromEntries(counts.map((x) => [x.status, x.n])), tenant: tenant.id };
}

export const list = async () => (await Promise.all(((await db.prepare('SELECT id FROM connector ORDER BY created_at').all()) as { id: string }[]).map(async (r) => (await view(r.id)))));
export const outbox = async (id: string, status?: string) =>
  (await db.prepare(`SELECT id, event, object_key, status, attempts, last_error, external_ref, created_at, sent_at FROM connector_outbox WHERE connector_id = ? ${status ? 'AND status = ?' : ''} ORDER BY created_at DESC LIMIT 100`).all(...(status ? [id, status] : [id])));

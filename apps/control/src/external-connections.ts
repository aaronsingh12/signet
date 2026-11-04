import { newId, sha256, request as httpRequest, evaluateTs } from '@signet/core';
import type { AgentListFields, ConnectionHealth, ExternalConnectionConfig, ExternalConnectionView, ExternalOperation } from '@signet/core/types';
import { db, nowIso, tx } from './db';
import { PolicyError, forbidden, invalid, notFound } from './errors';
import { adaptRecords, agentListFields, endpointUrl, object, parseConfig, pointer, nextExecutionOffset, type ImportedRecord, type Json } from './external-contract';
import { readJson, requestJson } from './external-http';
import { detectAgentMapping, detectRestApi } from './rest-discovery';
import * as ledger from './ledger';
import { assertCan, getAgent, registerAgent, activeCertificate } from './registry';
import { agentLevel } from './enforcement';
import { usableCertificate, exchangeClientCredentials } from './identity';
import { getTool } from './tools';
import { requireRunner, listRunners } from './edge';
import type { Principal } from './rbac';
import * as secrets from './secrets';
import { tenant } from './tenant';
import * as workflow from './workflow';
import { compilePolicy } from './compile';

/**
 * Tenant-scoped outbound connections. SCHEMA_SQL adds these tables at control-plane startup.
 * Deploy control, Gateway, web and maintenance artifacts together, with a stable SIGNET_BROKER_KEY
 * and DATABASE_URL. SIGNET_GATEWAY_URL must point to this deployment's Gateway for private calls.
 * Non-Vercel control processes schedule work(); Vercel's maintenance daemon invokes
 * /internal/maintenance/connections using the existing internal service binding and token.
 *
 * Public REST/OAuth setup requires connectors.manage, an existing agent and a harmless GET endpoint.
 * Supply discovery.write for imports, documented JSON pointers for response adapters, and ledger.read
 * for observations. Grant approved HTTP actions matching the platform URL and endpoint templates
 * before enabling remote management. Client-credentials grants reacquire expired tokens; outbound
 * authorization-code grants are deliberately unsupported. Read responses are capped at 1 MiB and
 * 1000 records; a sync supports at most 25 mapped agents and a four-minute work budget. Configure
 * platform-side scopes or split connections when these bounds are exceeded. Offset/limit pagination
 * is opt-in using explicit total/offset/limit response pointers and is bounded to 1000 executions.
 *
 * Private HTTP setup reuses an enrolled edge runner and its local destination allowlist. Register
 * operation-named HTTP actions, approve them in the connection agent's seal, and generate a dedicated
 * environment-bound Signet OAuth client. Store that client ID/secret here; upstream API credentials
 * stay in the runner's token_env. Each request traverses the existing Gateway and runner lease checks.
 * The runner supports HTTP tools, not private MCP transport or full local DLP. Connection revocation
 * erases its credential copy and cached token; revoke issuer credentials and runner identities through
 * their existing lifecycle endpoints when they must no longer be usable outside this connection.
 * External metadata never enters the Gateway transaction stream or confers certification.
 */
interface Stored { config: ExternalConnectionConfig; credential: string; token: string | null; expires_at: number }
interface Row { id: string; agent_id: string | null; secret_id: string; state: ExternalConnectionView['state']; health: string }
const initialHealth = (): ConnectionHealth => ({ reachable: null, authentication: 'unverified', discovered: null, monitoring: false, remote_control: false, gateway_enforcement: false, last_success_at: null, last_sync_at: null, last_error: null });

async function rowOf(id: string): Promise<Row> {
  const row = await db.prepare('SELECT id, agent_id, secret_id, state, health FROM external_connection WHERE id = ? AND tenant_id = ?').get(id, tenant.id) as Row | undefined;
  if (!row) throw notFound(`connection ${id}`);
  return row;
}
async function storedOf(row: Row): Promise<Stored> {
  await secrets.getSecretMeta(row.secret_id);
  const value = object(JSON.parse((await secrets.revealForGateway(row.secret_id)).value), 'stored connection');
  if (typeof value.credential !== 'string' || (value.token !== null && typeof value.token !== 'string') || typeof value.expires_at !== 'number') throw invalid('Stored connection credentials are malformed');
  return { config: parseConfig(value.config), credential: value.credential, token: value.token, expires_at: value.expires_at };
}
function requireManager(actor: Principal): void {
  if (!actor.permissions.includes('connectors.manage')) throw forbidden('RBAC', 'Connection configuration and remote actions require connectors.manage');
}
async function audit(id: string, event: string, actor: string): Promise<void> {
  await ledger.append({ kind: 'admin', data: { event: `connection.${event}`, connection_id: id, actor, coverage: 'external_monitoring' } });
}
export async function view(id: string): Promise<ExternalConnectionView> {
  const row = await rowOf(id);
  const { config } = await storedOf(row);
  const count = await db.prepare('SELECT COUNT(*) AS n FROM external_agent_mapping WHERE connection_id = ?').get(id) as { n: number };
  const health = JSON.parse(row.health) as ConnectionHealth;
  if (config.private_connector) {
    const runner = (await listRunners()).find((item) => item.id === config.private_connector!.runner_id);
    if (runner?.status !== 'online') { health.reachable = false; health.monitoring = false; health.gateway_enforcement = false; health.last_error = `Private connector is ${runner?.status ?? 'unknown'}`; }
  }
  return { id, agent_id: row.agent_id, state: row.state, config, health, direction: 'outbound', capabilities: Object.keys(config.endpoints), coverage: config.private_connector ? 'gateway_tools' : 'external_monitoring', agent_count: count.n };
}
async function validatePrivate(agentId: string | null, config: ExternalConnectionConfig): Promise<void> {
  const connector = config.private_connector;
  if (!connector) return;
  if (!agentId) throw invalid('Private connectors require an approved Signet agent');
  await requireRunner(connector.runner_id);
  const tool = await getTool(connector.tool_alias);
  if (!tool || tool.kind !== 'http' || tool.runner_id !== connector.runner_id || tool.url !== config.base_url) throw invalid('Private connection must match a registered HTTP tool URL and its enrolled runner');
  for (const [operation, spec] of Object.entries(config.endpoints)) if (!tool.actions[operation] || tool.actions[operation]!.method !== spec.method || tool.actions[operation]!.path !== spec.path) throw invalid(`Private ${operation} must exactly match the registered tool action's method and path`);
  const client = await db.prepare('SELECT environment FROM agent_client WHERE client_id = ? AND agent_id = ? AND revoked_at IS NULL').get(config.client_id, agentId) as { environment: string } | undefined;
  if (!client || client.environment !== connector.environment) throw invalid('Private connection requires an unrevoked Signet OAuth client for this agent and environment; complete approval and generate credentials first');
}
export async function list(): Promise<ExternalConnectionView[]> {
  const rows = await db.prepare('SELECT id FROM external_connection WHERE tenant_id = ? ORDER BY created_at DESC').all(tenant.id) as { id: string }[];
  return Promise.all(rows.map((row) => view(row.id)));
}
function credentialOf(input: Record<string, unknown>, config: ExternalConnectionConfig): string {
  if (config.auth === 'none') return '';
  if (typeof input.credential !== 'string' || input.credential.length < 8 || input.credential.length > 16000 || /[\r\n]/.test(input.credential)) throw invalid('Credential must contain 8–16000 characters without newlines');
  return input.credential;
}
export async function create(agentRef: string | null, value: unknown, actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  const agent = agentRef === null ? null : await getAgent(agentRef);
  const input = object(value, 'request');
  const config = parseConfig(input.config);
  if (!agent && config.method !== 'rest') throw invalid('Only REST platform connections can be created before agent onboarding');
  await validatePrivate(agent?.id ?? null, config);
  const credential = credentialOf(input, config);
  return tx(async () => {
    const id = newId('conn');
    const secret = await secrets.putSecret({ name: id.toLowerCase(), kind: 'tool', value: JSON.stringify({ config, credential, token: null, expires_at: 0 } satisfies Stored) }, actor);
    await db.prepare('INSERT INTO external_connection (id, tenant_id, agent_id, secret_id, state, health, next_sync_at, busy_until, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, tenant.id, agent?.id ?? null, secret.id, 'enabled', JSON.stringify(initialHealth()), Date.now() + config.sync_interval_seconds * 1000, 0, actor.id, nowIso());
    await audit(id, 'created', actor.id);
    return view(id);
  });
}
/** A database lease serializes token renewal, actions, rotation and sync across control replicas. */
async function exclusive<T>(id: string, operation: () => Promise<T>): Promise<T> {
  await rowOf(id);
  const result = await db.prepare('UPDATE external_connection SET busy_until = ? WHERE id = ? AND tenant_id = ? AND busy_until < ?').run(Date.now() + 600_000, id, tenant.id, Date.now());
  if (!result.changes) throw new PolicyError('CONNECTION_BUSY', 'Connection is busy; retry after the current operation finishes', 409);
  try { return await operation(); }
  finally { await db.prepare('UPDATE external_connection SET busy_until = ? WHERE id = ? AND tenant_id = ?').run(0, id, tenant.id); }
}
export async function update(id: string, value: unknown, actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    if (row.state === 'revoked') throw invalid('Revoked connections cannot be edited or reconnected; create a new connection');
    const old = await storedOf(row);
    const input = object(value, 'request');
    const config = parseConfig(input.config);
    if (row.agent_id === null && config.method !== 'rest') throw invalid('Onboard an agent before changing to a non-REST connection method');
    await validatePrivate(row.agent_id, config);
    const changedAuth = config.auth !== old.config.auth || config.base_url !== old.config.base_url || config.token_url !== old.config.token_url || config.client_id !== old.config.client_id || config.header !== old.config.header || JSON.stringify(config.private_connector) !== JSON.stringify(old.config.private_connector);
    if (changedAuth && config.auth !== 'none' && !input.credential) throw invalid('Changing credential destination or authentication requires resubmitting the credential');
    const credential = input.credential ? credentialOf(input, config) : config.auth === 'none' ? '' : old.credential;
    await tx(async () => {
      await secrets.rotateSecret(row.secret_id, JSON.stringify({ config, credential, token: null, expires_at: 0 } satisfies Stored), actor);
      await db.prepare('UPDATE external_connection SET health = ?, next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(initialHealth()), Date.now() + config.sync_interval_seconds * 1000, id, tenant.id);
      await audit(id, 'updated', actor.id);
    });
    return view(id);
  });
}
export async function transition(id: string, state: Row['state'], actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    if (row.state === 'revoked') throw invalid('Revoked connection cannot be reactivated');
    const stored = await storedOf(row);
    await tx(async () => {
      await secrets.rotateSecret(row.secret_id, JSON.stringify({ ...stored, credential: state === 'revoked' ? '' : stored.credential, token: null, expires_at: 0 }), actor);
      await db.prepare('UPDATE external_connection SET state = ?, health = ? WHERE id = ? AND tenant_id = ?').run(state, JSON.stringify(initialHealth()), id, tenant.id);
      await audit(id, state, actor.id);
    });
    return view(id);
  });
}
async function authHeaders(row: Row, stored: Stored, actor: Principal): Promise<Record<string, string>> {
  const c = stored.config;
  if (c.auth === 'none') return {};
  if (!stored.credential) throw new PolicyError('EXTERNAL_AUTH', 'Connection has no credential; rotate credentials before connecting', 400);
  if (c.auth === 'api_key') return { [c.header]: stored.credential };
  if (c.auth === 'bearer') return { authorization: `Bearer ${stored.credential}` };
  if (c.auth === 'connector') {
    await validatePrivate(row.agent_id, c);
    const identity = await exchangeClientCredentials(c.client_id, stored.credential);
    return { authorization: `Bearer ${identity.token}` };
  }
  if (stored.token && stored.expires_at > Date.now() + 30000) return { authorization: `Bearer ${stored.token}` };
  const body = new URLSearchParams({ grant_type: 'client_credentials', scope: c.scopes });
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  if (c.token_auth === 'client_secret_basic') headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(c.client_id)}:${encodeURIComponent(stored.credential)}`).toString('base64')}`;
  else { body.set('client_id', c.client_id); body.set('client_secret', stored.credential); }
  const response = object(await requestJson({ url: new URL(c.token_url), method: 'POST', headers, body: body.toString(), timeout: c.timeout_ms }), 'OAuth token response');
  if (typeof response.access_token !== 'string' || !response.access_token || /[\r\n]/.test(response.access_token) || typeof response.token_type !== 'string' || response.token_type.toLowerCase() !== 'bearer' || typeof response.expires_in !== 'number' || response.expires_in <= 30 || response.expires_in > 86400) throw new PolicyError('EXTERNAL_SCHEMA', 'OAuth response requires access_token, Bearer token_type and numeric expires_in between 31 and 86400 seconds', 502);
  const renewed: Stored = { ...stored, token: response.access_token, expires_at: Date.now() + response.expires_in * 1000 };
  await secrets.rotateSecret(row.secret_id, JSON.stringify(renewed), actor);
  return { authorization: `Bearer ${response.access_token}` };
}
async function call(row: Row, op: ExternalOperation, externalId: string | null, body: Json | null, actor: Principal, query: Record<string, string>): Promise<Json> {
  if (row.state !== 'enabled') throw invalid('Connection is disabled or revoked');
  const budget = await db.prepare('INSERT INTO external_connection_budget (connection_id, window_at, requests) VALUES (?, ?, 1) ON CONFLICT(connection_id) DO UPDATE SET requests = CASE WHEN external_connection_budget.window_at < ? THEN 1 ELSE external_connection_budget.requests + 1 END, window_at = CASE WHEN external_connection_budget.window_at < ? THEN excluded.window_at ELSE external_connection_budget.window_at END RETURNING requests').get(row.id, Date.now(), Date.now() - 60_000, Date.now() - 60_000) as { requests: number };
  if (budget.requests > 60) throw new PolicyError('RATE_LIMIT', 'Connection exceeded 60 operations per minute; wait before retrying', 429);
  const stored = await storedOf(row);
  const c = stored.config;
  const endpoint = c.endpoints[op];
  if (!endpoint) throw invalid(`Connection does not support ${op}`);
  if (c.private_connector) {
    await validatePrivate(row.agent_id, c);
    const gateway = process.env.SIGNET_GATEWAY_URL?.replace(/\/+$/, '');
    if (!gateway) throw invalid('SIGNET_GATEWAY_URL is required on the control plane for private connector requests');
    const headers = await authHeaders(row, stored, actor);
    const response = await httpRequest(`${gateway}/v1/tools/http/${c.private_connector.tool_alias}/${op}`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ ...query, ...(body !== null && typeof body === 'object' && !Array.isArray(body) ? body : {}), ...(externalId === null ? {} : { id: externalId }) }), timeoutMs: c.timeout_ms, signal: AbortSignal.timeout(c.timeout_ms), maxBytes: 1024 * 1024 });
    if (!response.ok) throw new PolicyError('PRIVATE_GATEWAY_REFUSED', `Private connector Gateway call returned HTTP ${response.status}; check runner heartbeat, approved action, seal, policy and identity. Response body withheld.`, 502);
    try { return response.json<Json>(); } catch { throw new PolicyError('EXTERNAL_SCHEMA', 'Private connector returned malformed JSON', 502); }
  }
  const url = endpointUrl(c.base_url, endpoint.path, externalId);
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
  const headers = { accept: 'application/json', ...(await authHeaders(row, stored, actor)), ...(body === null ? {} : { 'content-type': 'application/json' }) };
  const request = { url, method: endpoint.method, headers, body: body === null ? null : JSON.stringify(body), timeout: c.timeout_ms };
  try { return await (endpoint.method === 'GET' ? readJson(request) : requestJson(request)); }
  catch (error) {
    if (error instanceof PolicyError && error.rule === 'EXTERNAL_AUTH' && c.auth === 'oauth') {
      const latest = await storedOf(row);
      await secrets.rotateSecret(row.secret_id, JSON.stringify({ ...latest, token: null, expires_at: 0 }), actor);
    }
    throw error;
  }
}
async function healthFailure(row: Row, error: unknown): Promise<void> {
  if (!(error instanceof Error)) throw error;
  const prior = JSON.parse(row.health) as ConnectionHealth;
  const authFailed = error instanceof PolicyError && error.rule === 'EXTERNAL_AUTH';
  await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify({ ...prior, reachable: authFailed ? true : error instanceof PolicyError && error.rule === 'EXTERNAL_NETWORK' ? false : prior.reachable, authentication: authFailed ? 'invalid' : prior.authentication, monitoring: false, remote_control: false, gateway_enforcement: false, last_error: error instanceof PolicyError ? error.message : 'Connection operation failed; inspect server diagnostics' } satisfies ConnectionHealth), row.id, tenant.id);
}
export async function testConnection(id: string, actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    try {
      await audit(id, 'test_requested', actor.id);
      await call(row, 'test', null, null, actor, {});
      const { config } = await storedOf(row);
      const health: ConnectionHealth = { ...JSON.parse(row.health) as ConnectionHealth, reachable: true, authentication: config.auth === 'none' ? 'not_required' : 'valid', gateway_enforcement: !!config.private_connector, last_success_at: nowIso(), last_error: null };
      await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(health), id, tenant.id);
      await audit(id, 'test_succeeded', actor.id);
      return view(id);
    } catch (error) { await healthFailure(row, error); await audit(id, 'test_failed', actor.id); throw error; }
  });
}
/** Inspect a REST agent list for guided setup; expose field paths only, never raw API data. */
export async function inspectAgentList(id: string, actor: Principal): Promise<{ lists: AgentListFields[] }> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const { config } = await storedOf(row);
    if (config.method !== 'rest') throw invalid('Guided agent list inspection requires a REST connection');
    try {
      const lists = agentListFields(await call(row, 'discover', null, null, actor, {}));
      if (!lists.length) throw invalid('The agent endpoint returned no lists. Enter a GET endpoint that returns an array of agents');
      await audit(id, 'agent_fields_inspected', actor.id);
      return { lists };
    } catch (error) { await healthFailure(row, error); throw error; }
  });
}

interface RestAgentPreview { id: string; name: string; status: string | null; agent_id: string | null }
interface RestConnectResult { connection: ExternalConnectionView; agents: RestAgentPreview[] }

async function previewRecords(id: string, records: ImportedRecord[]): Promise<RestAgentPreview[]> {
  const rows = await db.prepare('SELECT external_id, agent_id FROM external_agent_mapping WHERE connection_id = ?').all(id) as { external_id: string; agent_id: string }[];
  const imported = new Map(rows.map((row) => [row.external_id, row.agent_id]));
  return records.map((record) => ({ id: record.id, name: record.name ?? record.id, status: record.status, agent_id: imported.get(record.id) ?? null }));
}

/** Connect and preview agents without registering or approving any remote identity. */
export async function connectRest(agentRef: string | null, value: unknown, actor: Principal): Promise<RestConnectResult> {
  requireManager(actor);
  if (agentRef !== null && (typeof agentRef !== 'string' || !agentRef)) throw invalid('agent_id must be a Signet agent ID or null');
  const parentId = agentRef === null ? null : (await getAgent(agentRef)).id;
  const input = object(value, 'REST connection');
  if (typeof input.base_url !== 'string') throw invalid('Enter the external API base URL');
  if (input.connection_id !== null && typeof input.connection_id !== 'string') throw invalid('connection_id must be a connection ID or null');
  if (typeof input.credential !== 'string') throw invalid('Enter your external API key');
  let credential = input.credential;
  let previous: ExternalConnectionConfig | null = null;
  if (input.connection_id !== null) {
    const existing = await rowOf(input.connection_id);
    const stored = await storedOf(existing);
    previous = stored.config;
    if (existing.agent_id !== parentId || stored.config.method !== 'rest') throw invalid('This REST connection belongs to another agent or connection method');
    if (!credential && input.base_url.replace(/\/+$/, '') !== stored.config.base_url.replace(/\/+$/, '')) throw invalid('Enter the API key again when changing the API address');
    if (!credential) credential = stored.credential;
  }
  if (credential.length < 8 || credential.length > 16000 || /[\r\n]/.test(credential)) throw invalid('API key must contain 8-16000 characters without newlines');
  const detected = await detectRestApi(input.base_url, credential);
  const config = previous ? { ...previous, base_url: detected.config.base_url, auth: detected.config.auth, header: detected.config.header, endpoints: { ...previous.endpoints, ...detected.config.endpoints }, agents_mapping: detected.config.agents_mapping } : detected.config;
  const connection = input.connection_id === null ? await create(agentRef, { config, credential }, actor) : await update(input.connection_id, { config, credential }, actor);
  const health: ConnectionHealth = { ...connection.health, reachable: true, authentication: 'valid', last_success_at: nowIso(), last_error: null };
  await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(health), connection.id, tenant.id);
  await audit(connection.id, 'rest_connected', actor.id);
  return { connection: await view(connection.id), agents: await previewRecords(connection.id, detected.agents) };
}

/** Refresh the real external list without importing agents. */
export async function previewRestAgents(id: string, actor: Principal): Promise<RestConnectResult> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const { config } = await storedOf(row);
    if (config.method !== 'rest') throw invalid('Agent preview requires a REST connection');
    const data = await call(row, 'discover', null, null, actor, {});
    const mapping = config.agents_mapping ?? detectAgentMapping(data);
    return { connection: await view(id), agents: await previewRecords(id, mapping ? adaptRecords(data, mapping) : []) };
  });
}

/** Onboard only the chosen external agent; existing mappings remain idempotent. */
export async function onboardRestAgent(id: string, externalId: string, actor: Principal): Promise<{ agent_id: string }> {
  requireManager(actor);
  if (!actor.permissions.includes('discovery.write')) throw forbidden('RBAC', 'Onboarding requires agent discovery permission');
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const { config } = await storedOf(row);
    if (config.method !== 'rest') throw invalid('REST onboarding requires a REST connection');
    const data = await call(row, 'discover', null, null, actor, {});
    const mapping = config.agents_mapping ?? detectAgentMapping(data);
    const record = (mapping ? adaptRecords(data, mapping) : []).find((item) => item.id === externalId);
    if (!record) throw notFound('external agent; refresh the agent list');
    await importExternalAgents(row, [record], actor);
    const mapped = await db.prepare('SELECT agent_id FROM external_agent_mapping WHERE connection_id = ? AND external_id = ?').get(id, externalId) as { agent_id: string } | undefined;
    if (!mapped) throw new Error('REST agent onboarding did not create an agent mapping');
    await audit(id, 'agent_onboarded', actor.id);
    return { agent_id: mapped.agent_id };
  });
}

async function discoverRows(row: Row, actor: Principal): Promise<number> {
  const { config } = await storedOf(row);
  if (!config.agents_mapping) throw invalid('Configure the documented agent response mapping before discovery');
  const records = adaptRecords(await call(row, 'discover', null, null, actor, {}), config.agents_mapping);
  await importExternalAgents(row, records, actor);
  return records.length;
}

async function importExternalAgents(row: Row, records: ImportedRecord[], actor: Principal): Promise<void> {
  const { config } = await storedOf(row);
  await tx(async () => {
    for (const record of records) {
      const prior = await db.prepare('SELECT agent_id FROM external_agent_mapping WHERE connection_id = ? AND external_id = ?').get(row.id, record.id);
      if (prior) { await db.prepare('UPDATE external_agent_mapping SET last_seen_at = ? WHERE connection_id = ? AND external_id = ?').run(nowIso(), row.id, record.id); continue; }
      const parent = row.agent_id === null ? null : await getAgent(row.agent_id);
      const agent = await registerAgent({ handle: `ext-${sha256(`${row.id}:${record.id}`).slice(0, 24)}`, name: record.name ?? record.id, purpose: `External agent discovered through ${config.name}; classification and approval required`, sponsor: parent?.sponsor ?? actor.id, owner: actor.id, autonomy_level: 'L0', kind: 'third_party', vendor: config.name, connection_method: config.method === 'oauth' ? 'oauth' : 'rest' }, actor);
      await workflow.start(agent, {}, actor, 'initial', null);
      await db.prepare('INSERT INTO external_agent_mapping (connection_id, external_id, agent_id, last_seen_at) VALUES (?, ?, ?, ?)').run(row.id, record.id, agent.id, nowIso());
    }
  });
}

export async function discover(id: string, actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  if (!actor.permissions.includes('discovery.write')) throw forbidden('RBAC', 'Agent discovery import also requires discovery.write');
  return exclusive(id, async () => {
    const row = await rowOf(id);
    try {
      const count = await discoverRows(row, actor);
      const { config } = await storedOf(row);
      const health = { ...JSON.parse(row.health) as ConnectionHealth, reachable: true, authentication: config.auth === 'none' ? 'not_required' : 'valid', discovered: count, last_success_at: nowIso(), last_error: null } satisfies ConnectionHealth;
      await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(health), id, tenant.id);
      await audit(id, 'discovered', actor.id);
      return view(id);
    } catch (error) { await healthFailure(row, error); await audit(id, 'discovery_failed', actor.id); throw error; }
  });
}
export async function sync(id: string, actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const { config } = await storedOf(row);
    const startedAt = Date.now();
    try {
      if (!config.endpoints.track && !config.endpoints.executions) throw invalid('No monitoring endpoints configured');
      const mappings = await db.prepare('SELECT external_id FROM external_agent_mapping WHERE connection_id = ? ORDER BY external_id LIMIT 26').all(id) as { external_id: string }[];
      if (!mappings.length) throw invalid('Discover agents before synchronizing');
      if (mappings.length > 25) throw invalid('Connection exceeds the 25-agent sync limit; split it into scoped connections to stay within its rate and work budgets');
      for (const mapped of mappings) {
        if (Date.now() - startedAt > 240_000) throw new PolicyError('SYNC_TIMEOUT', 'Sync exceeded its four-minute work budget; reduce endpoint timeout or split this connection into smaller scopes', 504);
        if (config.endpoints.track) {
          // Tracking schemas are platform-specific. Validate against the same explicit metadata contract.
          if (!config.agents_mapping) throw invalid('Tracking requires an agent response mapping');
          const data = await call(row, 'track', mapped.external_id, null, actor, {});
          const tracked = pointer(data, config.tracking_pointer);
          if (tracked === undefined) throw invalid('Tracking response is missing the configured agent object pointer');
          const result = adaptRecords({ records: [tracked] }, { ...config.agents_mapping, items: '/records' });
          if (result[0]?.id !== mapped.external_id) throw invalid('Tracking response ID does not match the requested external agent');
          await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(connection_id, external_agent_id, kind, external_id) DO UPDATE SET metadata = excluded.metadata, observed_at = excluded.observed_at').run(id, mapped.external_id, mapped.external_id, 'tracking', JSON.stringify(result[0]), nowIso());
        }
        if (config.endpoints.executions) {
          if (!config.executions_mapping) throw invalid('Configure the documented execution response mapping before sync');
          let offset: number | null = 0;
          while (offset !== null) {
            if (Date.now() - startedAt > 240_000) throw new PolicyError('SYNC_TIMEOUT', 'Execution sync exceeded its four-minute work budget; narrow the platform scope', 504);
            const query: Record<string, string> = config.execution_pagination ? { offset: String(offset), limit: '100' } : {};
            const response = await call(row, 'executions', mapped.external_id, null, actor, query);
            const records = adaptRecords(response, config.executions_mapping);
            const next: number | null = config.execution_pagination ? nextExecutionOffset(response, config.execution_pagination, offset, records.length) : null;
            await tx(async () => {
              for (const record of records) await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(connection_id, external_agent_id, kind, external_id) DO UPDATE SET metadata = excluded.metadata, observed_at = excluded.observed_at').run(id, mapped.external_id, record.id, 'execution', JSON.stringify(record), nowIso());
            });
            offset = next;
          }
        }
      }
      const health = { ...JSON.parse(row.health) as ConnectionHealth, reachable: true, authentication: config.auth === 'none' ? 'not_required' : 'valid', monitoring: true, last_sync_at: nowIso(), last_success_at: nowIso(), last_error: null } satisfies ConnectionHealth;
      await db.prepare('UPDATE external_connection SET health = ?, next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(health), Date.now() + config.sync_interval_seconds * 1000, id, tenant.id);
      await audit(id, 'synchronized', actor.id);
      return view(id);
    } catch (error) {
      await healthFailure(row, error);
      await db.prepare('UPDATE external_connection SET next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(Date.now() + config.sync_interval_seconds * 1000, id, tenant.id);
      await audit(id, 'sync_failed', actor.id);
      throw error;
    }
  });
}
export async function remoteAction(id: string, agentId: string, action: string, body: unknown, actor: Principal): Promise<{ accepted: true }> {
  requireManager(actor);
  if (!['run', 'pause', 'stop', 'activate'].includes(action)) throw invalid('Unsupported remote action');
  const payload = object(body, 'action body');
  if (Buffer.byteLength(JSON.stringify(payload)) > 16000) throw invalid('Remote action body exceeds 16 KiB');
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const agent = await getAgent(agentId);
    assertCan(actor, 'connectors.manage', agent);
    const mapped = await db.prepare('SELECT external_id FROM external_agent_mapping WHERE connection_id = ? AND agent_id = ?').get(id, agent.id) as { external_id: string } | undefined;
    if (!mapped) throw notFound('connection agent mapping');
    const { config } = await storedOf(row);
    if (!config.remote_management) throw forbidden('REMOTE_DISABLED', 'Enable remote management explicitly before sending actions');
    const level = await agentLevel(agent.id);
    if (!(await activeCertificate(agent.id)) || agent.status === 'retired' || level === 'killed' || level === 'quarantined') throw forbidden('REMOTE_LIFECYCLE', 'Remote actions require an approved agent with a valid seal and no kill or quarantine');
    const certificate = await usableCertificate(agent.id);
    const endpoint = config.endpoints[action as ExternalOperation];
    if (!endpoint) throw invalid(`Connection does not support ${action}`);
    let approvedServer: string | null = null;
    for (const grant of certificate.tools) {
      if (!grant.server.startsWith('http://') || !grant.actions.some((item) => item.name === action)) continue;
      const tool = await getTool(grant.server.slice(7));
      if (tool?.url === config.base_url && tool.actions[action]?.method === endpoint.method && tool.actions[action]?.path === endpoint.path) approvedServer = grant.server;
    }
    if (!approvedServer) throw forbidden('REMOTE_SCOPE', 'Remote action must match an HTTP tool and action in this mapped agent’s approved seal');
    const decision = evaluateTs({ kind: 'tool', policy: compilePolicy(certificate, tenant.settings.baseline), action: { key: `${approvedServer}.${action}`, args: { ...payload, id: mapped.external_id } }, context: { step_up: level === 'step_up' } });
    await ledger.append({ kind: 'admin', agent_id: agent.id, data: { event: 'connection.remote_policy', connection_id: id, action, decision: decision.decision, rule_ids: decision.rule_ids, actor: actor.id, coverage: 'external_management' } });
    if (decision.decision !== 'allow') throw forbidden('REMOTE_POLICY', `Remote action refused by Signet policy: ${decision.decision}; rules: ${decision.rule_ids.join(', ')}. Use the Gateway approval flow for actions requiring human approval.`);
    await audit(id, `${action}_requested`, actor.id);
    try {
      await call(row, action as ExternalOperation, mapped.external_id, payload as Json, actor, {});
      await audit(id, `${action}_succeeded`, actor.id);
      const health = { ...JSON.parse(row.health) as ConnectionHealth, remote_control: true };
      await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(health), id, tenant.id);
      return { accepted: true };
    } catch (error) { await healthFailure(row, error); await audit(id, `${action}_failed`, actor.id); throw error; }
  });
}

/** Only previously imported mappings are synchronized; background jobs never register or certify agents. */
export async function work(): Promise<void> {
  const rows = await db.prepare("SELECT id FROM external_connection WHERE tenant_id = ? AND state = 'enabled' AND next_sync_at < ? AND busy_until < ? AND EXISTS (SELECT 1 FROM external_agent_mapping WHERE connection_id = external_connection.id) ORDER BY next_sync_at LIMIT 5").all(tenant.id, Date.now(), Date.now()) as { id: string }[];
  const actor: Principal = { id: 'svc:connection-sync', name: 'Connection synchronization', kind: 'service', roles: ['automation'], permissions: ['connectors.manage'], groups: [], mfa: false, auth: 'bearer', auth_time: null };
  for (const row of rows) {
    const { config } = await storedOf(await rowOf(row.id));
    if (!config.endpoints.track && !config.endpoints.executions) {
      await db.prepare('UPDATE external_connection SET next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(Date.now() + config.sync_interval_seconds * 1000, row.id, tenant.id);
      continue;
    }
    try { await sync(row.id, actor); }
    catch (error) { if (!(error instanceof Error)) throw error; console.warn('External connection sync failed', { connection_id: row.id, rule: error instanceof PolicyError ? error.rule : 'INTERNAL' }); }
  }
}

import { createHmac, timingSafeEqual } from 'node:crypto';
import { newId, sha256, request as httpRequest, evaluateTs } from '@signet/core';
import type { AgentListFields, ConnectionHealth, ExternalConnectionConfig, ExternalConnectionView, ExternalOperation, ResponseMapping } from '@signet/core/types';
import { db, nowIso, tx } from './db';
import { gatewayAddress } from './connection-settings';
import { PolicyError, forbidden, invalid, notFound } from './errors';
import { adaptRecords, agentListFields, endpointUrl, object, parseConfig, pointer, nextExecutionOffset, type ImportedRecord, type Json } from './external-contract';
import { readJson, requestJson } from './external-http';
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
import { normalizeExecution } from './external-normalize';
import { headerName, requestBody, requestQuery, requestVariables, validateResponse } from './external-options';

/** Tenant-scoped REST services, encrypted credentials and governance-gated actions.
 * Deployment, mapping syntax and authentication contracts: docs/rest-connectors.md.
 * HTTP transport, mapping validation and normalization live in their dedicated modules.
 */
interface Stored { config: ExternalConnectionConfig; credential: string; token: string | null; expires_at: number }
interface Row { id: string; agent_id: string | null; secret_id: string; state: ExternalConnectionView['state']; health: string; created_by: string; created_at: string; updated_at: string }
const initialHealth = (): ConnectionHealth => ({ reachable: null, authentication: 'unverified', discovered: null, monitoring: false, remote_control: false, gateway_enforcement: false, last_success_at: null, last_sync_at: null, last_error: null, last_tested_at: null, endpoint_verified: false, error_category: null, verified_operations: [] });

async function rowOf(id: string): Promise<Row> {
  const row = await db.prepare('SELECT id, agent_id, secret_id, state, health, created_by, created_at, updated_at FROM external_connection WHERE id = ? AND tenant_id = ?').get(id, tenant.id) as Row | undefined;
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
  const mappings = await db.prepare('SELECT agent_id FROM external_agent_mapping WHERE connection_id = ?').all(id) as { agent_id: string }[];
  const health = JSON.parse(row.health) as ConnectionHealth;
  if (config.private_connector) {
    const runner = (await listRunners()).find((item) => item.id === config.private_connector!.runner_id);
    if (runner?.status !== 'online') { health.reachable = false; health.monitoring = false; health.gateway_enforcement = false; health.last_error = `Private connector is ${runner?.status ?? 'unknown'}`; }
  }
  return { id, agent_id: row.agent_id, state: row.state, config, health, direction: 'outbound', capabilities: (health.verified_operations ?? []).filter((operation) => config.endpoints[operation as ExternalOperation]), coverage: config.private_connector ? 'gateway_tools' : 'external_monitoring', agent_count: mappings.length, mapped_agent_ids: mappings.map((mapping) => mapping.agent_id), created_by: row.created_by, created_at: row.created_at, updated_at: row.updated_at, configuration_status: row.state === 'enabled' ? health.endpoint_verified ? 'verified' : 'configured' : row.state };
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
  if (typeof input.credential !== 'string' || input.credential.length < (config.auth === 'basic' ? 1 : 8) || input.credential.length > 16000 || /[\r\n]/.test(input.credential)) throw invalid('Credential must contain 8–16000 characters without newlines');
  if (config.auth === 'custom_headers') {
    let values: Record<string, unknown>;
    try { values = object(JSON.parse(input.credential), 'custom secret headers'); } catch { throw invalid('Custom header credentials must be a JSON object of header names and secret string values'); }
    if (Object.keys(values).length !== config.secret_headers?.length || config.secret_headers.some((name) => typeof values[name] !== 'string' || !values[name] || /[\r\n]/.test(String(values[name])))) throw invalid('Provide exactly the configured custom secret headers with non-empty string values');
  }
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
    await db.prepare('INSERT INTO external_connection (id, tenant_id, agent_id, secret_id, state, health, next_sync_at, busy_until, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, tenant.id, agent?.id ?? null, secret.id, 'enabled', JSON.stringify(initialHealth()), Date.now() + config.sync_interval_seconds * 1000, 0, actor.id, nowIso(), nowIso());
    await audit(id, 'created', actor.id);
    return view(id);
  });
}

/** Associate a verified setup profile with its newly registered agent without granting runtime access. */
export async function attachToAgent(id: string, agentRef: string, actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  const agent = await getAgent(agentRef);
  assertCan(actor, 'agents.write', agent);
  return tx(async () => {
    await db.prepare('SELECT id FROM external_connection WHERE id = ? AND tenant_id = ? FOR UPDATE').get(id, tenant.id);
    const row = await rowOf(id);
    if (row.created_by !== actor.id && !actor.permissions.includes('tenant.admin')) throw forbidden('RBAC', 'Only the connection creator or tenant administrator can attach this setup');
    if (row.agent_id && row.agent_id !== agent.id) throw invalid('Connection already belongs to another agent');
    const health = (await view(id)).health;
    if (row.state !== 'enabled' || !health.endpoint_verified || !['valid', 'not_required'].includes(health.authentication)) throw invalid('Verify the endpoint and authentication before attaching this connection');
    await db.prepare('UPDATE external_connection SET agent_id = ?, updated_at = ? WHERE id = ? AND tenant_id = ?').run(agent.id, nowIso(), id, tenant.id);
    await audit(id, 'attached', actor.id);
    return view(id);
  });
}
/** A database lease serializes token renewal, actions, rotation and sync across control replicas. */
async function exclusive<T>(id: string, operation: () => Promise<T>): Promise<T> {
  await rowOf(id);
  const leaseUntil = Date.now() + 600_000;
  const result = await db.prepare('UPDATE external_connection SET busy_until = ? WHERE id = ? AND tenant_id = ? AND busy_until < ?').run(leaseUntil, id, tenant.id, Date.now());
  if (!result.changes) throw new PolicyError('CONNECTION_BUSY', 'Connection is busy; retry after the current operation finishes', 409);
  try { return await operation(); }
  finally { await db.prepare('UPDATE external_connection SET busy_until = ? WHERE id = ? AND tenant_id = ? AND busy_until = ?').run(0, id, tenant.id, leaseUntil); }
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
    const changedAuth = config.auth !== old.config.auth || config.base_url !== old.config.base_url || config.token_url !== old.config.token_url || config.client_id !== old.config.client_id || config.header !== old.config.header || config.username !== old.config.username || JSON.stringify(config.secret_headers) !== JSON.stringify(old.config.secret_headers) || JSON.stringify(config.private_connector) !== JSON.stringify(old.config.private_connector);
    if (changedAuth && config.auth !== 'none' && !input.credential) throw invalid('Changing credential destination or authentication requires resubmitting the credential');
    const credential = input.credential ? credentialOf(input, config) : config.auth === 'none' ? '' : old.credential;
    await tx(async () => {
      await secrets.rotateSecret(row.secret_id, JSON.stringify({ config, credential, token: null, expires_at: 0 } satisfies Stored), actor);
      await db.prepare('UPDATE external_connection SET health = ?, next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(initialHealth()), Date.now() + config.sync_interval_seconds * 1000, id, tenant.id);
      await db.prepare('UPDATE external_connection SET updated_at = ? WHERE id = ? AND tenant_id = ?').run(nowIso(), id, tenant.id);
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
      await db.prepare('UPDATE external_connection SET updated_at = ? WHERE id = ? AND tenant_id = ?').run(nowIso(), id, tenant.id);
      await audit(id, state, actor.id);
    });
    return view(id);
  });
}
async function authHeaders(row: Row, stored: Stored, actor: Principal): Promise<Record<string, string>> {
  const c = stored.config;
  if (c.auth === 'none') return {};
  if (!stored.credential) throw new PolicyError('EXTERNAL_AUTH', 'Connection has no credential; rotate credentials before connecting', 400);
  if (c.auth === 'api_key_query') return {};
  if (c.auth === 'basic') return { authorization: `Basic ${Buffer.from(`${c.username}:${stored.credential}`).toString('base64')}` };
  if (c.auth === 'custom_headers') return JSON.parse(stored.credential) as Record<string, string>;
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
  const runId = newId('evt');
  await db.prepare('INSERT INTO external_operation_run (id, tenant_id, connection_id, operation, outcome, actor, started_at, correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(runId, tenant.id, row.id, op, 'running', actor.id, nowIso(), runId);
  try {
    const result = await send(row, op, externalId, body, actor, { ...query, __correlation: runId });
    await db.prepare('UPDATE external_operation_run SET outcome = ?, completed_at = ? WHERE id = ? AND tenant_id = ?').run('succeeded', nowIso(), runId, tenant.id);
    const current = await rowOf(row.id);
    const health = JSON.parse(current.health) as ConnectionHealth;
    await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify({ ...health, verified_operations: [...new Set([...(health.verified_operations ?? []), op])] }), row.id, tenant.id);
    return result;
  } catch (error) {
    const rule = error instanceof PolicyError ? error.rule : 'EXTERNAL_FAILURE';
    const uncertain = ['run', 'pause', 'stop', 'activate'].includes(op) && ['EXTERNAL_NETWORK', 'EXTERNAL_TIMEOUT', 'EXTERNAL_SCHEMA', 'EXTERNAL_CONTENT', 'EXTERNAL_HTTP'].includes(rule);
    await db.prepare('UPDATE external_operation_run SET outcome = ?, completed_at = ?, error_category = ?, detail = ? WHERE id = ? AND tenant_id = ?').run(uncertain ? 'uncertain' : 'failed', nowIso(), rule, error instanceof PolicyError ? error.message : 'External operation failed; response withheld', runId, tenant.id);
    throw error;
  }
}

async function send(row: Row, op: ExternalOperation, externalId: string | null, body: Json | null, actor: Principal, query: Record<string, string>): Promise<Json> {
  if (row.state !== 'enabled') throw invalid('Connection is disabled or revoked');
  const budget = await db.prepare('INSERT INTO external_connection_budget (connection_id, window_at, requests) VALUES (?, ?, 1) ON CONFLICT(connection_id) DO UPDATE SET requests = CASE WHEN external_connection_budget.window_at < ? THEN 1 ELSE external_connection_budget.requests + 1 END, window_at = CASE WHEN external_connection_budget.window_at < ? THEN excluded.window_at ELSE external_connection_budget.window_at END RETURNING requests').get(row.id, Date.now(), Date.now() - 60_000, Date.now() - 60_000) as { requests: number };
  if (budget.requests > 60) throw new PolicyError('RATE_LIMIT', 'Connection exceeded 60 operations per minute; wait before retrying', 429);
  const stored = await storedOf(row);
  const c = stored.config;
  const endpoint = c.endpoints[op];
  if (!endpoint) throw invalid(`Connection does not support ${op}`);
  if (c.private_connector) {
    await validatePrivate(row.agent_id, c);
    const gateway = await gatewayAddress();
    const headers = await authHeaders(row, stored, actor);
    const response = await httpRequest(`${gateway}/v1/tools/http/${c.private_connector.tool_alias}/${op}`, { method: 'POST', headers: { ...headers, 'content-type': 'application/json', 'x-request-id': query.__correlation! }, body: JSON.stringify({ ...Object.fromEntries(Object.entries(query).filter(([key]) => !key.startsWith('__'))), ...(body !== null && typeof body === 'object' && !Array.isArray(body) ? body : {}), ...(externalId === null ? {} : { id: externalId }) }), timeoutMs: c.timeout_ms, signal: AbortSignal.timeout(c.timeout_ms), maxBytes: 1024 * 1024 });
    if (!response.ok) throw new PolicyError('PRIVATE_GATEWAY_REFUSED', `Private connector Gateway call returned HTTP ${response.status}; check runner heartbeat, approved action, seal, policy and identity. Response body withheld.`, 502);
    try { return validateResponse(response.json<Json>(), endpoint); } catch { throw new PolicyError('EXTERNAL_SCHEMA', 'Private connector returned malformed JSON', 502); }
  }
  const variables = requestVariables(body, externalId, query.execution_id ?? null);
  const path = Object.entries(endpoint.variables ?? {}).reduce((result, [name, source]) => {
    if (!variables[source]) throw invalid(`Missing path variable ${source}`);
    return result.replaceAll(`{${name}}`, encodeURIComponent(variables[source]));
  }, endpoint.path).replaceAll('{execution_id}', encodeURIComponent(variables.execution_id ?? '{execution_id}'));
  const url = endpointUrl(c.base_url, path, externalId);
  for (const [key, value] of Object.entries(requestQuery(endpoint, variables))) url.searchParams.set(key, value);
  for (const [key, value] of Object.entries(query)) if (!key.startsWith('__') && key !== 'execution_id') url.searchParams.set(key, value);
  if (c.auth === 'api_key_query') url.searchParams.set(c.header, stored.credential);
  const payload = requestBody(endpoint, body, variables);
  if (endpoint.method === 'GET' && payload !== null) throw invalid('GET mappings cannot send a request body');
  const headers = { accept: 'application/json', ...(await authHeaders(row, stored, actor)), ...(payload === null ? {} : { 'content-type': 'application/json' }), ...(endpoint.idempotency_header ? { [headerName(endpoint.idempotency_header)]: query.__idempotency ?? query.__correlation! } : {}) };
  const request = { url, method: endpoint.method, headers, body: payload === null ? null : JSON.stringify(payload), timeout: c.timeout_ms, expectedStatus: endpoint.expected_status, tlsMinVersion: c.tls_min_version, correlationId: query.__correlation };
  try { return validateResponse(await (endpoint.method === 'GET' && !['run', 'pause', 'stop', 'activate'].includes(op) ? readJson(request) : requestJson(request)), endpoint); }
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
  await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify({ ...prior, reachable: error instanceof PolicyError && error.extra.upstream_status !== undefined ? true : error instanceof PolicyError && ['EXTERNAL_NETWORK', 'EXTERNAL_DNS', 'EXTERNAL_TIMEOUT', 'EXTERNAL_TLS'].includes(error.rule) ? false : prior.reachable, authentication: authFailed ? 'invalid' : prior.authentication, monitoring: false, remote_control: false, gateway_enforcement: false, endpoint_verified: false, error_category: error instanceof PolicyError ? error.rule : 'EXTERNAL_FAILURE', last_error: error instanceof PolicyError ? error.message : 'Connection operation failed; inspect server diagnostics' } satisfies ConnectionHealth), row.id, tenant.id);
}
/** A positive public response alone cannot prove a credential was enforced. Probe the same harmless GET without secrets. */
async function verifyAuthentication(config: ExternalConnectionConfig): Promise<ConnectionHealth['authentication']> {
  if (config.auth === 'none') return 'not_required';
  if (config.private_connector) return 'valid';
  const endpoint = config.endpoints.test;
  if (!endpoint) throw invalid('Configure a harmless test endpoint');
  const url = endpointUrl(config.base_url, endpoint.path, null);
  for (const [key, value] of Object.entries(endpoint.query ?? {})) url.searchParams.set(key, value);
  if (config.auth === 'api_key_query') url.searchParams.delete(config.header);
  try {
    await requestJson({ url, method: 'GET', headers: { accept: 'application/json' }, body: null, timeout: config.timeout_ms, tlsMinVersion: config.tls_min_version });
    return 'unverified';
  } catch (error) {
    if (!(error instanceof PolicyError)) throw error;
    if (error.rule === 'EXTERNAL_AUTH' && [401, 403].includes(Number(error.extra.upstream_status))) return 'valid';
    console.warn('Credential enforcement probe was inconclusive', { rule: error.rule });
    return 'unverified';
  }
}

export async function testConnection(id: string, actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    try {
      await audit(id, 'test_requested', actor.id);
      await call(row, 'test', null, null, actor, {});
      const { config } = await storedOf(row);
      const health: ConnectionHealth = { ...JSON.parse((await rowOf(id)).health) as ConnectionHealth, reachable: true, authentication: await verifyAuthentication(config), gateway_enforcement: !!config.private_connector, last_tested_at: nowIso(), endpoint_verified: true, error_category: null, verified_operations: [...new Set([...(JSON.parse((await rowOf(id)).health) as ConnectionHealth).verified_operations ?? [], 'test'])], last_success_at: nowIso(), last_error: null };
      await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(health), id, tenant.id);
      await audit(id, 'test_succeeded', actor.id);
      return view(id);
    } catch (error) { await healthFailure(row, error); const failed = await rowOf(id); await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify({ ...JSON.parse(failed.health), last_tested_at: nowIso() }), id, tenant.id); await audit(id, 'test_failed', actor.id); throw error; }
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
  if (input.config === undefined && !previous) throw invalid('Configure and review the test endpoint, discovery endpoint and response mapping before connecting this generic REST API');
  const config = parseConfig(input.config === undefined ? { ...previous, base_url: input.base_url } : { ...object(input.config, 'connection config'), base_url: input.base_url });
  if (config.method !== 'rest') throw invalid('REST connect requires a REST configuration');
  const connection = input.connection_id === null ? await create(agentRef, { config, credential }, actor) : await update(input.connection_id, { config, credential }, actor);
  await testConnection(connection.id, actor);
  return config.endpoints.discover ? previewRestAgents(connection.id, actor) : { connection: await view(connection.id), agents: [] };
}

/** Refresh the real external list without importing agents. */
export async function previewRestAgents(id: string, actor: Principal): Promise<RestConnectResult> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const { config } = await storedOf(row);
    if (config.method !== 'rest') throw invalid('Agent preview requires a REST connection');
    const mapping = config.agents_mapping;
    if (!mapping) throw invalid('Configure an explicit agent response mapping before preview or onboarding');
    const result = await readMappedRecords(row, 'discover', null, mapping, actor);
    return { connection: await view(id), agents: await previewRecords(id, result.records) };
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
    const mapping = config.agents_mapping;
    if (!mapping) throw invalid('Configure an explicit agent response mapping before preview or onboarding');
    const result = await readMappedRecords(row, 'discover', null, mapping, actor);
    const record = result.records.find((item) => item.id === externalId);
    if (!record) throw notFound('external agent; refresh the agent list');
    await importExternalAgents(row, [record], actor);
    const mapped = await db.prepare('SELECT agent_id FROM external_agent_mapping WHERE connection_id = ? AND external_id = ?').get(id, externalId) as { agent_id: string } | undefined;
    if (!mapped) throw new Error('REST agent onboarding did not create an agent mapping');
    await audit(id, 'agent_onboarded', actor.id);
    return { agent_id: mapped.agent_id };
  });
}

async function readMappedRecords(row: Row, operation: 'discover' | 'executions', externalId: string | null, mapping: ResponseMapping, actor: Principal): Promise<{ records: ImportedRecord[]; errors: { index: number; rule: string }[] }> {
  const { config } = await storedOf(row);
  const pagination = operation === 'discover' ? config.discovery_pagination : config.execution_pagination;
  const records: ImportedRecord[] = [];
  const errors: { index: number; rule: string }[] = [];
  let offset: number | null = 0;
  const deadline = Date.now() + 240000;
  while (offset !== null) {
    if (Date.now() > deadline) throw new PolicyError('SYNC_TIMEOUT', 'Mapped read exceeded its four-minute budget; narrow the platform scope', 504);
    const data = await call(row, operation, externalId, null, actor, pagination ? { offset: String(offset), limit: '100' } : {});
    const items = pointer(data, mapping.items);
    if (!Array.isArray(items) || items.length + records.length + errors.length > 1000) throw invalid('Mapped list must contain at most 1000 records across all pages');
    const baseIndex = records.length + errors.length;
    for (const [index, item] of items.entries()) {
      try { records.push(...adaptRecords({ rows: [item] }, { ...mapping, items: '/rows' })); }
      catch (error) { if (!(error instanceof PolicyError)) throw error; errors.push({ index: baseIndex + index, rule: error.rule }); }
    }
    offset = pagination ? nextExecutionOffset(data, pagination, offset, items.length) : null;
  }
  if (new Set(records.map((record) => record.id)).size !== records.length) throw invalid('Provider returned duplicate external IDs across its pages');
  await db.prepare('INSERT INTO external_operation_run (id, tenant_id, connection_id, operation, outcome, actor, started_at, completed_at, correlation_id, record_count, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(newId('evt'), tenant.id, row.id, `${operation}_mapping`, errors.length ? 'partial' : 'succeeded', actor.id, nowIso(), nowIso(), newId('evt'), records.length, JSON.stringify({ errors }));
  if (errors.length && !records.length) throw invalid(`None of the ${errors.length} provider records matched the mapping; inspect connection history and correct the field mappings`);
  return { records, errors };
}

async function discoverRows(row: Row, actor: Principal): Promise<number> {
  const { config } = await storedOf(row);
  if (!config.agents_mapping) throw invalid('Configure the documented agent response mapping before discovery');
  const result = await readMappedRecords(row, 'discover', null, config.agents_mapping, actor);
  await tx(async () => {
    await importExternalAgents(row, result.records, actor);
    if (!result.errors.length) {
      const ids = result.records.map((record) => record.id);
      const suffix = ids.length ? ` AND external_id NOT IN (${ids.map(() => '?').join(',')})` : '';
      await db.prepare(`UPDATE external_agent_mapping SET presence = 'missing' WHERE connection_id = ?${suffix}`).run(row.id, ...ids);
    }
  });
  return result.records.length;
}

async function importExternalAgents(row: Row, records: ImportedRecord[], actor: Principal): Promise<void> {
  const deadline = Date.now() + 240000;
  const { config } = await storedOf(row);
  await tx(async () => {
    await db.prepare("SET LOCAL statement_timeout = '30s'").run();
    for (const record of records) {
      if (Date.now() > deadline) throw new PolicyError('SYNC_TIMEOUT', 'Agent import exceeded its four-minute budget; narrow the provider scope and retry', 504);
      const prior = await db.prepare('SELECT agent_id FROM external_agent_mapping WHERE connection_id = ? AND external_id = ?').get(row.id, record.id);
      if (prior) { await db.prepare("UPDATE external_agent_mapping SET last_seen_at = ?, normalized = ?, presence = 'present' WHERE connection_id = ? AND external_id = ?").run(nowIso(), JSON.stringify(record), row.id, record.id); continue; }
      const parent = row.agent_id === null ? null : await getAgent(row.agent_id);
      const agent = await registerAgent({ handle: `ext-${sha256(`${row.id}:${record.id}`).slice(0, 24)}`, name: record.name ?? record.id, purpose: `External agent discovered through ${config.name}; classification and approval required`, sponsor: parent?.sponsor ?? actor.id, owner: actor.id, autonomy_level: 'L0', kind: 'third_party', vendor: config.name, connection_method: config.method === 'oauth' ? 'oauth' : 'rest' }, actor);
      await workflow.start(agent, {}, actor, 'initial', null);
      await db.prepare('INSERT INTO external_agent_mapping (connection_id, external_id, agent_id, last_seen_at, normalized) VALUES (?, ?, ?, ?, ?)').run(row.id, record.id, agent.id, nowIso(), JSON.stringify(record));
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
      const health = { ...JSON.parse((await rowOf(id)).health) as ConnectionHealth, reachable: true, authentication: (JSON.parse((await rowOf(id)).health) as ConnectionHealth).authentication, discovered: count, last_success_at: nowIso(), last_error: null } satisfies ConnectionHealth;
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
          const result = await readMappedRecords(row, 'executions', mapped.external_id, config.executions_mapping, actor);
          await tx(async () => {
            await db.prepare("SET LOCAL statement_timeout = '30s'").run();
            for (const record of result.records) {
              if (Date.now() - startedAt > 240000) throw new PolicyError('SYNC_TIMEOUT', 'Execution persistence exceeded the sync budget', 504);
              await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(connection_id, external_agent_id, kind, external_id) DO UPDATE SET metadata = excluded.metadata, observed_at = excluded.observed_at').run(id, mapped.external_id, record.id, 'execution', JSON.stringify(normalizeExecution(record)), nowIso());
            }
          });
        }
      }
      const health = { ...JSON.parse((await rowOf(id)).health) as ConnectionHealth, reachable: true, authentication: (JSON.parse((await rowOf(id)).health) as ConnectionHealth).authentication, monitoring: config.monitoring_enabled !== false, last_sync_at: nowIso(), last_success_at: nowIso(), last_error: null } satisfies ConnectionHealth;
      await db.prepare('UPDATE external_connection SET health = ?, next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(health), Date.now() + config.sync_interval_seconds * 1000, id, tenant.id);
      await db.prepare('UPDATE external_connection SET sync_failures = 0 WHERE id = ? AND tenant_id = ?').run(id, tenant.id);
      await audit(id, 'synchronized', actor.id);
      return view(id);
    } catch (error) {
      await healthFailure(row, error);
      const failure = await db.prepare('UPDATE external_connection SET sync_failures = sync_failures + 1 WHERE id = ? AND tenant_id = ? RETURNING sync_failures').get(id, tenant.id) as { sync_failures: number };
      await db.prepare('UPDATE external_connection SET next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(Date.now() + Math.min(3600000, config.sync_interval_seconds * 1000 * 2 ** Math.min(failure.sync_failures, 6)), id, tenant.id);
      await audit(id, 'sync_failed', actor.id);
      throw error;
    }
  });
}
function secretValues(stored: Stored): string[] {
  const values = stored.config.auth === 'custom_headers' ? Object.values(JSON.parse(stored.credential) as Record<string, string>) : [stored.credential];
  return [...values, ...values.map((value) => encodeURIComponent(value)), stored.token ?? '', stored.config.auth === 'basic' ? Buffer.from(`${stored.config.username}:${stored.credential}`).toString('base64') : ''].filter(Boolean);
}
function redactResponse(value: Json, secretsToHide: string[]): Json {
  if (typeof value === 'string') return secretsToHide.filter(Boolean).reduce((text, secret) => text.replaceAll(secret, '[redacted]'), value).slice(0, 8000);
  if (Array.isArray(value)) return value.slice(0, 1000).map((item) => redactResponse(item, secretsToHide));
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([key]) => !/^(access_token|refresh_token|id_token|token|secret|password|credentials?|authorization|api.?key|client_secret|signing_secret)$/i.test(key)).slice(0, 100).map(([key, item]) => [key, redactResponse(item, secretsToHide)]));
  return value;
}

/** Optional signed webhook protocol: HMAC-SHA256(timestamp.event-id.raw-body), five-minute replay window. */
export async function configureWebhook(id: string, value: unknown, actor: Principal): Promise<{ enabled: boolean; path: string }> {
  requireManager(actor);
  const input = object(value, 'webhook settings');
  if (typeof input.enabled !== 'boolean') throw invalid('Webhook enabled must be boolean');
  const enabled = input.enabled;
  return exclusive(id, async () => {
    await rowOf(id);
    return tx(async () => {
    const prior = await db.prepare('SELECT webhook_secret_id FROM external_connection WHERE id = ? AND tenant_id = ?').get(id, tenant.id) as { webhook_secret_id: string | null };
    let secretId: string | null = null;
    let mapping: string | null = null;
    if (input.enabled) {
      if (typeof input.secret !== 'string' || input.secret.length < 32 || input.secret.length > 1000 || /[\r\n]/.test(input.secret)) throw invalid('Webhook signing secret must contain 32-1000 characters without newlines');
      if (typeof input.agent_pointer !== 'string' || !input.agent_pointer.startsWith('/') || input.agent_pointer.length > 200 || /~(?![01])/.test(input.agent_pointer)) throw invalid('Webhook agent_pointer must be a JSON Pointer to the external agent ID');
      if (!['execution', 'tracking'].includes(String(input.kind))) throw invalid('Webhook kind must be execution or tracking');
      const stored = await storedOf(await rowOf(id));
      if (input.kind === 'execution' ? !stored.config.executions_mapping : !stored.config.agents_mapping) throw invalid('Configure the corresponding response mapping before enabling webhooks');
      secretId = (await secrets.putSecret({ name: `hook-${newId('sec').toLowerCase()}`, kind: 'tool', value: input.secret }, actor)).id;
      mapping = JSON.stringify({ agent_pointer: input.agent_pointer, kind: input.kind });
    }
    await tx(async () => {
      await db.prepare('UPDATE external_connection SET webhook_secret_id = ?, webhook_mapping = ? WHERE id = ? AND tenant_id = ?').run(secretId, mapping, id, tenant.id);
      if (prior.webhook_secret_id) await db.prepare('DELETE FROM secret WHERE id = ? AND tenant_id = ?').run(prior.webhook_secret_id, tenant.id);
      await audit(id, input.enabled ? 'webhook_enabled' : 'webhook_disabled', actor.id);
    });
    return { enabled, path: `/api/v1/connection-webhooks/${id}` };
    });
  });
}

export async function receiveWebhook(id: string, raw: Buffer, timestamp: string, eventId: string, signature: string): Promise<{ accepted: true; records: number }> {
  const row = await rowOf(id);
  if (row.state !== 'enabled') throw forbidden('WEBHOOK_DISABLED', 'Connection is disabled');
  if (raw.length > 65536 || !/^\d{10}$/.test(timestamp) || Math.abs(Date.now() - Number(timestamp) * 1000) > 300000 || !/^[a-zA-Z0-9_-]{8,100}$/.test(eventId) || !/^sha256=[a-f0-9]{64}$/.test(signature)) throw forbidden('WEBHOOK_SIGNATURE', 'Invalid webhook timestamp, event ID or signature');
  const settings = await db.prepare('SELECT webhook_secret_id, webhook_mapping FROM external_connection WHERE id = ? AND tenant_id = ?').get(id, tenant.id) as { webhook_secret_id: string | null; webhook_mapping: string | null };
  if (!settings.webhook_secret_id || !settings.webhook_mapping) throw forbidden('WEBHOOK_DISABLED', 'Signed webhooks have not been enabled');
  await secrets.getSecretMeta(settings.webhook_secret_id);
  const secret = (await secrets.revealForGateway(settings.webhook_secret_id)).value;
  const expected = createHmac('sha256', secret).update(`${timestamp}.${eventId}.`).update(raw).digest();
  if (!timingSafeEqual(expected, Buffer.from(signature.slice(7), 'hex'))) throw forbidden('WEBHOOK_SIGNATURE', 'Webhook signature verification failed');
  const mapping = JSON.parse(settings.webhook_mapping) as { agent_pointer: string; kind: 'execution' | 'tracking' };
  let data: Json;
  try { data = JSON.parse(raw.toString('utf8')) as Json; } catch { throw invalid('Signed webhook body must be valid JSON'); }
  const externalId = pointer(data, mapping.agent_pointer);
  if (typeof externalId !== 'string' || !externalId) throw invalid('Webhook external agent ID must be a non-empty string');
  const agent = await db.prepare('SELECT agent_id FROM external_agent_mapping WHERE connection_id = ? AND external_id = ?').get(id, externalId);
  if (!agent) throw notFound('onboarded webhook agent');
  const stored = await storedOf(row);
  const fields = mapping.kind === 'execution' ? stored.config.executions_mapping : stored.config.agents_mapping;
  if (!fields) throw invalid('Webhook response mapping is missing');
  const records = adaptRecords(data, fields);
  if (mapping.kind === 'tracking' && records.some((record) => record.id !== externalId)) throw invalid('Tracking webhook records must match the signed external agent ID');
  try {
    await tx(async () => {
      await db.prepare('INSERT INTO external_webhook_nonce (connection_id, event_id, received_at) VALUES (?, ?, ?)').run(id, eventId, nowIso());
      for (const record of records) await db.prepare('INSERT INTO external_observation (connection_id, external_agent_id, external_id, kind, metadata, observed_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(connection_id, external_agent_id, kind, external_id) DO UPDATE SET metadata = excluded.metadata, observed_at = excluded.observed_at').run(id, externalId, record.id, mapping.kind, JSON.stringify(mapping.kind === 'execution' ? normalizeExecution(record) : record), nowIso());
      await audit(id, 'webhook_received', 'svc:connection-webhook');
      await db.prepare('INSERT INTO external_operation_run (id, tenant_id, connection_id, operation, outcome, actor, started_at, completed_at, correlation_id, record_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(newId('evt'), tenant.id, id, 'webhook', 'succeeded', 'svc:connection-webhook', nowIso(), nowIso(), eventId, records.length);
    });
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === '23505') throw new PolicyError('WEBHOOK_REPLAY', 'Webhook event ID has already been processed', 409);
    throw error;
  }
  return { accepted: true, records: records.length };
}

export async function deleteConnection(id: string, actor: Principal): Promise<{ deleted: true }> {
  requireManager(actor);
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const hook = await db.prepare('SELECT webhook_secret_id FROM external_connection WHERE id = ? AND tenant_id = ?').get(id, tenant.id) as { webhook_secret_id: string | null };
    await tx(async () => {
      await audit(id, 'deleted', actor.id);
      await db.prepare('DELETE FROM external_connection WHERE id = ? AND tenant_id = ?').run(id, tenant.id);
      await db.prepare('DELETE FROM secret WHERE id = ? AND tenant_id = ?').run(row.secret_id, tenant.id);
      if (hook.webhook_secret_id) await db.prepare('DELETE FROM secret WHERE id = ? AND tenant_id = ?').run(hook.webhook_secret_id, tenant.id);
    });
    return { deleted: true };
  });
}
export async function setMonitoring(id: string, enabled: boolean, actor: Principal): Promise<ExternalConnectionView> {
  requireManager(actor);
  if (typeof enabled !== 'boolean') throw invalid('Monitoring enabled must be boolean');
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const stored = await storedOf(row);
    if (row.state !== 'enabled') throw invalid('Reconnect this connection before changing monitoring');
    if (enabled && (!stored.config.endpoints.track && !stored.config.endpoints.executions)) throw invalid('Configure tracking or execution endpoints before enabling monitoring');
    await secrets.rotateSecret(row.secret_id, JSON.stringify({ ...stored, config: { ...stored.config, monitoring_enabled: enabled } }), actor);
    const health = JSON.parse(row.health) as ConnectionHealth;
    await db.prepare('UPDATE external_connection SET health = ?, next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify({ ...health, monitoring: false }), Date.now(), id, tenant.id);
    await audit(id, enabled ? 'monitoring_enabled' : 'monitoring_disabled', actor.id);
    return view(id);
  });
}
export async function inventory(id: string): Promise<{ items: { internal_id: string; agent_id: string; connection_id: string; external_agent_id: string; external_id: string; name: string; description: string | null; framework: string | null; provider: string | null; status: string | null; capabilities: string[] | null; metadata: Record<string, Json>; last_seen_at: string; presence: string }[] }> {
  await rowOf(id);
  const rows = await db.prepare('SELECT m.agent_id, m.external_id, m.normalized, m.last_seen_at, m.presence, a.name FROM external_agent_mapping m JOIN agent a ON a.id = m.agent_id WHERE m.connection_id = ? ORDER BY a.name, m.external_id').all(id) as { agent_id: string; external_id: string; normalized: string; last_seen_at: string; presence: string; name: string }[];
  return { items: rows.map((row) => {
    const normalized = JSON.parse(row.normalized) as Partial<ImportedRecord>;
    const metadata = normalized.metadata ?? {};
    return { internal_id: row.agent_id, agent_id: row.agent_id, connection_id: id, external_agent_id: row.external_id, external_id: row.external_id, name: normalized.name ?? row.name, description: typeof metadata.description === 'string' ? metadata.description : null, framework: typeof metadata.framework === 'string' ? metadata.framework : null, provider: typeof metadata.provider === 'string' ? metadata.provider : null, status: normalized.status ?? null, capabilities: Array.isArray(metadata.capabilities) ? metadata.capabilities as string[] : null, metadata, last_seen_at: row.last_seen_at, presence: row.presence };
  }) };
}

export async function history(id: string, actor: Principal): Promise<{ items: { id: string; operation: string; outcome: string; started_at: string; completed_at: string | null; error_category: string | null; detail: string | null; record_count: number | null }[] }> {
  if (!actor.permissions.includes('ledger.read')) throw forbidden('RBAC', 'Connection history requires ledger.read');
  await rowOf(id);
  return { items: await db.prepare('SELECT id, operation, outcome, started_at, completed_at, error_category, detail, record_count FROM external_operation_run WHERE tenant_id = ? AND connection_id = ? ORDER BY started_at DESC LIMIT 100').all(tenant.id, id) as { id: string; operation: string; outcome: string; started_at: string; completed_at: string | null; error_category: string | null; detail: string | null; record_count: number | null }[] };
}
export async function readAgentOperation(id: string, agentId: string, operation: string, executionId: string | null, actor: Principal): Promise<Json> {
  requireManager(actor);
  if (!['agent', 'track', 'executions', 'execution', 'logs', 'metrics'].includes(operation)) throw invalid('Unsupported read operation');
  return exclusive(id, async () => {
    const row = await rowOf(id);
    const mapping = await db.prepare('SELECT external_id FROM external_agent_mapping WHERE connection_id = ? AND agent_id = ?').get(id, agentId) as { external_id: string } | undefined;
    if (!mapping) throw notFound('connection agent mapping');
    const result = await call(row, operation as ExternalOperation, mapping.external_id, null, actor, executionId === null ? {} : { execution_id: executionId });
    const stored = await storedOf(row);
    return redactResponse(result, secretValues(stored));
  });
}

export async function remoteAction(id: string, agentId: string, action: string, body: unknown, actor: Principal): Promise<{ accepted: true; response: Json }> {
  requireManager(actor);
  if (!['run', 'pause', 'stop', 'activate'].includes(action)) throw invalid('Unsupported remote action');
  const envelope = object(body, 'action request');
  if (envelope.confirmation !== `${action}:${agentId}`) throw invalid('Explicit action confirmation must match action:agent_id');
  const payload = object(envelope.payload, 'action payload');
  if (envelope.idempotency_key !== undefined && (typeof envelope.idempotency_key !== 'string' || !/^[a-zA-Z0-9_-]{8,100}$/.test(envelope.idempotency_key))) throw invalid('idempotency_key must be 8-100 URL-safe characters');
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
    const variables = requestVariables(payload as Json, mapped.external_id, null);
    const outgoing = requestBody(endpoint, payload as Json, variables);
    const effectiveArguments = object(outgoing, 'mapped remote action payload');
    const decision = evaluateTs({ kind: 'tool', policy: compilePolicy(certificate, tenant.settings.baseline), action: { key: `${approvedServer}.${action}`, args: { ...effectiveArguments, ...requestQuery(endpoint, variables), id: mapped.external_id } }, context: { step_up: level === 'step_up' } });
    await ledger.append({ kind: 'admin', agent_id: agent.id, data: { event: 'connection.remote_policy', connection_id: id, action, decision: decision.decision, rule_ids: decision.rule_ids, actor: actor.id, coverage: 'external_management' } });
    if (decision.decision !== 'allow') throw forbidden('REMOTE_POLICY', `Remote action refused by Signet policy: ${decision.decision}; rules: ${decision.rule_ids.join(', ')}. Use the Gateway approval flow for actions requiring human approval.`);
    const connectionHealth = JSON.parse(row.health) as ConnectionHealth;
    if (!connectionHealth.endpoint_verified || (config.auth !== 'none' && connectionHealth.authentication !== 'valid')) throw forbidden('REMOTE_CONNECTION', 'Verify the configured test endpoint and credential enforcement before remote actions');
    await audit(id, `${action}_requested`, actor.id);
    try {
      const response = await call(row, action as ExternalOperation, mapped.external_id, payload as Json, actor, typeof envelope.idempotency_key === 'string' ? { __idempotency: envelope.idempotency_key } : {});
      await audit(id, `${action}_succeeded`, actor.id);
      const health = { ...JSON.parse((await rowOf(id)).health) as ConnectionHealth, remote_control: true };
      await db.prepare('UPDATE external_connection SET health = ? WHERE id = ? AND tenant_id = ?').run(JSON.stringify(health), id, tenant.id);
      const stored = await storedOf(row);
      return { accepted: true, response: redactResponse(response, secretValues(stored)) };
    } catch (error) {
      await healthFailure(row, error); await audit(id, `${action}_failed`, actor.id);
      if (error instanceof PolicyError && ['EXTERNAL_NETWORK', 'EXTERNAL_TIMEOUT', 'EXTERNAL_SCHEMA', 'EXTERNAL_CONTENT', 'EXTERNAL_HTTP'].includes(error.rule)) throw new PolicyError('REMOTE_UNCERTAIN', 'Provider action outcome is uncertain. Check provider state and action history before retrying; this mutation was not automatically replayed', 502, { cause_rule: error.rule });
      throw error;
    }
  });
}

/** Only previously imported mappings are synchronized; background jobs never register or certify agents. */
export async function work(): Promise<void> {
  await db.prepare('DELETE FROM external_webhook_nonce WHERE received_at < ? AND connection_id IN (SELECT id FROM external_connection WHERE tenant_id = ?)').run(new Date(Date.now() - 600000).toISOString(), tenant.id);
  await db.prepare('DELETE FROM external_operation_run WHERE tenant_id = ? AND started_at < ?').run(tenant.id, new Date(Date.now() - 90 * 86400000).toISOString());
  const rows = await db.prepare("SELECT id FROM external_connection WHERE tenant_id = ? AND state = 'enabled' AND next_sync_at < ? AND busy_until < ? AND EXISTS (SELECT 1 FROM external_agent_mapping WHERE connection_id = external_connection.id) ORDER BY next_sync_at LIMIT 1").all(tenant.id, Date.now(), Date.now()) as { id: string }[];
  const actor: Principal = { id: 'svc:connection-sync', name: 'Connection synchronization', kind: 'service', roles: ['automation'], permissions: ['connectors.manage'], groups: [], mfa: false, auth: 'bearer', auth_time: null };
  for (const row of rows) {
    const { config } = await storedOf(await rowOf(row.id));
    if (config.monitoring_enabled === false || (!config.endpoints.track && !config.endpoints.executions)) {
      await db.prepare('UPDATE external_connection SET next_sync_at = ? WHERE id = ? AND tenant_id = ?').run(Date.now() + config.sync_interval_seconds * 1000, row.id, tenant.id);
      continue;
    }
    try { await sync(row.id, actor); }
    catch (error) { if (!(error instanceof Error)) throw error; console.warn('External connection sync failed', { connection_id: row.id, rule: error instanceof PolicyError ? error.rule : 'INTERNAL' }); }
  }
}

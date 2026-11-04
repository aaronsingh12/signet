import type { AgentListFields, ExternalConnectionConfig, ExternalOperation, ResponseMapping } from '@signet/core/types';
import { invalid } from './errors';
import { connectionOptions, endpointOptions } from './external-options';

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export function object(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid(`${field} must be an object`);
  return value as Record<string, unknown>;
}
function text(value: unknown, field: string, max: number): string {
  if (typeof value !== 'string' || value.length > max) throw invalid(`${field} must be a string of at most ${max} characters`);
  return value;
}
export function publicUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw invalid('External endpoint must be an absolute HTTPS URL'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search || (url.port && url.port !== '443') || url.hostname.length > 253) throw invalid('External endpoints require HTTPS without credentials, query or fragment; use an enrolled runner for private APIs');
  return url;
}
export function endpointUrl(base: string, path: string, id: string | null): URL {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\') || /(?:\.\.|%2e|%2f|%5c)/i.test(path)) throw invalid('Endpoint path must start with / and cannot contain traversal or encoded separators');
  const filled = path.replaceAll('{agent_id}', '{id}').replaceAll('{id}', id === null ? '{id}' : encodeURIComponent(id));
  if (/[{}#\r\n]/.test(filled)) throw invalid('Endpoint requires an external agent ID, or contains an unsupported template parameter');
  const root = publicUrl(base);
  const url = new URL(root.toString().replace(/\/$/, '') + filled);
  if (url.origin !== root.origin || !url.pathname.startsWith(root.pathname.replace(/\/$/, '') + '/')) throw invalid('Endpoint escapes the configured API base URL');
  return url;
}
function mapping(value: unknown, field: string): ResponseMapping | null {
  if (value === null) return null;
  const row = object(value, field);
  const result = Object.fromEntries(['items', 'id', 'name', 'status', 'timestamp'].map((key) => [key, text(row[key], `${field}.${key}`, 200)])) as unknown as ResponseMapping;
  for (const path of Object.values(result)) if (path && (!path.startsWith('/') || /~(?![01])/g.test(path))) throw invalid(`${field}: mappings must be JSON pointers (empty string selects the root)`);
  if (row.fields !== undefined) {
    const fields = object(row.fields, `${field}.fields`);
    if (Object.keys(fields).length > 20 || Object.entries(fields).some(([key, path]) => !/^[a-z][a-z0-9_]{0,39}$/.test(key) || ['internal_id', 'tenant_id', 'agent_id', 'connection_id', 'owner', 'approved', 'tier'].includes(key) || typeof path !== 'string' || !path.startsWith('/') || path.length > 200 || /~(?![01])/.test(path))) throw invalid('Metadata mapping requires at most 20 non-reserved names and JSON Pointers');
    if (Object.entries(fields).some(([key, path]) => /^(token|access_token|refresh_token|api_key|password|secret|credential|authorization)$/i.test(key) || String(path).split('/').some((part) => /^(token|access_token|refresh_token|api_key|password|secret|credential|authorization)$/i.test(part)))) throw invalid('Secret values cannot be retained as provider metadata');
    result.fields = fields as Record<string, string>;
  }
  if (!result.id) throw invalid(`${field}.id must point to a stable ID field`);
  return result;
}
export function parseConfig(value: unknown): ExternalConnectionConfig {
  const input = object(value, 'connection');
  const name = text(input.name, 'name', 120).trim();
  if (!name) throw invalid('Connection name is required');
  if (input.method !== 'rest' && input.method !== 'oauth' && input.method !== 'hybrid') throw invalid('method must be rest, oauth or hybrid');
  if (!['none', 'api_key', 'api_key_query', 'basic', 'custom_headers', 'bearer', 'oauth', 'connector'].includes(String(input.auth))) throw invalid('Unsupported authentication type');
  if (input.method === 'oauth' && input.auth !== 'oauth') throw invalid('OAuth connections require OAuth authentication');
  const base = text(input.base_url, 'base_url', 2000);
  let privateConnector: ExternalConnectionConfig['private_connector'] = null;
  if (input.method === 'hybrid') {
    const connector = object(input.private_connector, 'private_connector');
    privateConnector = { runner_id: text(connector.runner_id, 'runner_id', 120), tool_alias: text(connector.tool_alias, 'tool_alias', 80), environment: text(connector.environment, 'environment', 80) };
    if (!privateConnector.runner_id || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(privateConnector.tool_alias) || !privateConnector.environment || input.auth !== 'connector') throw invalid('Private connections require an enrolled runner, registered tool alias, environment and connector authentication');
    let url: URL;
    try { url = new URL(base); } catch { throw invalid('Private endpoint must be an absolute HTTP(S) URL'); }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw invalid('Private endpoint must be HTTP(S) without credentials, query or fragment');
  } else { publicUrl(base); if (input.auth === 'connector') throw invalid('Connector identity requires a private connection'); }
  const header = text(input.header, 'header', 100);
  if (['api_key', 'api_key_query'].includes(String(input.auth)) && (!/^[a-zA-Z0-9_-]+$/.test(header) || /^(host|cookie|connection|content-length|transfer-encoding|proxy-.*|x-signet-.*)$/i.test(header))) throw invalid('API key header is invalid or reserved');
  const tokenUrl = text(input.token_url, 'token_url', 2000);
  const clientId = text(input.client_id, 'client_id', 500);
  if (input.auth === 'oauth') { publicUrl(tokenUrl); if (!clientId) throw invalid('OAuth client ID is required'); }
  if (!['client_secret_basic', 'client_secret_post'].includes(String(input.token_auth))) throw invalid('Unsupported OAuth token authentication method');
  for (const [key, min, max] of [['timeout_ms', 1000, 30000], ['sync_interval_seconds', 60, 86400]] as const) {
    if (!Number.isInteger(input[key]) || Number(input[key]) < min || Number(input[key]) > max) throw invalid(`${key} must be an integer between ${min} and ${max}`);
  }
  if (typeof input.remote_management !== 'boolean') throw invalid('remote_management must be a boolean');
  const endpoints: ExternalConnectionConfig['endpoints'] = {};
  const trackingPointer = text(input.tracking_pointer, 'tracking_pointer', 200);
  if (trackingPointer && (!trackingPointer.startsWith('/') || /~(?![01])/.test(trackingPointer))) throw invalid('tracking_pointer must be a JSON pointer selecting the agent object');
  let pagination: ExternalConnectionConfig['execution_pagination'] = null;
  if (input.execution_pagination !== null) {
    const fields = object(input.execution_pagination, 'execution_pagination');
    pagination = { total: text(fields.total, 'pagination.total', 200), offset: text(fields.offset, 'pagination.offset', 200), limit: text(fields.limit, 'pagination.limit', 200) };
    if (Object.values(pagination).some((path) => !path.startsWith('/') || /~(?![01])/.test(path))) throw invalid('Execution pagination requires total, offset and limit JSON pointers');
  }
  const provided = object(input.endpoints, 'endpoints');
  for (const op of ['test', 'discover', 'agent', 'track', 'executions', 'execution', 'logs', 'metrics', 'run', 'pause', 'stop', 'activate'] as const) {
    if (provided[op] === undefined) continue;
    const spec = object(provided[op], `endpoints.${op}`);
    const path = text(spec.path, `${op}.path`, 1000);
    const options = endpointOptions(spec);
    const checkedPath = Object.keys(options.variables ?? {}).reduce((result, key) => result.replaceAll(`{${key}}`, 'validation-id'), path).replaceAll('{execution_id}', 'validation-execution');
    endpointUrl(input.method === 'hybrid' ? 'https://private-placeholder.example' : base, checkedPath, 'validation-id');
    const checkedUrl = endpointUrl(input.method === 'hybrid' ? 'https://private-placeholder.example' : base, checkedPath, 'validation-id');
    for (const key of checkedUrl.searchParams.keys()) if (/^(token|access_token|refresh_token|api_key|password|secret|credential|authorization)$/i.test(key) || (input.auth === 'api_key_query' && key === header)) throw invalid('Do not put credential values in endpoint paths; use the encrypted authentication credential');
    for (const key of Object.keys(options.query ?? {})) if (/^(token|access_token|refresh_token|api_key|password|secret|credential|authorization)$/i.test(key) || (input.auth === 'api_key_query' && key === header)) throw invalid('Secret query parameters must come from the encrypted authentication credential');
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(String(spec.method))) throw invalid(`${op}: unsupported HTTP method`);
    if (op === 'test' && spec.method !== 'GET') throw invalid(`${op} must use read-only GET`);
    endpoints[op as ExternalOperation] = { ...options, path, method: spec.method as 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' };
  }
  if (!endpoints.test || /[{}]/.test(endpoints.test.path)) throw invalid('Configure a harmless test GET endpoint without an agent ID');
  return { ...connectionOptions(input), name, method: input.method, private_connector: privateConnector, base_url: base, auth: input.auth as ExternalConnectionConfig['auth'], header, token_url: tokenUrl, client_id: clientId, token_auth: input.token_auth as ExternalConnectionConfig['token_auth'], scopes: text(input.scopes, 'scopes', 1000), timeout_ms: Number(input.timeout_ms), sync_interval_seconds: Number(input.sync_interval_seconds), remote_management: input.remote_management, endpoints, agents_mapping: mapping(input.agents_mapping, 'agents_mapping'), executions_mapping: mapping(input.executions_mapping, 'executions_mapping'), tracking_pointer: trackingPointer, execution_pagination: pagination };
}

/** Offset pagination is opt-in and must use the platform's observed total/offset/limit schema. */
export function nextExecutionOffset(value: Json, pagination: NonNullable<ExternalConnectionConfig['execution_pagination']>, offset: number, count: number): number | null {
  const total = pointer(value, pagination.total);
  const actualOffset = pointer(value, pagination.offset);
  const limit = pointer(value, pagination.limit);
  if (typeof total !== 'number' || !Number.isInteger(total) || total < 0 || total > 1000 || actualOffset !== offset || typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > 100 || count > limit || offset + count > total) throw invalid('Execution pagination must return matching offset, limit 1–100 and total 0–1000; narrow the platform scope for larger histories');
  if (offset + count === total) return null;
  if (!count) throw invalid('Execution pagination returned an empty page before its reported total; synchronization is incomplete');
  return offset + count;
}

export function pointer(value: Json, path: string): Json | undefined {
  if (!path) return value;
  return path.slice(1).split('/').map((key) => key.replaceAll('~1', '/').replaceAll('~0', '~')).reduce<Json | undefined>((current, key) => {
    if (!current || typeof current !== 'object') return undefined;
    if (Array.isArray(current)) return current[Number(key)];
    return Object.hasOwn(current, key) ? current[key] : undefined;
  }, value);
}
export interface ImportedRecord { id: string; name: string | null; status: string | null; timestamp: string | null; metadata?: Record<string, Json> }
/** Retain only explicitly mapped metadata; never persist arbitrary remote payloads or credentials. */
export function adaptRecords(value: Json, contract: ResponseMapping): ImportedRecord[] {
  const rows = pointer(value, contract.items);
  if (!Array.isArray(rows) || rows.length > 1000) throw invalid('Mapped response items must be an array of at most 1000 records; configure pagination at the platform');
  const read = (row: Json, path: string, field: string): string | null => {
    if (!path) return null;
    const raw = pointer(row, path);
    const result = field === 'id' && typeof raw === 'number' && Number.isSafeInteger(raw) && raw >= 0 ? String(raw) : raw;
    if (typeof result !== 'string' || !result || result.length > 500) throw invalid(`Mapped ${field} must be a non-empty string of at most 500 characters`);
    return result;
  };
  const records = rows.map((row) => {
    const id = read(row, contract.id, 'id');
    if (!id || id === '.' || id === '..') throw invalid('Mapped record ID must be a stable non-dot string');
    const timestamp = read(row, contract.timestamp, 'timestamp');
    if (timestamp && !Number.isFinite(Date.parse(timestamp))) throw invalid('Mapped timestamp must be an ISO date');
    const metadata = Object.fromEntries(Object.entries(contract.fields ?? {}).map(([key, path]) => { const value = pointer(row, path); if (value === undefined) throw invalid(`Mapped metadata field ${key} is missing`); return [key, value]; }));
    for (const key of ['description', 'framework', 'provider']) if (metadata[key] !== undefined && metadata[key] !== null && (typeof metadata[key] !== 'string' || String(metadata[key]).length > 4000)) throw invalid(`Mapped ${key} must be text or null`);
    if (metadata.capabilities !== undefined && metadata.capabilities !== null && (!Array.isArray(metadata.capabilities) || metadata.capabilities.length > 100 || !metadata.capabilities.every((item) => typeof item === 'string' && item.length <= 200))) throw invalid('Mapped capabilities must be at most 100 text entries');
    if (JSON.stringify(metadata).length > 8192) throw invalid('Mapped metadata exceeds 8 KiB per record');
    return { metadata, id, name: read(row, contract.name, 'name'), status: read(row, contract.status, 'status'), timestamp };
  });
  if (new Set(records.map((row) => row.id)).size !== records.length) throw invalid('Response contains duplicate external IDs');
  return records;
}

/** Describe selectable string fields without returning remote record values or guessing a schema. */
export function agentListFields(value: Json): AgentListFields[] {
  const escape = (key: string): string => key.replaceAll('~', '~0').replaceAll('/', '~1');
  const strings = (item: Json, path: string, depth: number): string[] => {
    if (depth > 12) throw invalid('Agent response nesting exceeds 12 levels; use a simpler agent list endpoint');
    if (typeof item === 'string') return item ? [path] : [];
    if (!item || typeof item !== 'object' || Array.isArray(item)) return [];
    return Object.entries(item).flatMap(([key, child]) => strings(child, `${path}/${escape(key)}`, depth + 1));
  };
  const lists = (item: Json, path: string, depth: number): AgentListFields[] => {
    if (depth > 12) throw invalid('Agent response nesting exceeds 12 levels; use a simpler agent list endpoint');
    if (Array.isArray(item)) {
      if (item.length > 1000) throw invalid('Agent list exceeds 1000 records; narrow the API scope');
      const fields = item.length ? strings(item[0]!, '', 0).filter((field) => item.every((record) => typeof pointer(record, field) === 'string' && Boolean(pointer(record, field)))) : [];
      return [{ path, count: item.length, fields }];
    }
    if (!item || typeof item !== 'object') return [];
    return Object.entries(item).flatMap(([key, child]) => lists(child, `${path}/${escape(key)}`, depth + 1));
  };
  return lists(value, '', 0);
}

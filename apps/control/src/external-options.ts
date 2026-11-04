import { Ajv, type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import type { ConnectionEndpoint, ConnectorJson, ExternalConnectionConfig } from '@signet/core/types';
import { PolicyError, invalid } from './errors';
import { object, pointer, type Json } from './external-contract';

export function headerName(value: string): string {
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(value) || /^(host|cookie|set-cookie|connection|content-length|transfer-encoding|proxy-.*|x-signet-.*|x-forwarded-.*)$/i.test(value)) throw invalid('Header name is invalid or reserved');
  return value;
}
function template(value: Json, variables: Record<string, string>, input: Json | null): Json {
  if (typeof value === 'string') {
    const exact = value.match(/^\{([a-zA-Z0-9_]+)\}$/);
    if (exact && !['id', 'agent_id', 'execution_id'].includes(exact[1]!) && input !== null && typeof input === 'object' && !Array.isArray(input) && input[exact[1]!] !== undefined) return input[exact[1]!]!;
  }
  if (typeof value === 'string') return value.replace(/\{([a-zA-Z0-9_]+)\}/g, (_match, key: string) => {
    const replacement = variables[key];
    if (replacement === undefined) throw invalid(`Missing request template variable ${key}`);
    return replacement;
  });
  if (Array.isArray(value)) return value.map((item) => template(item, variables, input));
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, template(item, variables, input)]));
  return value;
}
export function requestVariables(input: Json | null, externalId: string | null, executionId: string | null): Record<string, string> {
  const parameters = input !== null && typeof input === 'object' && !Array.isArray(input) ? input : {};
  return { ...Object.fromEntries(Object.entries(parameters).filter((entry): entry is [string, string | number | boolean] => ['string', 'number', 'boolean'].includes(typeof entry[1])).map(([key, value]) => [key, String(value)])), ...(externalId === null ? {} : { id: externalId, agent_id: externalId }), ...(executionId === null ? {} : { execution_id: executionId }) };
}
export function requestQuery(endpoint: ConnectionEndpoint, variables: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(endpoint.query ?? {}).map(([key, value]) => [key, value.replace(/\{([a-zA-Z0-9_]+)\}/g, (_match, name: string) => { if (variables[name] === undefined) throw invalid(`Missing query variable ${name}`); return variables[name]; })]));
}

export function requestBody(endpoint: ConnectionEndpoint, input: Json | null, variables: Record<string, string>): Json | null {
  return endpoint.request_body === undefined ? input : template(endpoint.request_body, variables, input);
}

/** Schemas are synchronous Draft 7, local-reference only, bounded and free of untrusted regular expressions. */
export function schemaValidator(schema: { [key: string]: ConnectorJson }): ValidateFunction {
  if (JSON.stringify(schema).length > 16000) throw invalid('Response schema exceeds 16 KiB');
  let nodes = 0;
  const check = (value: Json, depth: number): void => {
    if (++nodes > 1000 || depth > 16) throw invalid('Response schema exceeds complexity limits');
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) { for (const child of value) check(child, depth + 1); return; }
    for (const [key, child] of Object.entries(value)) {
      if (['pattern', 'patternProperties', '$async', 'formatMinimum', 'formatMaximum'].includes(key)) throw invalid(`Response schema keyword ${key} is not supported`);
      if (key === '$ref' && (typeof child !== 'string' || !child.startsWith('#/'))) throw invalid('Only local response schema references are supported');
      check(child, depth + 1);
    }
  };
  check(schema, 0);
  const validator = new Ajv({ strict: true, allErrors: false, ownProperties: true });
  addFormats(validator, { mode: 'fast' });
  try { return validator.compile(schema); }
  catch { throw invalid('Response schema is not a supported strict Draft 7 JSON Schema; check types, required fields and local references'); }
}

export function endpointOptions(value: Record<string, unknown>): Partial<ConnectionEndpoint> {
  const result: Partial<ConnectionEndpoint> = {};
  if (value.variables !== undefined) {
    const variables = object(value.variables, 'endpoint.variables');
    if (Object.entries(variables).some(([key, item]) => !/^[a-zA-Z][a-zA-Z0-9_]{0,39}$/.test(key) || !['id', 'execution_id'].includes(String(item)))) throw invalid('Endpoint variables must map template names to id or execution_id');
    result.variables = variables as Record<string, 'id' | 'execution_id'>;
  }
  if (value.query !== undefined) {
    const query = object(value.query, 'endpoint.query');
    if (Object.keys(query).length > 20 || Object.entries(query).some(([key, item]) => !/^[a-zA-Z0-9_-]{1,80}$/.test(key) || typeof item !== 'string' || item.length > 1000 || /[\r\n]/.test(item))) throw invalid('Query mapping allows at most 20 named string templates');
    result.query = query as Record<string, string>;
  }
  if (value.request_body !== undefined) {
    if (JSON.stringify(value.request_body).length > 16000) throw invalid('Request body template exceeds 16 KiB');
    const check = (item: Json, depth: number): void => {
      if (depth > 16) throw invalid('Request body template exceeds 16 nesting levels');
      if (Array.isArray(item)) { for (const child of item) check(child, depth + 1); return; }
      if (item !== null && typeof item === 'object') for (const [key, child] of Object.entries(item)) {
        if (/^(password|secret|token|access_token|authorization|api_key|credential)$/i.test(key)) throw invalid('Put secrets in the authentication credential, not the request body mapping');
        check(child, depth + 1);
      }
    };
    check(value.request_body as Json, 0);
    result.request_body = value.request_body as ConnectorJson;
  }
  if (value.expected_status !== undefined) {
    if (!Array.isArray(value.expected_status) || !value.expected_status.length || value.expected_status.length > 10 || !value.expected_status.every((item) => Number.isInteger(item) && item >= 200 && item <= 299)) throw invalid('Expected status must contain 1-10 successful HTTP status codes');
    result.expected_status = value.expected_status as number[];
  }
  if (value.response_schema !== undefined) {
    const schema = object(value.response_schema, 'endpoint.response_schema') as { [key: string]: ConnectorJson };
    schemaValidator(schema);
    result.response_schema = schema;
  }
  if (value.response_path !== undefined) {
    if (typeof value.response_path !== 'string' || (value.response_path && !value.response_path.startsWith('/')) || value.response_path.length > 200 || /~(?![01])/.test(value.response_path)) throw invalid('Response extraction uses a JSON Pointer');
    result.response_path = value.response_path;
  }
  if (value.idempotency_header !== undefined) result.idempotency_header = headerName(String(value.idempotency_header));
  return result;
}
export function validateResponse(data: Json, endpoint: ConnectionEndpoint): Json {
  if (endpoint.response_schema && !schemaValidator(endpoint.response_schema)(data)) throw new PolicyError('EXTERNAL_SCHEMA', 'External JSON does not match the configured response schema; response values withheld', 502);
  if (endpoint.response_path === undefined) return data;
  const extracted = pointer(data, endpoint.response_path);
  if (extracted === undefined) throw new PolicyError('EXTERNAL_SCHEMA', 'Configured response extraction path was not present', 502);
  return extracted;
}
export function connectionOptions(input: Record<string, unknown>): Partial<ExternalConnectionConfig> {
  if (input.provider_type !== undefined && input.provider_type !== 'generic_rest') throw invalid('provider_type must be generic_rest');
  if (input.tls_min_version !== undefined && !['TLSv1.2', 'TLSv1.3'].includes(String(input.tls_min_version))) throw invalid('TLS minimum must be TLSv1.2 or TLSv1.3; certificate verification cannot be disabled');
  for (const key of ['monitoring_enabled', 'query_key_acknowledged']) if (input[key] !== undefined && typeof input[key] !== 'boolean') throw invalid(`${key} must be boolean`);
  if (input.auth === 'api_key_query' && input.query_key_acknowledged !== true) throw invalid('Query API keys require explicit query_key_acknowledged because intermediaries may log URLs');
  if (input.auth === 'basic' && (typeof input.username !== 'string' || !input.username || input.username.includes(':') || /[\r\n]/.test(input.username))) throw invalid('Basic authentication requires a username without colons or newlines');
  const names = input.secret_headers;
  if (input.auth === 'custom_headers' && (!Array.isArray(names) || !names.length || names.length > 10 || !names.every((name) => typeof name === 'string'))) throw invalid('Custom authentication requires 1-10 secret header names');
  if (Array.isArray(names)) {
    for (const name of names) headerName(String(name));
    if (new Set(names.map((name) => String(name).toLowerCase())).size !== names.length) throw invalid('Custom secret header names must be unique');
  }
  let pagination: ExternalConnectionConfig['discovery_pagination'] = null;
  if (input.discovery_pagination !== undefined && input.discovery_pagination !== null) {
    const fields = object(input.discovery_pagination, 'discovery_pagination');
    if (['total', 'offset', 'limit'].some((key) => typeof fields[key] !== 'string' || !String(fields[key]).startsWith('/'))) throw invalid('Discovery pagination requires total, offset and limit JSON Pointers');
    pagination = fields as { total: string; offset: string; limit: string };
  }
  return { provider_type: 'generic_rest', tls_min_version: input.tls_min_version as 'TLSv1.2' | 'TLSv1.3' | undefined, username: typeof input.username === 'string' ? input.username : '', secret_headers: Array.isArray(names) ? names as string[] : [], query_key_acknowledged: input.query_key_acknowledged === true, monitoring_enabled: input.monitoring_enabled !== false, discovery_pagination: pagination };
}

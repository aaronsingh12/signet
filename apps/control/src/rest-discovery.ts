import type { ExternalConnectionConfig, ResponseMapping } from '@signet/core/types';
import { PolicyError, invalid } from './errors';
import { agentListFields, adaptRecords, endpointUrl, pointer, publicUrl, type ImportedRecord, type Json } from './external-contract';
import { readJson } from './external-http';

interface DetectedRestApi { config: ExternalConnectionConfig; agents: ImportedRecord[] }
interface ApiAuthentication { auth: 'api_key' | 'bearer'; header: string }
const isObject = (value: Json | undefined): value is { [key: string]: Json } => value !== null && typeof value === 'object' && !Array.isArray(value);

function authentication(document: Json): ApiAuthentication {
  const components = isObject(document) ? document.components : undefined;
  const schemes = isObject(components) ? components.securitySchemes : undefined;
  if (!isObject(schemes)) return { auth: 'api_key', header: 'x-api-key' };
  const supported = Object.values(schemes).flatMap((scheme): ApiAuthentication[] => {
    if (!isObject(scheme)) return [];
    if (scheme.type === 'apiKey' && scheme.in === 'header' && typeof scheme.name === 'string' && /^[a-zA-Z0-9_-]+$/.test(scheme.name) && !/^(host|cookie|connection|content-length|transfer-encoding|proxy-.*|x-signet-.*)$/i.test(scheme.name)) return [{ auth: 'api_key', header: scheme.name }];
    if (scheme.type === 'http' && typeof scheme.scheme === 'string' && scheme.scheme.toLowerCase() === 'bearer') return [{ auth: 'bearer', header: 'authorization' }];
    return [];
  });
  if (supported.length !== 1) throw invalid('This API does not document one API-key or Bearer authentication method. Ask the platform owner to expose a single agent-list API authentication scheme');
  return supported[0]!;
}

/** Inspect the observed response and use known identity field names only when unambiguous and valid. */
export function detectAgentMapping(data: Json): ResponseMapping | null {
  const lists = agentListFields(data);
  const preferred = ['/agents', '/data/agents', '/data', '/items', ''];
  const ranked = preferred.flatMap((path) => lists.filter((list) => list.path === path));
  const list = ranked[0] ?? (lists.length === 1 ? lists[0] : undefined);
  if (!list) throw invalid('The API response does not expose a recognizable agent list. Ask the platform owner to return an agents array with a unique id and name');
  if (list.count === 0) return null;
  const rows = pointer(data, list.path);
  if (!Array.isArray(rows)) throw invalid('The detected agent list is not an array');
  const id = ['/id', '/agent_id', '/agentId', '/key', '/uuid'].find((path) => rows.every((row) => {
    const value = pointer(row, path);
    return typeof value === 'string' ? value.length > 0 && value.length <= 500 : typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
  }));
  if (!id) throw invalid('Agents need a unique id, agent_id, agentId, key or uuid. Ask the platform owner to include one in the agent list');
  return { items: list.path, id, name: ['/name', '/label', '/display_name', '/displayName'].find((field) => list.fields.includes(field)) ?? '', status: list.fields.includes('/status') ? '/status' : '', timestamp: '' };
}

/** Auto-detection probes only same-origin API descriptions and conventional read-only agent lists. */
export async function detectRestApi(baseUrl: string, credential: string): Promise<DetectedRestApi> {
  const base = publicUrl(baseUrl).toString().replace(/\/$/, '');
  let auth: ApiAuthentication = { auth: 'api_key', header: 'x-api-key' };
  let paths: string[] = [];
  const docs = [...new Set([`${base}/openapi.json`, `${new URL(base).origin}/openapi.json`])];
  for (const address of docs) {
    try {
      const document = await readJson({ url: new URL(address), method: 'GET', headers: { accept: 'application/json', 'x-api-key': credential }, body: null, timeout: 10000 });
      if (!isObject(document) || !isObject(document.paths)) throw invalid('The API description is missing its paths object');
      auth = authentication(document);
      const prefix = new URL(base).pathname.replace(/\/$/, '');
      paths = Object.entries(document.paths).filter(([path, item]) => !/[{}]/.test(path) && /\/(agents|assistants|bots)$/.test(path) && isObject(item) && isObject(item.get)).map(([path]) => prefix && path.startsWith(`${prefix}/`) ? path.slice(prefix.length) : path);
      if (!paths.length) throw invalid('This API does not document an agent-list GET endpoint. Ask the platform owner to expose one');
      paths.sort((a, b) => a.length - b.length);
      break;
    } catch (error) {
      if (!(error instanceof PolicyError) || error.extra.upstream_status !== 404) throw error;
      console.warn('REST API description not found; continuing agent endpoint detection', { url: address, status: 404 });
    }
  }
  if (!paths.length) paths = ['/agents', '/api/agents', '/api/v1/agents'];
  for (const path of paths) {
    try {
      const data = await readJson({ url: endpointUrl(base, path, null), method: 'GET', headers: { accept: 'application/json', [auth.header]: auth.auth === 'bearer' ? `Bearer ${credential}` : credential }, body: null, timeout: 10000 });
      const mapping = detectAgentMapping(data);
      const agents = mapping ? adaptRecords(data, mapping) : [];
      return { agents, config: { name: new URL(base).hostname, method: 'rest', private_connector: null, base_url: base, auth: auth.auth, header: auth.header, client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 10000, sync_interval_seconds: 300, remote_management: false, endpoints: { test: { method: 'GET', path }, discover: { method: 'GET', path } }, agents_mapping: mapping, executions_mapping: null, tracking_pointer: '', execution_pagination: null } };
    } catch (error) {
      if (!(error instanceof PolicyError) || error.extra.upstream_status !== 404) throw error;
      console.warn('REST agent endpoint not found; continuing endpoint detection', { base_url: base, path, status: 404 });
    }
  }
  throw invalid('No agent-list API was found. This platform needs an OpenAPI description or a GET /agents, /api/agents or /api/v1/agents endpoint');
}

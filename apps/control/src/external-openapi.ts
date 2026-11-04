import type { ConnectionEndpoint } from '@signet/core/types';
import { invalid } from './errors';
import { object } from './external-contract';

/** Parse pasted OpenAPI 3.x JSON. Suggestions never save mappings, fetch references or authorize actions. */
export function suggestOpenApi(value: unknown): { operations: { label: string; endpoint: ConnectionEndpoint; path_variables: string[] }[]; authentication: { type: string; header: string | null }[] } {
  const document = object(value, 'OpenAPI document');
  if (JSON.stringify(document).length > 262144 || typeof document.openapi !== 'string' || !/^3\.[01]\./.test(document.openapi)) throw invalid('Import a JSON OpenAPI 3.0 or 3.1 document of at most 256 KiB');
  const paths = object(document.paths, 'OpenAPI paths');
  if (Object.keys(paths).length > 200) throw invalid('OpenAPI import supports at most 200 paths; import a scoped document');
  const operations: { label: string; endpoint: ConnectionEndpoint; path_variables: string[] }[] = [];
  for (const [path, raw] of Object.entries(paths)) {
    if (!path.startsWith('/') || path.startsWith('//') || /[\\#\r\n]/.test(path) || path.includes('..')) throw invalid('OpenAPI path is unsafe');
    const item = object(raw, 'OpenAPI path item');
    for (const method of ['get', 'post', 'put', 'patch', 'delete'] as const) {
      if (item[method] === undefined) continue;
      const operation = object(item[method], 'OpenAPI operation');
      const name = typeof operation.operationId === 'string' ? operation.operationId.slice(0, 120) : typeof operation.summary === 'string' ? operation.summary.slice(0, 120) : path;
      operations.push({ label: `${method.toUpperCase()} ${path} - ${name}`, endpoint: { path, method: method.toUpperCase() as ConnectionEndpoint['method'] }, path_variables: [...path.matchAll(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g)].map((match) => match[1]!) });
    }
  }
  if (!operations.length) throw invalid('OpenAPI document has no supported HTTP operations');
  const authentication: { type: string; header: string | null }[] = [];
  if (document.components !== undefined) {
    const components = object(document.components, 'OpenAPI components');
    if (components.securitySchemes !== undefined) {
      for (const raw of Object.values(object(components.securitySchemes, 'OpenAPI security schemes'))) {
        const scheme = object(raw, 'OpenAPI security scheme');
        if (scheme.type === 'apiKey' && typeof scheme.name === 'string') authentication.push({ type: scheme.in === 'header' ? 'api_key' : scheme.in === 'query' ? 'api_key_query' : 'unsupported', header: scheme.name.slice(0, 100) });
        else if (scheme.type === 'http' && ['basic', 'bearer'].includes(String(scheme.scheme))) authentication.push({ type: String(scheme.scheme), header: null });
        else if (scheme.type === 'oauth2') authentication.push({ type: 'oauth', header: null });
      }
    }
  }
  return { operations, authentication };
}

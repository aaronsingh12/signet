import { useState } from 'react';
import type { ConnectionEndpoint, ConnectorJson, ExternalConnectionConfig, ExternalOperation } from '@signet/core/types';
import { ApiError, api } from '../lib/api';
import { ErrorNote } from './ui';

function JsonEditor({ label, value, onApply }: { label: string; value: ConnectorJson; onApply: (value: ConnectorJson) => void }) {
  const [text, setText] = useState(JSON.stringify(value, null, 2));
  const [error, setError] = useState(false);
  return <div><label className="label">{label}<textarea data-testid={`json-${label.replaceAll(' ', '-')}`} className="input mono min-h-32" value={text} onChange={(event) => setText(event.target.value)} /></label><button type="button" className="btn-ghost" onClick={() => { try { onApply(JSON.parse(text) as ConnectorJson); setError(false); } catch { setError(true); } }}>Apply JSON</button>{error && <p role="alert" className="text-sm text-bad">Enter a valid JSON object with the required fields. Do not put credentials here.</p>}</div>;
}
const OPERATIONS: ExternalOperation[] = ['test', 'discover', 'agent', 'track', 'executions', 'execution', 'logs', 'metrics', 'run', 'pause', 'stop', 'activate'];
interface Suggestion { label: string; endpoint: ConnectionEndpoint; path_variables: string[] }

/** Optional provider-neutral mapping tools; saving and authorizing remain separate explicit actions. */
export function ConnectorMappingEditor({ config, onChange }: { config: ExternalConnectionConfig; onChange: (config: ExternalConnectionConfig) => void }) {
  const [document, setDocument] = useState('');
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const inspect = async (): Promise<void> => {
    setBusy(true); setError(null);
    try {
      let parsed: ConnectorJson;
      try { parsed = JSON.parse(document) as ConnectorJson; } catch { throw new ApiError(400, 'VALIDATION', 'OpenAPI input must be valid JSON'); }
      const result = await api<{ operations: Suggestion[] }>('/connections/openapi', { method: 'POST', body: parsed });
      setSuggestions(result.operations);
    } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  return <div className="space-y-4">
    <details className="rounded-lg border border-line p-3"><summary>Import OpenAPI suggestions (optional)</summary><p className="my-2 text-xs text-ink-3">Paste OpenAPI 3.0/3.1 JSON. Pick which operation each endpoint represents, review the mappings, then save. Import does not authorize remote actions.</p><textarea data-testid="connector-openapi" className="input mono min-h-32" value={document} onChange={(event) => setDocument(event.target.value)} /><button data-testid="connector-openapi-inspect" type="button" className="btn" disabled={busy} onClick={() => void inspect()}>Read API specification</button><ErrorNote error={error} />{suggestions.length > 0 && <div className="mt-3 grid gap-3 md:grid-cols-2">{OPERATIONS.map((operation) => <label key={operation} className="label">{operation}<select data-testid={`openapi-${operation}`} className="input" value="" onChange={(event) => { const suggestion = suggestions[Number(event.target.value)]; if (suggestion) onChange({ ...config, endpoints: { ...config.endpoints, [operation]: suggestion.endpoint } }); }}><option value="">Choose a documented operation</option>{suggestions.map((suggestion, index) => <option key={index} value={index}>{suggestion.label}</option>)}</select></label>)}</div>}</details>
    <details className="rounded-lg border border-line p-3"><summary>Endpoint templates, expected responses and schemas</summary><p className="my-2 text-xs text-ink-3">Use JSON Pointer for response_path and field mappings. Templates accept id and agent_id. For other path names set variables, for example: variables: {"{\"botId\":\"id\"}"}. Endpoints can define query, request_body, expected_status, response_schema and idempotency_header. Schemas use strict Draft 7 JSON Schema; external references and regex are disabled.</p>{OPERATIONS.filter((operation) => config.endpoints[operation]).map((operation) => <details key={operation} className="my-2 border-t border-line pt-2"><summary>{operation}</summary><JsonEditor key={JSON.stringify(config.endpoints[operation])} label={`${operation} endpoint options`} value={JSON.parse(JSON.stringify(config.endpoints[operation])) as ConnectorJson} onApply={(value) => { if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.path !== 'string' || typeof value.method !== 'string') throw new Error('Endpoint must contain method and path'); onChange({ ...config, endpoints: { ...config.endpoints, [operation]: { ...value, path: value.path, method: value.method as ConnectionEndpoint['method'] } } }); }} /></details>)}</details>
    <details className="rounded-lg border border-line p-3"><summary>Pagination and selected provider metadata</summary><p className="my-2 text-xs text-ink-3">Pagination uses explicit total, offset and limit response pointers and offset/limit query parameters, capped at 1000 records. Metadata fields are explicitly selected JSON Pointers, bounded to 8 KiB; trusted Signet identity fields cannot be overwritten.</p><JsonEditor key={JSON.stringify(config.discovery_pagination ?? null)} label="Discovery pagination" value={config.discovery_pagination ?? null} onApply={(value) => { if (value !== null && (typeof value !== 'object' || Array.isArray(value) || !['total', 'offset', 'limit'].every((key) => typeof value[key] === 'string'))) throw new Error('Pagination pointers required'); onChange({ ...config, discovery_pagination: value as ExternalConnectionConfig['discovery_pagination'] }); }} />{(['agents_mapping', 'executions_mapping'] as const).filter((key) => config[key]).map((key) => <JsonEditor key={key + JSON.stringify(config[key])} label={`${key} metadata fields`} value={config[key]?.fields ?? {}} onApply={(value) => { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.values(value).some((path) => typeof path !== 'string')) throw new Error('Use field names and pointer strings'); const mapping = config[key]; if (!mapping) throw new Error('Configure response mapping first'); onChange({ ...config, [key]: { ...mapping, fields: value as Record<string, string> } }); }} />)}</details>
    <label className="label">Minimum TLS version<select data-testid="connector-tls" className="input" value={config.tls_min_version ?? 'TLSv1.2'} onChange={(event) => onChange({ ...config, tls_min_version: event.target.value as 'TLSv1.2' | 'TLSv1.3' })}><option>TLSv1.2</option><option>TLSv1.3</option></select><span className="text-xs text-ink-3">TLS certificate validation is always enabled.</span></label>
  </div>;
}

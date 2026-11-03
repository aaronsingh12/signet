import { useState } from 'react';
import { Link } from 'react-router-dom';
import { supportLabConnectionConfig } from '@signet/core/types';
import type { ExternalConnectionConfig, ExternalConnectionView, ExternalOperation, ResponseMapping } from '@signet/core/types';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { Card, ErrorNote } from './ui';

export interface ConnectionDraft { config: ExternalConnectionConfig; credential: string }
export function newConnectionDraft(method: 'rest' | 'oauth' | 'hybrid'): ConnectionDraft {
  return { credential: '', config: { name: '', method, private_connector: method === 'hybrid' ? { runner_id: '', tool_alias: '', environment: 'dev' } : null, base_url: '', auth: method === 'hybrid' ? 'connector' : method === 'oauth' ? 'oauth' : 'api_key', header: 'x-api-key', client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 10000, sync_interval_seconds: 300, remote_management: false, endpoints: { test: { method: 'GET', path: '/' } }, agents_mapping: null, executions_mapping: null, tracking_pointer: '', execution_pagination: null } };
}
const OPERATIONS: ExternalOperation[] = ['test', 'discover', 'track', 'executions', 'run', 'pause', 'stop', 'activate'];

/** Credentials stay in React memory until sent to the broker and are cleared after successful save. */
export function ExternalConnectionFields({ draft, onChange }: { draft: ConnectionDraft; onChange: (value: ConnectionDraft) => void }) {
  const c = draft.config;
  const set = <K extends keyof ExternalConnectionConfig>(key: K, value: ExternalConnectionConfig[K]): void => onChange({ ...draft, config: { ...c, [key]: value } });
  const field = (key: 'name' | 'base_url' | 'header' | 'client_id' | 'token_url' | 'scopes' | 'tracking_pointer', label: string) => <div><label className="label" htmlFor={`external-${key}`}>{label}</label><input id={`external-${key}`} data-testid={`external-${key}`} className="input" value={c[key]} onChange={(e) => set(key, e.target.value)} required={['name', 'base_url'].includes(key)} /></div>;
  const mapping = (key: 'agents_mapping' | 'executions_mapping', label: string) => {
    const value = c[key];
    return <details className="rounded-lg border border-line p-3"><summary>{label}</summary><p className="my-2 text-xs text-ink-3">Use JSON pointers from the platform's documentation or an observed response. No platform schema is assumed. Empty items selects a root array; leave optional field pointers empty. Tracking expects one object using the agent field pointers.</p><label className="flex gap-2 text-sm"><input type="checkbox" checked={value !== null} onChange={(e) => set(key, e.target.checked ? { items: '', id: '', name: '', status: '', timestamp: '' } : null)} />Configure explicit mapping</label>{value && <div className="mt-2 grid gap-2 md:grid-cols-3">{(['items', 'id', 'name', 'status', 'timestamp'] as (keyof ResponseMapping)[]).map((part) => <label className="label" key={part}>{part}<input data-testid={`external-${key}-${part}`} className="input" value={value[part]} onChange={(e) => set(key, { ...value, [part]: e.target.value })} /></label>)}</div>}</details>;
  };
  return <div className="space-y-3">
    <p className="text-sm text-ink-2">Signet sends backend requests to this platform. Discovery and monitoring do not intercept its internal model or tool calls. Public endpoints require HTTPS; private addresses require an enrolled runner.</p>
    <button type="button" data-testid="support-lab-profile" className="btn-ghost" onClick={() => onChange({ credential: draft.credential, config: supportLabConnectionConfig() })}>Use observed Customer Support Lab endpoints and response adapters</button>
    <div className="grid gap-3 md:grid-cols-2">{field('name', 'Connection name')}{field('base_url', 'External API Base URL')}
      <label className="label">Authentication<select data-testid="external-auth" className="input" value={c.auth} onChange={(e) => set('auth', e.target.value as ExternalConnectionConfig['auth'])} disabled={c.method === 'oauth' || c.method === 'hybrid'}>{['api_key', 'bearer', 'oauth', 'none', 'connector'].map((value) => <option key={value} value={value}>{({ api_key: 'API Key', bearer: 'Bearer Token', oauth: 'OAuth 2.0', none: 'None', connector: 'Signet connector identity' })[value]}</option>)}</select></label>
      {c.auth === 'api_key' && field('header', 'API Key header name')}
      {c.private_connector && <>{field('client_id', 'Approved agent Signet Client ID')}<p className="text-xs text-ink-3">Use the Client ID and Secret generated above for this approved agent. Private API credentials stay in the runner's token_env. Register HTTP actions named test, discover, track, executions, run, pause, stop or activate as needed, and include them in the approved agent manifest.</p>{(['runner_id', 'tool_alias', 'environment'] as const).map((key) => <label key={key} className="label">{key}<input data-testid={`private-${key}`} className="input" value={c.private_connector![key]} onChange={(e) => set('private_connector', { ...c.private_connector!, [key]: e.target.value })} /></label>)}</>}
      {c.auth !== 'none' && <label className="label">{c.auth === 'oauth' ? 'Client Secret' : 'API Key / Token'}<input data-testid="external-credential" className="input" type="password" autoComplete="new-password" value={draft.credential} onChange={(e) => onChange({ ...draft, credential: e.target.value })} /><span className="text-xs text-ink-3">Stored encrypted in Secrets Broker. Leave empty when editing to retain the existing credential.</span></label>}
      {c.auth === 'oauth' && <><label className="label">Grant type<select className="input" value="client_credentials" disabled><option>client_credentials</option></select></label>{field('client_id', 'Client ID')}{field('token_url', 'Token URL')}{field('scopes', 'Scopes')}<label className="label">Token authentication method<select data-testid="external-token-auth" className="input" value={c.token_auth} onChange={(e) => set('token_auth', e.target.value as ExternalConnectionConfig['token_auth'])}><option value="client_secret_basic">client_secret_basic</option><option value="client_secret_post">client_secret_post</option></select></label><p className="text-xs text-ink-3">Client credentials uses the token URL only. Authorization-code grants are not supported by this outbound connector.</p></>}
      <label className="label">Request timeout (milliseconds)<input data-testid="external-timeout" className="input" type="number" min={1000} max={30000} value={c.timeout_ms} onChange={(e) => set('timeout_ms', Number(e.target.value))} /></label>
      <label className="label">Synchronization interval (seconds)<input data-testid="external-interval" className="input" type="number" min={60} max={86400} value={c.sync_interval_seconds} onChange={(e) => set('sync_interval_seconds', Number(e.target.value))} /></label>
    </div>
    <label className="flex gap-2 text-sm"><input data-testid="external-remote-management" type="checkbox" checked={c.remote_management} onChange={(e) => set('remote_management', e.target.checked)} />Enable remote management actions (requires approved mapped agents)</label>
    <div className="space-y-2">{OPERATIONS.map((op) => <div key={op} className="grid grid-cols-[90px_100px_1fr] items-center gap-2"><label className="label" htmlFor={`endpoint-${op}`}>{op}</label><select aria-label={`${op} method`} data-testid={`endpoint-${op}-method`} className="input" disabled={['test', 'discover', 'track', 'executions'].includes(op)} value={c.endpoints[op]?.method ?? (['run', 'pause', 'stop', 'activate'].includes(op) ? 'POST' : 'GET')} onChange={(e) => set('endpoints', { ...c.endpoints, [op]: { path: c.endpoints[op]?.path ?? '/', method: e.target.value } })}>{['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((value) => <option key={value}>{value}</option>)}</select><input id={`endpoint-${op}`} data-testid={`endpoint-${op}`} className="input mono" placeholder={op === 'test' ? 'Required harmless GET path' : 'Optional path, supports {id}'} value={c.endpoints[op]?.path ?? ''} onChange={(e) => { const entries = Object.fromEntries(Object.entries(c.endpoints).filter(([key]) => key !== op)); set('endpoints', e.target.value ? { ...entries, [op]: { path: e.target.value, method: c.endpoints[op]?.method ?? (['run', 'pause', 'stop', 'activate'].includes(op) ? 'POST' : 'GET') } } : entries); }} /></div>)}</div>
    {field('tracking_pointer', 'Tracking agent object JSON pointer (empty selects root)')}{mapping('agents_mapping', 'Agent discovery / tracking response adapter')}{mapping('executions_mapping', 'Execution history response adapter')}
    <details className="rounded-lg border border-line p-3"><summary>Execution history pagination</summary><p className="my-2 text-xs text-ink-3">Opt-in offset/limit pagination using observed numeric response fields. Requests use offset and limit query parameters. Maximum 1000 executions per agent per sync.</p><label className="flex gap-2 text-sm"><input data-testid="external-pagination" type="checkbox" checked={c.execution_pagination !== null} onChange={(e) => set('execution_pagination', e.target.checked ? { total: '/total', offset: '/offset', limit: '/limit' } : null)} />Enable documented offset pagination</label>{c.execution_pagination && (['total', 'offset', 'limit'] as const).map((key) => <label className="label" key={key}>{key} JSON pointer<input className="input" data-testid={`pagination-${key}`} value={c.execution_pagination![key]} onChange={(e) => set('execution_pagination', { ...c.execution_pagination!, [key]: e.target.value })} /></label>)}</details>
    <p className="text-xs text-ink-3">Paths append to the API Base URL, including its prefix. Only read-only GETs are retried. Actions are sent once. Discovery creates proposed agents requiring classification, approval and certification.</p>
  </div>;
}

export function ExternalConnectionEditor({ agentId, method, existing, onSaved, onCancel }: { agentId: string; method: 'rest' | 'oauth' | 'hybrid'; existing: ExternalConnectionView | null; onSaved: () => void; onCancel: () => void }) {
  const [draft, setDraft] = useState<ConnectionDraft>(existing ? { config: existing.config, credential: '' } : newConnectionDraft(method));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [connectionId, setConnectionId] = useState<string | null>(existing?.id ?? null);
  const persist = async (): Promise<ExternalConnectionView> => {
    const connection = await api<ExternalConnectionView>(connectionId ? `/connections/${connectionId}` : '/connections', { method: connectionId ? 'PUT' : 'POST', body: { agent_id: agentId, ...draft } });
    setConnectionId(connection.id);
    setDraft({ ...draft, credential: '' });
    return connection;
  };
  const can = useCan();
  const save = async (): Promise<void> => {
    setBusy(true); setError(null);
    try {
      await persist(); onSaved();
    } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const test = async (): Promise<void> => {
    setBusy(true); setError(null);
    try {
      const connection = await persist();
      await api(`/connections/${connection.id}/test`, { method: 'POST' });
      onSaved();
    } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  return <Card title={existing ? 'Edit connection / rotate credential' : 'Configure external platform'}><form onSubmit={(e) => { e.preventDefault(); void save(); }}><ExternalConnectionFields draft={draft} onChange={setDraft} /><div className="mt-4 flex gap-2"><button data-testid="external-test" type="button" className="btn" disabled={busy || !can('connectors.manage')} onClick={() => void test()}>Test Connection</button><button data-testid="external-save" className="btn-primary" disabled={busy || !can('connectors.manage')}>Save Connection</button><button type="button" className="btn-ghost" onClick={onCancel}>Cancel</button></div><p className="mt-2 text-xs text-ink-3">Test Connection saves encrypted configuration in the broker before making a real server-side request.</p>{!can('connectors.manage') && <p className="text-sm text-warn">A platform administrator with connectors.manage must save this configuration.</p>}<ErrorNote error={error} /></form></Card>;
}

export function ExternalConnections({ agentId }: { agentId: string | null }) {
  const { data, error: loadError, reload } = useApi<{ items: ExternalConnectionView[] }>('/connections');
  const [editing, setEditing] = useState<ExternalConnectionView | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [details, setDetails] = useState<string | null>(null);
  const can = useCan();
  const items = (data?.items ?? []).filter((item) => agentId === null || item.agent_id === agentId);
  const act = async (id: string, action: string): Promise<void> => {
    setBusy(true); setError(null);
    try { await api(`/connections/${id}/${action}`, { method: 'POST' }); }
    catch (error) { setError(error as ApiError); }
    finally { await reload(); setBusy(false); }
  };
  return <div className="space-y-4">{editing && <ExternalConnectionEditor key={editing.id} agentId={editing.agent_id} method={editing.config.method} existing={editing} onSaved={() => { setEditing(null); void reload(); }} onCancel={() => setEditing(null)} />}
    <Card title="External platform connections"><ErrorNote error={error ?? loadError} />{!items.length ? <p className="text-sm text-ink-3">No external platform connection configured.</p> : <div className="overflow-x-auto"><table data-testid="connections-table" className="w-full"><thead><tr>{['Connection / method', 'Direction / agents', 'API reachable', 'Authentication', 'Discovery', 'Monitoring', 'Remote control', 'Gateway enforcement', 'Last success / sync', 'Capabilities / coverage', 'Last error', 'Actions'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead><tbody>{items.map((item) => <tr key={item.id} data-testid={`connection-${item.id}`}><td className="td"><Link className="text-royal" to={`/agents/${item.agent_id}?tab=connection`}>{item.config.name}</Link><p>{item.config.method} · {item.state}</p></td><td className="td">Outbound · {item.agent_count}</td><td className="td">{item.health.reachable === null ? 'Unverified' : item.health.reachable ? 'Reachable' : 'Unreachable'}</td><td className="td">{item.health.authentication}</td><td className="td">{item.health.discovered === null ? 'Unverified' : `${item.health.discovered} discovered`}</td><td className="td">{item.health.monitoring && item.health.last_sync_at && Date.now() - Date.parse(item.health.last_sync_at) < item.config.sync_interval_seconds * 2000 ? 'Active' : 'Inactive / stale'}</td><td className="td">{item.health.remote_control ? 'Action verified' : item.config.remote_management ? 'Enabled, unverified' : 'Disabled'}</td><td className="td">{item.health.gateway_enforcement ? "Verified for connector calls" : "Inactive"}</td><td className="td text-xs">{item.health.last_success_at ?? 'Never'}<br />{item.health.last_sync_at ?? 'Never'}</td><td className="td text-xs">{item.capabilities.join(', ')}<br />{item.coverage === "gateway_tools" ? "Gateway governs connector tool requests; platform internals unobserved" : "External monitoring"}</td><td className="td text-xs">{item.health.last_error ?? 'None'}</td><td className="td"><div className="flex flex-wrap gap-2"><button data-testid={`connection-details-${item.id}`} className="btn-ghost" onClick={() => setDetails(details === item.id ? null : item.id)}>Details</button>{can('connectors.manage') && <>{['test', ...(item.config.endpoints.discover ? ['discover'] : []), ...(item.config.endpoints.track || item.config.endpoints.executions ? ['sync'] : []), ...(item.state === 'enabled' ? ['disconnect', 'revoke'] : item.state === 'disconnected' ? ['reconnect', 'revoke'] : [])].map((action) => <button data-testid={`connection-${action}-${item.id}`} className="btn-ghost" disabled={busy || item.state === 'revoked'} key={action} onClick={() => void act(item.id, action)}>{action}</button>)}<button data-testid={`connection-edit-${item.id}`} className="btn-ghost" disabled={busy || item.state === 'revoked'} onClick={() => setEditing(item)}>Edit / Rotate</button></>}</div></td></tr>)}</tbody></table></div>}</Card>
    {details && <ConnectionRecords id={details} />}
  </div>;
}

function ConnectionRecords({ id }: { id: string }) {
  const { data, error } = useApi<{ items: { external_id: string; agent_id: string; last_seen_at: string }[] }>(`/connections/${id}/agents`);
  const [selected, setSelected] = useState('');
  const [action, setAction] = useState('pause');
  const [body, setBody] = useState('');
  const [result, setResult] = useState('');
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const can = useCan();
  const { data: observations, error: observationError } = useApi<{ items: { external_agent_id: string; external_id: string; kind: string; metadata: string; observed_at: string }[] }>(can('ledger.read') ? `/connections/${id}/observations` : null);
  const send = async (): Promise<void> => {
    setBusy(true); setActionError(null); setResult('');
    try {
      let payload: object;
      try { payload = JSON.parse(body) as object; } catch { throw new ApiError(400, 'VALIDATION', 'Action body must be valid JSON'); }
      await api(`/connections/${id}/agents/${selected}/actions/${action}`, { method: 'POST', body: payload });
      setResult('External API accepted the action. This does not establish Gateway enforcement.');
    } catch (error) { setActionError(error as ApiError); } finally { setBusy(false); }
  };
  return <Card title="Discovered agents and remote management"><ErrorNote error={error ?? actionError ?? observationError} /><ul className="space-y-2">{data?.items.map((item) => <li key={item.agent_id}><Link className="text-royal" to={`/agents/${item.agent_id}?tab=lifecycle`}>{item.external_id} → {item.agent_id}</Link><span className="ml-2 text-xs text-ink-3">Last seen {item.last_seen_at} · approval lifecycle applies</span></li>)}</ul>{can('connectors.manage') && <div className="mt-4 space-y-2"><select data-testid="remote-agent" aria-label="Mapped agent" className="input" value={selected} onChange={(e) => setSelected(e.target.value)}><option value="">Select mapped agent</option>{data?.items.map((item) => <option key={item.agent_id} value={item.agent_id}>{item.external_id}</option>)}</select><select data-testid="remote-action" aria-label="Remote action" className="input" value={action} onChange={(e) => setAction(e.target.value)}>{['run', 'pause', 'stop', 'activate'].map((value) => <option key={value}>{value}</option>)}</select><textarea data-testid="remote-body" aria-label="Documented action JSON body" className="input mono" value={body} onChange={(e) => setBody(e.target.value)} placeholder="Enter the platform's documented JSON action body" /><button data-testid="remote-submit" className="btn-primary" disabled={busy || !selected || !body} onClick={() => void send()}>Send action once</button><p className="text-sm">{result}</p><p className="text-xs text-ink-3">Requires connectors.manage, explicit remote management opt-in, agent mapping and a valid approved seal with a matching HTTP tool action. Policy decisions requiring approval must use the Gateway approval flow. Timeouts leave the outcome uncertain; check the external platform before sending another action.</p></div>}
    {observations && <div className="mt-4 overflow-x-auto"><p className="mb-2 text-sm">External tracking and execution metadata · separate from Gateway evidence</p><table className="w-full" data-testid="external-observations"><thead><tr>{['External agent', 'Record', 'Kind', 'Metadata', 'Observed'].map((h) => <th className="th" key={h}>{h}</th>)}</tr></thead><tbody>{observations.items.map((item) => <tr key={`${item.external_agent_id}:${item.kind}:${item.external_id}`}><td className="td">{item.external_agent_id}</td><td className="td">{item.external_id}</td><td className="td">{item.kind}</td><td className="td mono text-xs">{item.metadata}</td><td className="td text-xs">{item.observed_at}</td></tr>)}</tbody></table></div>}
  </Card>;
}

export function IdentityConnections() {
  const [cursor, setCursor] = useState<string | null>(null);
  const { data, error } = useApi<{ items: { id: string; name: string; connection_method: string; connection: string; last_activity: string | null }[]; next_cursor: string | null }>(`/agents?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
  return <Card title="Agent workload connections"><ErrorNote error={error} /><p className="mb-3 text-sm text-ink-2">Agent → Signet Gateway. Authentication, bootstrap exchange, credentials, revocation and actual Gateway decisions are available in each agent's connection details. External discovery and monitoring capabilities are listed separately below.</p><div className="overflow-x-auto"><table data-testid="identity-connections" className="w-full"><thead><tr>{['Agent', 'Method', 'Identity / Gateway evidence', 'Last activity', 'Actions'].map((h) => <th className="th" key={h}>{h}</th>)}</tr></thead><tbody>{data?.items.map((item) => <tr key={item.id}><td className="td">{item.name}</td><td className="td">{item.connection_method}</td><td className="td">{item.connection.replaceAll('_', ' ')}</td><td className="td">{item.last_activity ?? 'Never'}</td><td className="td"><Link data-testid={`identity-details-${item.id}`} className="text-royal" to={`/agents/${item.id}?tab=connection`}>Details / Test / Rotate / Revoke</Link></td></tr>)}</tbody></table></div><div className="mt-3 flex gap-2">{cursor && <button className="btn-ghost" data-testid="identities-first" onClick={() => setCursor(null)}>First page</button>}{data?.next_cursor && <button className="btn-ghost" data-testid="identities-next" onClick={() => setCursor(data.next_cursor)}>Next page</button>}</div></Card>;
}

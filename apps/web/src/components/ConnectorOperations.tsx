import { useState } from 'react';
import type { ConnectorJson, ExternalConnectionView, ExternalOperation } from '@signet/core/types';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ErrorNote } from './ui';

interface Agent { agent_id: string; name: string; presence: string; last_seen_at: string; capabilities: string[] | null; status: string | null; framework: string | null }
interface Run { id: string; operation: string; outcome: string; started_at: string; error_category: string | null; record_count: number | null; detail: string | null }

/** All controls use server-side authorization, tenant lookup and the existing governance action gates. */
export function ConnectorOperations({ id, onDeleted }: { id: string; onDeleted: () => void }) {
  const can = useCan();
  const { data: connection, reload } = useApi<ExternalConnectionView>(`/connections/${id}`);
  const { data: inventory, reload: reloadInventory } = useApi<{ items: Agent[] }>(`/connections/${id}/agents`);
  const { data: history, reload: reloadHistory } = useApi<{ items: Run[] }>(can('ledger.read') ? `/connections/${id}/history` : null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [agent, setAgent] = useState('');
  const [operation, setOperation] = useState('');
  const [executionId, setExecutionId] = useState('');
  const [hookSecret, setHookSecret] = useState('');
  const [hookPointer, setHookPointer] = useState('');
  const [hookKind, setHookKind] = useState('execution');
  const [hookUrl, setHookUrl] = useState('');
  const [body, setBody] = useState('{}');
  const [requestKey, setRequestKey] = useState(crypto.randomUUID());
  const [response, setResponse] = useState<ConnectorJson | null>(null);
  const refresh = async (): Promise<void> => { await Promise.all([reload(), reloadInventory(), reloadHistory()]); };
  const discover = async (): Promise<void> => {
    if (!window.confirm('Discover and register all returned agents as pending approval?')) return;
    setBusy(true); setError(null);
    try { await api(`/connections/${id}/discover`, { method: 'POST' }); await refresh(); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const sync = async (): Promise<void> => {
    setBusy(true); setError(null);
    try { await api(`/connections/${id}/sync`, { method: 'POST' }); await refresh(); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const monitoring = async (): Promise<void> => {
    setBusy(true); setError(null);
    try { await api(`/connections/${id}/monitoring`, { method: 'POST', body: { enabled: connection?.config.monitoring_enabled === false } }); await refresh(); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const disconnect = async (): Promise<void> => {
    setBusy(true); setError(null);
    try { await api(`/connections/${id}/disconnect`, { method: 'POST' }); await refresh(); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const reconnect = async (): Promise<void> => {
    setBusy(true); setError(null);
    try { await api(`/connections/${id}/reconnect`, { method: 'POST' }); await refresh(); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const remove = async (): Promise<void> => {
    if (!window.confirm('Delete this connection, encrypted credentials and external monitoring history? Registered agents and governance evidence remain.')) return;
    setBusy(true); setError(null);
    try { await api(`/connections/${id}`, { method: 'DELETE' }); onDeleted(); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const enableWebhook = async (): Promise<void> => {
    setBusy(true); setError(null);
    try { const result = await api<{ path: string }>(`/connections/${id}/webhook`, { method: 'POST', body: { enabled: true, secret: hookSecret, agent_pointer: hookPointer, kind: hookKind } }); setHookUrl(location.origin + result.path); setHookSecret(''); await refresh(); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const disableWebhook = async (): Promise<void> => {
    setBusy(true); setError(null);
    try { await api(`/connections/${id}/webhook`, { method: 'POST', body: { enabled: false } }); setHookUrl(''); await refresh(); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const send = async (): Promise<void> => {
    const mutation = ['run', 'pause', 'stop', 'activate'].includes(operation);
    if (mutation && !window.confirm(`Confirm ${operation} for this agent. Check provider state before retrying a timeout.`)) return;
    setBusy(true); setError(null); setResponse(null);
    try {
      if (mutation) {
        let payload: ConnectorJson;
        try { payload = JSON.parse(body) as ConnectorJson; } catch { throw new ApiError(400, 'VALIDATION', 'Action payload must be valid JSON'); }
        const result = await api<{ response: ConnectorJson }>(`/connections/${id}/agents/${agent}/actions/${operation}`, { method: 'POST', body: { payload, confirmation: `${operation}:${agent}`, idempotency_key: requestKey } });
        setResponse(result.response); setRequestKey(crypto.randomUUID());
      } else setResponse(await api<ConnectorJson>(`/connections/${id}/agents/${agent}/read/${operation}`, { method: 'POST', body: { execution_id: executionId || null } }));
      await refresh();
    } catch (error) { setError(error as ApiError); await reloadHistory(); } finally { setBusy(false); }
  };
  if (!connection) return null;
  const endpoints = connection.config.endpoints;
  const monitoringSupported = Boolean(endpoints.track || endpoints.executions);
  return <details className="mt-4 rounded-lg border border-line p-3"><summary>Inventory, monitoring, actions and history</summary><ErrorNote error={error} />
    <p className="my-3 text-sm">State: {connection.state} ? Imported: {connection.agent_count} ? Discovery: {connection.health.discovered ?? 'Not verified'} ? Monitoring: {connection.health.monitoring ? 'Active' : connection.config.monitoring_enabled === false ? 'Disabled' : 'Not yet verified'}</p>
    <p className="mb-3 text-xs text-ink-3">Verified operations: {connection.capabilities.join(', ') || 'None'}. Unconfigured operations are unsupported. Metrics not supplied by the provider are unavailable.</p>
    {can('connectors.manage') && <div className="flex flex-wrap gap-2"><button data-testid="connector-discover" className="btn" disabled={busy || !endpoints.discover || !connection.config.agents_mapping || !can('discovery.write')} onClick={() => void discover()}>Discover & import agents</button><button data-testid="connector-sync" className="btn" disabled={busy || !monitoringSupported} onClick={() => void sync()}>Refresh activity</button><button data-testid="connector-monitoring" className="btn" disabled={busy || !monitoringSupported} onClick={() => void monitoring()}>{connection.config.monitoring_enabled === false ? 'Enable monitoring' : 'Disable monitoring'}</button>{connection.state === 'enabled' ? <button data-testid="connector-disable" className="btn" disabled={busy} onClick={() => void disconnect()}>Disable connection</button> : <button data-testid="connector-enable" className="btn" disabled={busy || connection.state === 'revoked'} onClick={() => void reconnect()}>Enable connection</button>}<button data-testid="connector-delete" className="btn-ghost text-bad" disabled={busy} onClick={() => void remove()}>Delete connection</button></div>}
    <ul className="my-4 space-y-2">{inventory?.items.map((item) => <li key={item.agent_id} className="text-sm">{item.name} ? {item.presence} ? Last seen {item.last_seen_at}<p className="text-xs text-ink-3">Provider status: {item.status ?? 'Unavailable'} ? Framework: {item.framework ?? 'Unavailable'} ? Capabilities: {item.capabilities?.join(', ') || 'Unavailable'}</p></li>)}</ul>
    {can('connectors.manage') && <div className="space-y-3 border-t border-line pt-3"><label className="label">Imported agent<select data-testid="connector-agent" className="input" value={agent} onChange={(event) => { setAgent(event.target.value); setRequestKey(crypto.randomUUID()); }}><option value="">Select agent</option>{inventory?.items.map((item) => <option key={item.agent_id} value={item.agent_id}>{item.name}</option>)}</select></label><label className="label">Configured operation<select data-testid="connector-operation" className="input" value={operation} onChange={(event) => { setOperation(event.target.value); setRequestKey(crypto.randomUUID()); }}><option value="">Select operation</option>{(['agent', 'execution', 'logs', 'metrics', 'run', 'pause', 'stop', 'activate'] as ExternalOperation[]).filter((name) => endpoints[name]).map((name) => <option key={name}>{name}</option>)}</select></label>{operation === 'execution' && <label className="label">External execution ID<input data-testid="connector-execution-id" className="input" value={executionId} onChange={(event) => setExecutionId(event.target.value)} /></label>}{['run', 'pause', 'stop', 'activate'].includes(operation) && <><p className="text-xs text-ink-3">Remote management must be enabled in API settings. Agent approval, tool grants and policy checks apply.</p><textarea data-testid="connector-action-body" className="input mono" value={body} onChange={(event) => { setBody(event.target.value); setRequestKey(crypto.randomUUID()); }} /></>}<button data-testid="connector-send" className="btn" disabled={busy || !agent || !operation} onClick={() => void send()}>Send configured request</button>{response !== null && <pre className="overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(response, null, 2)}</pre>}</div>}
    {can('connectors.manage') && <details className="my-3 rounded-lg border border-line p-3"><summary>Signed inbound webhooks (optional)</summary><p className="my-2 text-xs text-ink-3">The provider must sign the exact request bytes with the documented HMAC protocol. Configure response mappings first; received events do not approve agents.</p><label className="label">Signing secret<input data-testid="connector-webhook-secret" className="input" type="password" autoComplete="new-password" value={hookSecret} onChange={(event) => setHookSecret(event.target.value)} /></label><label className="label">External agent ID JSON Pointer<input data-testid="connector-webhook-agent" className="input" value={hookPointer} onChange={(event) => setHookPointer(event.target.value)} /></label><select data-testid="connector-webhook-kind" aria-label="Webhook event type" className="input" value={hookKind} onChange={(event) => setHookKind(event.target.value)}><option value="execution">Execution</option><option value="tracking">Tracking</option></select><div className="mt-3 flex gap-2"><button data-testid="connector-webhook-enable" className="btn" disabled={busy || !hookSecret || !hookPointer} onClick={() => void enableWebhook()}>Enable / rotate signing secret</button><button data-testid="connector-webhook-disable" className="btn-ghost" disabled={busy} onClick={() => void disableWebhook()}>Disable webhook</button></div>{hookUrl && <p className="mt-2 break-all text-sm">Webhook ready at {hookUrl}. Delivery is unverified until the provider sends a valid signed event.</p>}</details>}
    {history && <table data-testid="connector-history" className="mt-4 w-full text-sm"><thead><tr><th className="th">Operation</th><th className="th">Outcome</th><th className="th">Started</th><th className="th">Details</th></tr></thead><tbody>{history.items.map((run) => <tr key={run.id}><td className="td">{run.operation}</td><td className="td">{run.outcome}</td><td className="td">{run.started_at}</td><td className="td">{run.error_category ?? run.detail ?? (run.record_count === null ? '' : `${run.record_count} records`)}</td></tr>)}</tbody></table>}
  </details>;
}

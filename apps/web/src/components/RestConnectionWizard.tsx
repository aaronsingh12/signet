import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { ExternalConnectionView } from '@signet/core/types';
import type { ConnectionDraft } from './ExternalConnections';
import { ApiError, api } from '../lib/api';
import { useCan } from '../lib/auth';
import { Card, ErrorNote } from './ui';

interface RestAgent { id: string; name: string; status: string | null; agent_id: string | null }
interface RestResult { connection: ExternalConnectionView; agents: RestAgent[] }
interface Props {
  agentId: string | null;
  initialDraft: ConnectionDraft;
  connectionId: string | null;
  onSaved: () => void;
  onCancel: () => void;
}

/** Preview remote agents first, then onboard only the identities chosen by the user. */
export function RestConnectionWizard(props: Props) {
  const [baseUrl, setBaseUrl] = useState(props.initialDraft.config.base_url);
  const [credential, setCredential] = useState('');
  const [connectionId, setConnectionId] = useState<string | null>(props.connectionId);
  const [agents, setAgents] = useState<RestAgent[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const can = useCan();
  useEffect(() => {
    if (!props.connectionId || !can('connectors.manage')) return;
    let cancelled = false;
    setBusy(true);
    void api<RestResult>(`/connections/${props.connectionId}/preview-agents`, { method: 'POST' }).then((result) => {
      if (!cancelled) setAgents(result.agents);
    }).catch((error: ApiError) => { if (!cancelled) setError(error); }).finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [props.connectionId]);
  const connect = async (): Promise<void> => {
    setBusy(true); setError(null); setAgents(null);
    try {
      const result = await api<RestResult>('/connections/rest/connect', { method: 'POST', body: { agent_id: props.agentId, base_url: baseUrl.trim(), credential, connection_id: connectionId } });
      setConnectionId(result.connection.id); setCredential(''); setAgents(result.agents);
    } catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  const onboard = async (externalId: string): Promise<void> => {
    setBusy(true); setError(null);
    try {
      if (!connectionId) throw new Error('Connect the REST API before onboarding an agent');
      const result = await api<{ agent_id: string }>(`/connections/${connectionId}/onboard`, { method: 'POST', body: { external_id: externalId } });
      setAgents((current) => current?.map((agent) => agent.id === externalId ? { ...agent, agent_id: result.agent_id } : agent) ?? null);
    } catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  return <Card title="Connect your REST API">
    <p className="mb-4 text-sm text-ink-2">Enter your platform's API address and key. Signet finds its agents; you choose which ones to onboard.</p>
    <form data-testid="rest-connect-form" className="space-y-4" onSubmit={(event) => { event.preventDefault(); void connect(); }}>
      <fieldset disabled={busy || !can('connectors.manage')} className="grid gap-3 md:grid-cols-2">
        <label className="label">Base URL<input data-testid="rest-url" className="input" required type="url" placeholder="https://your-platform.com" value={baseUrl} onChange={(event) => { setBaseUrl(event.target.value); setAgents(null); setError(null); }} /></label>
        <label className="label">API key<input data-testid="rest-secret" className="input" type="password" autoComplete="new-password" required={!connectionId} value={credential} placeholder={connectionId ? 'Leave blank to keep your saved key' : 'Paste your platform API key'} onChange={(event) => { setCredential(event.target.value); setAgents(null); setError(null); }} /></label>
      </fieldset>
      <div className="flex gap-3"><button data-testid="rest-connect" disabled={busy || !can('connectors.manage')} className="btn-primary">{busy ? 'Please wait...' : agents === null ? 'Connect' : 'Refresh agents'}</button><button type="button" data-testid="rest-close" disabled={busy} className="btn-ghost" onClick={() => { if (connectionId) props.onSaved(); else props.onCancel(); }}>Close</button></div>
    </form>
    <ErrorNote error={error} />
    {agents !== null && <section data-testid="rest-agent-list" className="mt-6 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">Agents from your API ({agents.length})</h3><span className="text-sm text-ok">API connected</span></div>
      {!agents.length && <p className="rounded-lg bg-canvas p-4 text-sm">Your API returned no agents. Add agents on your platform, then refresh this list.</p>}
      <ul className="space-y-3">{agents.map((agent) => <li key={agent.id} data-testid={`rest-agent-${agent.id}`} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line p-4">
        <div><p className="font-semibold">{agent.name}</p><p className="text-xs text-ink-3">{agent.status ?? 'Available'} · {agent.agent_id ? 'Onboarding started' : 'Not onboarded'}</p></div>
        {agent.agent_id ? <Link data-testid={`rest-onboarded-${agent.id}`} className="btn" to={`/agents/${agent.agent_id}?tab=lifecycle`}>Continue approval</Link> : <button data-testid={`rest-onboard-${agent.id}`} disabled={busy || !can('discovery.write')} className="btn-primary" onClick={() => void onboard(agent.id)}>Onboard</button>}
      </li>)}</ul>
      <p className="text-xs text-ink-3">Onboard starts Signet's approval process for that agent. Connecting this API does not route its model calls through the Gateway.</p>
    </section>}
    {!can('connectors.manage') && <p className="mt-3 text-sm text-warn">A platform administrator must connect this API.</p>}
    {agents !== null && !can('discovery.write') && <p className="mt-3 text-sm text-warn">Agent discovery permission is required to onboard agents.</p>}
  </Card>;
}

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { ExternalConnectionView } from '@signet/core/types';
import { ExternalConnectionFields, type ConnectionDraft } from './ExternalConnections';
import { ApiError, api } from '../lib/api';
import { useCan } from '../lib/auth';
import { Card, ErrorNote } from './ui';
import { ConnectorOperations } from './ConnectorOperations';

interface RestAgent { id: string; name: string; status: string | null; agent_id: string | null }
interface RestResult { connection: ExternalConnectionView; agents: RestAgent[] }
interface Props {
  agentId: string | null;
  initialDraft: ConnectionDraft;
  connectionId: string | null;
  onSaved: () => void;
  onCancel: () => void;
  onVerified?: (connection: ExternalConnectionView) => void;
}

/** Preview remote agents first, then onboard only the identities chosen by the user. */
export function RestConnectionWizard(props: Props) {
  const [revision, setRevision] = useState(0);
  const [draft, setDraft] = useState<ConnectionDraft>(props.initialDraft);
  const [health, setHealth] = useState<ExternalConnectionView['health'] | null>(null);
  const [baseUrl, setBaseUrl] = useState(props.initialDraft.config.base_url);
  const [credential, setCredential] = useState('');
  const [connectionId, setConnectionId] = useState<string | null>(props.connectionId);
  const [agents, setAgents] = useState<RestAgent[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const can = useCan();
  useEffect(() => {
    if (!props.connectionId || !can('connectors.manage')) return;
    let cancelled = false;
    setBusy(true);
    void api<ExternalConnectionView>(`/connections/${props.connectionId}`).then(async (connection) => {
      if (!cancelled) setHealth(connection.health);
      if (!connection.config.endpoints.discover || !connection.config.agents_mapping) return;
      const result = await api<RestResult>(`/connections/${props.connectionId}/preview-agents`, { method: 'POST' });
      if (!cancelled) { setAgents(result.agents); setHealth(result.connection.health); }
    }).catch((error: ApiError) => { if (!cancelled) setError(error); }).finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled = true; };
  }, [props.connectionId]);
  const persist = async (): Promise<ExternalConnectionView> => {
    let hostname: string;
    try { hostname = new URL(baseUrl).hostname; } catch { throw new ApiError(400, 'VALIDATION', 'Enter a valid absolute HTTPS API base URL'); }
    const config = { ...draft.config, base_url: baseUrl.trim(), name: draft.config.name.trim() || hostname };
    const saved = await api<ExternalConnectionView>(connectionId ? `/connections/${connectionId}` : '/connections', { method: connectionId ? 'PUT' : 'POST', body: { agent_id: props.agentId, config, credential } });
    setConnectionId(saved.id); setCredential(''); setDraft({ config: saved.config, credential: '' }); setHealth(saved.health); setRevision((value) => value + 1);
    return saved;
  };
  const save = async (): Promise<void> => {
    setBusy(true); setError(null); setNotice(null);
    try { await persist(); setNotice('Connection settings saved. Test the connection to verify the API.'); } catch (error) { setError(error as ApiError); } finally { setBusy(false); }
  };
  const connect = async (): Promise<void> => {
    let testedId: string | null = null;
    setBusy(true); setError(null); setNotice(null); setAgents(null);
    try {
      const saved = await persist();
      testedId = saved.id;
      const tested = await api<ExternalConnectionView>(`/connections/${saved.id}/test`, { method: 'POST' });
      setHealth(tested.health); setRevision((value) => value + 1);
      if (tested.health.endpoint_verified && ['valid', 'not_required'].includes(tested.health.authentication)) props.onVerified?.(tested);
      if (saved.config.endpoints.discover && saved.config.agents_mapping) {
        const result = await api<RestResult>(`/connections/${saved.id}/preview-agents`, { method: 'POST' });
        setAgents(result.agents);
      }
    } catch (error) {
      setError(error as ApiError);
      if (testedId) {
        try { setHealth((await api<ExternalConnectionView>(`/connections/${testedId}`)).health); }
        catch (refreshError) { setError(new ApiError(502, 'STATUS_REFRESH', `${error instanceof Error ? error.message : 'Test failed'}; status refresh also failed: ${refreshError instanceof Error ? refreshError.message : 'unknown error'}`)); }
      }
    } finally { setBusy(false); }
  };
  const onboard = async (externalId: string): Promise<void> => {
    setBusy(true); setError(null);
    try {
      if (!connectionId) throw new Error('Connect the REST API before onboarding an agent');
      const result = await api<{ agent_id: string }>(`/connections/${connectionId}/onboard`, { method: 'POST', body: { external_id: externalId } });
      setAgents((current) => current?.map((agent) => agent.id === externalId ? { ...agent, agent_id: result.agent_id } : agent) ?? null);
      setRevision((value) => value + 1);
    } catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  return <Card title={draft.config.method === 'oauth' ? 'Connect with OAuth 2.0' : draft.config.method === 'hybrid' ? 'Connect your private network / on-prem API' : 'Connect your REST API'}>
    <p className="mb-4 text-sm text-ink-2">{draft.config.method === 'oauth' ? 'Enter your API base URL, token URL, Client ID and Client Secret, then test the connection.' : draft.config.method === 'hybrid' ? 'Connect through an enrolled runner using an approved agent’s Signet credentials and private tool binding.' : "Enter your API address and credentials. Review API settings once to map your provider's endpoints and agent fields, then test and choose agents to onboard."}</p>
    <form aria-busy={busy} data-testid="rest-connect-form" className="space-y-4" onSubmit={(event) => { event.preventDefault(); void connect(); }}><fieldset disabled={busy || !can('connectors.manage')} className="space-y-4">
      {draft.config.method === 'rest' && <><fieldset disabled={busy || !can('connectors.manage')} className="grid gap-3 md:grid-cols-2">
        <label className="label">Base URL<input data-testid="rest-url" className="input" required type="url" placeholder="https://your-platform.com" value={baseUrl} onChange={(event) => { setBaseUrl(event.target.value); setAgents(null); setError(null); setNotice(null); }} /></label>
        {draft.config.auth !== 'none' && <label className="label">API key / secret<input data-testid="rest-secret" className="input" type="password" autoComplete="new-password" required={!connectionId} value={credential} placeholder={connectionId ? 'Leave blank to keep your saved key' : 'Paste your platform API key'} onChange={(event) => { setCredential(event.target.value); setAgents(null); setError(null); setNotice(null); }} /></label>}
      </fieldset>
      <details className="rounded-lg border border-line p-3"><summary>API settings and endpoint mapping</summary><div className="mt-3"><ExternalConnectionFields draft={{ config: { ...draft.config, base_url: baseUrl }, credential }} onChange={(next) => { setDraft(next); setBaseUrl(next.config.base_url); setCredential(next.credential); setHealth(null); setAgents(null); setNotice(null); }} /></div></details></>}
      {draft.config.method !== 'rest' && <ExternalConnectionFields draft={{ config: { ...draft.config, base_url: baseUrl }, credential }} onChange={(next) => { setDraft(next); setBaseUrl(next.config.base_url); setCredential(next.credential); setHealth(null); setAgents(null); setNotice(null); }} />}
      <div className="flex flex-wrap gap-3"><button type="button" data-testid="rest-save" className="btn-ghost" disabled={busy || !can('connectors.manage')} onClick={() => void save()}>Save connection / mappings</button><button data-testid="rest-connect" disabled={busy || !can('connectors.manage')} className="btn-primary">{busy ? 'Please wait...' : agents === null ? 'Test connection & find agents' : 'Test & refresh agents'}</button><button type="button" data-testid="rest-close" disabled={busy} className="btn-ghost" onClick={() => { if (connectionId) props.onSaved(); else props.onCancel(); }}>Close</button></div>
    </fieldset></form>
    <div role="status" aria-live="polite" className="mt-4 space-y-2 text-sm">{busy ? <p>Updating connection. Please wait...</p> : health ? <><div className="flex flex-wrap gap-2"><span className="rounded-full border border-line px-3 py-1">{health.reachable === true ? 'Reachable' : health.reachable === false ? 'Unreachable' : 'Reachability unverified'}</span><span className={`rounded-full border border-line px-3 py-1 ${health.authentication === 'invalid' ? 'text-bad' : health.authentication === 'unverified' ? 'text-warn' : 'text-ok'}`}>{health.authentication === 'valid' ? 'Authentication verified' : health.authentication === 'invalid' ? 'Authentication failed' : health.authentication === 'not_required' ? 'Authentication not required' : 'Authentication unverified'}</span><span className="rounded-full border border-line px-3 py-1">{health.endpoint_verified ? 'Test endpoint verified' : 'Test endpoint unverified'}</span></div><p className="text-xs text-ink-3">Last tested: {health.last_tested_at ? new Date(health.last_tested_at).toLocaleString() : 'Never'}</p></> : <p className="text-ink-3">Save and test your API configuration.</p>}</div>
    {health?.endpoint_verified && !draft.config.agents_mapping && <p className="mt-2 text-sm text-ink-3">Connection test passed. Configure the discovery endpoint and agent response mapping to find agents.</p>}
    <ErrorNote error={error} />
    {notice && <p role="status" className="mt-3 rounded-lg border border-line bg-ok-50 px-3 py-2 text-sm text-ok">{notice}</p>}
    {agents !== null && <section data-testid="rest-agent-list" className="mt-6 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">Agents from your API ({agents.length})</h3><span className={`text-sm ${health?.authentication === 'unverified' ? 'text-warn' : 'text-ok'}`}>{health?.authentication === 'valid' || health?.authentication === 'not_required' ? 'API connected' : 'Endpoint responded; authentication unverified'}</span></div>
      {!agents.length && <p className="rounded-lg bg-canvas p-4 text-sm">Your API returned no agents. Add agents on your platform, then refresh this list.</p>}
      <ul className="space-y-3">{agents.map((agent) => <li key={agent.id} data-testid={`rest-agent-${agent.id}`} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line p-4">
        <div><p className="font-semibold">{agent.name}</p><p className="text-xs text-ink-3">{agent.status ?? 'Available'} · {agent.agent_id ? 'Registered in Signet' : 'Not onboarded'}</p></div>
        {agent.agent_id ? <Link data-testid={`rest-onboarded-${agent.id}`} className="btn-ghost" to={`/agents/${agent.agent_id}?tab=lifecycle`}>View agent</Link> : <button data-testid={`rest-onboard-${agent.id}`} disabled={busy || !can('discovery.write')} className="btn-primary" onClick={() => void onboard(agent.id)}>Onboard</button>}
      </li>)}</ul>
      <p className="text-xs text-ink-3">Onboard starts Signet's approval process for that agent. Connecting this API does not route its model calls through the Gateway.</p>
    </section>}
    {connectionId && <ConnectorOperations key={`${connectionId}:${revision}`} id={connectionId} onDeleted={props.onSaved} />}
    {!can('connectors.manage') && <p className="mt-3 text-sm text-warn">A platform administrator must connect this API.</p>}
    {agents !== null && !can('discovery.write') && <p className="mt-3 text-sm text-warn">Agent discovery permission is required to onboard agents.</p>}
  </Card>;
}

import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { Card, ErrorNote, Modal } from './ui';
import { ExternalConnectionEditor, ExternalConnections } from './ExternalConnections';
import { ServiceNowGateway } from './ServiceNowGateway';

interface LinkedAgent {
  agent_id: string; external_id: string; connection_id: string; name: string; handle: string;
  monitoring: boolean; last_sync_at: string | null; gateway_enforcement: boolean;
}

export function ServiceNowAgents({ connectionId }: { connectionId: string }) {
  const path = '/plugins/servicenow/connections/' + encodeURIComponent(connectionId) + '/agents';
  const { data, error, reload } = useApi<{ items: LinkedAgent[] }>(path);
  const [adding, setAdding] = useState(false);
  const can = useCan();
  useEffect(() => {
    const timer = setInterval(() => { void reload(); }, 15000);
    return () => clearInterval(timer);
  }, [reload]);
  return <div className="mt-5 border-t border-line pt-4">
    <h3 className="text-sm font-semibold">Linked ServiceNow AI agents</h3>
    <p className="mt-1 text-xs text-ink-3">Link an existing agent to the registry, configure activity sync, then complete approval and gateway setup.</p>
    {can('agents.write') && <button type="button" data-testid={`servicenow-link-agent-${connectionId}`} className="btn-primary mt-3" onClick={() => setAdding(true)}>Link existing ServiceNow agent</button>}
    <ErrorNote error={error} />
    {data && !data.items.length && <p className="mt-3 text-sm text-ink-3">No agent linked yet. MCP tool discovery does not import agents.</p>}
    {data?.items.map(agent => <LinkedServiceNowAgent key={agent.agent_id} agent={agent} onChanged={() => { void reload(); }} />)}
    <ServiceNowGateway connectionId={connectionId} />
    {adding && <Modal title="Link existing ServiceNow agent" onClose={() => setAdding(false)}>
      <LinkServiceNowAgentForm path={path} onSaved={() => { setAdding(false); void reload(); }} />
    </Modal>}
  </div>;
}

function LinkServiceNowAgentForm({ path, onSaved }: { path: string; onSaved: () => void }) {
  const [draft, setDraft] = useState({ external_id: '', name: '', purpose: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [available, setAvailable] = useState<{ id: string; name: string; description: string }[] | null>(null);
  const [loadingAgents, setLoadingAgents] = useState(false);
  const loadAgents = async (): Promise<void> => {
    setLoadingAgents(true); setError(null);
    try { const result = await api<{ items: { id: string; name: string; description: string }[] }>(path + '/available'); setAvailable(result.items); }
    catch (failure) { setError(failure instanceof Error ? failure : new Error('ServiceNow agent list could not be loaded')); }
    finally { setLoadingAgents(false); }
  };
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault(); setBusy(true); setError(null);
    try { await api(path, { method: 'POST', body: draft }); onSaved(); }
    catch (failure) { setError(failure instanceof Error ? failure : new Error('ServiceNow agent could not be linked')); }
    finally { setBusy(false); }
  };
  return <form data-testid="servicenow-link-agent-form" className="space-y-4" onSubmit={event => void save(event)}>
    <p className="text-sm text-ink-2">Use the existing AI Agent Studio record. Linking registers its identity in Signet; it does not create or modify the agent in ServiceNow.</p>
    <button type="button" data-testid="servicenow-load-agents" className="btn-ghost" disabled={loadingAgents || busy} onClick={() => void loadAgents()}>{loadingAgents ? 'Loading agents…' : 'Load agents from ServiceNow'}</button>
    {available && <div><label className="label" htmlFor="servicenow-select-agent">Select an existing active agent</label>
      <select id="servicenow-select-agent" className="input" value={available.some(agent => agent.id === draft.external_id) ? draft.external_id : ''} onChange={event => {
        const selected = available.find(agent => agent.id === event.target.value);
        if (selected) setDraft({ external_id: selected.id, name: selected.name, purpose: selected.description });
      }}><option value="">Select an agent</option>{available.map(agent => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</select>
      {!available.length && <p className="mt-1 text-xs text-ink-3">No active agents were returned for this ServiceNow user.</p>}
    </div>}
    <div><label className="label" htmlFor="servicenow-external-agent-id">ServiceNow AI agent sys_id</label>
      <input id="servicenow-external-agent-id" className="input" required pattern="[a-fA-F0-9]{32}" minLength={32} maxLength={32} value={draft.external_id} onChange={event => setDraft({ ...draft, external_id: event.target.value })} />
      <p className="mt-1 text-xs text-ink-3">The 32-character ID of the AI agent record, not the MCP server or an execution.</p></div>
    <div><label className="label" htmlFor="servicenow-agent-name">Agent name</label><input id="servicenow-agent-name" className="input" required maxLength={200} value={draft.name} onChange={event => setDraft({ ...draft, name: event.target.value })} /></div>
    <div><label className="label" htmlFor="servicenow-agent-purpose">What does this agent do?</label><textarea id="servicenow-agent-purpose" className="input" required minLength={10} maxLength={4000} value={draft.purpose} onChange={event => setDraft({ ...draft, purpose: event.target.value })} /></div>
    <ErrorNote error={error} />
    <button type="submit" data-testid="servicenow-save-agent-link" className="btn-primary" disabled={busy}>{busy ? 'Linking…' : 'Link agent to Signet'}</button>
  </form>;
}

function LinkedServiceNowAgent({ agent, onChanged }: { agent: LinkedAgent; onChanged: () => void }) {
  const [configuring, setConfiguring] = useState(false);
  const [showSources, setShowSources] = useState(false);
  const can = useCan();
  return <div data-testid={`servicenow-linked-agent-${agent.agent_id}`} className="mt-4 rounded-xl border border-line p-4">
    <Link className="font-semibold text-royal" to={`/agents/${agent.agent_id}`}>{agent.name}</Link>
    <p className="mt-1 break-all text-xs text-ink-3">ServiceNow ID: {agent.external_id}</p>
    <p className="mt-2 text-sm">{agent.gateway_enforcement ? 'Gateway enforcement verified' : 'Gateway enforcement not verified'} · {agent.monitoring ? 'Activity sync verified' : 'Activity monitoring not configured or not verified'}</p>
    {agent.last_sync_at && <p className="mt-1 text-xs text-ink-3">Last sync: {new Date(agent.last_sync_at).toLocaleString()}</p>}
    <div className="mt-3 flex flex-wrap gap-2">
      {can('connectors.manage') && <button type="button" className="btn-ghost" data-testid={`servicenow-configure-monitoring-${agent.agent_id}`} onClick={() => setConfiguring(true)}>Configure activity monitoring</button>}
      <button type="button" className="btn-ghost" data-testid={`servicenow-monitoring-sources-${agent.agent_id}`} onClick={() => setShowSources(!showSources)}>Activity sources and sync</button>
      <Link className="btn-ghost" to={`/agents/${agent.agent_id}?tab=lifecycle`}>Review and approval</Link>
      <Link className="btn-ghost" to={`/agents/${agent.agent_id}?tab=connection`}>Gateway setup</Link>
    </div>
    {showSources && <div className="mt-4"><ExternalConnections agentId={agent.agent_id} /><button type="button" className="btn-ghost mt-2" onClick={onChanged}>Refresh coverage</button></div>}
    {configuring && <Modal title="Configure ServiceNow activity monitoring" width="max-w-5xl" onClose={() => setConfiguring(false)}>
      <p className="mb-4 text-sm text-ink-2">Enter the documented read-only activity API and credentials. Use GET endpoints and scope the executions request with {'{agent_id}'} or this agent's exact sys_id. Configure its response mapping; leave discovery and remote actions disabled. Activity import does not intercept internal calls or grant gateway approval.</p>
      <ExternalConnectionEditor agentId={agent.agent_id} method="rest" existing={null} onSaved={() => { setConfiguring(false); setShowSources(true); onChanged(); }} onCancel={() => setConfiguring(false)} />
    </Modal>}
  </div>;
}

export function ServiceNowAgentCoverage({ agentId }: { agentId: string }) {
  const { data, error } = useApi<{ items: LinkedAgent[] }>('/agents/' + encodeURIComponent(agentId) + '/servicenow');
  if (error) return <ErrorNote error={error} />;
  if (!data?.items.length) return null;
  return <Card title="ServiceNow connection and monitoring">
    {data.items.map(agent => <LinkedServiceNowAgent key={agent.connection_id} agent={agent} onChanged={() => window.location.reload()} />)}
  </Card>;
}

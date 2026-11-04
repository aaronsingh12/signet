import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { AgentListFields, ExternalConnectionView, ResponseMapping } from '@signet/core/types';
import type { ConnectionDraft } from './ExternalConnections';
import { ApiError, api } from '../lib/api';
import { useCan } from '../lib/auth';
import { Card, ErrorNote } from './ui';

interface ImportedAgent { name: string; external_id: string; agent_id: string; last_seen_at: string }
interface Props {
  agentId: string;
  initialDraft: ConnectionDraft;
  connectionId: string | null;
  onSaved: () => void;
  onCancel: () => void;
  renderAdvanced: (draft: ConnectionDraft, onChange: (draft: ConnectionDraft) => void) => ReactNode;
}

/** Test the real API, explicitly select observed fields, then import into the existing approval lifecycle. */
export function RestConnectionWizard(props: Props) {
  const [draft, setDraft] = useState<ConnectionDraft>(props.initialDraft);
  const [connectionId, setConnectionId] = useState<string | null>(props.connectionId);
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [lists, setLists] = useState<AgentListFields[] | null>(null);
  const [selectedList, setSelectedList] = useState<string | null>(null);
  const [agents, setAgents] = useState<ImportedAgent[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const can = useCan();
  const config = draft.config;
  const mapping = config.agents_mapping;
  const list = lists?.find((item) => item.path === selectedList);
  const change = (next: ConnectionDraft): void => {
    setDraft(next);
    setLists(null);
    setSelectedList(null);
    setError(null);
  };
  const persist = async (): Promise<ExternalConnectionView> => {
    const saved = await api<ExternalConnectionView>(connectionId ? `/connections/${connectionId}` : '/connections', {
      method: connectionId ? 'PUT' : 'POST', body: { agent_id: props.agentId, ...draft },
    });
    setConnectionId(saved.id);
    setDraft({ config: saved.config, credential: '' });
    return saved;
  };
  const saveAndClose = async (): Promise<void> => {
    setBusy(true); setError(null);
    try { await persist(); props.onSaved(); }
    catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  const connect = async (): Promise<void> => {
    setBusy(true); setError(null);
    try {
      const saved = await persist();
      await api<ExternalConnectionView>(`/connections/${saved.id}/test`, { method: 'POST' });
      setStep(2);
    } catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  const inspect = async (): Promise<void> => {
    setBusy(true); setError(null); setLists(null); setSelectedList(null);
    try {
      const saved = await persist();
      const response = await api<{ lists: AgentListFields[] }>(`/connections/${saved.id}/agent-fields`, { method: 'POST' });
      setLists(response.lists);
    } catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  const discover = async (): Promise<void> => {
    setBusy(true); setError(null);
    try {
      const saved = await persist();
      await api<ExternalConnectionView>(`/connections/${saved.id}/discover`, { method: 'POST' });
      const response = await api<{ items: ImportedAgent[] }>(`/connections/${saved.id}/agents`);
      setAgents(response.items); setStep(3);
    } catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  const selectField = (key: 'id' | 'name' | 'status', label: string): ReactNode => <label className="label">{label}
    <select data-testid={`rest-field-${key}`} className="input" required={key === 'id'} value={mapping?.[key] ?? ''} onChange={(event) => {
      if (!mapping) throw new Error('Select the agent list before choosing its fields');
      setDraft({ ...draft, config: { ...config, agents_mapping: { ...mapping, [key]: event.target.value } } });
    }}><option value="">{key === 'id' ? 'Select a unique agent ID' : 'Skip this field'}</option>{list?.fields.map((field) => <option key={field} value={field}>{field.slice(1).replaceAll('/', ' ? ')}</option>)}</select>
  </label>;
  return <Card title="Connect a REST API">
    <ol aria-label="REST connection steps" className="mb-6 grid grid-cols-3 gap-2">{['Connect API', 'Find agents', 'Onboard agents'].map((label, index) => <li key={label} aria-current={step === index + 1 ? 'step' : undefined} className={`rounded-lg border p-3 text-sm ${step === index + 1 ? 'border-royal bg-royal-50 font-semibold' : 'border-line text-ink-3'}`}>{index + 1}. {label}</li>)}</ol>
    <p className="mb-4 text-sm text-ink-2">Connect your platform, find its agents, then complete their approval in Signet. This connection reads external activity; model calls are governed only when routed through the Gateway.</p>
    <ErrorNote error={error} />
    <fieldset disabled={busy || !can('connectors.manage')} className="space-y-4">
    {step === 1 && <form data-testid="rest-connect-form" className="space-y-4" onSubmit={(event) => { event.preventDefault(); void connect(); }}>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="label">Connection name<input data-testid="rest-name" className="input" required maxLength={120} placeholder="My AI platform" value={config.name} onChange={(event) => change({ ...draft, config: { ...config, name: event.target.value } })} /></label>
        <label className="label">Your API address<input data-testid="rest-url" className="input" required type="url" placeholder="https://your-app.example.com" value={config.base_url} onChange={(event) => change({ ...draft, config: { ...config, base_url: event.target.value } })} /></label>
        <label className="label">How does your API sign in?<select data-testid="rest-auth" className="input" value={config.auth} onChange={(event) => change({ ...draft, config: { ...config, auth: event.target.value as 'api_key' | 'bearer' | 'none' } })}><option value="api_key">API key</option><option value="bearer">Bearer token</option><option value="none">No authentication</option></select></label>
        {config.auth === 'api_key' && <label className="label">API key header<input data-testid="rest-header" className="input" required placeholder="x-api-key" value={config.header} onChange={(event) => change({ ...draft, config: { ...config, header: event.target.value } })} /></label>}
        {config.auth !== 'none' && <label className="label">API key or token<input data-testid="rest-secret" className="input" type="password" autoComplete="new-password" required={!connectionId} value={draft.credential} onChange={(event) => change({ ...draft, credential: event.target.value })} /><span className="text-xs text-ink-3">{connectionId ? 'Leave blank to keep your saved key.' : 'Use the key issued by your external platform.'}</span></label>}
        <label className="label">Health check path<input data-testid="rest-health-path" className="input" required pattern="/.*" placeholder="/api/health" value={config.endpoints.test?.path ?? ''} onChange={(event) => change({ ...draft, config: { ...config, endpoints: { ...config.endpoints, test: { method: 'GET', path: event.target.value } } } })} /><span className="text-xs text-ink-3">A read-only JSON endpoint from your API documentation.</span></label>
      </div>
      <details className="rounded-lg border border-line p-3"><summary>Advanced settings and existing monitoring</summary><div className="mt-4">{props.renderAdvanced(draft, change)}</div></details>
      <p className="text-xs text-ink-3">Your connection is saved securely before the health check. Testing does not approve or import agents.</p>
      <div className="flex flex-wrap gap-3"><button data-testid="rest-connect" className="btn-primary">{busy ? 'Checking API?' : 'Test API & continue'}</button>{props.connectionId && <button data-testid="rest-save-changes" type="button" className="btn" onClick={() => void saveAndClose()}>Save changes & close</button>}</div>
    </form>}
    {step === 2 && <div className="space-y-4">
      <p className="text-sm text-ok">API connection verified. Now choose where your platform lists its agents.</p>
      <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => { event.preventDefault(); void inspect(); }}><label className="label flex-1">Agent list path<input data-testid="rest-discover-path" className="input" required pattern="/.*" placeholder="Enter the path from your API docs, e.g. /agents" value={config.endpoints.discover?.path ?? ''} onChange={(event) => change({ ...draft, config: { ...config, endpoints: { ...config.endpoints, discover: { method: 'GET', path: event.target.value } } } })} /></label><button data-testid="rest-read-fields" className="btn">{busy ? 'Reading API?' : 'Read agent fields'}</button></form>
      {lists && <div className="space-y-3 rounded-lg border border-line p-4"><p className="text-sm">Select the agent list and its fields below. These options come from your API; you do not need to write JSON paths.</p>
        <label className="label">Which list contains your agents?<select data-testid="rest-agent-list" className="input" value={selectedList ?? '__select__'} onChange={(event) => {
          const path = event.target.value === '__select__' ? null : event.target.value;
          setSelectedList(path);
          const next: ResponseMapping | null = path === null ? null : { items: path, id: '', name: '', status: '', timestamp: '' };
          setDraft({ ...draft, config: { ...config, agents_mapping: next } });
        }}><option value="__select__">Select an agent list</option>{lists.map((item) => <option key={item.path} value={item.path}>{item.path || 'Top-level list'} ({item.count} records)</option>)}</select></label>
        {list && list.fields.length > 0 && <div className="grid gap-3 md:grid-cols-3">{selectField('id', 'Unique agent ID')}{selectField('name', 'Agent name (optional)')}{selectField('status', 'Agent status (optional)')}</div>}
        {list && !list.fields.length && <p role="status" className="text-sm text-warn">{list.count === 0 ? 'This list is empty. Add an agent in your platform, then read the fields again.' : 'This list has no shared text fields. Your API needs a stable text ID for each agent.'}</p>}
      </div>}
      <div className="flex flex-wrap gap-3"><button data-testid="rest-back-connect" className="btn-ghost" onClick={() => { setStep(1); setError(null); }}>Back</button><button data-testid="rest-import" className="btn-primary" disabled={!list || !mapping?.id || !can('discovery.write')} onClick={() => void discover()}>{busy ? 'Importing agents?' : 'Import agents & start onboarding'}</button></div>
      {!can('discovery.write') && <p className="text-sm text-warn">An administrator with agent discovery permission must import agents.</p>}
      <button data-testid="rest-finish-later" className="btn-ghost" onClick={() => void saveAndClose()}>Save and finish later</button>
      <p className="text-xs text-ink-3">Imported agents remain pending approval. Importing again reuses agents already linked to this connection.</p>
    </div>}
    {step === 3 && <div className="space-y-4">
      <p className="text-sm font-semibold">{agents.length} agent{agents.length === 1 ? '' : 's'} ready for onboarding</p>
      <p className="text-sm text-ink-2">Open each agent, describe its purpose, and complete classification, assessment, testing and approval. No approval checks are skipped.</p>
      <ul className="divide-y divide-line">{agents.map((agent) => <li key={agent.agent_id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div><p className="text-sm font-semibold">{agent.name}</p><p className="text-xs text-ink-3">{agent.external_id}</p></div><Link data-testid={`rest-onboard-${agent.agent_id}`} className="btn-primary" to={`/agents/${agent.agent_id}?tab=lifecycle`}>Continue onboarding</Link></li>)}</ul>
      {!agents.length && <p className="text-sm">No agents were returned. Check the list endpoint and its field selection.</p>}
      <button data-testid="rest-done" className="btn" onClick={props.onSaved}>Done</button>
    </div>}
    <button data-testid="rest-close" type="button" className="btn-ghost" onClick={props.onCancel}>Close setup</button>
    </fieldset>
    {!can('connectors.manage') && <p className="mt-3 text-sm text-warn">A platform administrator must set up this connection.</p>}
  </Card>;
}

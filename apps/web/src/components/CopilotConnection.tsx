import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, Bot, RefreshCw } from 'lucide-react';
import { Card, ErrorNote, Modal } from './ui';
import { ConnectionIcon } from './ConnectionIcon';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';

// Microsoft Copilot Studio agents: connect a Dataverse environment, list its agents, link one to Signet.
// Linking registers the agent's identity only; review, approval and gateway setup follow as for any agent.

interface CopilotConnectionView {
  id: string; label: string; environment_url: string; status: string; status_detail: string | null; created_at: string; linked_agents: number;
}
interface CopilotBot { id: string; name: string; active: boolean; schema_name: string | null }
interface LinkedAgent { agent_id: string; bot_id: string; connection_id: string; name: string; handle: string; purpose: string; gateway_enforcement: boolean }

const BASE = '/plugins/copilot';
const errorOf = (failure: unknown, fallback: string): Error => failure instanceof Error ? failure : new Error(fallback);

export function CopilotConnection() {
  const canManage = useCan()('tenant.admin');
  const { data, error, loading, reload } = useApi<{ items: CopilotConnectionView[] }>(canManage ? BASE : null);
  const [adding, setAdding] = useState(false);
  return <div className="space-y-4">
    <Card>
      <h2 className="text-base font-semibold">Microsoft Copilot Studio connections and AI agents</h2>
      {canManage ? <button type="button" data-testid="copilot-add-connection" className="btn-primary mt-3" onClick={() => setAdding(true)}>Add Copilot Studio Agents</button>
        : <p className="mt-2 text-sm text-ink-3">A Tenant Admin can manage these connections.</p>}
      {loading && <p role="status">Loading connections…</p>}
      <ErrorNote error={error} />
      {data && !data.items.length && <p className="mt-3 text-sm text-ink-3">No Copilot Studio connections saved yet.</p>}
    </Card>
    <div className="grid grid-cols-[repeat(auto-fill,minmax(180px,220px))] gap-4">
      {data?.items.map(connection => <SavedCopilotConnection key={connection.id} connection={connection} onChanged={() => { void reload(); }} />)}
    </div>
    {adding && <Modal title="Add Copilot Studio Agents" onClose={() => setAdding(false)}>
      <CopilotSetup onSaved={() => { setAdding(false); void reload(); }} onCancel={() => setAdding(false)} />
    </Modal>}
  </div>;
}

export function CopilotSetup({ onSaved, onCancel }: { onSaved: () => void; onCancel: () => void }) {
  const [draft, setDraft] = useState({ label: '', environment_url: '', tenant_id: '', client_id: '', client_secret: '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault(); setSaving(true); setError(null);
    try {
      const response = await api<{ connection: CopilotConnectionView }>(BASE + '/connections', { method: 'POST', body: draft });
      if (typeof response?.connection?.id !== 'string') throw new Error('The Copilot Studio connection was saved without an ID; reload this page to check it');
      setDraft({ label: '', environment_url: '', tenant_id: '', client_id: '', client_secret: '' });
      onSaved();
    } catch (failure) { setError(errorOf(failure, 'Copilot Studio connection could not be saved')); }
    finally { setSaving(false); }
  };
  const field = (key: keyof typeof draft, label: string, help: string, extra: Record<string, unknown> = {}) => <div>
    <label className="label" htmlFor={`copilot-${key}`}>{label}</label>
    <input id={`copilot-${key}`} data-testid={`copilot-${key}`} className="input" value={draft[key]} onChange={event => setDraft({ ...draft, [key]: event.target.value })} {...extra} />
    <p className="mt-1 text-xs text-ink-3">{help}</p>
  </div>;
  return <form data-testid="copilot-setup-form" className="space-y-4" onSubmit={event => void save(event)}>
    <p className="text-sm text-ink-2">Signet signs in to your Power Platform environment with an Entra app registration and lists its Copilot Studio agents. The app must be added to the environment as an application user. Signet checks the sign-in before saving anything.</p>
    {field('label', 'Connection name', 'A name you will recognise, e.g. Copilot Studio – Sales', { maxLength: 120, placeholder: 'Copilot Studio – Test' })}
    {field('environment_url', 'Environment URL', 'Power Platform admin center → Environments → your environment → Environment URL.', { type: 'url', required: true, placeholder: 'https://orgxxxxxxx.crm.dynamics.com' })}
    {field('tenant_id', 'Directory (tenant) ID', 'Microsoft Entra ID → App registrations → your app → Overview.', { required: true, maxLength: 64 })}
    {field('client_id', 'Application (client) ID', 'From the same app registration Overview page.', { required: true, maxLength: 64 })}
    {field('client_secret', 'Client secret value', 'App registration → Certificates & secrets → the secret Value (not the Secret ID). Stored encrypted.', { type: 'password', autoComplete: 'new-password', required: true, minLength: 8, maxLength: 4096 })}
    <ErrorNote error={error} />
    <div className="flex flex-wrap gap-2">
      <button type="submit" data-testid="copilot-save-connection" className="btn-primary" disabled={saving}>{saving ? 'Checking and saving…' : 'Save and connect'}</button>
      <button type="button" className="btn-ghost" onClick={onCancel} disabled={saving}>Cancel</button>
    </div>
  </form>;
}

function SavedCopilotConnection({ connection, onChanged }: { connection: CopilotConnectionView; onChanged: () => void }) {
  const path = BASE + '/connections/' + encodeURIComponent(connection.id);
  const ok = connection.status === 'connected';
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState<'test' | 'remove' | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const run = async (kind: 'test' | 'remove'): Promise<void> => {
    setBusy(kind); setError(null);
    try {
      await api(kind === 'test' ? path + '/test' : path, { method: kind === 'test' ? 'POST' : 'DELETE' });
      if (kind === 'remove') setExpanded(false);
      onChanged();
    } catch (failure) { setError(errorOf(failure, kind === 'test' ? 'Connection test failed' : 'Connection could not be removed')); }
    finally { setBusy(null); }
  };
  return <Card className={`aspect-square [&>div]:h-full !bg-none ${ok ? '!bg-ok-50 !border-ok/30' : '!bg-warn-50 !border-warn/30'}`} pad={false}>
    <section className="h-full" data-testid={`copilot-connection-${connection.id}`}>
      <button type="button" data-testid={`copilot-open-connection-${connection.id}`} className="flex h-full w-full flex-col items-start rounded-2xl p-4 text-left transition-colors hover:brightness-95 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2" aria-haspopup="dialog" onClick={() => setExpanded(true)}>
        <span className="flex w-full items-start justify-between gap-2">
          <ConnectionIcon tone={ok ? 'ok' : 'warn'}><Bot size={23} strokeWidth={1.8} /></ConnectionIcon>
          <ArrowUpRight size={16} aria-hidden="true" className="shrink-0 text-ink-3" />
        </span>
        <span className="mt-3 line-clamp-2 break-words text-sm font-semibold">{connection.label}</span>
        <span className={`mt-2 rounded px-1.5 py-0.5 text-[11px] font-medium ${ok ? 'bg-ok-50 text-ok' : 'bg-slate-100 text-ink-2'}`}>{ok ? 'Connected' : 'Check connection'}</span>
        <span className="mt-auto pt-3 text-xs text-ink-3">{connection.linked_agents} linked {connection.linked_agents === 1 ? 'agent' : 'agents'}</span>
        <span className="mt-1 text-xs text-ink-2">View details</span>
      </button>
      {expanded && <Modal title={connection.label} width="max-w-5xl" onClose={() => setExpanded(false)}>
        <p className="text-sm text-ink-2">Copilot Studio environment</p>
        <p className="mt-1 break-all text-xs text-ink-3">{connection.environment_url}</p>
        {connection.status_detail && <p className={`mt-2 text-sm ${ok ? 'text-ok' : 'text-warn'}`}>{connection.status_detail}</p>}
        <ErrorNote error={error} />
        <div className="mt-3 flex flex-wrap gap-2">
          <button type="button" data-testid={`copilot-test-${connection.id}`} className="btn-ghost inline-flex items-center gap-1.5" disabled={busy !== null} onClick={() => void run('test')}><RefreshCw size={14} />{busy === 'test' ? 'Testing…' : 'Test connection'}</button>
          <button type="button" data-testid={`copilot-remove-${connection.id}`} className="btn-ghost text-bad" disabled={busy !== null} onClick={() => void run('remove')}>{busy === 'remove' ? 'Removing…' : 'Remove connection'}</button>
        </div>
        <CopilotAgents connectionId={connection.id} onChanged={onChanged} />
      </Modal>}
    </section>
  </Card>;
}

function CopilotAgents({ connectionId, onChanged }: { connectionId: string; onChanged: () => void }) {
  const path = BASE + '/connections/' + encodeURIComponent(connectionId) + '/agents';
  const { data, error, reload } = useApi<{ items: LinkedAgent[] }>(path);
  const [adding, setAdding] = useState(false);
  const can = useCan();
  return <div className="mt-5 border-t border-line pt-4">
    <h3 className="text-sm font-semibold">Linked Copilot Studio agents</h3>
    <p className="mt-1 text-xs text-ink-3">Link an existing agent to the registry, then complete review, approval and gateway setup.</p>
    {can('agents.write') && <button type="button" data-testid={`copilot-link-agent-${connectionId}`} className="btn-primary mt-3" onClick={() => setAdding(true)}>Link existing Copilot Studio agent</button>}
    <ErrorNote error={error} />
    {data && !data.items.length && <p className="mt-3 text-sm text-ink-3">No agent linked yet.</p>}
    {data?.items.map(agent => <LinkedCopilotAgent key={agent.agent_id} agent={agent} />)}
    {adding && <Modal title="Link existing Copilot Studio agent" onClose={() => setAdding(false)}>
      <LinkCopilotAgentForm path={path} onSaved={() => { setAdding(false); void reload(); onChanged(); }} />
    </Modal>}
  </div>;
}

function LinkCopilotAgentForm({ path, onSaved }: { path: string; onSaved: () => void }) {
  const [draft, setDraft] = useState({ bot_id: '', name: '', purpose: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [available, setAvailable] = useState<CopilotBot[] | null>(null);
  const [loading, setLoading] = useState(false);
  const loadAgents = async (): Promise<void> => {
    setLoading(true); setError(null);
    try {
      const result = await api<{ items: CopilotBot[] }>(path + '/available');
      if (!Array.isArray(result?.items)) throw new TypeError('The Copilot Studio agent list response must contain items');
      setAvailable(result.items);
    } catch (failure) { setError(errorOf(failure, 'Copilot Studio agents could not be loaded')); }
    finally { setLoading(false); }
  };
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault(); setBusy(true); setError(null);
    try { await api(path, { method: 'POST', body: draft }); onSaved(); }
    catch (failure) { setError(errorOf(failure, 'Copilot Studio agent could not be linked')); }
    finally { setBusy(false); }
  };
  return <form data-testid="copilot-link-agent-form" className="space-y-4" onSubmit={event => void save(event)}>
    <p className="text-sm text-ink-2">Choose an existing Copilot Studio agent. Linking registers its identity in Signet; it does not create or change the agent in Microsoft.</p>
    <button type="button" data-testid="copilot-load-agents" className="btn-ghost" disabled={loading || busy} onClick={() => void loadAgents()}>{loading ? 'Loading agents…' : 'Load agents from Copilot Studio'}</button>
    {available && <div><label className="label" htmlFor="copilot-select-agent">Select an agent</label>
      <select id="copilot-select-agent" data-testid="copilot-select-agent" className="input" value={available.some(agent => agent.id === draft.bot_id) ? draft.bot_id : ''} onChange={event => {
        const selected = available.find(agent => agent.id === event.target.value);
        if (selected) setDraft({ ...draft, bot_id: selected.id, name: selected.name });
      }}><option value="">Select an agent</option>{available.map(agent => <option key={agent.id} value={agent.id}>{agent.name}{agent.active ? '' : ' (inactive)'}</option>)}</select>
      {!available.length && <p className="mt-1 text-xs text-ink-3">This environment returned no agents. Save the agent in Copilot Studio first, then load again.</p>}
    </div>}
    <div><label className="label" htmlFor="copilot-bot-id">Copilot Studio agent ID</label>
      <input id="copilot-bot-id" data-testid="copilot-bot-id" className="input" required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" value={draft.bot_id} onChange={event => setDraft({ ...draft, bot_id: event.target.value })} />
      <p className="mt-1 text-xs text-ink-3">The GUID after /agents/ in the Copilot Studio address bar. Filled in when you select an agent above.</p></div>
    <div><label className="label" htmlFor="copilot-agent-name">Agent name</label>
      <input id="copilot-agent-name" data-testid="copilot-agent-name" className="input" required maxLength={200} value={draft.name} onChange={event => setDraft({ ...draft, name: event.target.value })} /></div>
    <div><label className="label" htmlFor="copilot-agent-purpose">What does this agent do?</label>
      <textarea id="copilot-agent-purpose" data-testid="copilot-agent-purpose" className="input" required minLength={10} maxLength={4000} value={draft.purpose} onChange={event => setDraft({ ...draft, purpose: event.target.value })} /></div>
    <ErrorNote error={error} />
    <button type="submit" data-testid="copilot-save-agent-link" className="btn-primary" disabled={busy}>{busy ? 'Linking…' : 'Link agent to Signet'}</button>
  </form>;
}

function LinkedCopilotAgent({ agent }: { agent: LinkedAgent }) {
  return <div data-testid={`copilot-linked-agent-${agent.agent_id}`} className="mt-4 rounded-xl border border-line p-4">
    <Link className="font-semibold text-royal" to={`/agents/${agent.agent_id}`}>{agent.name}</Link>
    <p className="mt-1 break-all text-xs text-ink-3">Copilot Studio agent ID: {agent.bot_id}</p>
    <p className="mt-2 text-sm">{agent.gateway_enforcement ? 'Gateway enforcement verified' : 'Gateway enforcement not verified yet'}</p>
    <div className="mt-3 flex flex-wrap gap-2">
      <Link className="btn-ghost" to={`/agents/${agent.agent_id}?tab=lifecycle`}>Review and approval</Link>
      <Link className="btn-ghost" to={`/agents/${agent.agent_id}?tab=connection`}>Gateway setup</Link>
    </div>
  </div>;
}

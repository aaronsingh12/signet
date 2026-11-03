import { AlertTriangle, ArrowLeft, Bot, Search, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, useApi, type ApiError } from '../lib/api';
import { useCan } from '../lib/auth';
import { Card, Empty, ErrorNote, Modal, PageHeader, Pill } from '../components/ui';

interface Agent { id: string; name: string; handle: string; purpose: string; status: string; enforcement: string }
interface Agents { items: Agent[]; next_cursor: string | null }
interface RemovalPreview { id: string; name: string; handle: string; certificates: number; deployments: number; credentials: number; records: number }

function parsePreview(value: RemovalPreview): RemovalPreview {
  if (!value || typeof value.id !== 'string' || typeof value.name !== 'string' || typeof value.handle !== 'string') throw new TypeError('Agent deletion preview is missing its identity');
  for (const key of ['certificates', 'deployments', 'credentials', 'records'] as const) if (!Number.isSafeInteger(value[key]) || value[key] < 0) throw new TypeError(`Agent deletion preview ${key} must be a nonnegative integer`);
  return value;
}

export function AgentSettings() {
  const can = useCan();
  const [cursor, setCursor] = useState<string | null>(null);
  const { data, error, loading, reload } = useApi<Agents>(can('agents.delete') ? `/agents?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}` : null);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Agent | null>(null);
  const [preview, setPreview] = useState<RemovalPreview | null>(null);
  const [confirmation, setConfirmation] = useState('');
  const [failure, setFailure] = useState<ApiError | { message: string } | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [message, setMessage] = useState('');
  const open = async (agent: Agent): Promise<void> => {
    setSelected(agent); setPreview(null); setConfirmation(''); setFailure(null); setMessage('');
    try {
      const result = parsePreview(await api<RemovalPreview>(`/agents/${agent.id}/removal-preview`));
      if (result.id !== agent.id) throw new TypeError('Deletion preview belongs to a different agent');
      setPreview(result);
    } catch (problem) { setFailure({ message: problem instanceof Error ? problem.message : String(problem) }); }
  };
  const remove = async (): Promise<void> => {
    if (!selected || !preview || confirmation !== selected.handle || deleting) return;
    setDeleting(true); setFailure(null);
    try {
      const result = await api<{ deleted: boolean }>(`/agents/${selected.id}`, { method: 'DELETE', body: { confirm_handle: confirmation } });
      if (result.deleted !== true) throw new TypeError('The server did not confirm permanent agent deletion');
      setMessage(`${selected.name} and its managed data have been permanently removed.`);
      setSelected(null); setPreview(null); setConfirmation('');
      await reload();
    } catch (problem) { setFailure({ message: problem instanceof Error ? problem.message : String(problem) }); }
    finally { setDeleting(false); }
  };
  const agents = data?.items.filter((agent) => [agent.name, agent.handle].some((value) => value.toLowerCase().includes(query.toLowerCase().trim()))) ?? [];
  return <>
    <PageHeader title="Agent settings" subtitle="Permanently remove AI agents and their managed data from Signet. Each agent is managed independently." actions={<Link className="btn-ghost" to="/agents"><ArrowLeft size={14} />Back to AI agents</Link>} />
    {!can('agents.delete') ? <div className="card"><Empty>Only a workspace administrator can permanently remove agents.</Empty></div> : <>
      <div className="mb-6 flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4"><AlertTriangle size={19} className="mt-0.5 shrink-0 text-amber-700" /><div className="text-sm"><strong className="font-semibold text-amber-900">Permanent deletion cannot be undone.</strong><p className="mt-1 text-xs leading-relaxed text-amber-800">Removal stops the agent and deletes its registration, approvals, deployments, credentials and activity data. Shared tools, workspace credentials and other agents are kept.</p></div></div>
      {message && <p role="status" className="mb-5 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">{message}</p>}
      <ErrorNote error={error} />
      <Card pad={false}><div className="flex flex-wrap items-center justify-between gap-3 border-b border-line p-4"><div><h2 className="text-sm font-semibold">Registered AI agents</h2><p className="mt-1 text-xs text-ink-3">Active, paused and stopped agents can all be removed.</p></div><label className="relative"><span className="sr-only">Search agents to remove</span><Search size={15} className="absolute left-3 top-3 text-ink-3" /><input className="input pl-9" data-testid="agent-settings-search" placeholder="Search name or handle…" value={query} onChange={(event) => setQuery(event.target.value)} /></label></div>
        {!data && loading ? <Empty>Loading agents…</Empty> : agents.length ? <ul className="divide-y divide-line">{agents.map((agent) => <li className="flex flex-wrap items-center gap-4 p-5" key={agent.id} data-testid={`agent-settings-row-${agent.id}`}><span className="agent-symbol bg-royal-50 text-royal"><Bot size={21} /></span><div className="min-w-0 flex-1"><Link to={`/agents/${agent.id}`} className="text-sm font-semibold hover:text-royal">{agent.name}</Link><p className="mt-1 break-all text-xs text-ink-3">{agent.handle}</p></div><Pill value={agent.enforcement === 'active' ? agent.status : agent.enforcement} /><button className="btn-ghost border-red-200 text-red-700 hover:bg-red-50" data-testid={`remove-agent-${agent.id}`} aria-label={`Permanently remove ${agent.name}`} onClick={() => void open(agent)}><Trash2 size={14} />Remove agent</button></li>)}</ul> : <Empty>{query ? 'No agents match this search.' : 'There are no agents to remove.'}</Empty>}
        <div className="flex justify-end gap-2 border-t border-line p-4"><button className="btn-ghost" disabled={!cursor || loading} onClick={() => setCursor(null)}>First page</button><button className="btn-ghost" disabled={!data?.next_cursor || loading} onClick={() => setCursor(data!.next_cursor)}>Next page</button></div>
      </Card>
    </>}
    {selected && <Modal title={`Permanently remove ${selected.name}?`} onClose={() => { if (!deleting) setSelected(null); }}><div className="space-y-5"><p className="text-sm leading-relaxed text-ink-2">This stops the agent, invalidates its access and permanently erases its managed data from Signet. It cannot be restored with an undo button.</p>{preview ? <dl className="grid grid-cols-2 gap-3 rounded-xl bg-canvas p-4 text-sm">{[['Approval certificates', preview.certificates], ['Deployments', preview.deployments], ['Deployment credentials', preview.credentials], ['Activity records', preview.records]].map(([label, count]) => <div key={label}><dt className="text-xs text-ink-3">{label}</dt><dd className="mt-1 font-semibold">{count}</dd></div>)}</dl> : !failure && <p className="text-sm text-ink-3" role="status">Checking the agent’s data…</p>}<p className="text-xs leading-relaxed text-ink-3">Anonymous signed hash markers remain to preserve other agents’ audit proofs. Managed evidence copies and generated deployment files are cleaned. Downloaded exports, external backups and data in the hospital application are outside this action.</p><div><label className="label" htmlFor="agent-removal-confirmation">Type <strong>{selected.handle}</strong> to confirm</label><input id="agent-removal-confirmation" data-testid="agent-removal-confirmation" className="input" autoComplete="off" spellCheck={false} disabled={deleting} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></div><ErrorNote error={failure} /><div className="flex justify-end gap-3"><button className="btn-ghost" disabled={deleting} onClick={() => setSelected(null)}>Cancel</button><button className="btn-danger" data-testid="agent-removal-confirm" disabled={!preview || confirmation !== selected.handle || deleting} onClick={() => void remove()}><Trash2 size={14} />{deleting ? 'Stopping & removing…' : 'Permanently remove'}</button></div></div></Modal>}
  </>;
}

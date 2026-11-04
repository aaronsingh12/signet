import { useState } from 'react';
import { ActivityChart } from './AgentCharts';
import { ErrorNote } from './ui';
import { ApiError, api } from '../lib/api';
import type { AgentAnalytics } from '../lib/analytics';
import { useCan } from '../lib/auth';

/** External execution reports are monitoring evidence, never Gateway enforcement decisions. */
export function ProviderActivity({ agents, onRefresh }: { agents: AgentAnalytics[]; onRefresh: () => Promise<void> }) {
  const can = useCan();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const connected = agents.filter((agent) => agent.provider.connection_ids.length > 0);
  if (!connected.length) return null;
  const total = connected.reduce((sum, agent) => sum + agent.provider.executions, 0);
  const succeeded = connected.reduce((sum, agent) => sum + agent.provider.succeeded, 0);
  const failed = connected.reduce((sum, agent) => sum + agent.provider.failed, 0);
  const sync = async (): Promise<void> => {
    setBusy(true); setError(null);
    try {
      for (const id of new Set(connected.flatMap((agent) => agent.provider.connection_ids))) await api(`/connections/${id}/sync`, { method: 'POST' });
      await onRefresh();
    } catch (failure) { setError(failure as ApiError); } finally { setBusy(false); }
  };
  const chart = connected.map((agent) => ({ ...agent, requests: agent.provider.executions, activity: agent.provider.activity.map((bucket) => ({ hour: bucket.hour, requests: bucket.executions, allowed: 0, blocked: 0, review: 0, failed: 0 })) }));
  const recent = connected.flatMap((agent) => agent.provider.recent.map((record) => ({ ...record, agentId: agent.id, name: agent.name }))).sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 20);
  return <section data-testid="provider-activity" className="chart-card my-5" aria-busy={busy}>
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="font-semibold">REST provider activity</h2><p className="mt-1 text-sm text-ink-3">Actual synchronized executions in the last 24 hours. Provider reports are separate from Gateway requests and safety decisions.</p></div>{can('connectors.manage') && <button data-testid="provider-sync" className="btn-ghost" disabled={busy} onClick={() => void sync()}>{busy ? 'Syncing provider activity...' : 'Sync provider activity'}</button>}</div>
    <ErrorNote error={error} />
    <dl className="my-5 grid grid-cols-2 gap-3 sm:grid-cols-4">{[['Provider executions', total], ['Reported success', succeeded], ['Reported failure', failed], ['Other / in progress', total - succeeded - failed]].map(([label, value]) => <div key={label} className="rounded-lg border border-line bg-canvas p-3"><dt className="text-xs text-ink-3">{label}</dt><dd className="mt-1 text-2xl font-semibold">{value}</dd></div>)}</dl>
    <ActivityChart agents={chart} />
    <div className="my-3 space-y-1 text-xs text-ink-3">{connected.map((agent) => <p key={agent.id}>{agent.name}: last successful sync {agent.provider.last_sync_at ? new Date(agent.provider.last_sync_at).toLocaleString() : 'not yet recorded'}; average execution time {agent.provider.avg_duration_ms === null ? 'unavailable' : `${Math.round(agent.provider.avg_duration_ms)} ms`}.</p>)}</div>
    {!recent.length ? <p className="text-sm text-ink-3">No dated executions synchronized in this period. Sync provider activity or check the execution endpoint and response mapping under Connection.</p> : <div className="overflow-x-auto"><table data-testid="provider-executions" className="w-full text-sm"><thead><tr>{['Agent', 'Execution', 'Provider status', 'Event time', 'Duration'].map((label) => <th key={label} className="th">{label}</th>)}</tr></thead><tbody>{recent.map((record) => <tr key={`${record.agentId}/${record.id}`}><td className="td">{record.name}</td><td className="td">{record.id.split('/').at(-1)}</td><td className="td">{record.status ?? 'Unavailable'}</td><td className="td whitespace-nowrap">{new Date(record.timestamp).toLocaleString()}</td><td className="td">{record.duration_ms === null ? 'Unavailable' : `${Math.round(record.duration_ms)} ms`}</td></tr>)}</tbody></table></div>}
    <p className="mt-3 text-xs text-ink-3">Costs and token usage are unavailable here unless explicitly mapped and supported. Provider activity does not establish that Signet intercepted or blocked a call.</p>
  </section>;
}

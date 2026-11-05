import { ArrowRight, Plus, Search } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { AgentCard } from '../components/AgentCharts';
import { Empty, ErrorNote } from '../components/ui';
import { agentState, useAgentAnalytics } from '../lib/analytics';
import { useCan } from '../lib/auth';

const filters = [{ id: 'all', label: 'All agents' }, { id: 'governed', label: 'Protected' }, { id: 'attention', label: 'Needs attention' }];

export function Registry() {
  const { data, error, loading } = useAgentAnalytics();
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const can = useCan();
  const agents = data?.agents ?? [];
  const shown = agents.filter((agent) => {
    const governed = agentState(agent).tone === 'ok';
    const matchesFilter = filter === 'all' || (filter === 'governed' ? governed : !governed);
    return matchesFilter && [agent.name, agent.handle, agent.owner].some((value) => value.toLowerCase().includes(search.trim().toLowerCase()));
  });
  return <>
    <div className="dashboard-heading mb-7 flex flex-wrap items-center justify-between gap-4"><div><h1>Agents</h1><p>Know what each agent does, how it’s performing and whether it needs your attention.</p></div>{can('agents.write') && <Link className="btn-primary" to="/agents/new"><Plus size={15} />Add an agent</Link>}</div>
    <div className="agent-filter-row">{filters.map((item) => <button key={item.id} data-testid={`agent-filter-${item.id}`} aria-pressed={filter === item.id} className={`filter-chip ${filter === item.id ? 'active' : ''}`} onClick={() => setFilter(item.id)}>{item.label} <span className="ml-1 opacity-60">{agents.filter((agent) => item.id === 'all' || (item.id === 'governed' ? agentState(agent).tone === 'ok' : agentState(agent).tone !== 'ok')).length}</span></button>)}<label className="agent-search"><span className="sr-only">Search AI agents</span><Search size={15} /><input data-testid="agent-search" className="input" placeholder="Search agents or owners…" value={search} onChange={(event) => setSearch(event.target.value)} /></label></div>
    <ErrorNote error={error} />
    {!data && loading ? <div className="dashboard-loading" role="status">Loading your AI agents…</div> : data && <>{shown.length ? <div className="agent-grid">{shown.map((agent) => <AgentCard key={agent.id} agent={agent} />)}</div> : <div className="card"><Empty>{agents.length ? 'No agents match these filters. Try another name or select All agents.' : 'Your first agent will appear here after you add it.'}</Empty></div>}<div className="mt-6 flex flex-wrap items-center justify-between gap-3 text-[11px] text-ink-3"><span>Showing {shown.length} of {agents.length} agents · Activity from the last 24 hours</span><Link className="flex items-center gap-1 text-royal" to="/">Back to home <ArrowRight size={13} /></Link></div></>}
  </>;
}

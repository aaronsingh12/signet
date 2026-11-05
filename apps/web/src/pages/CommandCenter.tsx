import { ArrowRight, Check, Plus } from 'lucide-react';
import { Link } from 'react-router-dom';
import { ActivityChart, AgentCard, AgentMetrics, OutcomeChart, UsageComparison } from '../components/AgentCharts';
import { CostQuality } from '../components/CostQuality';
import { ProviderActivity } from '../components/ProviderActivity';
import { ErrorNote, TierChip } from '../components/ui';
import { useApi } from '../lib/api';
import { agentState, useAgentAnalytics } from '../lib/analytics';
import { useCan, useMe } from '../lib/auth';

// Home: what needs a person first, then how each agent is doing. A new workspace gets its first steps.

export function CommandCenter() {
  const me = useMe();
  const can = useCan();
  const { data, error, loading, reload } = useAgentAnalytics();
  const { data: waiting } = useApi<{ items: any[] }>('/approvals?mine=1');
  const agents = data?.agents ?? [];
  const firstName = me.principal.name.split(' ')[0];
  if (!data && loading) return <div className="dashboard-loading" role="status">Loading your workspace…</div>;
  if (data && !agents.length) return <Welcome firstName={firstName!} canAdd={can('agents.write')} />;
  const decisions = waiting?.items ?? [];
  const attention = agents.filter((a) => ['bad', 'warn'].includes(agentState(a).tone));
  const total = decisions.length + attention.length;
  return <>
    <div className="dashboard-heading mb-6 flex flex-wrap items-center justify-between gap-4"><div><h1>Hello, {firstName}</h1><p data-testid="home-summary">{total ? `${total} ${total === 1 ? 'thing needs' : 'things need'} you.` : 'Nothing needs you right now.'}</p></div>{can('agents.write') && <Link to="/agents/new" className="btn-primary"><Plus size={15} />Add an agent</Link>}</div>
    <ErrorNote error={error} />
    {data && <>
      {total > 0 && <section className="card mb-6 p-5">
        <div className="flex items-center justify-between"><h2 className="font-semibold">Needs you</h2><Link className="text-sm font-medium text-royal" to="/needs-you">See all</Link></div>
        <ul className="mt-2 divide-y divide-line">
          {decisions.slice(0, 4).map((r) => <li key={r.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div className="min-w-0"><b className="text-sm">{r.title}</b>{r.tier && <span className="ml-2"><TierChip tier={r.tier} /></span>}<div className="line-clamp-1 text-xs text-ink-3">{r.summary}</div></div><Link className="btn-primary" to={`/needs-you?id=${r.id}`}>Review</Link></li>)}
          {attention.slice(0, 3).map((a) => <li key={a.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div><b className="text-sm">{a.name}: {agentState(a).label}</b><div className="text-xs text-ink-3">{agentState(a).description}</div></div><Link className="btn-ghost" to={`/agents/${a.id}`}>See why</Link></li>)}
        </ul>
      </section>}
      <AgentMetrics agents={agents} />
      <div className="section-heading"><div><h2>Your agents</h2></div><Link to="/agents">Manage agents <ArrowRight size={14} /></Link></div>
      <div className="agent-grid">{agents.map((agent) => <AgentCard key={agent.id} agent={agent} />)}</div>
      <details className="mt-7"><summary className="cursor-pointer text-sm font-medium text-ink-2">Charts, usage and cost</summary>
        <ProviderActivity agents={agents} onRefresh={reload} />
        <div className="chart-layout"><section className="chart-card"><div className="chart-heading"><div><h2>Activity</h2><p>Requests per hour, last 24 hours, in your local time</p></div></div><ActivityChart agents={agents} /></section><section className="chart-card"><div className="chart-heading"><div><h2>Outcomes</h2><p>Requests checked by Signet</p></div></div><OutcomeChart agents={agents} /></section></div>
        <section className="chart-card mt-5"><div className="chart-heading"><div><h2>Requests by agent</h2></div></div><UsageComparison agents={agents} /></section>
        <CostQuality />
      </details>
    </>}
  </>;
}

function Welcome({ firstName, canAdd }: { firstName: string; canAdd: boolean }) {
  return (
    <div className="mx-auto mt-6 max-w-3xl">
      <h1 className="flow-title">Welcome, {firstName}. Let's get your first AI agent under control.</h1>
      <p className="flow-lead">Signet makes sure your AI only does what you approved, and keeps a record of everything it does.</p>
      <ol className="card task-list mt-7 p-5" data-testid="welcome-steps">
        <li className="done"><i><Check size={13} /></i><div><b>Your workspace is ready</b></div></li>
        <li><i>2</i><div className="flex flex-1 flex-wrap items-center justify-between gap-3"><div><b>Add your first agent</b><small>Answer a few plain questions.</small></div>{canAdd && <Link className="btn-primary" to="/agents/new">Add an agent</Link>}</div></li>
        <li><i>3</i><div><b>Connect it and send a test</b><small>Most agents need just two settings changed.</small></div></li>
        <li><i>4</i><div><b>Watch it in shadow mode, then enforce</b><small>See what would be blocked before anything is blocked.</small></div></li>
      </ol>
      <p className="mt-5 text-sm text-ink-2">Not sure what AI your company uses? <Link className="font-semibold text-royal" to="/settings/discovery">Let Signet look for it</Link></p>
    </div>
  );
}

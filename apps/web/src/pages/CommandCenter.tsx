import { ArrowRight, CalendarDays, CheckCheck, Plus, RefreshCw, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ActivityChart, AgentCard, AgentMetrics, OutcomeChart, UsageComparison } from '../components/AgentCharts';
import { Empty, ErrorNote } from '../components/ui';
import { CostQuality } from '../components/CostQuality';
import { agentState, money, useAgentAnalytics } from '../lib/analytics';
import { useCan } from '../lib/auth';

export function CommandCenter() {
  const { data, error, loading, reload } = useAgentAnalytics();
  const [selected, setSelected] = useState('');
  const can = useCan();
  const agents = data?.agents ?? [];
  const shown = selected ? agents.filter((agent) => agent.id === selected) : agents;
  const attention = agents.filter((agent) => agentState(agent).tone !== 'ok');
  return <>
    <div className="flex flex-wrap items-center justify-between gap-5 dashboard-heading"><div><div className="eyebrow">YOUR AI WORKSPACE</div><h1>Your AI, at a glance.</h1><p>See what your AI agents are doing, and how Signet is keeping them in check.</p></div><div className="overview-toolbar"><span className="period-chip"><CalendarDays size={14} />Last 24 hours</span><button className="icon-button" data-testid="dashboard-refresh" aria-label="Refresh dashboard" disabled={loading} onClick={() => void reload()}><RefreshCw size={17} className={loading ? 'animate-spin' : ''} /></button>{can('agents.write') && <Link to="/agents/new" className="btn-primary"><Plus size={15} /> Add AI agent</Link>}</div></div>
    <div className={`safety-banner ${attention.length ? 'attention' : ''}`}><span className="safety-banner-icon"><ShieldCheck size={21} /></span><div><strong>{!data ? 'Getting your workspace ready' : !agents.length ? 'Your AI workspace starts here' : attention.length ? `${attention.length} ${attention.length === 1 ? 'agent needs' : 'agents need'} your attention` : 'Your agents have active governance'}</strong><p>{!data ? 'Loading the latest approvals and request records.' : !agents.length ? 'Add your first agent to start tracking its activity and safety.' : attention.length ? 'Check paused, stopped or unapproved agents. Other agents keep their own safety settings.' : 'Each agent has its own approval. Every request is checked and recorded.'}</p></div><Link to="/agents">Review agents <ArrowRight size={14} /></Link></div>
    <ErrorNote error={error} />
    {!data && loading ? <div className="dashboard-loading" role="status">Loading your AI overview…</div> : data && <>
      <AgentMetrics agents={agents} />
      <div className="section-heading mb-0"><div><h2>What’s happening with your AI?</h2><p>Choose an agent to explore its own activity and request outcomes.</p></div><label className="sr-only" htmlFor="dashboard-agent-filter">Filter charts by agent</label><select id="dashboard-agent-filter" data-testid="dashboard-agent-filter" className="input dashboard-filter" value={selected} onChange={(event) => setSelected(event.target.value)}><option value="">All AI agents</option>{agents.map((agent) => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</select></div>
      <div className="chart-layout"><section className="chart-card"><div className="chart-heading"><div><h2>Agent activity</h2><p>Requests per hour · times shown in your local timezone</p></div><ActivityBadge /></div><ActivityChart agents={shown} /></section><section className="chart-card"><div className="chart-heading"><div><h2>Request outcomes</h2><p>What happened after Signet checked a request</p></div><CheckCheck size={17} className="text-ink-3" /></div><OutcomeChart agents={shown} /><p className="chart-note">A blocked request is an action Signet refused. Service errors are tracked separately.</p></section></div>
      <div className="section-heading"><div><h2>Your AI agents <span className="ml-2 rounded-md bg-white px-2 py-1 text-xs text-ink-3">{agents.length}</span></h2><p>One card for each agent. Independent identity, approval and activity.</p></div><Link to="/agents">Manage agents <ArrowRight size={14} /></Link></div>
      {agents.length ? <div className="agent-grid">{agents.map((agent) => <AgentCard key={agent.id} agent={agent} />)}</div> : <div className="card"><Empty>No AI agents yet. Add an agent to see its status and charts.</Empty></div>}
      <div className="chart-layout"><section className="chart-card"><div className="chart-heading"><div><h2>Requests by agent</h2><p>Compare how much work each agent is handling</p></div></div><UsageComparison agents={shown} /></section><section className="chart-card"><div className="chart-heading"><div><h2>Usage & daily budget</h2><p>Recorded cost compared with each agent’s own limit</p></div></div><div className="mt-6 space-y-5">{shown.map((agent) => <div key={agent.id}><div className="mb-2 flex justify-between gap-3 text-[10px]"><Link to={`/agents/${agent.id}`} className="truncate text-ink-2">{agent.name}</Link><span className="whitespace-nowrap font-medium">{money(agent.cost_usd)} <span className="text-ink-3">/ {agent.daily_budget_usd === null ? 'No active budget' : money(agent.daily_budget_usd)}</span></span></div><div className="comparison-track" role="img" aria-label={`${agent.name}: ${money(agent.cost_usd)} used; ${agent.daily_budget_usd === null ? 'no active budget' : `${money(agent.daily_budget_usd)} daily budget`}`}><div className="comparison-fill" style={{ background: agent.color, width: `${agent.daily_budget_usd ? Math.min(100, agent.cost_usd / agent.daily_budget_usd * 100) : 0}%` }} /></div></div>)}</div><p className="chart-note">Costs use configured model prices. The chart covers a rolling 24 hours; enforced daily limits reset at UTC midnight.</p></section></div>
      <CostQuality />
      <p className="chart-note mt-5">Updated {new Date(data.to).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })} · Refreshes every 30 seconds · Charts include recorded model and tool requests only.</p>
    </>}
  </>;
}

function ActivityBadge() {
  return <span className="agent-status ok"><span className="status-dot ok" />Recorded activity</span>;
}

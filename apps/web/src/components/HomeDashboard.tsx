import { Activity, Bot, Coins, RefreshCw, ShieldCheck, ShieldX, TrendingUp } from 'lucide-react';
import { useState, type CSSProperties } from 'react';
import { Link } from 'react-router-dom';
import { agentState, gatewayCostDisplay, money, type AgentAnalytics } from '../lib/analytics';
import { num } from '../lib/format';
import { Sparkline } from './AgentCharts';
import { HomeOutcomes, HomeTraffic, trafficBuckets } from './HomeTraffic';
import './HomeDashboard.css';

const COLORS = ['#8b5cf6', '#06b6d4', '#10b981', '#f97316', '#ec4899', '#3b82f6'];

/** The home overview uses the validated, automatically refreshed all-time processing records. */
export function HomeDashboard({ agents, from, updatedAt, loading, onRefresh }: { agents: AgentAnalytics[]; from: string; updatedAt: string; loading: boolean; onRefresh: () => Promise<void> }) {
  const [agentId, setAgentId] = useState('');
  const shown = agentId ? agents.filter(agent => agent.id === agentId) : agents;
  const requests = shown.reduce((sum, agent) => sum + agent.processing.requests, 0);
  const completed = shown.reduce((sum, agent) => sum + agent.processing.allowed, 0);
  const blocked = shown.reduce((sum, agent) => sum + agent.processing.blocked, 0);
  const cost = shown.reduce((sum, agent) => sum + agent.cost_usd, 0);
  const costDisplay = gatewayCostDisplay(shown);
  const tokens = shown.reduce((sum, agent) => sum + agent.tokens, 0);
  const governed = shown.filter(agent => agentState(agent).tone === 'ok').length;
  const executions = shown.reduce((sum, agent) => sum + agent.provider.executions, 0);
  const providerHours = [...new Set(shown.flatMap(agent => agent.provider.activity.map(bucket => bucket.hour)))].sort();
  const providerActivity = providerHours.map(hour => shown.reduce((sum, agent) => sum + (agent.provider.activity.find(bucket => bucket.hour === hour)?.executions ?? 0), 0));
  const gatewayActivity = trafficBuckets(shown);
  const metrics = [
    { label: 'Governed agents', value: num(governed), detail: `${shown.length} registered · active approvals`, Icon: ShieldCheck, tone: 'emerald' },
    { label: 'Processed events', value: num(requests), detail: 'Gateway calls and safety checks · all time', Icon: Activity, tone: 'violet' },
    { label: 'Blocked events', value: num(blocked), detail: 'Gateway and safety blocks, counted once · all time', Icon: ShieldX, tone: 'orange' },
    { label: 'Gateway cost', value: costDisplay.label, detail: 'Recorded token-based cost · all time · USD', Icon: Coins, tone: 'blue' },
  ];
  const ranked = [...shown].sort((a, b) => b.requests - a.requests);
  const maximum = Math.max(1, ...shown.map(agent => agent.requests));
  const costMaximum = Math.max(0.000001, ...shown.map(agent => agent.cost_usd));
  return <div className="home-dashboard" data-testid="home-dashboard">
    <div className="home-dashboard-toolbar"><div><span className="home-live-dot" /><span>All-time overview</span><small>Updates every 30s · {new Date(updatedAt).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</small></div><div><select className="input" aria-label="Dashboard agent" data-testid="home-agent-filter" value={agentId} onChange={event => setAgentId(event.target.value)}><option value="">All agents</option>{agents.map(agent => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</select><button className="btn-ghost" disabled={loading} data-testid="home-refresh" onClick={() => void onRefresh()}><RefreshCw size={15} className={loading ? 'animate-spin' : ''} />{loading ? 'Updating…' : 'Refresh'}</button></div></div>
    <div className="home-kpis">{metrics.map(({ label, value, detail, Icon, tone }) => <article className={`home-kpi home-kpi-${tone}`} key={label} data-testid={`home-kpi-${tone}`}><div><span>{label}</span><Icon size={21} /></div><strong>{value}</strong><p>{detail}</p><span className="home-kpi-orbit" aria-hidden="true" /></article>)}</div>
    <div className="home-primary-charts"><HomeTraffic agents={shown} from={from} to={updatedAt} /><HomeOutcomes agents={shown} /></div>
    <div className="home-insights">
      <section className="home-insight home-insight-violet" data-testid="home-completion"><div className="home-insight-heading"><TrendingUp size={20} /><span>Processing completion</span></div><strong>{requests ? `${(completed / requests * 100).toFixed(1)}%` : '—'}</strong><p>{requests ? `${num(completed)} completed out of ${num(requests)} processed events` : 'No processing recorded yet'}</p><div className="home-insight-chart"><Sparkline values={gatewayActivity.map(bucket => bucket.allowed)} color="#a78bfa" label="Completed processing events per hour, all time" /></div><footer>Completed processing events per hour · all time</footer></section>
      <section className="home-insight home-insight-cyan" data-testid="home-provider-executions"><div className="home-insight-heading"><Bot size={20} /><span>Provider executions</span></div><strong>{num(executions)}</strong><p>Synced external activity · separate from gateway calls</p><div className="home-insight-chart"><Sparkline values={providerActivity} color="#22d3ee" label="Synchronized provider executions per hour, all time" /></div><footer>{shown.filter(agent => agent.provider.connection_ids.length > 0).length} agents with REST provider connections</footer></section>
      <section className="chart-card home-usage" data-testid="home-agent-usage"><div className="chart-heading"><div><span className="home-eyebrow">WORKLOAD DISTRIBUTION</span><h2>Gateway usage by agent</h2><p>All time · {num(tokens)} recorded tokens</p></div></div><div className="home-usage-bars">{ranked.map((agent, index) => <div className="home-usage-row" key={agent.id}><div><Link to={`/agents/${agent.id}`}>{agent.name}</Link><b>{num(agent.requests)}</b></div><div className="home-bar-track" role="img" aria-label={`${agent.name}: ${agent.requests} gateway requests`}><div style={{ width: `${agent.requests / maximum * 100}%`, '--home-bar-color': COLORS[index % COLORS.length] } as CSSProperties} /></div></div>)}</div>{!ranked.length && <p className="home-card-note">No agents match the selected filter.</p>}</section>
    </div>
    <section className="chart-card home-spend" data-testid="home-gateway-spend"><div className="chart-heading"><div><span className="home-eyebrow">SPEND OVERVIEW</span><h2>Gateway cost by agent</h2><p>Recorded costs in USD · all time</p></div><strong title={costDisplay.detail}>{costDisplay.label}</strong></div><div className="home-spend-grid">{shown.map((agent, index) => <div className="home-spend-item" key={agent.id}><div><span><i className="legend-dot" style={{ background: COLORS[index % COLORS.length] }} />{agent.name}</span><b title={gatewayCostDisplay([agent]).detail}>{gatewayCostDisplay([agent]).label}</b></div><div className="home-bar-track" role="img" aria-label={`${agent.name}: ${money(agent.cost_usd)} gateway cost`}><div style={{ width: `${agent.cost_usd / costMaximum * 100}%`, '--home-bar-color': COLORS[index % COLORS.length] } as CSSProperties} /></div><small>{num(agent.tokens)} tokens · daily budget {agent.daily_budget_usd === null ? 'not set' : money(agent.daily_budget_usd)}</small></div>)}</div>{!costDisplay.complete && <p className="home-card-note">{costDisplay.detail} <Link className="text-royal hover:underline" to="/settings/gateway-cost">Configure model rates</Link></p>}{cost === 0 && costDisplay.complete && <p className="home-card-note">No gateway cost recorded in this period. External provider costs are not included.</p>}</section>
  </div>;
}

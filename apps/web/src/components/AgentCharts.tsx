import { Activity, ArrowRight, Bot, CalendarDays, FileHeart, FlaskConical, HeartHandshake, ShieldCheck, ShieldX } from 'lucide-react';
import { useId, type CSSProperties } from 'react';
import { Link } from 'react-router-dom';
import { agentState, money, type AgentAnalytics } from '../lib/analytics';
import { ago, num } from '../lib/format';

export function AgentStatus({ agent }: { agent: AgentAnalytics }) {
  const state = agentState(agent);
  return <span className={`agent-status ${state.tone}`} title={state.description}><span className={`status-dot ${state.tone}`} />{state.label}</span>;
}

function AgentSymbol({ handle, color }: { handle: string; color: string }) {
  const Icon = handle.includes('appointment') ? CalendarDays : handle.includes('records') ? FileHeart : handle.includes('lab-agent') ? FlaskConical : handle.includes('care-agent') ? HeartHandshake : Bot;
  return <span className="agent-symbol" style={{ color, background: `${color}13` }}><Icon size={20} strokeWidth={1.7} /></span>;
}

export function Sparkline({ values, color, label }: { values: number[]; color: string; label: string }) {
  const max = Math.max(1, ...values);
  const points = values.map((value, index) => `${(index / Math.max(1, values.length - 1)) * 240},${38 - (value / max) * 32}`).join(' ');
  return <svg width="100%" height="45" viewBox="0 0 240 45" preserveAspectRatio="none" role="img" aria-label={label}><polygon points={`0,45 ${points} 240,45`} fill={color} opacity=".06" /><polyline points={points} fill="none" stroke={color} strokeWidth="1.8" strokeLinejoin="round" vectorEffect="non-scaling-stroke" /></svg>;
}

export function AgentCard({ agent }: { agent: AgentAnalytics }) {
  const color = agent.color;
  return <article className="agent-card" style={{ '--agent-color': color } as CSSProperties} data-testid={`agent-card-${agent.id}`}>
    <div className="agent-card-top"><AgentSymbol handle={agent.handle} color={color} /><AgentStatus agent={agent} /></div>
    <h3><Link to={`/agents/${agent.id}`}>{agent.name}</Link></h3>
    <p className="agent-purpose" title={agent.purpose}>{agent.purpose}</p>
    <div className="agent-stats"><div><span>{agent.provider.connection_ids.length ? 'Provider executions' : 'Gateway requests'}</span><strong>{num(agent.provider.connection_ids.length ? agent.provider.executions : agent.requests)}</strong></div><div><span>Gateway blocked</span><strong className={agent.blocked ? 'text-bad' : ''}>{num(agent.blocked)}</strong></div><div><span>Gateway cost</span><strong>{money(agent.cost_usd)}</strong></div></div>
    <div className="agent-mini-chart"><Sparkline values={agent.provider.connection_ids.length ? agent.provider.activity.map((bucket) => bucket.executions) : agent.activity.map((bucket) => bucket.requests)} color={color} label={`${agent.name}: ${agent.provider.connection_ids.length ? agent.provider.executions : agent.requests} ${agent.provider.connection_ids.length ? 'provider executions' : 'Gateway requests'} in the last 24 hours`} /></div>
    <div className="agent-card-footer"><span>{agent.provider.connection_ids.length ? agent.provider.last_sync_at ? `Provider synced ${ago(agent.provider.last_sync_at)}` : 'Provider sync pending' : agent.last_activity ? `Last request ${ago(agent.last_activity)}` : 'No activity in the last 24h'}</span><Link to={`/agents/${agent.id}`} aria-label={`View ${agent.name} details`}>View agent <ArrowRight size={12} /></Link></div>
  </article>;
}

export function ActivityChart({ agents }: { agents: AgentAnalytics[] }) {
  const id = useId().replace(/:/g, '');
  const maximum = Math.max(1, ...agents.flatMap((agent) => agent.activity.map((bucket) => bucket.requests)));
  const ceiling = maximum <= 4 ? maximum : Math.ceil(maximum / 4) * 4;
  const hours = agents[0]?.activity ?? [];
  const x = (index: number): number => 35 + (index / Math.max(1, hours.length - 1)) * 625;
  const y = (value: number): number => 170 - (value / ceiling) * 145;
  const total = agents.reduce((sum, agent) => sum + agent.requests, 0);
  const tickIndexes = [0, 6, 12, 18, 24].filter((index) => index < hours.length);
  return <>
    <div className="chart-legend">{agents.map((agent) => <span key={agent.id}><i className="legend-dot" style={{ background: agent.color }} />{agent.name}</span>)}</div>
    <svg className="activity-chart" viewBox="0 0 680 205" role="img" aria-label={`Hourly requests by AI agent. ${total} requests in the last 24 hours.`}>
      <defs>{agents.map((agent, index) => <linearGradient key={agent.id} id={`${id}-${index}`} x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor={agent.color} stopOpacity=".12" /><stop offset="100%" stopColor={agent.color} stopOpacity="0" /></linearGradient>)}</defs>
      {[0, 1, 2, 3, 4].map((step) => <g key={step}><line x1="35" x2="660" y1={25 + step * 36.25} y2={25 + step * 36.25} stroke="#eef2f4" strokeDasharray="4 5" /><text x="24" y={29 + step * 36.25} textAnchor="end" className="chart-ticks">{Number((ceiling * (4 - step) / 4).toFixed(1))}</text></g>)}
      {agents.map((agent, index) => {
        const points = agent.activity.map((bucket, bucketIndex) => `${x(bucketIndex)},${y(bucket.requests)}`).join(' ');
        return <g key={agent.id}><polygon points={`35,170 ${points} 660,170`} fill={`url(#${id}-${index})`} /><polyline points={points} fill="none" stroke={agent.color} strokeWidth="2" strokeLinejoin="round" />{agent.activity.map((bucket, bucketIndex) => <circle key={bucket.hour} cx={x(bucketIndex)} cy={y(bucket.requests)} r={bucket.requests ? 3 : 0} fill={agent.color}><title>{agent.name} · {new Date(bucket.hour).toLocaleString()} · {bucket.requests} requests</title></circle>)}</g>;
      })}
      {tickIndexes.map((index) => <text key={index} x={x(index)} y="197" textAnchor={index === 0 ? 'start' : index === 24 ? 'end' : 'middle'} className="chart-ticks">{new Date(hours[index].hour).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</text>)}
      {total === 0 && <text x="340" y="98" textAnchor="middle" fill="#73858e" fontSize="12">No activity in the last 24 hours</text>}
    </svg>
    <details className="chart-note"><summary className="cursor-pointer">View chart data</summary><div className="overflow-x-auto"><table className="mt-2 w-full"><thead><tr><th className="th">Agent</th><th className="th">Requests</th><th className="th">Blocked</th><th className="th">Review</th><th className="th">Failed</th></tr></thead><tbody>{agents.map((agent) => <tr key={agent.id}><td className="td">{agent.name}</td><td className="td">{agent.requests}</td><td className="td">{agent.blocked}</td><td className="td">{agent.review}</td><td className="td">{agent.failed}</td></tr>)}</tbody></table></div></details>
  </>;
}

export function OutcomeChart({ agents }: { agents: AgentAnalytics[] }) {
  const categories = [
    { key: 'allowed', label: 'Completed', color: '#17877d' },
    { key: 'blocked', label: 'Blocked', color: '#ce6c68' },
    { key: 'review', label: 'Needs review', color: '#d6a24f' },
    { key: 'failed', label: 'Service errors', color: '#a4afba' },
  ] as const;
  const values = categories.map((category) => ({ ...category, value: agents.reduce((sum, agent) => sum + agent[category.key], 0) }));
  const total = values.reduce((sum, category) => sum + category.value, 0);
  const stops = values.map((category, index) => {
    const start = values.slice(0, index).reduce((sum, item) => sum + item.value, 0);
    return `${category.color} ${total ? start / total * 100 : 0}% ${total ? (start + category.value) / total * 100 : 0}%`;
  });
  return <div className="donut-layout"><div className="donut" role="img" aria-label={total ? values.map((category) => `${category.value} ${category.label.toLowerCase()}`).join(', ') : 'No requests in the last 24 hours'} style={{ background: total ? `conic-gradient(${stops.join(',')})` : '#edf1f3' }}><div className="donut-center"><strong>{num(total)}</strong><span>Total requests</span></div></div><div className="donut-key">{values.map((category) => <div key={category.key}><i className="legend-dot" style={{ background: category.color }} /><span>{category.label}</span><strong>{num(category.value)}</strong></div>)}</div></div>;
}

export function UsageComparison({ agents }: { agents: AgentAnalytics[] }) {
  const maximum = Math.max(1, ...agents.map((agent) => agent.requests));
  return <div>{agents.map((agent) => <div className="comparison-row" key={agent.id}><Link to={`/agents/${agent.id}`} title={agent.name}>{agent.name}</Link><div className="comparison-track" role="img" aria-label={`${agent.name}: ${agent.requests} requests`}><div className="comparison-fill" style={{ width: `${agent.requests / maximum * 100}%`, background: agent.color }} /></div><strong className="text-right font-medium">{num(agent.requests)}</strong></div>)}{agents.length === 0 && <p className="py-8 text-center text-xs text-ink-3">Add an AI agent to see its activity here.</p>}</div>;
}

export function AgentMetrics({ agents }: { agents: AgentAnalytics[] }) {
  const requests = agents.reduce((sum, agent) => sum + agent.requests, 0);
  const blocked = agents.reduce((sum, agent) => sum + agent.blocked, 0);
  const governed = agents.filter((agent) => agentState(agent).tone === 'ok').length;
  const cost = agents.reduce((sum, agent) => sum + agent.cost_usd, 0);
  const metrics = [
    { label: 'Protected agents', value: `${governed}`, description: `${agents.length} registered · active approvals`, icon: ShieldCheck, color: '#17877d' },
    { label: 'Gateway requests', value: num(requests), description: 'Requests routed through Signet / last 24h', icon: Activity, color: '#8170d4' },
    { label: 'Blocked requests', value: num(blocked), description: requests ? `${(blocked / requests * 100).toFixed(1)}% of requests stopped by safety checks` : 'No Gateway requests recorded yet', icon: ShieldX, color: '#c68a32' },
    { label: 'Gateway cost', value: money(cost), description: 'Recorded usage · last 24 hours · USD', icon: Bot, color: '#4b8ecb' },
  ];
  return <div className="metric-grid">{metrics.map(({ label, value, description, icon: Icon, color }) => <div className="metric-card" style={{ '--metric-color': color } as CSSProperties} key={label}><div className="metric-top"><span>{label}</span><span className="metric-icon" style={{ color, background: `${color}12` }}><Icon size={17} strokeWidth={1.7} /></span></div><div className="metric-number">{value}</div><div className="metric-description">{description}</div></div>)}</div>;
}

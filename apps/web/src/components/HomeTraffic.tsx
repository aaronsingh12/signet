import { useEffect, useId, useState } from 'react';
import { parseAgentAnalytics, type AgentAnalyticsResponse } from '../../../../packages/core/src/analytics';
import type { ActivityBucket, AgentAnalytics } from '../lib/analytics';
import { num } from '../lib/format';
import { useApi } from '../lib/api';
import { ErrorNote } from './ui';

/** Align hourly gateway records by timestamp before combining agents. */
export function trafficBuckets(agents: AgentAnalytics[]): ActivityBucket[] {
  const hours = [...new Set(agents.flatMap(agent => agent.processing.activity.map(bucket => bucket.hour)))].sort();
  return hours.map(hour => agents.reduce<ActivityBucket>((total, agent) => {
    const bucket = agent.processing.activity.find(item => item.hour === hour);
    return { hour, requests: total.requests + (bucket?.requests ?? 0), allowed: total.allowed + (bucket?.allowed ?? 0), blocked: total.blocked + (bucket?.blocked ?? 0), review: total.review + (bucket?.review ?? 0), failed: total.failed + (bucket?.failed ?? 0) };
  }, { hour, requests: 0, allowed: 0, blocked: 0, review: 0, failed: 0 }));
}

const SERIES = [
  { key: 'requests', label: 'Processed events', color: '#8b5cf6' },
  { key: 'allowed', label: 'Completed', color: '#06b6d4' },
  { key: 'blocked', label: 'Blocked', color: '#f97316' },
] as const;

export function HomeTraffic({ agents, from, to }: { agents: AgentAnalytics[]; from: string; to: string }) {
  const id = useId().replaceAll(':', '');
  const [interval, setInterval] = useState(1);
  const [range, setRange] = useState<'all' | 'today'>('all');
  const now = new Date();
  const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
  const { data: todayData, error: todayError, loading: todayLoading, reload: reloadToday } = useApi<AgentAnalyticsResponse>(range === 'today' ? `/stats/agents/today?start=${encodeURIComponent(midnight)}` : null, []);
  useEffect(() => {
    if (range !== 'today') return;
    const timer = window.setInterval(() => void reloadToday(), 30_000);
    return () => window.clearInterval(timer);
  }, [range, reloadToday]);
  const today = todayData ? parseAgentAnalytics(todayData) : null;
  const selectedIds = new Set(agents.map(agent => agent.id));
  const shown: AgentAnalytics[] = range === 'today' ? (today?.agents ?? []).filter(agent => selectedIds.has(agent.id)).map(agent => ({ ...agent, color: agents.find(item => item.id === agent.id)!.color })) : agents;
  const period = range === 'today' ? 'Today' : 'All time';
  const [hidden, setHidden] = useState<string[]>([]);
  const [active, setActive] = useState<number | null>(null);
  const hourly = trafficBuckets(shown);
  const baseInterval = Math.max(1, Math.ceil(hourly.length / 48));
  const bucketSize = range === 'today' ? 1 : baseInterval * interval;
  const elapsedHours = Math.max(1, (Date.parse(range === 'today' ? today?.to ?? midnight : to) - Date.parse(range === 'today' ? midnight : from)) / 3_600_000);
  const buckets = Array.from({ length: Math.ceil(hourly.length / bucketSize) }, (_, index) => {
    const group = hourly.slice(index * bucketSize, (index + 1) * bucketSize);
    return group.reduce<ActivityBucket>((total, bucket) => ({ hour: total.hour, requests: total.requests + bucket.requests, allowed: total.allowed + bucket.allowed, blocked: total.blocked + bucket.blocked, review: total.review + bucket.review, failed: total.failed + bucket.failed }), { hour: group[0]!.hour, requests: 0, allowed: 0, blocked: 0, review: 0, failed: 0 });
  });
  const visible = SERIES.filter(series => !hidden.includes(series.key));
  const maximum = Math.max(1, ...buckets.flatMap(bucket => visible.map(series => bucket[series.key])));
  const ceiling = maximum <= 4 ? maximum : Math.ceil(maximum / 4) * 4;
  const total = buckets.reduce((sum, bucket) => sum + bucket.requests, 0);
  const width = 616 / Math.max(1, buckets.length);
  const x = (index: number): number => 46 + (index + 0.5) * width;
  const y = (value: number): number => 224 - value / ceiling * 176;
  const focused = active === null ? null : buckets[active];
  return <section className="chart-card home-traffic" data-testid="home-traffic">
    <div className="chart-heading"><div><span className="home-eyebrow">ACTIVITY OVERVIEW</span><h2>Processing activity</h2><p>Gateway calls and safety checks · {period}{range === 'today' ? ' (local time)' : ''}</p></div><select className="input home-period" aria-label="Traffic period and bucket size" data-testid="home-traffic-grouping" value={range === 'today' ? 'today' : String(interval)} onChange={event => { if (event.target.value === 'today') setRange('today'); else { setRange('all'); setInterval(Number(event.target.value)); } setActive(null); }}><option value="today">Today</option><option value="1">All time · {baseInterval}-hour buckets</option><option value="3">All time · {baseInterval * 3}-hour buckets</option><option value="6">All time · {baseInterval * 6}-hour buckets</option></select></div>
    <ErrorNote error={range === 'today' ? todayError : null} />
    <div className="home-chart-totals"><div><strong>{range === 'today' && (todayLoading || todayError) ? '—' : num(total)}</strong><span>Total processed</span></div><div><strong>{hourly.length && !(range === 'today' && (todayLoading || todayError)) ? (total / elapsedHours).toLocaleString(undefined, { maximumFractionDigits: 1 }) : '—'}</strong><span>Average / hour</span></div></div>
    <div className="home-plot">
      <svg viewBox="0 0 690 266" role="img" aria-label={`Processing activity, ${period}: ${total} events in ${bucketSize}-hour buckets. Focus a time bucket for details.`}>
        <defs><linearGradient id={`${id}-bars`} x1="0" x2="0" y1="0" y2="1"><stop stopColor="#8b5cf6" /><stop offset="100%" stopColor="#6366f1" stopOpacity=".55" /></linearGradient><linearGradient id={`${id}-area`} x1="0" x2="0" y1="0" y2="1"><stop stopColor="#06b6d4" stopOpacity=".22" /><stop offset="100%" stopColor="#06b6d4" stopOpacity="0" /></linearGradient></defs>
        {[0, 1, 2, 3, 4].map(tick => <g key={tick}><line className="home-gridline" x1="46" x2="662" y1={y(ceiling * tick / 4)} y2={y(ceiling * tick / 4)} /><text className="chart-ticks" x="35" y={y(ceiling * tick / 4) + 4} textAnchor="end">{Number((ceiling * tick / 4).toFixed(1))}</text></g>)}
        {!hidden.includes('requests') && buckets.map((bucket, index) => <rect key={bucket.hour} x={x(index) - width * .29} y={y(bucket.requests)} width={width * .58} height={224 - y(bucket.requests)} rx="3" fill={`url(#${id}-bars)`} opacity={active === null || active === index ? 1 : .45} />)}
        {!hidden.includes('allowed') && buckets.length > 0 && <polygon points={`${x(0)},224 ${buckets.map((bucket, index) => `${x(index)},${y(bucket.allowed)}`).join(' ')} ${x(buckets.length - 1)},224`} fill={`url(#${id}-area)`} />}
        {visible.filter(series => series.key !== 'requests').map(series => <polyline key={series.key} points={buckets.map((bucket, index) => `${x(index)},${y(bucket[series.key])}`).join(' ')} fill="none" stroke={series.color} strokeWidth="3" strokeLinejoin="round" strokeLinecap="round" />)}
        {buckets.map((bucket, index) => <g key={bucket.hour}>{index % Math.max(1, Math.ceil(buckets.length / 6)) === 0 && <text className="chart-ticks" x={x(index)} y="248" textAnchor="middle">{new Date(bucket.hour).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit' })}</text>}<rect className="home-bucket-focus" x={x(index) - width / 2} y="40" width={width} height="188" fill="transparent" tabIndex={0} role="button" data-testid={`traffic-bucket-${index}`} aria-label={`${new Date(bucket.hour).toLocaleString()}: ${bucket.requests} processed, ${bucket.allowed} completed, ${bucket.blocked} blocked, ${bucket.review} need review, ${bucket.failed} failed`} onMouseEnter={() => setActive(index)} onMouseLeave={() => setActive(null)} onFocus={() => setActive(index)} onBlur={() => setActive(null)} onClick={() => setActive(index)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setActive(index); } }} /></g>)}
        {active !== null && buckets[active] && <line x1={x(active)} x2={x(active)} y1="40" y2="224" stroke="currentColor" opacity=".2" strokeDasharray="4 4" pointerEvents="none" />}
        {total === 0 && <text x="345" y="130" textAnchor="middle" className="home-empty-chart">{range === 'today' && todayLoading ? 'Loading today’s activity…' : range === 'today' && todayError ? 'Today’s activity could not be loaded' : 'No processing recorded in this period'}</text>}
      </svg>
      <div className="home-chart-readout" aria-live="polite">{focused ? <><b>{new Date(focused.hour).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</b><span>{num(focused.requests)} processed</span><span>{num(focused.allowed)} completed</span><span>{num(focused.blocked)} blocked</span><span>{num(focused.review)} review</span><span>{num(focused.failed)} errors</span></> : 'Hover or focus a time bucket to inspect activity.'}</div>
    </div>
    <div className="home-chart-legend">{SERIES.map(series => <button key={series.key} data-testid={`traffic-toggle-${series.key}`} aria-pressed={!hidden.includes(series.key)} onClick={() => setHidden(current => current.includes(series.key) ? current.filter(key => key !== series.key) : [...current, series.key])}><i style={{ background: series.color }} />{series.label}</button>)}</div>
  </section>;
}

const OUTCOMES = [
  { key: 'allowed', label: 'Completed', color: '#10b981' },
  { key: 'blocked', label: 'Blocked', color: '#f97316' },
  { key: 'review', label: 'Needs review', color: '#8b5cf6' },
  { key: 'failed', label: 'Service errors', color: '#06b6d4' },
] as const;

export function HomeOutcomes({ agents }: { agents: AgentAnalytics[] }) {
  const [active, setActive] = useState<string | null>(null);
  const values = OUTCOMES.map(outcome => ({ ...outcome, value: agents.reduce((sum, agent) => sum + agent.processing[outcome.key], 0) }));
  const total = values.reduce((sum, value) => sum + value.value, 0);
  const gatewayCalls = agents.reduce((sum, agent) => sum + agent.requests, 0);
  const selected = values.find(value => value.key === active);
  const length = 2 * Math.PI * 86;
  return <section className="chart-card home-outcomes" data-testid="home-outcomes"><div className="chart-heading"><div><span className="home-eyebrow">DECISION BREAKDOWN</span><h2>Processing outcomes</h2><p>Recorded outcomes · all time</p></div></div>
    <div className="home-ring"><svg viewBox="0 0 230 230" role="img" aria-label={total ? values.map(value => `${value.label}: ${value.value}`).join(', ') : 'No processing outcomes yet'}><circle cx="115" cy="115" r="86" fill="none" stroke="currentColor" opacity=".07" strokeWidth="28" />{values.map((value, index) => <circle key={value.key} cx="115" cy="115" r="86" fill="none" stroke={value.color} strokeWidth={active === value.key ? 34 : 28} strokeDasharray={`${total ? value.value / total * length : 0} ${length}`} strokeDashoffset={-values.slice(0, index).reduce((sum, item) => sum + item.value, 0) / (total || 1) * length} transform="rotate(-90 115 115)" opacity={active === null || active === value.key ? 1 : .3} />)}</svg><div className="home-ring-label"><strong>{selected ? total ? `${(selected.value / total * 100).toFixed(1)}%` : '—' : num(total)}</strong><span>{selected?.label ?? 'Processing outcomes'}</span></div></div>
    <div className="home-outcome-key">{values.map(value => <button key={value.key} data-testid={`outcome-${value.key}`} aria-pressed={active === value.key} onClick={() => setActive(current => current === value.key ? null : value.key)}><i style={{ background: value.color }} /><span>{value.label}</span><b>{num(value.value)}</b><small>{total ? `${(value.value / total * 100).toFixed(1)}%` : '—'}</small></button>)}</div>
    <p className="home-card-note">{num(gatewayCalls)} gateway calls + {num(total - gatewayCalls)} safety events. Matched ServiceNow block confirmations are counted once. Provider executions are reported separately.</p>
  </section>;
}

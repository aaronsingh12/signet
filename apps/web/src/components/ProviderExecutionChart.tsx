import { useId, useState } from 'react';
import type { AgentAnalytics } from '../lib/analytics';
import { num } from '../lib/format';

/** Plot provider executions without presenting them as gateway policy decisions. */
export function ProviderExecutionChart({ agents, periodLabel }: { agents: AgentAnalytics[]; periodLabel: string }) {
  const id = useId().replaceAll(':', '');
  const [active, setActive] = useState<number | null>(null);
  const hours = [...new Set(agents.flatMap(agent => agent.provider.activity.map(bucket => bucket.hour)))].sort();
  const interval = Math.max(1, Math.ceil(hours.length / 48));
  const buckets = Array.from({ length: Math.ceil(hours.length / interval) }, (_, index) => {
    const group = hours.slice(index * interval, (index + 1) * interval);
    return { hour: group[0]!, end: group.at(-1)!, executions: agents.reduce((sum, agent) => sum + agent.provider.activity.filter(bucket => group.includes(bucket.hour)).reduce((count, bucket) => count + bucket.executions, 0), 0) };
  });
  const total = agents.reduce((sum, agent) => sum + agent.provider.executions, 0);
  const maximum = Math.max(1, ...buckets.map(bucket => bucket.executions));
  const ceiling = maximum <= 4 ? maximum : Math.ceil(maximum / 4) * 4;
  const width = 616 / Math.max(1, buckets.length);
  const x = (index: number): number => 46 + (index + .5) * width;
  const y = (value: number): number => 210 - value / ceiling * 175;
  const selected = active === null ? null : buckets[active];
  return <div data-testid="provider-execution-chart">
    <p className="mb-3 text-xs text-ink-3">{num(total)} provider executions · {periodLabel} · {interval}-hour buckets</p>
    <svg className="activity-chart" viewBox="0 0 690 252" role="img" aria-label={`${num(total)} synchronized provider executions, ${periodLabel}. Hover or focus a bucket for details.`}>
      <defs><linearGradient id={id} x1="0" x2="0" y1="0" y2="1"><stop stopColor="#06b6d4" /><stop offset="100%" stopColor="#8b5cf6" stopOpacity=".6" /></linearGradient></defs>
      {[0, 1, 2, 3, 4].map(tick => <g key={tick}><line x1="46" x2="662" y1={y(ceiling * tick / 4)} y2={y(ceiling * tick / 4)} stroke="currentColor" opacity=".1" strokeDasharray="4 5" /><text className="chart-ticks" x="35" y={y(ceiling * tick / 4) + 4} textAnchor="end">{Number((ceiling * tick / 4).toFixed(1))}</text></g>)}
      {buckets.map((bucket, index) => <g key={bucket.hour}>
        <rect x={x(index) - width * .3} y={y(bucket.executions)} width={width * .6} height={210 - y(bucket.executions)} rx="3" fill={`url(#${id})`} opacity={active === null || active === index ? 1 : .4} />
        {index % Math.max(1, Math.ceil(buckets.length / 5)) === 0 && <text className="chart-ticks" x={x(index)} y="236" textAnchor="middle">{new Date(bucket.hour).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit' })}</text>}
        <rect x={x(index) - width / 2} y="30" width={width} height="185" fill="transparent" className="home-bucket-focus" tabIndex={0} role="button" data-testid={`provider-bucket-${index}`} aria-label={`${new Date(bucket.hour).toLocaleString()}: ${bucket.executions} provider executions`} onMouseEnter={() => setActive(index)} onMouseLeave={() => setActive(null)} onFocus={() => setActive(index)} onBlur={() => setActive(null)} onClick={() => setActive(index)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setActive(index); } }} />
      </g>)}
      {total === 0 && <text className="chart-ticks" x="345" y="110" textAnchor="middle">No dated provider executions recorded in this period</text>}
    </svg>
    <p className="min-h-8 text-xs text-ink-3" aria-live="polite">{selected ? `${new Date(selected.hour).toLocaleString()} – ${new Date(Date.parse(selected.end) + 3600000).toLocaleString()}: ${num(selected.executions)} executions` : 'Hover or focus a bucket to inspect provider activity.'}</p>
    <details className="chart-note"><summary className="cursor-pointer" data-testid="provider-chart-data">View provider chart data</summary><div className="overflow-x-auto"><table className="mt-2 w-full"><thead><tr>{['Agent', 'Executions', 'Succeeded', 'Failed', 'Other / in progress'].map(label => <th className="th" key={label}>{label}</th>)}</tr></thead><tbody>{agents.map(agent => <tr key={agent.id}><td className="td">{agent.name}</td><td className="td">{num(agent.provider.executions)}</td><td className="td">{num(agent.provider.succeeded)}</td><td className="td">{num(agent.provider.failed)}</td><td className="td">{num(agent.provider.other)}</td></tr>)}</tbody></table></div></details>
  </div>;
}

import { Link } from 'react-router-dom';
import { Card, Empty, LEVEL_LABEL, PageHeader, Pill, Stat, TierChip } from '../components/ui';
import { useApi } from '../lib/api';
import { useMe } from '../lib/auth';
import { ago, daysLeft, num } from '../lib/format';

const TIERS = [
  ['T1', 'Critical'],
  ['T2', 'High'],
  ['T3', 'Moderate'],
  ['T4', 'Low'],
] as const;

export function CommandCenter() {
  const me = useMe();
  const { data: s } = useApi<any>('/stats/command-center');
  const { data: ev } = useApi<any>('/enforcement-events?limit=6');
  const byTier = (tier: string) => (s?.agents_by_tier_status ?? []).filter((r: any) => r.tier === tier);
  const count = (tier: string, status?: string) => byTier(tier).filter((r: any) => !status || r.status === status).reduce((a: number, r: any) => a + r.n, 0);
  const total = (s?.agents_by_tier_status ?? []).reduce((a: number, r: any) => a + r.n, 0);
  const dec = Object.fromEntries((s?.decisions_60m ?? []).map((d: any) => [d.d, d.n])) as Record<string, number>;
  const decTotal = Object.values(dec).reduce((a, b) => a + b, 0) || 1;
  const pct = (k: string[]) => `${((k.reduce((a, x) => a + (dec[x] ?? 0), 0) / decTotal) * 100).toFixed(1)}%`;
  const hour = new Date().getHours();
  return (
    <>
      <PageHeader
        title="Command Center"
        subtitle={`Good ${hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening'}, ${me.principal.name.split(' ')[0]}. Every agent, every decision, last 24 hours.`}
        actions={
          <Link className="btn-primary" to="/agents/new">
            Propose agent
          </Link>
        }
      />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Governed agents" value={num(total)} hint={`${count('T1') + count('T2')} at T1/T2`} />
        <Stat label="Transactions · 24 h" value={num(s?.transactions_24h)} hint="model and tool calls" />
        <Stat label="Blocks · 24 h" value={num(s?.blocks_24h)} hint={s?.transactions_24h ? `${((s.blocks_24h / s.transactions_24h) * 100).toFixed(1)}% of requests` : undefined} />
        <Stat label="Kills · 24 h" value={num(s?.kills_24h)} hint={s?.max_kill_propagation_ms ? `max propagation ${(s.max_kill_propagation_ms / 1000).toFixed(2)} s` : 'none'} tone={s?.kills_24h ? 'bad' : undefined} />
        <Stat label="Keyless agents" value={s ? '100%' : '—'} hint={`${s?.keyless?.unmanaged_keys_open ?? 0} unmanaged keys open`} tone={s?.keyless?.unmanaged_keys_open ? 'warn' : 'ok'} />
        <Stat label="Gateway p95 · 24 h" value={s?.gateway_p95_ms_24h !== null && s?.gateway_p95_ms_24h !== undefined ? `${s.gateway_p95_ms_24h} ms` : '—'} hint="budget 50 ms (BP 2)" tone={s?.gateway_p95_ms_24h > 50 ? 'bad' : 'ok'} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Card title="Agents by tier and seal status" action={<Link className="text-xs text-royal hover:underline" to="/agents">Open registry</Link>}>
          <div className="space-y-2">
            {TIERS.map(([t, label]) => {
              const n = count(t);
              const sealed = count(t, 'sealed');
              const bad = count(t, 'quarantined') + count(t, 'killed');
              return (
                <div key={t} className="flex items-center gap-3 text-sm">
                  <TierChip tier={t} />
                  <span className="w-20 text-ink-2">{label}</span>
                  <div className="flex h-2.5 flex-1 overflow-hidden rounded-full bg-slate-100">
                    <div className="bg-ok" style={{ width: `${n ? (sealed / n) * 100 : 0}%` }} />
                    <div className="bg-slate-300" style={{ width: `${n ? ((n - sealed - bad) / n) * 100 : 0}%` }} />
                    <div className="bg-bad" style={{ width: `${n ? (bad / n) * 100 : 0}%` }} />
                  </div>
                  <span className="w-8 text-right font-semibold">{n}</span>
                </div>
              );
            })}
          </div>
          <div className="mt-3 flex gap-4 text-xs text-ink-3">
            <span><span className="mr-1 inline-block h-2 w-2 rounded-full bg-ok" />Sealed</span>
            <span><span className="mr-1 inline-block h-2 w-2 rounded-full bg-slate-300" />Proposed</span>
            <span><span className="mr-1 inline-block h-2 w-2 rounded-full bg-bad" />Quarantined or killed</span>
          </div>
        </Card>

        <Card title="Decisions · last 60 min" action={<Link className="text-xs text-royal hover:underline" to="/live">Open Live Traffic</Link>}>
          <div className="grid grid-cols-4 gap-3 text-center">
            {[
              ['Allowed', pct(['allow']), 'text-ok'],
              ['With obligations', pct(['allow_with_obligations', 'step_up']), 'text-royal'],
              ['Needs approval', pct(['require_approval']), 'text-warn'],
              ['Denied / killed', pct(['deny', 'kill', 'quarantine', 'throttle']), 'text-bad'],
            ].map(([l, v, c]) => (
              <div key={l} className="rounded-md bg-canvas px-2 py-3">
                <div className={`text-xl font-semibold ${c}`}>{v}</div>
                <div className="text-xs text-ink-3">{l}</div>
              </div>
            ))}
          </div>
          <div className="mt-3 text-xs text-ink-3">{num(Object.values(dec).reduce((a, b) => a + b, 0))} decisions in the last hour</div>
        </Card>

        <Card title="Certificates expiring in 30 days" pad={false}>
          {s?.expiring_30d?.length ? (
            <table className="w-full">
              <thead>
                <tr><th className="th">Agent</th><th className="th">Tier</th><th className="th">Expires</th></tr>
              </thead>
              <tbody>
                {s.expiring_30d.map((c: any) => (
                  <tr key={c.handle}>
                    <td className="td mono">{c.handle}</td>
                    <td className="td"><TierChip tier={c.tier} /></td>
                    <td className="td">in {daysLeft(c.valid_to)} days</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>No seal expires in the next 30 days.</Empty>
          )}
        </Card>

        <Card title="Recent enforcement" action={<Link className="text-xs text-royal hover:underline" to="/enforcement">Open Enforcement Center</Link>} pad={false}>
          {ev?.items?.length ? (
            <ul className="divide-y divide-line">
              {ev.items.map((e: any) => (
                <li key={e.id} className="flex items-start gap-3 px-4 py-2.5 text-sm">
                  <span className="w-14 shrink-0 text-xs text-ink-3">{ago(e.published_at)}</span>
                  <Pill value={e.level} label={LEVEL_LABEL[e.level] ?? e.level} />
                  <div className="min-w-0">
                    <Link className="mono text-ink hover:underline" to={`/agents/${e.agent_id}`}>{e.agent_id}</Link>
                    <div className="truncate text-xs text-ink-3">{e.rule_id ? `${e.rule_id} · ` : ''}{e.reason}</div>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No ladder events yet.</Empty>
          )}
        </Card>
      </div>
    </>
  );
}

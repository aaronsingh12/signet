import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, Empty, KV, Mono, PageHeader, Pill } from '../components/ui';
import { api, useApi, useLive } from '../lib/api';
import { dlpSummary, time } from '../lib/format';

// Every gateway decision as it happens. Payload values never appear here, only classes, counts and
// hashes (Console UI & UX, Live Traffic).
export function LiveTraffic() {
  const { data } = useApi<any>('/ledger/records?kind=transaction&limit=60');
  const [rows, setRows] = useState<any[]>([]);
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const [filter, setFilter] = useState('');
  useEffect(() => {
    if (data) setRows(data.items.map((r: any) => ({ record_id: r.record_id, ts: r.ts, agent_id: r.agent_id, target: r.data.target, decision: r.data.policy_decision, dlp_actions: r.data.dlp_actions, latency_ms_gateway: r.data.latency_ms_gateway, action_type: r.data.action_type, rule_ids: r.data.policy_rule_ids })));
  }, [data]);
  useLive<any>((e) => {
    if (e.kind !== 'transaction') return;
    setRows((prev) => (paused ? prev : [e, ...prev].slice(0, 300)));
  });
  const shown = rows.filter((r) => !filter || r.decision === filter);
  return (
    <>
      <PageHeader
        title="Live Traffic"
        subtitle="Every gateway decision as it happens. Payload values never appear here, only classes, counts and hashes."
        actions={<button className="btn-ghost" onClick={() => setPaused(!paused)}>{paused ? 'Resume' : 'Pause'}</button>}
      />
      <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
        <Card pad={false}>
          <div className="flex flex-wrap gap-1.5 border-b border-line px-4 py-2.5">
            {['', 'allow', 'allow_with_obligations', 'require_approval', 'deny', 'kill', 'taint'].map((d) => (
              <button key={d} onClick={() => setFilter(d)} className={`rounded-full px-2.5 py-0.5 text-xs ${filter === d ? 'bg-royal text-white' : 'bg-canvas text-ink-2'}`}>
                {d ? d.replace(/_/g, ' ') : 'all'}
              </button>
            ))}
            <span className="ml-auto flex items-center gap-1.5 text-xs text-ink-3"><span className={`h-2 w-2 rounded-full ${paused ? 'bg-slate-300' : 'animate-pulse bg-ok'}`} />{paused ? 'paused' : 'streaming'}</span>
          </div>
          {shown.length ? (
            <table className="w-full">
              <thead><tr>{['Time (UTC)', 'Agent', 'Target', 'Decision', 'DLP', 'ms'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.record_id} className={`cursor-pointer hover:bg-canvas ${selected?.record?.record_id === r.record_id ? 'bg-royal-50' : ''}`} onClick={() => void api(`/ledger/records/${r.record_id}`).then(setSelected)}>
                    <td className="td mono whitespace-nowrap">{time(r.ts)}</td>
                    <td className="td mono text-xs">{r.handle ?? r.agent_id ?? '—'}</td>
                    <td className="td mono text-xs">{r.target ?? r.action_type}</td>
                    <td className="td"><Pill value={r.decision} /></td>
                    <td className="td text-xs">{dlpSummary(r.dlp_actions)}</td>
                    <td className="td text-right">{r.latency_ms_gateway ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>No decisions yet. Run <span className="mono">npm run demo</span> to send traffic.</Empty>
          )}
        </Card>
        <Card title="Gateway pipeline">
          {selected ? <Pipeline r={selected.record} /> : <Empty>Select a decision to see each of the 14 pipeline steps.</Empty>}
        </Card>
      </div>
    </>
  );
}

export function Pipeline({ r }: { r: any }) {
  const d = r.data;
  return (
    <div className="space-y-3 text-sm">
      <KV
        rows={[
          ['Decision', <Pill key="d" value={d.policy_decision} />],
          ['Rules', d.policy_rule_ids?.length ? <Mono key="r">{d.policy_rule_ids.join(', ')}</Mono> : '—'],
          ['Target', <Mono key="t">{d.target}</Mono>],
          ['Node', <Mono key="n">{d.node_id}</Mono>],
          ['Gateway / upstream', `${d.latency_ms_gateway ?? '—'} ms / ${d.latency_ms_upstream ?? '—'} ms`],
        ]}
      />
      {d.reasons?.length > 0 && <div className="rounded-md bg-canvas p-2 text-xs text-ink-2">{d.reasons.join(' · ')}</div>}
      <ol className="space-y-1">
        {(d.steps ?? []).map((s: any, i: number) => (
          <li key={i} className={`flex items-start gap-2 rounded px-2 py-1 ${s.result === 'fail' ? 'bg-bad-50' : ''}`}>
            <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${s.result === 'fail' ? 'bg-bad text-white' : 'bg-ok-50 text-ok'}`}>{s.n}</span>
            <div className="min-w-0 flex-1">
              <div className="font-medium">{s.name}</div>
              {s.detail && <div className="break-words text-xs text-ink-3">{s.detail}</div>}
            </div>
            <span className="mono text-xs text-ink-3">{s.ms}</span>
          </li>
        ))}
      </ol>
      {d.detectors?.length > 0 && (
        <div className="text-xs text-ink-2">
          Detectors: {d.detectors.map((x: any) => `${x.id} ${x.status}${x.score !== undefined ? ` ${x.score} (${x.band})` : ''}`).join(' · ')}
        </div>
      )}
      <Link className="text-xs text-royal hover:underline" to={`/ledger?record=${r.record_id}`}>Open ledger record</Link>
    </div>
  );
}

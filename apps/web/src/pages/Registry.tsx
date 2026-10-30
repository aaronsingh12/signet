import { Search } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card, Empty, PageHeader, Pill, TierChip } from '../components/ui';
import { useApi } from '../lib/api';
import { ago, date } from '../lib/format';

export function Registry() {
  const nav = useNavigate();
  const [tier, setTier] = useState('');
  const [q, setQ] = useState('');
  const [cursor, setCursor] = useState<string | null>(null);
  const params = new URLSearchParams({ limit: '25', ...(tier ? { tier } : {}), ...(q ? { q } : {}), ...(cursor ? { cursor } : {}) });
  const { data } = useApi<any>(`/agents?${params}`, [tier, q, cursor]);
  return (
    <>
      <PageHeader
        title="Agent Registry"
        subtitle="Every agent has an Agent ID, a workload identity and, once approved, a seal. Agent IDs never change; handles can."
        actions={
          <Link className="btn-primary" to="/agents/new">
            Propose agent
          </Link>
        }
      />
      <Card pad={false}>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
          {['', 'T1', 'T2', 'T3', 'T4'].map((t) => (
            <button key={t} onClick={() => (setTier(t), setCursor(null))} className={`rounded-md px-2.5 py-1 text-xs font-medium ${tier === t ? 'bg-royal text-white' : 'bg-canvas text-ink-2 hover:bg-slate-200'}`}>
              {t || 'All'}
            </button>
          ))}
          <div className="relative ml-auto w-72">
            <Search size={14} className="absolute left-2.5 top-2.5 text-ink-3" />
            <input className="input pl-8" placeholder="Search handle, name or owner" value={q} onChange={(e) => (setQ(e.target.value), setCursor(null))} />
          </div>
        </div>
        {data?.items?.length ? (
          <table className="w-full">
            <thead>
              <tr>
                {['Agent', 'Model', 'Tier', 'Autonomy', 'Seal', 'Ladder', 'Valid to', 'Owner', 'Last activity'].map((h) => (
                  <th key={h} className="th">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.items.map((a: any) => (
                <tr key={a.id} className="cursor-pointer hover:bg-canvas" onClick={() => nav(`/agents/${a.id}`)}>
                  <td className="td">
                    <div className="font-medium">{a.name}</div>
                    <div className="mono text-ink-3">{a.handle}</div>
                  </td>
                  <td className="td text-ink-2">gpt-oss (cloud LLM)</td>
                  <td className="td"><TierChip tier={a.tier} /></td>
                  <td className="td">{a.autonomy_level}</td>
                  <td className="td">{a.cert_id ? <Pill value="sealed" label={`sealed ${a.version}`} /> : <Pill value={a.status} />}</td>
                  <td className="td"><Pill value={a.enforcement} /></td>
                  <td className="td">{date(a.valid_to)}</td>
                  <td className="td text-ink-2">{a.owner}</td>
                  <td className="td text-ink-2">{ago(a.last_activity)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty>No agents match. Propose one, or claim one from the Discovery Inbox.</Empty>
        )}
        <div className="flex justify-end gap-2 px-4 py-3">
          <button className="btn-ghost" disabled={!cursor} onClick={() => setCursor(null)}>
            First page
          </button>
          <button className="btn-ghost" disabled={!data?.next_cursor} onClick={() => setCursor(data.next_cursor)}>
            Next
          </button>
        </div>
      </Card>
    </>
  );
}

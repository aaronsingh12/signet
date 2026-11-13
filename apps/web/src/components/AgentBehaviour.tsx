import { Card, Empty, KV, Pill } from './ui';
import { useApi } from '../lib/api';
import { ago } from '../lib/format';

// "Is it behaving normally?" (DET-ANOM) and "Is it telling the truth?" (DET-GROUND), DA 5.
export function AgentBehaviour({ agentId }: { agentId: string }) {
  const { data } = useApi<any>(`/agents/${agentId}/behaviour`);
  if (!data) return <p className="py-6 text-center text-sm text-ink-3">Loading…</p>;
  const a = data.anomaly;
  const b = a.baseline;
  const g = data.groundedness;
  const peak = b ? Math.max(1, ...b.requests_mean) : 1;
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card title="Normal behaviour (DET-ANOM)">
        <KV rows={[
          ['Detector', <Pill key="m" value={a.mode === 'active' ? 'allow' : a.mode === 'shadow' ? 'allow_with_obligations' : 'none'} label={a.mode} />],
          ['Baseline', b ? `${b.days} day(s), ${b.records} requests${a.ready ? '' : ` (needs ${a.min_days} days and ${a.min_records} requests before it is used)`}` : 'not built yet: it is built from the last 14 days of activity'],
          ...(b ? [['Usual error rate', `${Math.round(b.error_rate * 1000) / 10}%`], ['Tools it uses', Object.entries(b.tool_share).map(([t, s]) => `${t} ${Math.round(Number(s) * 100)}%`).join(' · ') || 'none'], ['Built', ago(b.computed_at)]] as [string, string][] : []),
        ]} />
        {b && (
          <div className="mt-3">
            <p className="mb-1 text-xs text-ink-3">Average requests per hour of the day (UTC)</p>
            <div className="flex h-20 items-end gap-px" role="img" aria-label="Average requests per hour of day">
              {b.requests_mean.map((v: number, h: number) => <div key={h} title={`${String(h).padStart(2, '0')}:00 · ${v} per hour`} className="flex-1 rounded-t bg-royal" style={{ height: `${Math.max(2, (v / peak) * 100)}%`, opacity: v ? 1 : 0.2 }} />)}
            </div>
            <div className="flex justify-between text-[10px] text-ink-3"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div>
          </div>
        )}
        <p className="mt-3 text-xs text-ink-3">Each request is compared with this agent's own normal volume, cost and errors for that hour, and with the tools it usually calls. Much more than usual raises the score; less than usual never does. While active, a high score holds or pauses the agent; it is only stopped when a seal limit is also passed by 200% for 10 minutes.</p>
      </Card>
      <Card title="Answers checked against their sources (DET-GROUND)">
        <KV rows={[
          ['Detector', <Pill key="m" value={g.mode === 'active' ? 'allow' : g.mode === 'shadow' ? 'allow_with_obligations' : 'none'} label={g.mode} />],
          ['Judged', `${g.judged} answer(s)${g.grounded_rate !== null ? `, ${Math.round(g.grounded_rate * 100)}% supported by their sources` : ''}`],
        ]} />
        <p className="my-2 text-xs text-ink-3">A sample of answers that used documents or tool results (1%, 5% for T1) is checked by your cloud model. The text is deleted after the check; only the score and reason are kept. Findings go to the owner and never change a decision.</p>
        {g.items.length ? (
          <table className="w-full">
            <thead><tr>{['When', 'Result', 'Score', 'Reason'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {g.items.slice(0, 15).map((i: any) => (
                <tr key={i.id}>
                  <td className="td text-xs">{ago(i.created_at)}</td>
                  <td className="td"><Pill value={i.verdict === 'grounded' ? 'allow' : i.verdict === 'ungrounded' ? 'deny' : 'none'} label={i.verdict ?? i.status} /></td>
                  <td className="td text-xs">{i.score ?? '—'}</td>
                  <td className="td text-xs text-ink-2">{i.rationale ?? ''}{i.unsupported?.length ? <span className="text-ink-3"> · not in sources: {i.unsupported.slice(0, 3).join('; ')}</span> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <Empty>No sampled answers yet.</Empty>}
      </Card>
    </div>
  );
}

import { Card, Empty } from './ui';
import { useApi } from '../lib/api';

// Cost, activity and quality per agent over 30 days (Phase C3/C4), plus AI usage outside Signet that
// OpenAI and Anthropic report. All from records; quality appears only where sampled scoring is on.

interface AgentCost { id: string; name: string; handle: string; tier: string; requests: number; model_calls: number; tool_calls: number; blocked: number; tokens_in: number; tokens_out: number; cost_usd: number; evaluations: number; helpfulness: number | null; safety: number | null; on_policy: number | null; flagged: number }
interface Outside { connection_id: string; platform: string; label: string; workload_id: string; requests: number; input_tokens: number; output_tokens: number; last_day: string }

const n = (v: unknown) => Number(v ?? 0).toLocaleString();
const score = (v: number | null) => (v === null || v === undefined ? '—' : Number(v).toFixed(1));

export function CostQuality() {
  const { data } = useApi<{ days: number; agents: AgentCost[]; outside_signet: Outside[] }>('/stats/costs?days=30');
  if (!data) return null;
  return (
    <Card title="Cost, activity and quality · last 30 days" className="mt-4" pad={false}>
      {data.agents.length ? (
        <table className="w-full">
          <thead><tr>{['Agent', 'Model calls', 'Tool calls', 'Blocked', 'Tokens in / out', 'Cost (USD)', 'Quality (helpful · safe · on-policy)', 'Flagged'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {data.agents.map((a) => (
              <tr key={a.id}>
                <td className="td"><div className="font-medium">{a.name}</div><div className="mono text-xs text-ink-3">{a.handle} · {a.tier}</div></td>
                <td className="td text-right">{n(a.model_calls)}</td>
                <td className="td text-right">{n(a.tool_calls)}</td>
                <td className="td text-right">{n(a.blocked)}</td>
                <td className="td text-right text-xs">{n(a.tokens_in)} / {n(a.tokens_out)}</td>
                <td className="td text-right">{Number(a.cost_usd ?? 0).toFixed(2)}</td>
                <td className="td text-xs">{Number(a.evaluations) ? `${score(a.helpfulness)} · ${score(a.safety)} · ${score(a.on_policy)} (${n(a.evaluations)} scored)` : <span className="text-ink-3">not sampled</span>}</td>
                <td className="td text-right">{n(a.flagged)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <Empty>No agent activity in the last 30 days.</Empty>}
      <div className="border-t border-line px-4 py-3">
        <div className="text-sm font-semibold">AI use outside Signet (reported by the provider)</div>
        {data.outside_signet.length ? (
          <table className="mt-2 w-full">
            <tbody>
              {data.outside_signet.map((u) => (
                <tr key={`${u.connection_id}:${u.workload_id}`}>
                  <td className="td text-xs">{u.label}</td>
                  <td className="td mono text-xs">{u.workload_id.split(':').slice(1).join(' / ')}</td>
                  <td className="td text-right text-xs">{n(u.requests)} requests</td>
                  <td className="td text-right text-xs">{n(u.input_tokens)} in / {n(u.output_tokens)} out tokens</td>
                  <td className="td text-xs text-ink-3">up to {u.last_day}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="mt-1 text-xs text-ink-3">None reported. Connect OpenAI or Anthropic under Connections and sync usage to see direct use that bypasses Signet.</p>}
      </div>
      <p className="px-4 pb-3 text-xs text-ink-3">Quality scores come from sampling answers with the tenant's own model as judge; set SIGNET_EVAL_SAMPLE_RATE (for example 0.05) on the gateways to turn it on.</p>
    </Card>
  );
}

import { useState } from 'react';
import { Card, ErrorNote, PageHeader } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago } from '../lib/format';
import { useAgentAnalytics } from '../lib/analytics';
import { EventsTable } from './Agent360';

const LEVELS = [
  ['L1', 'Blocked requests', 'deny', 'Individual requests refused'],
  ['L2', 'Extra checks', 'step_up', 'Additional safety checks applied'],
  ['L3', 'Rate limits', 'throttled', 'Request rates reduced'],
  ['L4', 'Paused agents', 'quarantined', 'A review is needed to resume'],
  ['L5', 'Stopped agents', 'killed', 'A new approval is required'],
  ['L6', 'Group controls', 'breaker', 'Safety controls for multiple agents'],
] as const;

export function Enforcement() {
  const { data: analytics } = useAgentAnalytics();
  const can = useCan();
  const { data: ev, reload } = useApi<any>('/enforcement-events?limit=100');
  const { data: br, reload: reloadBr } = useApi<any>('/circuit-breakers');
  const { data: blocks } = useApi<any>('/ledger/records?kind=transaction&decision=deny&limit=500');
  const events: any[] = ev?.items ?? [];
  const since = Date.now() - 86_400_000;
  const count = (level: string) => (level === 'deny' ? (blocks?.items ?? []).filter((r: any) => Date.parse(r.ts) > since).length : level === 'breaker' ? (br?.items ?? []).length : events.filter((e) => e.level === level && e.published_ms > since).length);
  const lastKill = events.find((e) => e.level === 'killed');
  return (
    <>
      <PageHeader title="Safety center" subtitle="See which actions were blocked, which agents need review, and where safety controls were applied." />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {LEVELS.map(([l, name, key, lift]) => (
          <div key={l} className="card px-4 py-3">
            <div className="mb-2 text-[10px] text-ink-3">{key === 'breaker' ? 'Currently configured' : 'Last 24 hours'}</div>
            <div className="text-sm font-semibold">{name}</div>
            <div className="mt-1 text-2xl font-semibold">{count(key)}</div>
            <div className="text-[11px] text-ink-3">{lift}</div>
          </div>
        ))}
      </div>
      {lastKill && (
        <Card className="mt-4" title={<span><span className="mr-2 rounded bg-bad px-1.5 py-0.5 text-[11px] text-white">Stopped</span><span>{analytics?.agents.find((agent) => agent.id === lastKill.agent_id)?.name ?? lastKill.agent_id}</span> · {ago(lastKill.published_at)}</span>}>
          <div className="text-sm text-ink-2">{lastKill.rule_id ? <span className="mono mr-1">{lastKill.rule_id}</span> : null}{lastKill.reason}</div>
          <div className="mt-3 text-sm font-medium">
            Propagation {lastKill.acks.length}/{lastKill.nodes_expected} · {lastKill.acks.length ? `${(Math.max(...lastKill.acks.map((a: any) => a.latency_ms)) / 1000).toFixed(3)} s` : 'waiting'}
          </div>
          <div className="mt-2 grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-6">
            {lastKill.acks.map((a: any) => (
              <div key={a.gateway_node_id} className="rounded-md border border-ok/30 bg-ok-50 px-2 py-1.5 text-xs">
                <div className="mono font-medium text-ink">{a.gateway_node_id}</div>
                <div className="text-ok">{a.latency_ms} ms</div>
              </div>
            ))}
          </div>
          <div className="mt-2 text-xs text-ink-3">This agent cannot run. It needs a new approval process before it can return.</div>
        </Card>
      )}
      <div className="mt-4 space-y-5">
        <Card title="Safety actions" pad={false} action={<button className="text-xs text-royal hover:underline" onClick={() => void reload()}>Refresh</button>}>
          <EventsTable events={events} />
        </Card>
        <details><summary className="cursor-pointer text-sm text-ink-2">Advanced: manage safety controls for a group of agents</summary><div className="mt-4"><Breaker canArm={can('circuit_breaker.arm')} armed={br?.items ?? []} onArmed={() => (void reloadBr(), void reload())} /></div></details>
      </div>
    </>
  );
}

function Breaker({ canArm, armed, onArmed }: { canArm: boolean; armed: any[]; onArmed: () => void }) {
  const [sel, setSel] = useState({ model: '', tool: '', tag: '', tier: '' });
  const [action, setAction] = useState<'quarantine' | 'kill'>('quarantine');
  const [reason, setReason] = useState('');
  const [preview, setPreview] = useState<string[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const selector = Object.fromEntries(Object.entries(sel).filter(([, v]) => v));
  const run = async (arm: boolean) => {
    setError(null);
    try {
      if (!arm) setPreview((await api('/circuit-breakers/preview', { method: 'POST', body: { selector } })).matched);
      else {
        await api('/circuit-breakers', { method: 'POST', body: { selector, action, reason } });
        setPreview(null);
        onArmed();
      }
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <Card title="Circuit breaker (level 6)">
      <p className="text-xs text-ink-3">Quarantine or kill every agent matching a selector at once: a compromised tool, model version or tag. Human-only; never triggered by a detector (RB-KILL-13). There is no provider selector: with one cloud LLM it would stop every agent (D-20).</p>
      <div className="mt-3 grid grid-cols-2 gap-2">
        {(['tool', 'model', 'tag', 'tier'] as const).map((k) => (
          <div key={k}>
            <label className="label">{k}</label>
            <input className="input mono" value={sel[k]} placeholder={{ tool: 'mcp://orders', model: 'gpt-oss:*', tag: 'customer-facing', tier: 'T3' }[k]} onChange={(e) => setSel({ ...sel, [k]: e.target.value })} disabled={!canArm} />
          </div>
        ))}
      </div>
      <div className="mt-2 flex gap-3 text-sm">
        <label className="flex items-center gap-1"><input type="radio" checked={action === 'quarantine'} onChange={() => setAction('quarantine')} /> Quarantine</label>
        <label className="flex items-center gap-1"><input type="radio" checked={action === 'kill'} onChange={() => setAction('kill')} /> Kill</label>
      </div>
      <label className="label mt-2">Reason</label>
      <input className="input" value={reason} onChange={(e) => setReason(e.target.value)} disabled={!canArm} />
      {preview && <div className="mt-2 text-sm">Matches <b>{preview.length}</b> agent(s){preview.length ? `: ${preview.join(', ')}` : ''}</div>}
      <ErrorNote error={error} />
      <div className="mt-3 flex gap-2">
        <button className="btn-ghost" disabled={!canArm || !Object.keys(selector).length} onClick={() => void run(false)}>Preview</button>
        <button className="btn-danger" disabled={!canArm || !preview?.length || !reason} onClick={() => void run(true)}>Arm breaker</button>
      </div>
      {armed.length > 0 && (
        <div className="mt-4 border-t border-line pt-3 text-xs text-ink-2">
          {armed.map((b) => (
            <div key={b.id} className="mb-1"><span className="mono">{b.id}</span> · {b.action} · {JSON.parse(b.matched).length} agents · {b.armed_by} · {ago(b.armed_at)}</div>
          ))}
        </div>
      )}
    </Card>
  );
}

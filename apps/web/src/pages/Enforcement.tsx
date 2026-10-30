import { useState } from 'react';
import { Card, ErrorNote, PageHeader } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago } from '../lib/format';
import { EventsTable } from './Agent360';

const LEVELS = [
  ['L1', 'Block', 'deny', 'Next request evaluated fresh'],
  ['L2', 'Step-up', 'step_up', 'Window expires or Security clears'],
  ['L3', 'Throttle', 'throttled', 'Cool-down or manual'],
  ['L4', 'Quarantine', 'quarantined', 'Owner + Security release'],
  ['L5', 'Kill', 'killed', 'Never lifted'],
  ['L6', 'Circuit breaker', 'breaker', 'Lifted per agent'],
] as const;

export function Enforcement() {
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
      <PageHeader title="Enforcement Center" subtitle="The response ladder, kill propagation and circuit breakers. Automatic actions always cite the deterministic rule behind them (RB-INV-05)." />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {LEVELS.map(([l, name, key, lift]) => (
          <div key={l} className="card px-4 py-3">
            <div className="text-xs text-ink-3">Level {l.slice(1)}</div>
            <div className="text-sm font-semibold">{name}</div>
            <div className="mt-1 text-2xl font-semibold">{count(key)}</div>
            <div className="text-[11px] text-ink-3">{lift}</div>
          </div>
        ))}
      </div>
      {lastKill && (
        <Card className="mt-4" title={<span><span className="mr-2 rounded bg-bad px-1.5 py-0.5 text-[11px] text-white">L5 Kill</span><span className="mono">{lastKill.agent_id}</span> killed {ago(lastKill.published_at)}</span>}>
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
          <div className="mt-2 text-xs text-ink-3">Kill is never lifted. Re-entry only by a new seal from Stage 3. Gateways also poll the bundle every 5 s, so a missed push cannot keep an agent alive.</div>
        </Card>
      )}
      <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_380px]">
        <Card title="Ladder events" pad={false} action={<button className="text-xs text-royal hover:underline" onClick={() => void reload()}>Refresh</button>}>
          <EventsTable events={events} />
        </Card>
        <Breaker canArm={can('circuit_breaker.arm')} armed={br?.items ?? []} onArmed={() => (void reloadBr(), void reload())} />
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

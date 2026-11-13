import { useState } from 'react';
import { Card, Empty, ErrorNote, Mono, Pill } from './ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan, useMe } from '../lib/auth';
import { ago } from '../lib/format';

// Detector release process (DA 6 mechanism 4): benchmark results, the promotion gate and the Security /
// AI Assurance sign-offs, for one detector.
const RUNNABLE = new Set(['DET-ANOM', 'DET-SAFE', 'DET-PII', 'DET-GROUND']);

export function DetectorRelease({ id, onChange }: { id: string; onChange: () => void }) {
  const can = useCan();
  const me = useMe();
  const roles: string[] = me.principal?.roles ?? [];
  const solo = !!me.single_operator; // one administrator gives each sign-off (recorded as a waiver)
  const { data, reload } = useApi<any>(`/detectors/${id}/release`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); setError(null); await reload(); onChange(); } catch (e) { setError(e as Error); } finally { setBusy(false); }
  };
  const approve = (as: 'security' | 'ai_assurance', target?: 'challenger') => {
    const reason = prompt(`Reason for the ${as === 'security' ? 'Security' : 'AI Assurance'} sign-off on promoting ${target ? 'the challenger of ' : ''}${id} (written to the ledger)`);
    if (reason) void act(() => api(`/detectors/${id}/approvals`, { method: 'POST', body: { as, reason, target } }));
  };
  const ask = (what: string) => prompt(`Reason to ${what} (written to the ledger)`);
  if (!data) return <p className="px-4 py-3 text-xs text-ink-3">Loading…</p>;
  return (
    <div className="grid gap-3 bg-canvas px-4 py-3">
      <ErrorNote error={error as ApiError} />
      <div>
        <p className="mb-1 text-xs font-semibold text-ink-2">Before this version can be promoted to active</p>
        <ul className="grid gap-1 text-xs">
          {data.gate.checks.map((c: any) => (
            <li key={c.what} className="flex gap-2"><Pill value={c.ok ? 'allow' : 'deny'} label={c.ok ? 'met' : 'not met'} /><span className="font-medium">{c.what}</span><span className="text-ink-3">{c.detail}</span></li>
          ))}
        </ul>
      </div>
      <div className="flex flex-wrap gap-2">
        {can('detectors.manage') && RUNNABLE.has(id) && <button className="btn-ghost text-xs" disabled={busy} onClick={() => void act(() => api(`/detectors/${id}/benchmarks`, { method: 'POST' }))}>{busy ? 'Running…' : 'Run benchmark'}</button>}
        {!RUNNABLE.has(id) && <span className="text-xs text-ink-3">This detector runs in the gateway: benchmark it with <Mono>npx tsx scripts/bench-model.mts --detector {id} --record</Mono> where the model is installed.</span>}
        {(solo || roles.includes('security_officer')) && <button className="btn-ghost text-xs" disabled={busy} onClick={() => approve('security')}>Approve as Security</button>}
        {(solo || roles.includes('risk_officer')) && <button className="btn-ghost text-xs" disabled={busy} onClick={() => approve('ai_assurance')}>Approve as AI Assurance</button>}
      </div>
      {data.challenger ? (
        <div className="rounded-md border border-line bg-white px-3 py-2">
          <p className="mb-1 text-xs font-semibold text-ink-2">Challenger: <Mono>{data.challenger.version}</Mono> running beside the current version since {ago(data.challenger.since)} (scores only, never changes a decision)</p>
          <ul className="grid gap-1 text-xs">
            {data.challenger.gate.checks.map((c: any) => (
              <li key={c.what} className="flex gap-2"><Pill value={c.ok ? 'allow' : 'deny'} label={c.ok ? 'met' : 'not met'} /><span className="font-medium">{c.what}</span><span className="text-ink-3">{c.detail}</span></li>
            ))}
          </ul>
          <div className="mt-2 flex flex-wrap gap-2">
            {can('detectors.manage') && RUNNABLE.has(id) && <button className="btn-ghost text-xs" disabled={busy} onClick={() => void act(() => api(`/detectors/${id}/benchmarks`, { method: 'POST', body: { target: 'challenger' } }))}>{busy ? 'Running…' : 'Benchmark the challenger'}</button>}
            {(solo || roles.includes('security_officer')) && <button className="btn-ghost text-xs" disabled={busy} onClick={() => approve('security', 'challenger')}>Approve challenger as Security</button>}
            {(solo || roles.includes('risk_officer')) && <button className="btn-ghost text-xs" disabled={busy} onClick={() => approve('ai_assurance', 'challenger')}>Approve challenger as AI Assurance</button>}
            {can('detectors.manage') && <button className="btn-ghost text-xs" disabled={busy} onClick={() => { const reason = ask('replace the current version with the challenger'); if (reason) void act(() => api(`/detectors/${id}/challenger/promote`, { method: 'POST', body: { reason } })); }}>Promote challenger</button>}
            {can('detectors.manage') && <button className="text-xs text-ink-3 hover:underline" disabled={busy} onClick={() => { const reason = ask('stop the challenger'); if (reason) void act(() => api(`/detectors/${id}/challenger/stop`, { method: 'POST', body: { reason } })); }}>Stop challenger</button>}
          </div>
        </div>
      ) : id === 'DET-SAFE' && can('detectors.manage') ? (
        <div>
          <button className="btn-ghost text-xs" disabled={busy} onClick={() => { const reason = ask('run IBM Granite Guardian 2B beside the current safety check'); if (reason) void act(() => api(`/detectors/${id}/challenger`, { method: 'POST', body: { version: 'granite3-guardian-2b-v1', reason } })); }}>Run Granite Guardian (small safety model) as challenger</button>
          <p className="mt-1 text-xs text-ink-3">Needs a model server with <Mono>granite3-guardian:2b</Mono> (for example Ollama) at SIGNET_SAFETY_MODEL_URL on the gateway.</p>
        </div>
      ) : null}
      {data.benchmarks.length ? (
        <table className="w-full">
          <thead><tr>{['Set', 'Version', 'Result', 'Precision', 'Recall', 'False positives', 'By language', 'Run'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {data.benchmarks.map((b: any) => (
              <tr key={b.id}>
                <td className="td mono text-xs">{b.set_id}</td>
                <td className="td mono text-xs" title={b.sha256}>{b.version} · {b.sha256.slice(0, 10)}</td>
                <td className="td"><Pill value={b.passed ? 'allow' : 'deny'} label={b.passed ? 'passed' : 'failed'} /></td>
                <td className="td text-xs">{b.metrics.precision}</td>
                <td className="td text-xs">{b.metrics.recall}</td>
                <td className="td text-xs">{b.metrics.fpr} ({b.metrics.fp} of {b.metrics.fp + b.metrics.tn})</td>
                <td className="td text-xs text-ink-2">{Object.entries(b.metrics.by_lang ?? {}).map(([l, v]: [string, any]) => `${l} ${v.correct}/${v.n}`).join(' · ')}</td>
                <td className="td text-xs text-ink-3">{b.ran_by} · {ago(b.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <Empty>No benchmark run for this detector yet.</Empty>}
    </div>
  );
}

// Replay (DA 6 mechanism 3): the daily random sample of re-run decisions (SGC-SELF-007).
export function ReplayRuns() {
  const can = useCan();
  const { data, reload } = useApi<any>('/replay/runs');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = async () => {
    setBusy(true);
    try { await api('/replay/sample', { method: 'POST', body: {} }); setError(null); await reload(); } catch (e) { setError(e as ApiError); } finally { setBusy(false); }
  };
  return (
    <Card title="Decision replay" className="xl:col-span-2" action={can('detectors.manage') && <button className="btn-ghost text-xs" disabled={busy} onClick={() => void run()}>{busy ? 'Replaying…' : 'Replay a sample now'}</button>}>
      <ErrorNote error={error} />
      <p className="mb-2 text-xs text-ink-3">Every day Signet re-runs a random sample of up to 100 decisions from the ledger: each detector score is re-banded with the thresholds that were used, its version hash is checked against the released pins, and the decision is combined again. Every outcome must match. You can replay any single decision from the Evidence ledger.</p>
      {data?.items?.length ? (
        <table className="w-full">
          <thead><tr>{['When', 'Sampled', 'Reproduced', 'Did not match', 'By'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {data.items.slice(0, 10).map((r: any) => (
              <tr key={r.id}>
                <td className="td text-xs">{ago(r.created_at)}</td>
                <td className="td text-xs">{r.sampled}</td>
                <td className="td text-xs">{r.reproduced}</td>
                <td className="td text-xs">{r.mismatched ? <span className="text-bad" title={r.details.map((d: any) => d.record_id).join(', ')}>{r.mismatched}</span> : 0}</td>
                <td className="td text-xs text-ink-3">{r.actor}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <Empty>No replay sample yet.</Empty>}
    </Card>
  );
}

export function ReplayButton({ recordId }: { recordId: string }) {
  const [r, setR] = useState<any>(null);
  const [error, setError] = useState<ApiError | null>(null);
  return (
    <div>
      <button className="btn-ghost" onClick={() => void api(`/replay`, { method: 'POST', body: { record_id: recordId } }).then((x) => { setR(x); setError(null); }, setError)}>Replay this decision</button>
      <ErrorNote error={error} />
      {r && (
        <div className="mt-2 rounded-md bg-canvas p-2 text-xs">
          <div className="mb-1 flex items-center gap-2"><Pill value={r.status === 'reproduced' ? 'allow' : r.status === 'mismatch' ? 'deny' : 'none'} label={r.status.replace('_', ' ')} />{r.recorded && <span>recorded {r.recorded} · replayed {r.replayed}</span>}</div>
          {r.reason && <p className="text-ink-3">{r.reason}</p>}
          <ul className="grid gap-0.5">{r.checks.map((c: any, i: number) => <li key={i} className={c.ok ? 'text-ink-2' : 'text-bad'}>{c.ok ? '✓' : '✗'} {c.what}: {c.detail}</li>)}</ul>
        </div>
      )}
    </div>
  );
}

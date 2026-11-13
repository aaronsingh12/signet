import { useEffect, useState } from 'react';
import { Card, Empty, ErrorNote, Mono, Pill } from './ui';
import { ApiError, api, useApi } from '../lib/api';
import { ago } from '../lib/format';

// Test Lab attack suites (BP 6 Stage 4): Signet probes against the agent's test address, or imported
// garak / promptfoo / PyRIT reports. T1/T2 need passing results before the seal.
const LABEL: Record<string, string> = {
  prompt_injection_direct: 'Prompt injection (direct)', prompt_injection_indirect: 'Prompt injection (in documents)', jailbreak: 'Jailbreak',
  data_leakage_live: 'Data leakage', groundedness: 'Groundedness', load: 'Load',
};

export function AttackLab({ lifecycleId, tier }: { lifecycleId: string; tier: string }) {
  const { data, reload } = useApi<any>(`/lifecycles/${lifecycleId}/attack-runs`);
  const [target, setTarget] = useState({ url: '', api_key: '' });
  const [tool, setTool] = useState('garak');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const running = (data?.items ?? []).some((r: any) => r.status === 'running');
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => void reload(), 3000);
    return () => clearInterval(t);
  }, [running, reload]);
  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); setError(null); await reload(); } catch (e) { setError(e as Error); } finally { setBusy(false); }
  };
  const start = () => act(async () => {
    if (target.url) await api(`/lifecycles/${lifecycleId}/attack-target`, { method: 'POST', body: { url: target.url, api_key: target.api_key || undefined } });
    await api(`/lifecycles/${lifecycleId}/attack-runs`, { method: 'POST' });
  });
  const upload = (file: File) => act(async () => api(`/lifecycles/${lifecycleId}/attack-reports`, { method: 'POST', body: { tool, report: await file.text() } }));
  const last = (data?.items ?? [])[0];
  return (
    <Card title={`Attack tests${tier === 'T1' || tier === 'T2' ? ' (required for this tier)' : ' (optional for this tier)'}`} className="xl:col-span-2">
      <ErrorNote error={error as ApiError} />
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <p className="mb-2 text-xs text-ink-3">Signet sends {data?.probe_set ?? 'its'} probes to the agent's test chat address (OpenAI-style): direct and hidden prompt injection, jailbreaks, attempts to extract planted customer details, questions on a document, and a small load check. Use a test copy of the agent with its tools pointed at stubs.</p>
          <input className="input mb-2" placeholder="https://agent-test.example.com/v1/chat/completions" value={target.url} onChange={(e) => setTarget({ ...target, url: e.target.value })} />
          <input className="input mono mb-2" type="password" placeholder="bearer key for the test address (optional)" value={target.api_key} onChange={(e) => setTarget({ ...target, api_key: e.target.value })} />
          <button className="btn-primary w-full" disabled={busy || running} onClick={() => void start()}>{running ? 'Attacks running…' : 'Run attack suites'}</button>
        </div>
        <div>
          <p className="mb-2 text-xs text-ink-3">Or import results from your own red-team run: garak (report.jsonl), promptfoo (results.json), or the simple JSON format for PyRIT and other tools.</p>
          <select className="input mb-2" value={tool} onChange={(e) => setTool(e.target.value)}>
            <option value="garak">garak report.jsonl</option>
            <option value="promptfoo">promptfoo results.json</option>
            <option value="json">PyRIT / other (JSON)</option>
          </select>
          <label className="btn-ghost block cursor-pointer text-center">Upload report<input type="file" className="hidden" onChange={(e) => e.target.files?.[0] && void upload(e.target.files[0])} /></label>
        </div>
      </div>
      {last ? (
        <div className="mt-4">
          <p className="mb-2 text-xs text-ink-2">Latest: {last.source} · {last.status} · started {ago(last.started_at)}{last.target_url ? <> · <Mono>{last.target_url}</Mono></> : null}{last.error ? <span className="text-bad"> · {last.error}</span> : null}</p>
          <table className="w-full">
            <thead><tr>{['Suite', 'Result', 'Rate', 'Threshold', 'Failures'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {Object.entries(last.suites ?? {}).map(([s, r]: [string, any]) => (
                <tr key={s}>
                  <td className="td text-sm">{LABEL[s] ?? s}</td>
                  <td className="td"><Pill value={r.passed_threshold ? 'allow' : 'deny'} label={r.passed_threshold ? 'pass' : 'fail'} /></td>
                  <td className="td text-xs">{r.passed}/{r.cases}{r.p95_ms ? ` · p95 ${r.p95_ms} ms` : ''}</td>
                  <td className="td text-xs text-ink-3">{data?.thresholds?.[s]?.label ?? ''}</td>
                  <td className="td text-xs text-ink-2">{(r.failures ?? []).slice(0, 3).join('; ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-xs text-ink-3">Results count for the current manifest; changing the manifest needs a new run. Then use "Run tests" to apply them.</p>
        </div>
      ) : <div className="mt-4"><Empty>No attack run yet.</Empty></div>}
    </Card>
  );
}

import { useState } from 'react';
import { Card, Empty, ErrorNote, Mono, PageHeader, Pill, Stat } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { ago } from '../lib/format';

// Control Library & Compliance (BP 9): Signet Controls are the hub; framework requirements map to
// them. Automated controls are tested continuously from live evidence; scores follow the results.

const STATUS_PILL: Record<string, string> = { effective: 'allow', partially_effective: 'require_approval', ineffective: 'deny', not_tested: 'none' };

export function Controls() {
  const lib = useApi<any>('/library');
  const scores = useApi<any>('/compliance/scores');
  const [framework, setFramework] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const evaluate = async () => {
    setBusy(true);
    try {
      await api('/library/evaluate', { method: 'POST' });
      await Promise.all([lib.reload(), scores.reload()]);
      setError(null);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const controls = (lib.data?.controls ?? []).filter(
    (c: any) => (!framework || c.mappings.some((m: any) => m.framework_id === framework)) && (!q || `${c.id} ${c.objective} ${c.domain}`.toLowerCase().includes(q.toLowerCase())),
  );
  const count = (s: string) => (lib.data?.controls ?? []).filter((c: any) => (c.status ?? 'not_tested') === s).length;
  return (
    <>
      <PageHeader
        title="Control Library & Compliance"
        subtitle="One set of Signet Controls, mapped to each framework. A framework score is the share of its requirements whose mapped controls are all effective."
        actions={<button className="btn-primary" disabled={busy} onClick={() => void evaluate()}>{busy ? 'Evaluating…' : 'Evaluate now'}</button>}
      />
      <ErrorNote error={error} />
      <div className="mb-4 grid gap-3 md:grid-cols-4">
        <Stat label="Effective" value={count('effective')} tone="ok" hint="controls" />
        <Stat label="Partially effective" value={count('partially_effective')} tone="warn" hint="controls" />
        <Stat label="Ineffective" value={count('ineffective')} tone="bad" hint="controls" />
        <Stat label="Not tested" value={count('not_tested')} hint="manual or no evidence yet" />
      </div>
      <div className="mb-4 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        {(scores.data?.items ?? []).map((f: any) => (
          <button key={f.framework_id} onClick={() => setFramework(framework === f.framework_id ? null : f.framework_id)} className={`card px-3 py-2.5 text-left ${framework === f.framework_id ? 'ring-2 ring-royal' : ''}`}>
            <div className="line-clamp-2 text-xs font-medium text-ink-2">{f.name}</div>
            <div className="mt-1 text-xl font-semibold">{f.score === null ? '—' : `${f.score}%`}</div>
            <div className="mt-1 h-1.5 rounded bg-slate-100"><div className="h-1.5 rounded bg-royal" style={{ width: `${f.score ?? 0}%` }} /></div>
            <div className="mt-1 text-[11px] text-ink-3">{f.requirements.length} requirements</div>
          </button>
        ))}
      </div>
      <Card pad={false} title={framework ? `Controls mapped to ${(scores.data?.items ?? []).find((f: any) => f.framework_id === framework)?.name}` : 'All controls'} action={<input className="input w-56" placeholder="Search controls" value={q} onChange={(e) => setQ(e.target.value)} />}>
        {controls.length ? (
          <table className="w-full">
            <thead><tr>{['Control', 'Objective', 'Test', 'Status', 'Maps to', 'Evaluated'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {controls.map((c: any) => (
                <tr key={c.id}>
                  <td className="td"><Mono>{c.id}</Mono><div className="text-[11px] text-ink-3">{c.domain} · {c.severity}</div></td>
                  <td className="td text-sm">{c.objective}<div className="text-xs text-ink-3">{c.detail}</div></td>
                  <td className="td text-xs text-ink-2">{c.test_type.replace('_', ' ')}</td>
                  <td className="td"><Pill value={STATUS_PILL[c.status ?? 'not_tested']} label={(c.status ?? 'not_tested').replace('_', ' ')} /></td>
                  <td className="td text-xs text-ink-2">{c.mappings.map((m: any) => m.external_id).join(', ') || '—'}</td>
                  <td className="td text-xs text-ink-2">{ago(c.evaluated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty>No controls match.</Empty>
        )}
      </Card>
    </>
  );
}

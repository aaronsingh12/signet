import { useState } from 'react';
import { Card, Empty, ErrorNote, Mono } from './ui';
import { ApiError, api, useApi } from '../lib/api';
import { ago } from '../lib/format';

// Audit packs (BP 9.6): one-click, signed exports per framework or for the board.
export function AuditPacks({ frameworks }: { frameworks: { framework_id: string; name: string; enabled: boolean }[] }) {
  const { data, reload } = useApi<any>('/audit-packs');
  const today = new Date().toISOString().slice(0, 10);
  const start = new Date(Date.now() - 90 * 86_400_000).toISOString().slice(0, 10);
  const [form, setForm] = useState({ framework_id: 'board', from: start, to: today, agents: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [check, setCheck] = useState<string | null>(null);
  const generate = async () => {
    setBusy(true);
    try {
      await api('/audit-packs', { method: 'POST', body: { framework_id: form.framework_id, from: form.from, to: form.to, agents: form.agents.split(',').map((s) => s.trim()).filter(Boolean) } });
      setError(null); await reload();
    } catch (e) { setError(e as ApiError); } finally { setBusy(false); }
  };
  const verify = async (file: File) => {
    try {
      const r = await api<any>('/audit-packs/verify', { method: 'POST', body: JSON.parse(await file.text()) });
      setCheck(r.ok ? `Valid: signed by Signet, content unchanged (sha256 ${r.sha256.slice(0, 16)}…)` : 'Not valid: the content was changed after it was signed');
    } catch (e) { setCheck(`Not valid: ${(e as Error).message}`); }
  };
  const name = (id: string) => (id === 'board' ? 'Board pack' : frameworks.find((f) => f.framework_id === id)?.name ?? id);
  return (
    <Card title="Audit packs">
      <p className="mb-3 text-xs text-ink-3">A signed export for an auditor or the board: every requirement with its Signet Controls and current results, the AI inventory, an independence statement, activity and enforcement in the period, and the ledger roots that prove the evidence. The EU AI Act pack adds the Annex IV outline; NIST AI RMF a profile and gaps; NIST 800-53 and FedRAMP implementation statements and an OSCAL fragment.</p>
      <div className="grid gap-2 md:grid-cols-[2fr_1fr_1fr_2fr_auto]">
        <select className="input" value={form.framework_id} onChange={(e) => setForm({ ...form, framework_id: e.target.value })}>
          <option value="board">Board pack (all frameworks)</option>
          {frameworks.filter((f) => f.enabled).map((f) => <option key={f.framework_id} value={f.framework_id}>{f.name}</option>)}
        </select>
        <input className="input" type="date" value={form.from} onChange={(e) => setForm({ ...form, from: e.target.value })} aria-label="From" />
        <input className="input" type="date" value={form.to} onChange={(e) => setForm({ ...form, to: e.target.value })} aria-label="To" />
        <input className="input" placeholder="agents (handles, comma-separated; empty = all)" value={form.agents} onChange={(e) => setForm({ ...form, agents: e.target.value })} />
        <button className="btn-primary" disabled={busy} onClick={() => void generate()}>{busy ? 'Building…' : 'Generate'}</button>
      </div>
      <ErrorNote error={error} />
      {data?.items?.length ? (
        <table className="mt-3 w-full">
          <thead><tr>{['Pack', 'Period', 'Agents', 'Fingerprint', 'Made', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {data.items.map((p: any) => (
              <tr key={p.id}>
                <td className="td text-sm">{name(p.framework_id)}</td>
                <td className="td text-xs">{p.scope.from} to {p.scope.to}</td>
                <td className="td text-xs">{Array.isArray(p.scope.agents) ? p.scope.agents.join(', ') : p.scope.agents}</td>
                <td className="td"><Mono title={p.sha256}>{p.sha256.slice(0, 12)}</Mono></td>
                <td className="td text-xs text-ink-3">{p.created_by} · {ago(p.created_at)}</td>
                <td className="td whitespace-nowrap text-xs"><a className="mr-3 text-royal hover:underline" href={`/api/v1/audit-packs/${p.id}`}>Signed JSON</a><a className="text-royal hover:underline" href={`/api/v1/audit-packs/${p.id}?format=csv`}>CSV</a></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <div className="mt-3"><Empty>No audit pack yet.</Empty></div>}
      <div className="mt-3 flex items-center gap-3 text-xs">
        <label className="btn-ghost cursor-pointer">Check a downloaded pack<input type="file" accept="application/json" className="hidden" onChange={(e) => e.target.files?.[0] && void verify(e.target.files[0])} /></label>
        {check && <span className={check.startsWith('Valid') ? 'text-ok' : 'text-bad'}>{check}</span>}
      </div>
    </Card>
  );
}

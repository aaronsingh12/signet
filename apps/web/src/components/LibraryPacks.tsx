import { useState } from 'react';
import { Card, Empty, ErrorNote, Mono, Pill } from './ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago } from '../lib/format';

// Library packs (BP 9.1, 9.4): which library version is in use, how new versions are adopted, what a new
// pack would change, and offline import of signed .ppack files.
export function LibraryPacks({ onChange }: { onChange: () => void }) {
  const can = useCan();
  const { data, reload } = useApi<any>('/library/packs');
  const [diffs, setDiffs] = useState<Record<string, any>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try { await fn(); setError(null); await reload(); onChange(); } catch (e) { setError(e as ApiError); } finally { setBusy(false); }
  };
  const showDiff = (id: string) => void api(`/library/packs/${id}/diff`).then((d) => setDiffs((x) => ({ ...x, [id]: d })), setError);
  const upload = (file: File) => act(async () => { const r = await api<any>('/library/packs/import', { method: 'POST', body: JSON.parse(await file.text()) }); setDiffs((x) => ({ ...x, [r.id]: r.diff })); });
  if (!data) return null;
  const adopted = data.items.find((p: any) => p.status === 'adopted');
  const waiting = data.items.filter((p: any) => p.status === 'available');
  const summary = (d: any) => [
    d.frameworks.added.length && `${d.frameworks.added.length} framework(s) added (${d.frameworks.added.join(', ')})`,
    d.frameworks.removed.length && `${d.frameworks.removed.length} removed (${d.frameworks.removed.join(', ')})`,
    d.frameworks.changed.length && `${d.frameworks.changed.length} updated`,
    `requirements +${d.requirements.added} / −${d.requirements.removed} / ${d.requirements.changed} reworded`,
    `links +${d.mappings.added} / −${d.mappings.removed}`,
    (d.controls.added.length || d.controls.changed.length) && `controls: ${d.controls.added.length} new, ${d.controls.changed.length} updated`,
  ].filter(Boolean).join(' · ');
  return (
    <Card title="Library version">
      <ErrorNote error={error} />
      <div className="mb-3 flex flex-wrap items-center gap-3 text-sm">
        <span>In use: <b>{adopted ? `v${adopted.version}` : 'none'}</b>{adopted && <span className="text-xs text-ink-3"> · adopted {ago(adopted.adopted_at)} by {adopted.adopted_by}</span>}</span>
        <span className="text-xs text-ink-3">This release ships v{data.built_in.version} ({data.built_in.released})</span>
        {can('library.edit') && (
          <label className="ml-auto flex items-center gap-2 text-xs">New versions:
            <select className="input py-1 text-xs" value={data.mode} disabled={busy} onChange={(e) => void act(() => api('/library/adoption-mode', { method: 'PUT', body: { mode: e.target.value } }))}>
              <option value="auto">adopt automatically</option>
              <option value="review">wait for review</option>
            </select>
          </label>
        )}
      </div>
      {waiting.length ? (
        <ul className="grid gap-2">
          {waiting.map((p: any) => (
            <li key={p.id} className="rounded-md border border-line p-2 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <Pill value="require_approval" label="waiting" /> <b>v{p.version}</b>
                <span className="text-xs text-ink-3">{p.source === 'built_in' ? 'from this Signet release' : `imported, signed by ${p.signer}`} · <Mono title={p.sha256}>{p.sha256.slice(0, 12)}</Mono></span>
                <button className="ml-auto text-xs text-royal hover:underline" onClick={() => showDiff(p.id)}>What changes</button>
                {can('library.edit') && <button className="btn-primary text-xs" disabled={busy} onClick={() => confirm(`Adopt library v${p.version}? Requirement text and links change for every framework it covers.`) && void act(() => api(`/library/packs/${p.id}/adopt`, { method: 'POST' }))}>Adopt</button>}
              </div>
              {diffs[p.id] && <p className="mt-1 text-xs text-ink-2">Compared with v{diffs[p.id].previous ?? 'none'}: {summary(diffs[p.id])}</p>}
            </li>
          ))}
        </ul>
      ) : <Empty>No new library version waiting.</Empty>}
      {can('library.edit') && (
        <div className="mt-3 flex items-center gap-3 text-xs">
          <label className="btn-ghost cursor-pointer">Import a signed pack (.ppack)<input type="file" accept=".ppack,application/json" className="hidden" onChange={(e) => e.target.files?.[0] && void upload(e.target.files[0])} /></label>
          <span className="text-ink-3">For offline installs. Only packs signed with a key in SIGNET_LIBRARY_TRUSTED_KEYS are accepted.</span>
        </div>
      )}
    </Card>
  );
}

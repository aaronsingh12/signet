import { useState } from 'react';
import { Card, Empty, ErrorNote, Mono, Pill } from './ui';
import { ApiError, api, useApi } from '../lib/api';
import { ago } from '../lib/format';

// AI Bill of Materials (CycloneDX 1.6) and its vulnerabilities (OSV.dev + CISA KEV), BP 6 Stage 3.
const SEV: Record<string, string> = { critical: 'deny', high: 'deny', medium: 'require_approval', low: 'none', unknown: 'none' };

export function SupplyChain({ agentId, canEdit }: { agentId: string; canEdit: boolean }) {
  const { data, reload } = useApi<any>(`/agents/${agentId}/aibom`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const run = async (sbom?: unknown) => {
    setBusy(true);
    try {
      const r = await api<any>(`/agents/${agentId}/aibom`, { method: 'POST', body: sbom === undefined ? {} : { sbom } });
      setNote(r.error ? r.error : `${r.components} components, ${r.scanned} packages checked: ${r.findings} vulnerabilities (${r.critical} critical, ${r.kev} known exploited).`);
      setError(null);
      await reload();
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  };
  const upload = async (file: File) => {
    try { await run(JSON.parse(await file.text())); } catch (e) { setError(e as Error); }
  };
  const download = () => {
    const blob = new Blob([JSON.stringify(data.cyclonedx, null, 2)], { type: 'application/vnd.cyclonedx+json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${data.cyclonedx.metadata?.component?.name ?? 'agent'}-aibom.cdx.json`;
    a.click();
  };
  if (!data) return <p className="py-6 text-center text-sm text-ink-3">Loading…</p>;
  return (
    <div className="grid gap-4">
      <Card title="AI Bill of Materials" action={canEdit && (
        <div className="flex flex-wrap items-center gap-2">
          <label className="btn-ghost cursor-pointer">Upload SBOM<input type="file" accept=".json" className="hidden" onChange={(e) => e.target.files?.[0] && void upload(e.target.files[0])} /></label>
          <button className="btn-primary" disabled={busy} onClick={() => void run()}>{busy ? 'Scanning…' : data.id ? 'Rebuild and scan' : 'Build and scan'}</button>
        </div>
      )}>
        <ErrorNote error={error as ApiError} />
        {note && <p className="mb-2 text-sm text-ink-2">{note}</p>}
        {data.id ? (
          <div className="text-sm">
            <p className="text-ink-2">Built {ago(data.created_at)} by {data.created_by} · last scanned {data.scanned_at ? ago(data.scanned_at) : 'never'} · CycloneDX {data.cyclonedx.specVersion} · <Mono>{data.sha256.slice(0, 16)}</Mono> <button className="btn-ghost px-1 py-0 text-xs" onClick={download}>Download</button></p>
            <ul className="mt-2 grid gap-1 text-xs text-ink-2 md:grid-cols-2">
              {data.cyclonedx.components.slice(0, 40).map((c: any) => <li key={c['bom-ref']}><span className="text-ink-3">{c.type}</span> {c.group ? `${c.group}/` : ''}{c.name}{c.version ? `@${c.version}` : ''}</li>)}
              {data.cyclonedx.services.map((s: any) => <li key={s['bom-ref']}><span className="text-ink-3">tool</span> {s.name}</li>)}
            </ul>
            {data.cyclonedx.components.length > 40 && <p className="mt-1 text-xs text-ink-3">and {data.cyclonedx.components.length - 40} more (download for all)</p>}
            <p className="mt-2 text-xs text-ink-3">Upload the agent's own SBOM (CycloneDX or SPDX JSON, for example from Syft) to include its packages in the vulnerability scan. It is rescanned every night.</p>
          </div>
        ) : <Empty>No AI Bill of Materials yet.</Empty>}
      </Card>
      <Card title={`Open vulnerabilities (${data.findings.length})`} pad={false}>
        {data.findings.length ? (
          <table className="w-full">
            <thead><tr>{['Severity', 'Advisory', 'Package', 'Summary', 'Since'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {data.findings.slice(0, 100).map((f: any) => (
                <tr key={`${f.component}${f.vuln_id}`}>
                  <td className="td"><Pill value={SEV[f.severity] ?? 'none'} label={f.kev ? 'known exploited' : f.severity} /></td>
                  <td className="td text-xs"><a className="hover:underline" href={`https://osv.dev/vulnerability/${f.vuln_id}`} target="_blank" rel="noreferrer">{f.vuln_id}</a><div className="text-ink-3">{f.aliases.filter((a: string) => a.startsWith('CVE-')).join(', ')}</div></td>
                  <td className="td mono text-xs">{f.component.replace(/^pkg:/, '')}</td>
                  <td className="td text-xs text-ink-2">{f.summary}</td>
                  <td className="td text-xs text-ink-3">{ago(f.first_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <Empty>{data.id ? 'No known vulnerabilities in the listed packages.' : 'Build the AI Bill of Materials to scan it.'}</Empty>}
      </Card>
    </div>
  );
}

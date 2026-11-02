import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, Empty, ErrorNote, Mono, PageHeader, Pill, Stat } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago } from '../lib/format';

// Discovery Inbox: AI use Signet does not govern yet. Sources: Key Sweep (credentials in code), network
// and SaaS audit log uploads (traffic to AI providers), and the SDK's runtime diagnostics (ways around
// the gateway). A source that never delivered data shows as not connected; findings are never invented.

const TYPE_LABEL: Record<string, string> = {
  unmanaged_key: 'Credential in code',
  direct_traffic: 'Direct AI API traffic',
  ai_app_usage: 'AI app usage',
  bypass_risk: 'Gateway bypass risk',
  unregistered_agent: 'Unregistered agent',
};

// CSV with a header row (ts, src, user, host or url) or JSON lines / a JSON array of the same fields.
function parseLogs(text: string): Record<string, string>[] {
  const t = text.trim();
  if (!t) return [];
  if (t.startsWith('[')) return JSON.parse(t);
  if (t.startsWith('{')) return t.split(/\r?\n/).filter(Boolean).map((l) => JSON.parse(l));
  const [head, ...rows] = t.split(/\r?\n/);
  const cols = head!.split(',').map((c) => c.trim().toLowerCase());
  return rows.filter(Boolean).map((r) => Object.fromEntries(r.split(',').map((v, i) => [cols[i] ?? `c${i}`, v.trim()])));
}

export function Discovery() {
  const can = useCan();
  const { data, reload } = useApi<any>('/discovered-assets');
  const { data: src, reload: reloadSources } = useApi<any>('/discovery/sources');
  const [upload, setUpload] = useState({ source: 'network-logs', text: '', gateway_hosts: '' });
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<ApiError | { rule: string; message: string } | null>(null);
  const kpi = data?.kpi;
  const sources = src?.items ?? [];
  const resolve = async (id: string, status: string) => {
    const note = prompt(`Note for marking this finding ${status}`) ?? '';
    await api(`/discovered-assets/${id}/resolve`, { method: 'POST', body: { status, note } });
    void reload();
  };
  const send = async () => {
    let records;
    try {
      records = parseLogs(upload.text);
    } catch {
      return setError({ rule: 'FORMAT', message: 'could not read the logs: use CSV with a header row, JSON lines, or a JSON array' });
    }
    try {
      setResult(await api('/discovery/logs', { method: 'POST', body: { source: upload.source, records, gateway_hosts: upload.gateway_hosts.split(',').map((s) => s.trim()).filter(Boolean) } }));
      setError(null);
      void reload();
      void reloadSources();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <>
      <PageHeader title="Discovery Inbox" subtitle="AI use that does not go through Signet yet: credentials in code, direct traffic to AI providers, and agents whose runtime could bypass the gateway." />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Open findings" value={data ? data.items.filter((f: any) => f.status === 'open').length : '—'} hint={data ? `${data.items.length} in total` : ''} tone={data?.items?.some((f: any) => f.status === 'open') ? 'warn' : undefined} />
        <Stat label="Unmanaged keys open" value={kpi?.unmanaged_keys_open ?? '—'} hint={`${kpi?.unmanaged_keys_total ?? 0} found by Key Sweep`} tone={kpi?.unmanaged_keys_open ? 'warn' : undefined} />
        <Stat label="Agents keyless, verified" value={kpi ? `${kpi.keyless_verified}/${kpi.sealed_agents}` : '—'} hint={kpi ? `${kpi.bypass_risk_agents} with bypass risk · ${kpi.unverified_agents} never reported` : ''} tone={kpi?.bypass_risk_agents ? 'warn' : undefined} />
        <Stat label="Sources delivering" value={src ? `${sources.filter((s: any) => s.connected).length}/${sources.length}` : '—'} hint="see Sources below" />
      </div>

      <Card className="mt-4" pad={false} title="Findings" action={<span className="text-xs text-ink-3">npm run keysweep -- &lt;dir&gt; --upload</span>}>
        {data?.items?.length ? (
          <table className="w-full">
            <thead><tr>{['Type', 'What we found', 'Where', 'Source', 'Last seen', 'Status', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {data.items.map((f: any) => (
                <tr key={f.id}>
                  <td className="td text-xs">{TYPE_LABEL[f.type] ?? f.type.replace(/_/g, ' ')}</td>
                  <td className="td text-sm">
                    {f.summary}
                    {f.type === 'bypass_risk' && <div className="text-[11px] text-ink-3">detected in the runtime, not blocked: enforce with egress rules</div>}
                    {f.agent_id && <Link className="block text-[11px] text-royal hover:underline" to={`/agents/${f.agent_id}?tab=connection`}>open agent</Link>}
                  </td>
                  <td className="td mono text-xs">{f.location}{f.owner_hint ? <div className="text-ink-3">{f.owner_hint}</div> : null}</td>
                  <td className="td text-xs">{f.source}</td>
                  <td className="td text-xs">{ago(f.last_seen)}</td>
                  <td className="td"><Pill value={f.status === 'open' ? 'require_approval' : f.status === 'blocked' ? 'deny' : 'allow'} label={f.status} /></td>
                  <td className="td whitespace-nowrap">
                    {f.status === 'open' && can('discovery.write') && (
                      <>
                        <button className="mr-1 text-xs text-royal hover:underline" onClick={() => void resolve(f.id, 'migrated')}>Migrated</button>
                        <button className="mr-1 text-xs text-bad hover:underline" onClick={() => void resolve(f.id, 'blocked')}>Block</button>
                        <button className="text-xs text-ink-3 hover:underline" onClick={() => void resolve(f.id, 'dismissed')}>Dismiss</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty>Nothing found yet. Findings appear when a source below delivers data.</Empty>
        )}
      </Card>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Card title="Sources" pad={false}>
          <table className="w-full">
            <tbody>
              {sources.map((s: any) => (
                <tr key={s.id}>
                  <td className="td text-sm">{s.label}</td>
                  <td className="td"><Pill value={s.connected ? 'allow' : 'none'} label={s.connected ? 'delivering' : 'not connected'} /></td>
                  <td className="td text-xs text-ink-2">{s.connected ? `last ${ago(s.last_ingest_at)} · ${s.total} records` : s.id === 'keysweep' ? 'run npm run keysweep -- <dir> --upload' : s.id === 'sdk-diagnostics' ? 'reported when an agent starts with the SDK' : 'upload an export below'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="px-4 py-3 text-xs text-ink-3">Live connectors to SaaS admin APIs and proxy log streams are not built yet; exports are uploaded here.</p>
        </Card>
        {can('discovery.write') && (
          <Card title="Upload network or SaaS audit logs">
            <div className="grid gap-2 md:grid-cols-2">
              <select className="input" value={upload.source} onChange={(e) => setUpload({ ...upload, source: e.target.value })}>
                <option value="network-logs">Network logs (proxy, DNS, firewall)</option>
                <option value="saas-audit">SaaS audit logs</option>
              </select>
              <input className="input" placeholder="Signet gateway egress hosts to skip (comma-separated)" value={upload.gateway_hosts} onChange={(e) => setUpload({ ...upload, gateway_hosts: e.target.value })} />
            </div>
            <input
              type="file"
              accept=".csv,.json,.jsonl,.txt"
              className="mt-2 text-xs"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void f.text().then((text) => setUpload((u) => ({ ...u, text })));
              }}
            />
            <textarea className="input mono mt-2 min-h-28 text-xs" placeholder={'ts,src,user,host\n2026-11-02T09:14:00Z,build-runner-7,,api.openai.com'} value={upload.text} onChange={(e) => setUpload({ ...upload, text: e.target.value })} />
            <div className="mt-2 flex items-center gap-2">
              <button className="btn-primary" disabled={!upload.text.trim()} onClick={() => void send()}>Analyse</button>
              {result && <span className="text-xs text-ink-2">{result.received} records · {result.ai_matches} to AI providers · {result.new} new findings</span>}
            </div>
            <div className="mt-2"><ErrorNote error={error as any} /></div>
            <p className="mt-2 text-xs text-ink-3">Matched against {src?.providers?.length ?? 0} AI provider endpoints and apps. Columns: ts, src (host or IP), user, and host or url.</p>
          </Card>
        )}
      </div>
    </>
  );
}

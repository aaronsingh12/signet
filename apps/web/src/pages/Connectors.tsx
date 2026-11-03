import { useState } from 'react';
import { Card, Empty, ErrorNote, KV, Mono, PageHeader, Pill } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago } from '../lib/format';
import { EdgeRunners } from '../components/EdgeRunners';
import { ExternalConnections, IdentityConnections } from '../components/ExternalConnections';

// GRC connectors (BP 10): ServiceNow gets risks, CIs, control tests, indicator results, issues and
// incidents through an outbox with retries; its authority documents come back into the library.

export function Connectors() {
  const can = useCan();
  const { data, reload } = useApi<any>('/connectors');
  const [selected, setSelected] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const items = data?.items ?? [];
  const current = items.find((c: any) => c.id === selected) ?? items[0];
  return (
    <>
      <PageHeader
        title="Connectors"
        subtitle="Signet pushes governance records to ServiceNow GRC and pulls its authority documents. The credential sits in the Secrets Broker; every sync is ledgered."
        actions={can('connectors.manage') && <button className="btn-primary" onClick={() => setAdding(true)}>Connect ServiceNow</button>}
      />
      {adding && <NewConnector onDone={() => (setAdding(false), void reload())} onCancel={() => setAdding(false)} />}
      <div className="mb-4"><ExternalConnections agentId={null} /></div>
      <div className="mb-4"><IdentityConnections /></div>
      <div className="mb-4"><EdgeRunners /></div>
      {items.length ? (
        <div className="grid gap-4 xl:grid-cols-[320px_1fr]">
          <Card pad={false}>
            <ul className="divide-y divide-line">
              {items.map((c: any) => (
                <li key={c.id}>
                  <button className={`block w-full px-4 py-3 text-left hover:bg-canvas ${current?.id === c.id ? 'bg-royal-50' : ''}`} onClick={() => setSelected(c.id)}>
                    <div className="text-sm font-medium">{c.name}</div>
                    <div className="mt-0.5 text-xs text-ink-2">{c.config.instance_url}</div>
                    <div className="mt-1 flex gap-2 text-[11px]"><Pill value={c.status === 'ok' ? 'allow' : c.status === 'error' ? 'deny' : 'none'} label={c.status} /> {Object.entries(c.queue ?? {}).map(([k, n]) => `${k} ${n}`).join(' · ')}</div>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
          {current && <ConnectorDetail c={current} onChange={() => void reload()} />}
        </div>
      ) : (
        !adding && <Card><Empty>No connector yet.</Empty></Card>
      )}
    </>
  );
}

function NewConnector({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const [f, setF] = useState({ name: '', instance_url: '', auth: 'oauth_client_credentials', client_id: '', username: '', secret: '' });
  const [error, setError] = useState<ApiError | null>(null);
  const save = async () => {
    try {
      await api('/connectors', { method: 'POST', body: f });
      onDone();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <Card title="Connect ServiceNow" className="mb-4">
      <div className="grid gap-3 md:grid-cols-2">
        <div><label className="label">Name</label><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Northwind ServiceNow" /></div>
        <div><label className="label">Instance URL</label><input className="input" value={f.instance_url} onChange={(e) => setF({ ...f, instance_url: e.target.value })} placeholder="https://northwind.service-now.com" /></div>
        <div>
          <label className="label">Authentication</label>
          <select className="input" value={f.auth} onChange={(e) => setF({ ...f, auth: e.target.value })}>
            <option value="oauth_client_credentials">OAuth client credentials</option>
            <option value="basic">Basic (proof of concept only)</option>
          </select>
        </div>
        {f.auth === 'basic' ? (
          <div><label className="label">Username</label><input className="input" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></div>
        ) : (
          <div><label className="label">Client ID</label><input className="input" value={f.client_id} onChange={(e) => setF({ ...f, client_id: e.target.value })} /></div>
        )}
        <div className="md:col-span-2"><label className="label">{f.auth === 'basic' ? 'Password' : 'Client secret'} (stored in the Secrets Broker, never shown again)</label><input className="input" type="password" value={f.secret} onChange={(e) => setF({ ...f, secret: e.target.value })} /></div>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <button className="btn-primary" disabled={!f.instance_url || !f.secret} onClick={() => void save()}>Save</button>
        <button className="btn-ghost" onClick={onCancel}>Cancel</button>
        <ErrorNote error={error} />
      </div>
    </Card>
  );
}

function ConnectorDetail({ c, onChange }: { c: any; onChange: () => void }) {
  const can = useCan();
  const [status, setStatus] = useState('');
  const { data: ob, reload } = useApi<any>(can('connectors.manage') ? `/connectors/${c.id}/outbox${status ? `?status=${status}` : ''}` : null, [c.id, status]);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const act = async (path: string, label: string) => {
    try {
      const r = await api(path, { method: 'POST' });
      setResult({ label, r });
      setError(null);
      onChange();
      void reload();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <div className="space-y-4">
      <Card
        title={c.name}
        action={
          can('connectors.manage') && (
            <div className="flex gap-2">
              <button className="btn-ghost" onClick={() => void act(`/connectors/${c.id}/test`, 'Self-test')}>Self-test</button>
              <button className="btn-ghost" onClick={() => void act(`/connectors/${c.id}/pull`, 'Library pull')}>Pull library</button>
            </div>
          )
        }
      >
        <KV rows={[['Instance', c.config.instance_url], ['Auth', c.config.auth.replace(/_/g, ' ')], ['Status', c.status], ['Last sync', ago(c.last_sync_at)], ['Library watermark', c.watermark ?? '—'], ['Correlation', <Mono key="m">signet:{c.tenant}:&lt;object&gt;:&lt;id&gt;</Mono>]]} />
        {result && (
          <div className="mt-3 rounded-md bg-canvas p-3 text-xs">
            <div className="font-medium">{result.label}</div>
            {result.r.checks ? result.r.checks.map((x: any) => <div key={x.check}>{x.ok ? '✓' : '✗'} {x.check}{x.detail ? ` · ${x.detail}` : ''}</div>) : <pre className="mono">{JSON.stringify(result.r, null, 2)}</pre>}
          </div>
        )}
        <div className="mt-2"><ErrorNote error={error} /></div>
      </Card>
      {ob && (
        <Card pad={false} title="Outbox" action={<select className="input w-36" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All</option><option value="pending">Pending</option><option value="sent">Sent</option><option value="dead">Dead letters</option></select>}>
          {ob.items.length ? (
            <table className="w-full">
              <thead><tr>{['Event', 'Object', 'Status', 'Attempts', 'ServiceNow ref', 'Created', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>
                {ob.items.map((e: any) => (
                  <tr key={e.id}>
                    <td className="td mono text-xs">{e.event}</td>
                    <td className="td mono text-[11px] text-ink-2">{e.object_key.split(':').slice(2).join(':')}</td>
                    <td className="td"><Pill value={e.status === 'sent' ? 'allow' : e.status === 'dead' ? 'deny' : 'require_approval'} label={e.status} />{e.last_error && <div className="text-[11px] text-bad">{e.last_error}</div>}</td>
                    <td className="td text-xs">{e.attempts}</td>
                    <td className="td mono text-[11px]">{e.external_ref ?? '—'}</td>
                    <td className="td text-xs text-ink-2">{ago(e.created_at)}</td>
                    <td className="td">{e.status === 'dead' && <button className="btn-ghost text-xs" onClick={() => void act(`/outbox/${e.id}/retry`, 'Retry')}>Retry</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>Nothing in the outbox.</Empty>
          )}
        </Card>
      )}
    </div>
  );
}

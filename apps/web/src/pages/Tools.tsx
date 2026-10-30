import { useState } from 'react';
import { Card, Empty, ErrorNote, Mono, PageHeader } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago } from '../lib/format';

// Tool aliases and the Secrets Broker (BP 3 C9, 5.1). Values are write-only: no API returns them.
export function Tools() {
  const can = useCan();
  const { data: tools, reload: reloadTools } = useApi<any>('/tools');
  const { data: secrets, reload: reloadSecrets } = useApi<any>(can('secrets.manage') ? '/secrets' : null);
  const [sec, setSec] = useState({ name: '', kind: 'tool', value: '' });
  const [tool, setTool] = useState({ alias: '', kind: 'mcp', url: '', secret: '', actions: '' });
  const [error, setError] = useState<ApiError | null>(null);
  const run = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setError(null);
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <>
      <PageHeader title="Tools & secrets" subtitle="Agents call aliases through the gateway; the real address and credential live only here. Agents never hold keys (RB-INV-03)." />
      <ErrorNote error={error} />
      <div className="mt-2 grid gap-4 xl:grid-cols-2">
        <Card title="Tool aliases" pad={false}>
          {tools?.items?.length ? (
            <table className="w-full">
              <thead><tr>{['Alias', 'URL', 'Credential', 'Actions'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>
                {tools.items.map((t: any) => (
                  <tr key={t.alias}>
                    <td className="td mono">{t.kind}://{t.alias}</td>
                    <td className="td mono text-xs">{t.url}</td>
                    <td className="td mono text-xs">{t.secret_id ?? 'none'}</td>
                    <td className="td text-xs">{t.kind === 'http' ? Object.entries(t.actions).map(([k, v]: any) => `${k} (${v.method} ${v.path})`).join(', ') : 'from tools/list, filtered by each seal'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>No tools registered.</Empty>
          )}
          {can('tools.manage') && (
            <div className="grid gap-2 border-t border-line p-4 md:grid-cols-2">
              <input className="input mono" placeholder="alias" value={tool.alias} onChange={(e) => setTool({ ...tool, alias: e.target.value })} />
              <select className="input" value={tool.kind} onChange={(e) => setTool({ ...tool, kind: e.target.value })}>
                <option value="mcp">MCP (Streamable HTTP)</option>
                <option value="http">HTTP API</option>
              </select>
              <input className="input mono md:col-span-2" placeholder="https://tool.internal/mcp" value={tool.url} onChange={(e) => setTool({ ...tool, url: e.target.value })} />
              <input className="input mono" placeholder="secret name (optional)" value={tool.secret} onChange={(e) => setTool({ ...tool, secret: e.target.value })} />
              {tool.kind === 'http' && <input className="input mono" placeholder='{"get_customer":{"method":"GET","path":"/customers/{id}"}}' value={tool.actions} onChange={(e) => setTool({ ...tool, actions: e.target.value })} />}
              <button
                className="btn-primary md:col-span-2"
                onClick={() => void run(async () => {
                  await api('/tools', { method: 'POST', body: { ...tool, secret: tool.secret || null, actions: tool.actions ? JSON.parse(tool.actions) : undefined } });
                  setTool({ alias: '', kind: 'mcp', url: '', secret: '', actions: '' });
                  void reloadTools();
                })}
              >
                Register tool alias
              </button>
            </div>
          )}
        </Card>
        <Card title="Secrets Broker" pad={false}>
          {!can('secrets.manage') ? (
            <Empty>Platform admins manage brokered credentials.</Empty>
          ) : secrets?.items?.length ? (
            <table className="w-full">
              <thead><tr>{['Name', 'Kind', 'Fingerprint', 'Version', 'Rotation'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>
                {secrets.items.map((s: any) => (
                  <tr key={s.id}>
                    <td className="td mono">{s.name}</td>
                    <td className="td text-xs">{s.kind}</td>
                    <td className="td"><Mono>{s.fingerprint}</Mono></td>
                    <td className="td">v{s.version} · {ago(s.rotated_at ?? s.created_at)}</td>
                    <td className="td text-xs">
                      {s.rotation_due ? <span className="text-bad">due: {s.rotation_due}</span> : 'ok'}
                      <button className="ml-2 text-royal hover:underline" onClick={() => {
                        const value = prompt(`New value for ${s.name} (stored sealed; never shown again)`);
                        if (value) void run(async () => (await api(`/secrets/${s.id}/rotate`, { method: 'POST', body: { value } }), void reloadSecrets()));
                      }}>Rotate</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>No secrets stored.</Empty>
          )}
          {can('secrets.manage') && (
            <div className="grid gap-2 border-t border-line p-4 md:grid-cols-3">
              <input className="input mono" placeholder="name" value={sec.name} onChange={(e) => setSec({ ...sec, name: e.target.value })} />
              <select className="input" value={sec.kind} onChange={(e) => setSec({ ...sec, kind: e.target.value })}>
                <option value="tool">tool credential</option>
                <option value="llm_provider">LLM provider key</option>
              </select>
              <input className="input mono" type="password" placeholder="value (write-only)" value={sec.value} onChange={(e) => setSec({ ...sec, value: e.target.value })} />
              <button className="btn-primary md:col-span-3" onClick={() => void run(async () => (await api('/secrets', { method: 'POST', body: sec }), setSec({ name: '', kind: 'tool', value: '' }), void reloadSecrets()))}>
                Store in broker
              </button>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}

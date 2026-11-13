import { useEffect, useState } from 'react';
import type { ToolAlias } from '@signet/core/types';
import { Card, ErrorNote, Pill } from './ui';
import { CopyCode } from './CopyCode';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { downloadJson } from '../lib/download';

interface Runner { id: string; name: string; status: 'online' | 'offline' | 'revoked'; last_seen_at: string | null }
interface Enrollment { id: string; runner_secret: string }

/** Enroll an outbound runner and register its private HTTP destinations without editing JSON by hand. */
export function EdgeRunners() {
  const can = useCan();
  const { data, error: loadError, reload } = useApi<{ items: Runner[] }>('/edge-runners');
  const { data: tools, reload: reloadTools } = useApi<{ items: ToolAlias[] }>('/tools');
  const { data: info } = useApi<{ control_url: string }>('/connect/info');
  const [name, setName] = useState('');
  const [selected, setSelected] = useState('');
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [tool, setTool] = useState({ alias: '', url: '', action: '', method: 'GET', path: '/', credential: '', auth_header: 'authorization' });
  const [pairingSecret, setPairingSecret] = useState('');
  const [credentialEdits, setCredentialEdits] = useState<Record<string, string>>({});
  useEffect(() => { const timer = window.setInterval(() => void reload(), 5000); return () => window.clearInterval(timer); }, [reload]);
  const runners = data?.items.filter((runner) => runner.status !== 'revoked') ?? [];
  const active = selected || runners[0]?.id || '';
  const localTools = tools?.items.filter((item) => item.runner_id === active) ?? [];
  const act = async (action: () => Promise<void>): Promise<void> => {
    setBusy(true);
    try { await action(); setError(null); await reload(); }
    catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  return <Card title="On-prem connector runners">
    <p className="mb-3 text-sm text-ink-2">Run this worker inside your private network. It polls Signet outbound, executes only locally allowlisted HTTP actions, and returns results through the governed gateway. No inbound firewall port is required.</p>
    {can('connectors.manage') && <div className="mb-4 flex gap-2"><input data-testid="edge-runner-name" aria-label="Runner name" className="input" value={name} onChange={(event) => setName(event.target.value)} placeholder="Office network runner" /><button data-testid="edge-enroll" className="btn-primary whitespace-nowrap" disabled={busy || !name.trim()} onClick={() => void act(async () => { const created = await api<Enrollment>('/edge-runners', { method: 'POST', body: { name } }); setEnrollment(created); setSelected(created.id); setPairingSecret(''); setName(''); })}>Enroll runner</button></div>}
    <ErrorNote error={error ?? loadError} />
    <div className="space-y-2">{data?.items.map((runner) => <div key={runner.id} className="flex flex-wrap items-center gap-3 rounded border border-line px-3 py-2 text-sm"><span className="font-medium">{runner.name}</span><Pill value={runner.status === 'online' ? 'allow' : runner.status === 'revoked' ? 'deny' : 'none'} label={runner.status} /><span className="mono text-xs text-ink-3">{runner.id}</span>{can('connectors.manage') && runner.status !== 'revoked' && <button data-testid={`edge-revoke-${runner.id}`} className="ml-auto text-xs text-bad" disabled={busy} onClick={() => void act(async () => { await api(`/edge-runners/${runner.id}/revoke`, { method: 'POST' }); if (selected === runner.id) setSelected(''); if (enrollment?.id === runner.id) setEnrollment(null); })}>Revoke</button>}</div>)}</div>
    {!!runners.length && <div className="mt-4 space-y-3">
      <label className="label" htmlFor="edge-selected">Configure runner</label><select id="edge-selected" data-testid="edge-selected" className="input" value={active} onChange={(event) => { setSelected(event.target.value); setPairingSecret(''); setCredentialEdits({}); }}>{runners.map((runner) => <option key={runner.id} value={runner.id}>{runner.name}</option>)}</select>
      {can('tools.manage') && can('secrets.manage') && <details className="rounded-lg border border-line p-3" open={!localTools.length}><summary className="cursor-pointer text-sm font-medium">1. Add a private REST API</summary><div className="mt-3 grid gap-3 md:grid-cols-2">
        <div><label className="label" htmlFor="edge-tool-alias">Tool alias</label><input id="edge-tool-alias" data-testid="edge-tool-alias" className="input" value={tool.alias} placeholder="internal-records" onChange={(event) => setTool({ ...tool, alias: event.target.value })} /></div>
        <div><label className="label" htmlFor="edge-tool-url">Private base URL</label><input id="edge-tool-url" data-testid="edge-tool-url" className="input" value={tool.url} placeholder="http://records.internal:8080" onChange={(event) => setTool({ ...tool, url: event.target.value })} /></div>
        <div><label className="label" htmlFor="edge-tool-action">Action name</label><input id="edge-tool-action" data-testid="edge-tool-action" className="input" value={tool.action} placeholder="get-record" onChange={(event) => setTool({ ...tool, action: event.target.value })} /></div>
        <div><label className="label" htmlFor="edge-tool-method">HTTP method</label><select id="edge-tool-method" data-testid="edge-tool-method" className="input" value={tool.method} onChange={(event) => setTool({ ...tool, method: event.target.value })}>{['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((method) => <option key={method}>{method}</option>)}</select></div>
        <div className="md:col-span-2"><label className="label" htmlFor="edge-tool-path">Action path</label><input id="edge-tool-path" data-testid="edge-tool-path" className="input mono" value={tool.path} placeholder="/records/{id}" onChange={(event) => setTool({ ...tool, path: event.target.value })} /></div>
        <label className="label">API key / token (optional)<input data-testid="edge-tool-credential" className="input" type="password" autoComplete="new-password" value={tool.credential} onChange={(event) => setTool({ ...tool, credential: event.target.value })} /></label>
        <label className="label">Credential header<select data-testid="edge-tool-auth-header" className="input" value={tool.auth_header} onChange={(event) => setTool({ ...tool, auth_header: event.target.value })}><option value="authorization">Authorization: Bearer token</option><option value="x-api-key">x-api-key</option></select></label>
        <button data-testid="edge-register-tool" className="btn-primary md:col-span-2" disabled={busy || !tool.alias || !tool.url || !tool.action || !tool.path} onClick={() => void act(async () => { await api(`/edge-runners/${active}/tools`, { method: 'POST', body: { alias: tool.alias, url: tool.url, credential: tool.credential, auth_header: tool.auth_header, actions: { [tool.action]: { method: tool.method, path: tool.path } } } }); setTool({ alias: '', url: '', action: '', method: 'GET', path: '/', credential: '', auth_header: 'authorization' }); await reloadTools(); })}>Save private tool and credentials</button>
      </div><p className="mt-2 text-xs text-ink-3">Registration does not grant agents access. Add this tool and action to the agent's approved manifest.</p></details>}
      {!!localTools.length && <div className="space-y-3 rounded-lg border border-line p-3">
        <p className="text-sm font-medium">2. Download this runner's connection file</p>
        <p className="text-xs text-ink-3">API credentials stay encrypted in Signet's database. The paired runner reads the latest credential for its assigned tools on each request, after checking its local destination allowlist.</p>
        {enrollment?.id !== active && <label className="label">Runner enrollment secret<input data-testid="edge-pairing-secret" className="input" type="password" autoComplete="off" value={pairingSecret} onChange={(event) => setPairingSecret(event.target.value)} /><span className="text-xs text-ink-3">Use the secret saved at enrollment. If it was lost, revoke this runner and enroll a new one.</span></label>}
        <button type="button" data-testid="edge-download-config" className="btn-primary" disabled={!info?.control_url || !(enrollment?.id === active ? enrollment.runner_secret : pairingSecret)} onClick={() => downloadJson('signet-runner.json', JSON.stringify({ version: 1, control_url: info!.control_url, runner_id: active, runner_secret: enrollment?.id === active ? enrollment.runner_secret : pairingSecret, private_destinations: 'allow', tools: localTools.map((item) => ({ alias: item.alias, url: item.url, actions: item.actions, auth_header: item.auth_header, credential_source: 'broker' })) }, null, 2))}>Download signet-runner.json</button>
        <CopyCode testId="edge-start-from-file" text="npm run edge -- --config signet-runner.json" />
        <p className="text-xs text-ink-3">Run once inside your private network. No .env edit is required. Download a new allowlist after adding or changing tool destinations; credential rotations take effect without restarting the runner.</p>
        {can('secrets.manage') && localTools.map((item) => <div key={item.alias} className="flex flex-wrap items-end gap-2"><label className="label flex-1">Update {item.alias} credential<input data-testid={`edge-rotate-${item.alias}`} className="input" type="password" autoComplete="new-password" value={credentialEdits[item.alias] ?? ''} onChange={(event) => setCredentialEdits({ ...credentialEdits, [item.alias]: event.target.value })} /></label><button type="button" data-testid={`edge-save-credential-${item.alias}`} className="btn-ghost" disabled={busy || !credentialEdits[item.alias]} onClick={() => void act(async () => { await api(`/edge-runners/${active}/tools/${item.alias}/credential`, { method: 'PUT', body: { credential: credentialEdits[item.alias] } }); setCredentialEdits({ ...credentialEdits, [item.alias]: '' }); await reloadTools(); })}>Save credential</button></div>)}
      </div>}
      <details className="rounded-lg border border-line p-3"><summary className="text-sm">Existing environment-based runner setup</summary><div className="mt-3 space-y-3">
      {!!localTools.length && <><p className="text-sm font-medium">2. Save this local allowlist as edge-tools.json</p><CopyCode testId="edge-tools-config" text={JSON.stringify(localTools.map((item) => ({ alias: item.alias, url: item.url, actions: item.actions })), null, 2)} /><p className="text-xs text-ink-3">For authenticated tools, add <code>"token_env": "YOUR_LOCAL_TOKEN_VARIABLE"</code> and optionally <code>"auth_header": "x-api-key"</code> to the local tool definition. Keep the token value on the runner machine.</p></>}
      <p className="text-sm font-medium">3. Set these environment variables on the runner machine</p>
      <CopyCode testId="edge-enrollment-config" text={`SIGNET_CONTROL_URL=${info?.control_url ?? '<control-url>'}\nSIGNET_EDGE_RUNNER_ID=${active}\nSIGNET_EDGE_RUNNER_SECRET=${enrollment?.id === active ? enrollment.runner_secret : '<runner-secret-shown-at-enrollment>'}\nSIGNET_EDGE_TOOLS_FILE=./edge-tools.json\nSIGNET_TOOL_PRIVATE_DESTINATIONS=allow`} />
      {enrollment && <button data-testid="edge-hide-secret" className="text-xs text-royal" onClick={() => setEnrollment(null)}>Hide runner secret</button>}
      <CopyCode testId="edge-start-command" text="npm run edge" />
      <p className="text-xs text-ink-3">Run from your Signet checkout. Runner status turns online after its first poll. It supports HTTP tools, limits each response to 512 KB and never replays a private API operation automatically. Cloud metadata and link-local destinations stay blocked.</p>
      </div></details>
    </div>}
  </Card>;
}

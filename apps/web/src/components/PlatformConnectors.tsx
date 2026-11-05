import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, Empty, ErrorNote, Modal, Pill } from './ui';
import { ApiError, api, useApi } from '../lib/api';
import { ago } from '../lib/format';

// Platform connectors: connect Vercel, AWS, Azure or Google Cloud once; see the workloads there that use
// an AI provider or are AI agents themselves; register them as agents; and, where the platform allows,
// connect one to Signet with no code change (settings changed, old key removed, restarted). An agent
// shows Connected only after its first call actually reaches the gateway.

type Platform = 'vercel' | 'aws' | 'azure' | 'gcp' | 'copilot' | 'openai' | 'anthropic';
interface Signal { name: string; provider: string; kind: 'key' | 'base_url' | 'model' | 'platform' }
interface Workload { id: string; name: string; kind: string; framework: string | null; url: string | null; region: string | null; env_names: string[]; platform_ai: string | null; linkable: boolean; ai_signals: Signal[]; linked_agent_id: string | null; link_state: string | null; registered_agent_id: string | null }
interface Connection { id: string; platform: Platform; label: string; status: string; status_detail: string | null; last_scan_at: string | null }

const NAMES: Record<Platform, string> = { vercel: 'Vercel', aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud', copilot: 'Copilot Studio', openai: 'OpenAI', anthropic: 'Anthropic' };
const FIELDS: Record<Platform, { key: string; label: string; secret?: boolean; area?: boolean; optional?: boolean }[]> = {
  vercel: [{ key: 'token', label: 'Access token (Account settings → Tokens)', secret: true }, { key: 'team_id', label: 'Team ID', optional: true }],
  aws: [{ key: 'access_key_id', label: 'Access key ID' }, { key: 'secret_access_key', label: 'Secret access key', secret: true }, { key: 'regions', label: 'Regions, comma-separated', optional: true }],
  azure: [{ key: 'tenant_id', label: 'Tenant ID' }, { key: 'client_id', label: 'App (client) ID' }, { key: 'client_secret', label: 'Client secret', secret: true }, { key: 'subscription_id', label: 'Subscription ID' }],
  gcp: [{ key: 'service_account_json', label: 'Service account key (JSON)', area: true }, { key: 'regions', label: 'Regions, comma-separated', optional: true }],
  copilot: [{ key: 'environment_url', label: 'Environment URL (https://<org>.crm.dynamics.com)' }, { key: 'tenant_id', label: 'Tenant ID' }, { key: 'client_id', label: 'App (client) ID' }, { key: 'client_secret', label: 'Client secret', secret: true }],
  openai: [{ key: 'admin_key', label: 'Organization admin key', secret: true }],
  anthropic: [{ key: 'admin_key', label: 'Organization admin key', secret: true }],
};
const HELP: Record<Platform, string> = {
  vercel: 'Lists projects and their environment variable names; connects a project by setting its variables and redeploying.',
  aws: 'Read access lists Bedrock agents and Lambda functions; lambda:UpdateFunctionConfiguration lets Signet connect a function.',
  azure: 'Reader lists Azure OpenAI, AI Foundry and App Service; Website Contributor lets Signet connect an App Service app.',
  gcp: 'Viewer lists Vertex AI Agent Engine agents and Cloud Run services (Cloud Run connect is not built yet).',
  copilot: 'Lists Copilot Studio agents from the Dataverse environment (the app registration needs an application user there).',
  openai: 'Lists projects and API keys used directly against OpenAI, with their owners and usage; can delete a key.',
  anthropic: 'Lists API keys used directly against Anthropic, with usage; can set a key inactive.',
};
const STATE_LABEL: Record<string, [string, string]> = {
  registered: ['none', 'registered'],
  configuring: ['require_approval', 'configuring'],
  configured: ['allow_with_obligations', 'settings saved'],
  redeploying: ['require_approval', 'restarting'],
  connected_pending_traffic: ['allow', 'connected'],
  failed: ['deny', 'failed'],
  stopped: ['kill', 'stopped on platform'],
};
const STOPPABLE = new Set(['vercel_project', 'lambda', 'app_service', 'api_key']);

export function PlatformConnectors() {
  const { data, reload, error } = useApi<{ items: Connection[] }>('/platforms');
  const [platform, setPlatform] = useState<Platform>('vercel');
  const [form, setForm] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const connect = async () => {
    setBusy(true);
    try {
      await api('/platforms', { method: 'POST', body: { platform, ...form } });
      setForm({});
      setFormError(null);
      void reload();
    } catch (e) {
      setFormError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const ready = FIELDS[platform].every((f) => f.optional || (form[f.key] ?? '').trim());
  return (
    <Card title="Platforms → Signet (discover and connect without code)" className="mt-4">
      <ErrorNote error={error} />
      {(data?.items ?? []).map((c) => <PlatformConnection key={c.id} c={c} onChange={() => void reload()} />)}
      <div className={(data?.items ?? []).length ? 'mt-4 border-t border-line pt-4' : ''}>
        <div className="mb-2 flex flex-wrap gap-2">
          {(Object.keys(NAMES) as Platform[]).map((p) => (
            <button key={p} onClick={() => (setPlatform(p), setForm({}), setFormError(null))} className={`rounded-md px-3 py-1.5 text-sm ${platform === p ? 'bg-royal text-white' : 'bg-canvas text-ink-2 hover:bg-slate-200'}`}>{NAMES[p]}</button>
          ))}
        </div>
        <p className="text-xs text-ink-3">{HELP[platform]} The credential goes to the Secrets Broker; gateways can never read it.</p>
        <div className="mt-2 grid gap-2 md:grid-cols-2">
          {FIELDS[platform].map((f) => f.area ? (
            <textarea key={f.key} className="input mono min-h-24 text-xs md:col-span-2" placeholder={f.label} value={form[f.key] ?? ''} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />
          ) : (
            <input key={f.key} className="input" type={f.secret ? 'password' : 'text'} placeholder={`${f.label}${f.optional ? ' (optional)' : ''}`} value={form[f.key] ?? ''} onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />
          ))}
          <input className="input" placeholder="Label (optional)" value={form.label ?? ''} onChange={(e) => setForm({ ...form, label: e.target.value })} />
        </div>
        <button className="btn-primary mt-2" disabled={busy || !ready} onClick={() => void connect()}>{busy ? 'Checking…' : `Connect ${NAMES[platform]}`}</button>
        <div className="mt-2"><ErrorNote error={formError} /></div>
      </div>
    </Card>
  );
}

function PlatformConnection({ c, onChange }: { c: Connection; onChange: () => void }) {
  const { data, reload, error, loading } = useApi<{ items: Workload[] }>(`/platforms/${c.id}/workloads`, [c.id]);
  const [linking, setLinking] = useState<Workload | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const runScan = async () => {
    const r = await api<{ workloads: number; ai_workloads: number; new_findings: number }>(`/platforms/${c.id}/scan`, { method: 'POST' });
    setNote(`${r.workloads} workloads, ${r.ai_workloads} use or are AI, ${r.new_findings} sent to the Discovery Inbox`);
    onChange();
  };
  const register = async (w: Workload) => {
    try {
      const r = await api<{ agent_id: string; handle: string }>(`/platforms/${c.id}/workloads/${encodeURIComponent(w.id)}/register`, { method: 'POST' });
      setNote(`${w.name} registered as ${r.handle}; complete its proposal on the agent's Lifecycle tab`);
      setActionError(null);
      void reload();
    } catch (e) {
      setActionError(e as ApiError);
    }
  };
  const stopOnPlatform = async (w: Workload) => {
    const reason = prompt(`Stop ${w.name} on ${NAMES[c.platform]}? This pauses or disables it there. Reason (goes to the ledger):`);
    if (!reason) return;
    try {
      const r = await api<{ result: string }>(`/platforms/${c.id}/workloads/${encodeURIComponent(w.id)}/stop`, { method: 'POST', body: { reason } });
      setNote(`${w.name}: ${r.result}`);
      setActionError(null);
      void reload();
    } catch (e) {
      setActionError(e as ApiError);
    }
  };
  const syncUsage = async () => {
    const r = await api<{ rows: number; supported: boolean }>(`/platforms/${c.id}/usage/sync`, { method: 'POST', body: { days: 30 } });
    setNote(r.supported ? `${r.rows} daily usage rows pulled (last 30 days)` : `${NAMES[c.platform]} does not report usage to Signet yet`);
  };
  const disconnect = async () => {
    if (!confirm(`Disconnect ${c.label}? Workloads already connected keep running through Signet.`)) return;
    await api(`/platforms/${c.id}`, { method: 'DELETE' });
    onChange();
  };
  const items = (data?.items ?? []).sort((a, b) => b.ai_signals.length - a.ai_signals.length);
  return (
    <div className="mb-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold">{c.label}</span>
        <Pill value="allow" label={c.status} />
        <span className="text-xs text-ink-3">{c.status_detail}{c.last_scan_at ? ` · scanned ${ago(c.last_scan_at)}` : ''}</span>
        <span className="ml-auto flex gap-2">
          <button className="btn-ghost text-xs" onClick={() => void reload()}>Refresh</button>
          <button className="btn-ghost text-xs" onClick={() => void runScan()}>Scan for AI</button>
          {['openai', 'anthropic', 'aws', 'azure', 'gcp'].includes(c.platform) && <button className="btn-ghost text-xs" onClick={() => void syncUsage()}>Sync usage</button>}
          <button className="btn-ghost text-xs text-bad" onClick={() => void disconnect()}>Disconnect</button>
        </span>
      </div>
      {note && <p className="mt-1 text-xs text-ok">{note}</p>}
      <ErrorNote error={error ?? actionError} />
      {loading && !data ? <Empty>Reading workloads from {NAMES[c.platform]}…</Empty> : items.length ? (
        <table className="mt-2 w-full">
          <thead><tr>{['Workload', 'AI found (names only)', 'Signet', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {items.map((w) => (
              <tr key={w.id}>
                <td className="td"><div className="font-medium">{w.name}</div><div className="text-xs text-ink-3">{w.kind.replace('_', ' ')}{w.region ? ` · ${w.region}` : ''}{w.url ? ` · ${w.url}` : ''}</div></td>
                <td className="td text-xs">{w.ai_signals.length ? w.ai_signals.map((s) => <span key={s.name} className={`mr-1 inline-block rounded px-1.5 py-0.5 ${s.kind === 'platform' ? 'bg-royal-50 text-royal' : 'bg-canvas mono'}`}>{s.name}</span>) : <span className="text-ink-3">none</span>}</td>
                <td className="td text-xs">
                  {w.link_state ? <Pill value={STATE_LABEL[w.link_state]?.[0] ?? 'none'} label={STATE_LABEL[w.link_state]?.[1] ?? w.link_state} /> : w.registered_agent_id ? <Pill value="none" label="registered" /> : <span className="text-ink-3">not in Signet</span>}
                  {(w.linked_agent_id ?? w.registered_agent_id) && <Link className="ml-2 text-royal hover:underline" to={`/agents/${w.linked_agent_id ?? w.registered_agent_id}`}>agent</Link>}
                  {w.platform_ai && <div className="mt-1 text-ink-3">model runs inside {NAMES[c.platform]}: tools governed, model calls not intercepted</div>}
                </td>
                <td className="td whitespace-nowrap text-right">
                  {STOPPABLE.has(w.kind) && w.link_state !== 'stopped' && <button className="btn-ghost mr-1 text-xs text-bad" onClick={() => void stopOnPlatform(w)}>Stop on platform</button>}
                  {w.ai_signals.length > 0 && !w.registered_agent_id && w.kind !== 'api_key' && <button className="btn-ghost text-xs" onClick={() => void register(w)}>Register as agent</button>}
                  {w.linkable && w.ai_signals.some((s) => s.kind !== 'platform') && <button className="btn-primary ml-1 text-xs" onClick={() => setLinking(w)}>{w.linked_agent_id ? 'Reconnect' : 'Connect to Signet'}</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : <Empty>No workloads found.</Empty>}
      {linking && <LinkModal connectionId={c.id} platform={c.platform} workload={linking} onClose={() => setLinking(null)} onDone={() => (void reload(), onChange())} />}
    </div>
  );
}

function LinkModal({ connectionId, platform, workload, onClose, onDone }: { connectionId: string; platform: Platform; workload: Workload; onClose: () => void; onDone: () => void }) {
  const { data: agents } = useApi<{ items: { id: string; handle: string; name: string; cert_id: string | null; kind: string }[] }>('/agents?limit=100');
  const sealed = (agents?.items ?? []).filter((a) => a.cert_id && a.kind !== 'third_party');
  const firstOf = (kind: Signal['kind'], fallback: string) => workload.ai_signals.find((s) => s.kind === kind)?.name ?? fallback;
  const keyVar = workload.env_names.includes('OPENAI_API_KEY') ? 'OPENAI_API_KEY' : firstOf('key', 'OPENAI_API_KEY');
  const [f, setF] = useState({ agent_id: workload.registered_agent_id ?? '', base_url_var: firstOf('base_url', 'OPENAI_BASE_URL'), key_var: keyVar, model_var: firstOf('model', ''), redeploy: true });
  const [remove, setRemove] = useState<string[]>(workload.ai_signals.filter((s) => s.kind === 'key' && s.name !== keyVar).map((s) => s.name));
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<{ state: string; detail: string | null } | null>(null);
  const path = `/platforms/${connectionId}/workloads/${encodeURIComponent(workload.id)}/link`;
  useEffect(() => {
    if (!f.agent_id && sealed[0]) setF((x) => ({ ...x, agent_id: sealed[0]!.id }));
  }, [agents]);
  useEffect(() => {
    if (result?.state !== 'redeploying') return;
    const t = setInterval(() => void api<{ state: string; detail: string | null }>(path).then((r) => { setResult(r); if (r.state !== 'redeploying') onDone(); }), 4000);
    return () => clearInterval(t);
  }, [result?.state]);
  const submit = async () => {
    try {
      setResult(await api(path, { method: 'POST', body: { ...f, model_var: f.model_var || undefined, remove_vars: remove } }));
      setError(null);
      onDone();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <Modal title={`Connect ${workload.name} to Signet`} onClose={onClose} width="max-w-2xl">
      {result ? (
        <div className="space-y-3 text-sm">
          <Pill value={STATE_LABEL[result.state]?.[0] ?? 'none'} label={STATE_LABEL[result.state]?.[1] ?? result.state} />
          <p className="text-ink-2">{result.detail}</p>
          <p className="text-xs text-ink-3">Use the app's AI once. The agent's Connection tab turns Connected when that call reaches the gateway.</p>
          <button className="btn-ghost" onClick={onClose}>Close</button>
        </div>
      ) : (
        <div className="space-y-4 text-sm">
          <div>
            <label className="label">Signet agent (approved)</label>
            {sealed.length ? (
              <select className="input" value={f.agent_id} onChange={(e) => setF({ ...f, agent_id: e.target.value })}>{sealed.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.handle})</option>)}</select>
            ) : (
              <p className="text-ink-2">No approved agent yet. {workload.registered_agent_id ? <Link className="text-royal hover:underline" to={`/agents/${workload.registered_agent_id}?tab=lifecycle`}>Finish this workload's agent approval</Link> : <Link className="text-royal hover:underline" to={`/agents/new?name=${encodeURIComponent(workload.name)}&runtime=${platform}`}>Add an agent for it</Link>}, then come back.</p>
            )}
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <div><label className="label">Base URL variable</label><input className="input mono" value={f.base_url_var} onChange={(e) => setF({ ...f, base_url_var: e.target.value })} /></div>
            <div><label className="label">API key variable</label><input className="input mono" value={f.key_var} onChange={(e) => setF({ ...f, key_var: e.target.value })} /></div>
            <div><label className="label">Model variable (optional)</label><input className="input mono" value={f.model_var} onChange={(e) => setF({ ...f, model_var: e.target.value })} /></div>
          </div>
          <p className="text-xs text-ink-3">These must be the names the app reads. Signet sets them to the gateway URL, a Signet credential for this agent, and the tenant's model. An app hard-wired to its provider's SDK (for example the Groq SDK) also needs that SDK pointed at these variables.</p>
          {workload.ai_signals.some((s) => s.kind === 'key' && s.name !== f.key_var) && (
            <div>
              <label className="label">Remove these old provider keys (recommended, so the app cannot bypass Signet)</label>
              {workload.ai_signals.filter((s) => s.kind === 'key' && s.name !== f.key_var).map((s) => (
                <label key={s.name} className="mr-4 inline-flex items-center gap-1.5"><input type="checkbox" checked={remove.includes(s.name)} onChange={() => setRemove(remove.includes(s.name) ? remove.filter((x) => x !== s.name) : [...remove, s.name])} /> <span className="mono">{s.name}</span> ({s.provider})</label>
              ))}
            </div>
          )}
          <label className="flex items-center gap-2"><input type="checkbox" checked={f.redeploy} onChange={(e) => setF({ ...f, redeploy: e.target.checked })} /> {platform === 'vercel' ? 'Redeploy production now' : platform === 'azure' ? 'Restart the app now' : 'Apply now'}</label>
          <ErrorNote error={error} />
          <div className="flex justify-end gap-2">
            <button className="btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn-primary" disabled={!f.agent_id} onClick={() => void submit()}>Connect</button>
          </div>
        </div>
      )}
    </Modal>
  );
}

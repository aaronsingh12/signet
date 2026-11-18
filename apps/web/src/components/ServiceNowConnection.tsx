import { useState } from 'react';
import { ArrowUpRight, Link2, RefreshCw, ServerCog } from 'lucide-react';
import { Card, ErrorNote, Modal } from './ui';
import { EditServiceNowSetup, ServiceNowSetup } from './ServiceNowSetup';
import { ConnectionIcon } from './ConnectionIcon';
import { ServiceNowAgentCards } from './PlatformAgentCards';
import { ServiceNowAgents } from './ServiceNowAgents';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';

interface ServiceNowStatus {
  id: string;
  name?: string;
  configured: boolean;
  authorized: boolean;
  mcp_url: string | null;
  expires_at: number | null;
  monitoring: boolean;
  discovered_at: string | null;
  tools: { name: string; title: string; description: string }[];
}

function connectionDisplayName(connection: ServiceNowStatus): string {
  if (connection.name?.trim()) return connection.name;
  const endpoint = connection.mcp_url?.split('/').filter(Boolean).pop();
  if (!endpoint) return `ServiceNow connection ${connection.id.slice(-4)}`;
  return endpoint.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim().replace(/\s+/g, ' ').replace(/\b[a-z]/g, letter => letter.toUpperCase());
}

export function ServiceNowConnection() {
  const canManage = useCan()('tenant.admin');
  const { data, error, loading, reload } = useApi<{ items: ServiceNowStatus[] }>(canManage ? '/plugins/servicenow' : null);
  const [adding, setAdding] = useState(false);
  return <div className="space-y-4">
    <Card>
      <h2 className="text-base font-semibold">ServiceNow connections and AI agents</h2>
      {canManage ? <button type="button" data-testid="servicenow-add-connection" className="btn-primary mt-3" onClick={() => setAdding(true)}>Add ServiceNow AI Agents</button>
        : <p className="mt-2 text-sm text-ink-3">A Tenant Admin can manage these connections.</p>}
      {loading && <p role="status">Loading connections…</p>}
      <ErrorNote error={error} />
      {data && !data.items.length && <p className="mt-3 text-sm text-ink-3">No ServiceNow connections saved yet.</p>}
    </Card>
    <div className="grid grid-cols-[repeat(auto-fill,minmax(180px,220px))] gap-4">
      {data?.items.map(connection => <SavedServiceNowConnection key={connection.id} connection={connection} onChanged={() => { void reload(); }} />)}
      <ServiceNowAgentCards />
    </div>
    {adding && <Modal title="Add ServiceNow AI Agents" onClose={() => setAdding(false)}>
      <ServiceNowSetup onSaved={() => { void reload(); }} onCancel={() => setAdding(false)} />
    </Modal>}
  </div>;
}

function SavedServiceNowConnection({ connection: data, onChanged }: { connection: ServiceNowStatus; onChanged: () => void }) {
  const name = connectionDisplayName(data);
  const path = '/plugins/servicenow/connections/' + encodeURIComponent(data.id);
  const [expanded, setExpanded] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [editing, setEditing] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [discoveryError, setDiscoveryError] = useState<Error | null>(null);
  const discover = async (): Promise<void> => {
    setDiscovering(true);
    setDiscoveryError(null);
    try {
      await api(path + '/discover', { method: 'POST' });
      onChanged();
    } catch (failure) {
      setDiscoveryError(failure instanceof Error ? failure : new Error('ServiceNow discovery failed; reload and retry'));
    } finally {
      setDiscovering(false);
    }
  };
  const remove = async (): Promise<void> => {
    setRemoving(true);
    setDiscoveryError(null);
    try {
      await api(path, { method: 'DELETE' });
      onChanged();
    } catch (failure) {
      setDiscoveryError(failure instanceof Error ? failure : new Error('ServiceNow connection could not be removed'));
    } finally {
      setRemoving(false);
    }
  };
  return <Card className={`aspect-square [&>div]:h-full !bg-none ${data.authorized ? '!bg-ok-50 !border-ok/30' : '!bg-warn-50 !border-warn/30'}`} pad={false}>
    <section className="h-full" data-testid={`servicenow-mcp-connection-${data.id}`} aria-labelledby={`servicenow-mcp-heading-${data.id}`}>
      <button type="button" data-testid={`servicenow-open-connection-${data.id}`} className="flex h-full w-full flex-col items-start rounded-2xl p-4 text-left transition-colors hover:brightness-95 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2" aria-haspopup="dialog" onClick={() => setExpanded(!expanded)}>
        <span className="flex w-full items-start justify-between gap-2">
          <ConnectionIcon tone={data.authorized ? 'ok' : 'warn'}><ServerCog size={23} strokeWidth={1.8} /></ConnectionIcon>
          <ArrowUpRight size={16} aria-hidden="true" className="shrink-0 text-ink-3" />
        </span>
        <span id={`servicenow-mcp-heading-${data.id}`} className="mt-3 line-clamp-2 break-words text-sm font-semibold">{name}</span>
        <span className={`mt-2 rounded px-1.5 py-0.5 text-[11px] font-medium ${data.authorized ? 'bg-ok-50 text-ok' : 'bg-slate-100 text-ink-2'}`}>
          {data.authorized ? 'Authorized' : data.expires_at === null ? 'Not authorized' : 'Reauthorization required'}
        </span>
        <span className="mt-auto pt-3 text-xs text-ink-3">{data.tools.length} tools</span>
        <span className="mt-1 text-xs text-ink-2">View details</span>
      </button>
      {expanded && <Modal title={name} width="max-w-5xl" onClose={() => setExpanded(false)}>
      <p className="mt-1 text-sm text-ink-2">Connect to your ServiceNow MCP server and discover its available tools.</p>
      <ErrorNote error={discoveryError} />
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" data-testid={`servicenow-edit-settings-${data.id}`} className="btn-ghost" disabled={removing || discovering} onClick={() => setEditing(true)}>Edit connection settings</button>
        <button type="button" data-testid={`servicenow-remove-${data.id}`} className="btn-ghost text-bad" disabled={removing || discovering} onClick={() => void remove()}>{removing ? 'Removing…' : 'Remove connection'}</button>
      </div>
      {editing && <Modal title="ServiceNow connection settings" onClose={() => setEditing(false)}>
        <EditServiceNowSetup connectionId={data.id} onSaved={() => { setEditing(false); onChanged(); }} onCancel={() => setEditing(false)} />
      </Modal>}
      {data?.mcp_url && <p className="mt-3 break-all text-xs text-ink-3">{data.mcp_url}</p>}
      {data?.configured && <div className="mt-3 flex flex-wrap gap-2">
        <a data-testid={`servicenow-mcp-authorize-${data.id}`} className="btn-ghost inline-flex items-center gap-1.5" href={`/api/v1${path}/connect`}><Link2 size={14} />{data.authorized ? 'Reauthorize' : 'Authorize ServiceNow'}</a>
        {data.authorized && <button data-testid={`servicenow-mcp-discover-${data.id}`} className="btn-primary inline-flex items-center gap-1.5" disabled={discovering || removing} onClick={() => void discover()}><RefreshCw size={14} />{discovering ? 'Discovering…' : 'Discover tools'}</button>}
      </div>}
      {data && !data.configured && <p className="mt-3 text-xs text-warn">Configure the ServiceNow client ID and secret in Signet to authorize this connection.</p>}
      {data?.discovered_at && <div className="mt-4">
        <h3 className="text-sm font-semibold">Discovered tools ({data.tools.length})</h3>
        <p className="mt-1 text-xs text-ink-3">Last discovered {new Date(data.discovered_at).toLocaleString()}</p>
        <ul data-testid={`servicenow-mcp-tools-${data.id}`} className="mt-2 divide-y divide-line">
          {data.tools.map(tool => <li key={tool.name} className="py-3">
            <p className="text-sm font-medium">{tool.title}</p>
            <p className="mt-1 text-xs text-ink-3">{tool.name}</p>
            <p className="mt-1 text-sm text-ink-2">{tool.description}</p>
          </li>)}
        </ul>
        {!data.tools.length && <p className="mt-2 text-sm text-ink-2">This server exposed no tools to the authorized account.</p>}
      </div>}
      {data?.mcp_url && <p className="mt-3 text-xs text-ink-3">Discovered tools do not automatically provide execution history. Configure and verify activity sources for the linked agents below.</p>}
      <ServiceNowAgents connectionId={data.id} />
      </Modal>}
    </section>
  </Card>;
}

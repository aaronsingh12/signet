import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, useApi } from '../lib/api';
import { PlatformAccountForm, PLATFORM_NAMES, type Platform, type PlatformAccount } from './PlatformAccountForm';
import { Card, ErrorNote } from './ui';
import { PlatformConnections } from './PlatformConnectors';

export interface PlatformSource {
  connection_id: string;
  workload_id: string;
  platform: Platform;
  name: string;
  vendor: string | null;
}
interface SourceWorkload { id: string; name: string; kind: string; platform_ai: string | null; registered_agent_id: string | null }
interface Props { onSelected: (source: PlatformSource) => void; onInvalidate: () => void; activeWorkload: string | null }

/** Select a source identity without registering a second agent or granting runtime access. */
export function PlatformIntake({ onSelected, onInvalidate, activeWorkload }: Props) {
  const { data, error, reload } = useApi<{ items: PlatformAccount[] }>('/platforms');
  const [account, setAccount] = useState<PlatformAccount | null>(null);
  const [workloads, setWorkloads] = useState<SourceWorkload[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanError, setScanError] = useState<Error | null>(null);
  const scan = async (connection: PlatformAccount): Promise<void> => {
    onInvalidate(); setAccount(connection); setWorkloads(null); setScanError(null); setBusy(true);
    try {
      const result = await api<{ items: SourceWorkload[] }>(`/platforms/${connection.id}/workloads`);
      if (!result || !Array.isArray(result.items) || !result.items.every((item) => item && typeof item.id === 'string' && typeof item.name === 'string' && typeof item.kind === 'string' && (item.platform_ai === null || typeof item.platform_ai === 'string') && (item.registered_agent_id === null || typeof item.registered_agent_id === 'string'))) throw new TypeError('Platform workload response must contain IDs, names, kinds and registration status');
      setWorkloads(result.items);
    } catch (cause) { if (!(cause instanceof Error)) throw cause; setScanError(cause); }
    finally { setBusy(false); }
  };
  if (data && (!Array.isArray(data.items) || !data.items.every((item) => item && typeof item.id === 'string' && typeof item.label === 'string' && typeof item.platform === 'string' && Object.hasOwn(PLATFORM_NAMES, item.platform) && typeof item.status === 'string'))) return <ErrorNote error={new TypeError('Platform accounts response must contain account IDs, labels, supported providers and status')} />;
  return <Card title="Connect a platform and choose its agent" className="mt-4">
    <fieldset disabled={busy} className="space-y-4">
      <PlatformAccountForm onEdit={() => { onInvalidate(); setAccount(null); setWorkloads(null); setScanError(null); }} onConnected={(connection) => { void reload(); void scan(connection); }} />
      {!!data?.items.length && <label className="label">Use a connected account<select data-testid="intake-platform-account" className="input" value={account?.id ?? ''} onChange={(event) => {
        const connection = data.items.find((item) => item.id === event.target.value);
        if (connection) void scan(connection);
      }}><option value="" disabled>Choose an account</option>{data.items.map((item) => <option key={item.id} value={item.id} disabled={item.status !== 'connected'}>{PLATFORM_NAMES[item.platform]} — {item.label} ({item.status})</option>)}</select></label>}
      {account && <button type="button" data-testid="intake-platform-scan" className="btn-ghost" onClick={() => void scan(account)}>{busy ? 'Scanning...' : 'Scan / refresh workloads'}</button>}
      {workloads && account && <div data-testid="intake-platform-workloads" className="space-y-3">
        <p className="text-sm text-ink-2">Account verified. Choose the agent or workload these safety answers describe. For an API key, select the key used by this agent.</p>
        {!workloads.length && <p className="text-sm text-ink-3">No workloads found. Check this account's permissions and scan again.</p>}
        {workloads.map((workload) => <div key={workload.id} className="rounded-lg border border-line p-3">
          {workload.registered_agent_id ? <p className="text-sm">{workload.name} is already registered. <Link className="text-royal underline" to={`/agents/${workload.registered_agent_id}?tab=lifecycle`}>Open its safety review</Link></p> : <button type="button" data-testid={`intake-platform-workload-${workload.id}`} aria-pressed={activeWorkload === `${account.id}:${workload.id}`} className="btn-ghost w-full text-left" onClick={() => {
            onSelected({ connection_id: account.id, workload_id: workload.id, platform: account.platform, name: workload.name, vendor: workload.kind === 'api_key' ? null : workload.platform_ai });
          }}>{activeWorkload === `${account.id}:${workload.id}` ? 'Selected: ' : 'Select: '}{workload.name}</button>}
        </div>)}
        <p className="text-xs text-ink-3">This verifies account access and source identity. Runtime credentials and traffic routing follow safety review and approval.</p>
      </div>}
    </fieldset>
    <ErrorNote error={scanError ?? error} />
    <details className="mt-4" data-testid="intake-platform-management"><summary>Manage connected platforms</summary><PlatformConnections key={data?.items.map((item) => item.id).join(',')} onChange={() => { onInvalidate(); setAccount(null); setWorkloads(null); void reload(); }} /></details>
  </Card>;
}

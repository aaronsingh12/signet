import { useEffect, useState } from 'react';
import { api, useApi } from '../lib/api';
import { ErrorNote } from './ui';

interface Addresses { control_url: string; gateway_url: string | null }

/** Persist hosted endpoint addresses without changing server environment variables. */
export function HostedConnectionSettings({ onSaved }: { onSaved: () => void }) {
  const { data, error: loadError } = useApi<Addresses>('/connect/info');
  const [control, setControl] = useState('');
  const [gateway, setGateway] = useState('');
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  useEffect(() => {
    if (!data) return;
    if (typeof data.control_url !== 'string' || (data.gateway_url !== null && typeof data.gateway_url !== 'string')) { setError(new TypeError('Connection settings must contain Control and Gateway URLs')); return; }
    setControl(data.control_url); setGateway(data.gateway_url ?? '');
  }, [data]);
  const save = async (): Promise<void> => {
    setBusy(true); setError(null); setSaved(false);
    try {
      const result = await api<Addresses>('/connect/settings', { method: 'PUT', body: { control_url: control, gateway_url: gateway } });
      if (!result || typeof result.control_url !== 'string' || typeof result.gateway_url !== 'string') throw new TypeError('Saved connection settings response must contain Control and Gateway URLs');
      setControl(result.control_url); setGateway(result.gateway_url);
      setSaved(true); onSaved();
    } catch (cause) { if (!(cause instanceof Error)) throw cause; setError(cause); }
    finally { setBusy(false); }
  };
  return <details className="rounded-lg border border-line p-3" data-testid="hosted-connection-settings">
    <summary className="cursor-pointer text-sm font-medium">Hosted Signet addresses</summary>
    <p className="mt-2 text-xs text-ink-3">Set these once for this Signet installation. Saved in the database and used immediately for agent connections, tests and platform deployment.</p>
    <div className="mt-3 grid gap-3 sm:grid-cols-2">
      <label className="label">Public Control URL<input data-testid="connection-control-url" className="input" type="url" value={control} disabled={busy} onChange={(event) => { setControl(event.target.value); setSaved(false); }} placeholder="https://signet.example.com" /></label>
      <label className="label">Public Gateway URL<input data-testid="connection-gateway-url" className="input" type="url" value={gateway} disabled={busy} onChange={(event) => { setGateway(event.target.value); setSaved(false); }} placeholder="https://gateway.example.com" /></label>
    </div>
    <p className="mt-2 text-xs text-ink-3">Use the service origins without /api or /v1. Saving an address does not deploy the service or prove reachability; verify it with the connection test.</p>
    <button type="button" data-testid="connection-settings-save" className="btn-primary mt-3" disabled={busy || !control || !gateway} onClick={() => void save()}>{busy ? 'Saving...' : 'Save addresses'}</button>
    {saved && <p role="status" className="mt-2 text-sm text-ok">Saved. New requests use these addresses without a server restart.</p>}
    <ErrorNote error={error ?? loadError} />
  </details>;
}

import { useState, type FormEvent } from 'react';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ErrorNote } from './ui';
import { CopyCode } from './CopyCode';

interface GatewayRoute { alias: string; url: string }

export function ServiceNowGateway({ connectionId }: { connectionId: string }) {
  const path = '/plugins/servicenow/connections/' + encodeURIComponent(connectionId) + '/gateway';
  const { data, error, reload } = useApi<{ route: GatewayRoute | null }>(path);
  const [alias, setAlias] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Error | null>(null);
  const can = useCan();
  const prepare = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault(); setBusy(true); setFailure(null);
    try { await api(path, { method: 'POST', body: { alias } }); await reload(); }
    catch (error) { setFailure(error instanceof Error ? error : new Error('Gateway route could not be prepared')); }
    finally { setBusy(false); }
  };
  return <div className="mt-5 border-t border-line pt-4">
    <h3 className="text-sm font-semibold">Govern MCP tool calls through Signet</h3>
    <p className="mt-1 text-xs text-ink-3">Prepare a tool route, approve allowed actions for the linked agent, then point its ServiceNow MCP client at Signet. Internal calls that bypass this route are not governed.</p>
    <ErrorNote error={error ?? failure} />
    {data?.route ? <>
      <p className="mt-3 text-sm">Registered tool alias: <strong>{data.route.alias}</strong></p>
      <CopyCode testId={`servicenow-gateway-url-${connectionId}`} text={data.route.url} />
      <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-ink-2">
        <li>Open the linked agent's Review and approval page. Select the registered MCP alias and approve only the required actions.</li>
        <li>Open Gateway setup for that agent and create its client credentials after approval.</li>
        <li>In ServiceNow AI Agent Studio, configure the Signet MCP URL above with that agent's Signet OAuth credentials. Use the token endpoint shown in Gateway setup.</li>
        <li>Run a test through ServiceNow. Signet marks enforcement verified only after authenticated gateway traffic arrives.</li>
      </ol>
    </> : can('tools.manage') ? <form className="mt-3 space-y-2" onSubmit={event => void prepare(event)}>
      <label className="label" htmlFor={`servicenow-gateway-alias-${connectionId}`}>Gateway tool alias</label>
      <input id={`servicenow-gateway-alias-${connectionId}`} className="input" required pattern="[a-z0-9]+(-[a-z0-9]+)*" maxLength={63} placeholder="servicenow-cmdb" value={alias} onChange={event => setAlias(event.target.value)} />
      <button type="submit" data-testid={`servicenow-prepare-gateway-${connectionId}`} className="btn-primary" disabled={busy || !data}>{busy ? 'Preparing…' : 'Prepare gateway route'}</button>
    </form> : <p className="mt-2 text-xs text-ink-3">A platform administrator can register the MCP gateway route.</p>}
  </div>;
}

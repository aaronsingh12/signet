import { useState } from 'react';
import { Link } from 'react-router-dom';
import type { ConnectionMethod } from '@signet/core/types';
import { Card, ErrorNote } from './ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { EdgeRunners } from './EdgeRunners';
import { CopyCode } from './CopyCode';
import { CONNECTION_METHODS } from '../lib/connections';

interface ConnectInfo {
  control_url: string; gateway_url: string | null; gateway_url_source: string;
  models: string[];
}
interface Credentials { client_id: string; client_secret: string }
interface Bootstrap { bootstrap_credential: string; expires_at: string; environment: string }
interface SetupAgent { id: string; name: string; kind: string; connection_method: ConnectionMethod | null }

/** Keep credentials in component memory only; registration and seal approval remain separate steps. */
export function ConnectionSetup({ agent, certificate, state, onChange }: {
  agent: SetupAgent; certificate: { environments: string[]; tools?: { server: string; actions: { name: string }[] }[] } | null; state: string; onChange: () => void;
}) {
  const can = useCan();
  const { data: info, error: infoError } = useApi<ConnectInfo>('/connect/info');
  const [method, setMethod] = useState<ConnectionMethod>(agent.connection_method ?? (agent.kind === 'third_party' ? 'oauth' : 'bootstrap'));
  const [environment, setEnvironment] = useState(certificate?.environments[0] ?? 'dev');
  const [credentials, setCredentials] = useState<Credentials | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [label, setLabel] = useState('');
  const control = info?.control_url ?? '<control-url>';
  const gateway = info?.gateway_url ?? '<gateway-url>';
  const model = info?.models[0] ?? '<approved-model>';
  const tokenUrl = `${control}/api/v1/identity/token`;
  const permitted = !!certificate && can('identity.bootstrap') && state !== 'revoked' && state !== 'suspended';
  const unsupported = agent.kind === 'third_party' && (method === 'bootstrap' || method === 'hybrid');
  const generate = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      if (method === 'bootstrap') {
        setBootstrap(await api<Bootstrap>(`/agents/${agent.id}/bootstrap`, { method: 'POST', body: { environment } }));
      } else {
        setCredentials(await api<Credentials>(`/agents/${agent.id}/clients`, { method: 'POST', body: { label: label || `${agent.name} connection`, environment } }));
      }
      onChange();
    } catch (error) { setError(error as ApiError); }
    finally { setBusy(false); }
  };
  const client = credentials?.client_id ?? '<client-id>';
  const secret = credentials?.client_secret ?? '<client-secret>';
  const httpGrant = certificate?.tools?.find((tool) => tool.server.startsWith('http://') && tool.actions.length > 0);
  const toolEndpoint = `${gateway}/v1/tools/http/${httpGrant?.server.slice(7) ?? '<approved-tool-alias>'}/${httpGrant?.actions[0]?.name ?? '<approved-action>'}`;
  const identityEnv = `SIGNET_CONTROL_URL=${control}\nSIGNET_GATEWAY_URL=${gateway}\n${method === 'bootstrap' ? `SIGNET_BOOTSTRAP_CREDENTIAL=${bootstrap?.bootstrap_credential ?? '<single-use-bootstrap-credential>'}` : `SIGNET_CLIENT_ID=${client}\nSIGNET_CLIENT_SECRET=${secret}`}`;
  const exchange = JSON.stringify({ grant_type: 'client_credentials', client_id: client, client_secret: secret }, null, 2);
  const modelRequest = JSON.stringify({ model, messages: [{ role: 'user', content: 'Hello' }] }, null, 2);
  return <div className="space-y-4">
    <Card title="Connect your agent">
      <div className="grid gap-3 md:grid-cols-2">{CONNECTION_METHODS.map((item) => <button key={item.id} data-testid={`setup-method-${item.id}`} aria-pressed={method === item.id} disabled={busy} onClick={() => { setMethod(item.id); setCredentials(null); setBootstrap(null); }} className={`rounded-lg border p-3 text-left ${method === item.id ? 'border-royal bg-royal-50' : 'border-line hover:bg-canvas'}`}><div className="text-sm font-semibold">{item.label}</div><p className="mt-1 text-xs text-ink-2">{item.description}</p></button>)}</div>
      {!certificate && <div className="mt-4 rounded-lg border border-line bg-canvas p-4 text-sm"><strong>1. Complete approval</strong><p className="mt-1 text-ink-2">Your agent is registered. Complete its lifecycle to receive a signed seal, then return here to generate credentials.</p><Link data-testid="setup-open-lifecycle" className="mt-2 inline-block text-royal" to={`/agents/${agent.id}?tab=lifecycle`}>Open approval lifecycle →</Link></div>}
      {unsupported ? <p role="alert" className="mt-4 text-sm text-warn">Vendor-hosted agents connect with OAuth or REST for company tools. Select one of those methods.</p> : <>
        <div className="mt-4 flex flex-wrap items-end gap-3"><div><label className="label" htmlFor="setup-environment">Environment</label><select id="setup-environment" data-testid="setup-environment" className="input" value={environment} disabled={!certificate || busy} onChange={(event) => { setEnvironment(event.target.value); setCredentials(null); setBootstrap(null); }}>{(certificate?.environments ?? ['dev']).map((item) => <option key={item} value={item}>{item}</option>)}</select></div>{method !== 'bootstrap' && <div className="flex-1"><label className="label" htmlFor="setup-label">Connection label (optional)</label><input id="setup-label" className="input" value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Production agent" /></div>}<button data-testid="setup-generate" className="btn-primary" disabled={!permitted || busy} onClick={() => void generate()}>{busy ? 'Generating…' : method === 'bootstrap' ? 'Generate bootstrap credential' : 'Generate Client ID & Secret'}</button></div>
        {certificate && !can('identity.bootstrap') && <p className="mt-2 text-sm text-ink-3">Ask your agent owner or administrator to generate credentials.</p>}
        {(credentials || bootstrap) && <div className="mt-4 rounded-lg border border-line p-3"><p className="mb-2 text-sm font-medium">Save these credentials now. The secret is shown only in this session.</p>{credentials ? <CopyCode testId="setup-credentials" text={`Client ID: ${credentials.client_id}\nClient Secret: ${credentials.client_secret}\nToken URL: ${tokenUrl}\nGrant type: client_credentials\nEnvironment: ${environment}`} /> : bootstrap && <><CopyCode testId="setup-bootstrap" text={bootstrap.bootstrap_credential} /><p className="mt-2 text-xs text-ink-3">Single use · expires {new Date(bootstrap.expires_at).toLocaleString()}</p></>}<button data-testid="setup-hide-secret" className="mt-2 text-xs text-royal" onClick={() => { setCredentials(null); setBootstrap(null); }}>Hide credentials</button></div>}
      </>}
      <ErrorNote error={error ?? infoError} />
    </Card>
    {!unsupported && <Card title="Copy your connection settings">
      <p className="mb-3 text-sm text-ink-2">{method === 'bootstrap' ? '2. Install the SDK and supply the one-time credential. The SDK manages workload tokens and refresh.' : '2. Exchange your credentials for a short-lived JWT. Use access_token as a Bearer token for gateway requests.'}</p>
      {method === 'bootstrap' ? <>
        <CopyCode testId="setup-sdk-install" text="python -m pip install -e './sdk/python[openai]'" />
        <div className="mt-3"><CopyCode testId="setup-sdk-env" text={`${identityEnv}\nSIGNET_TOKEN_CACHE=.signet-token.json`} /></div>
        <p className="my-3 text-xs text-ink-3">Install from this repository. Place these settings in your agent's environment, then use the Python SDK.</p>
        <CopyCode testId="setup-sdk-code" text={`from signet_sdk import SignetAgent\n\nagent = SignetAgent.from_env()\nclient = agent.openai_client()\nresponse = client.chat.completions.create(\n    model=${JSON.stringify(model)},\n    messages=[{"role": "user", "content": "Hello"}],\n)\nprint(response.choices[0].message.content)`} />
      </> : <>
        <div className="mb-3"><CopyCode testId="setup-oauth-env" text={identityEnv} /></div>
        <dl className="mb-3 grid gap-2 text-sm md:grid-cols-2"><div><dt className="text-ink-3">Token URL (POST)</dt><dd className="mono break-all">{tokenUrl}</dd></div><div><dt className="text-ink-3">Authentication</dt><dd>client_credentials · JSON or form body</dd></div></dl>
        <CopyCode testId="setup-token-request" text={`POST ${tokenUrl}\nContent-Type: application/json\n\n${exchange}`} />
        <p className="my-3 text-xs text-ink-3">Tokens last 10 minutes for T1/T2 or 30 minutes for T3/T4. Exchange credentials again before expiry. Workload tokens authorize this agent's gateway calls; they do not grant administrator access to the control API.</p>
        {agent.kind !== 'third_party' && <CopyCode testId="setup-model-request" text={`POST ${gateway}/v1/chat/completions\nAuthorization: Bearer <access_token>\nContent-Type: application/json\n\n${modelRequest}`} />}
        <div className="mt-3"><CopyCode testId="setup-tool-request" text={`POST ${toolEndpoint}\nAuthorization: Bearer <access_token>\nContent-Type: application/json\n\n{"id": "example-record-id"}`} /></div>
        {method === 'rest' && <div className="mt-3"><CopyCode testId="setup-rest-python" text={`import os\nimport httpx\n\nwith httpx.Client(timeout=120) as client:\n    identity = client.post(\n        ${JSON.stringify(tokenUrl)},\n        json={"grant_type": "client_credentials",\n              "client_id": os.environ["SIGNET_CLIENT_ID"],\n              "client_secret": os.environ["SIGNET_CLIENT_SECRET"]},\n    )\n    identity.raise_for_status()\n    token = identity.json()["access_token"]\n    response = client.post(\n        ${JSON.stringify(toolEndpoint)},\n        headers={"Authorization": f"Bearer {token}"},\n        json={"id": "example-record-id"},\n    )\n    response.raise_for_status()\n    print(response.json())`} /></div>}
      </>}
      {(method === 'hybrid' || agent.kind === 'no_code') && <div className="mt-4 space-y-3"><p className="text-sm">Run the sidecar beside your private agent. Your agent uses its local endpoint; the sidecar connects outward to Signet.</p><CopyCode testId="setup-sidecar-env" text={`${identityEnv}\nSIGNET_SIDECAR_BIND=127.0.0.1\nSIGNET_SIDECAR_PORT=8300`} /><CopyCode testId="setup-sidecar-start" text="npm run sidecar" /><p className="text-sm">Set your agent's OpenAI base URL to <code>http://127.0.0.1:8300/v1</code>.</p>{method === 'hybrid' && <p className="text-sm">For private company APIs, enroll the connector runner below and register its HTTP tools.</p>}{method === 'hybrid' && <p className="text-xs text-ink-3">This connector sends approved request arguments and results through Signet. Full Hybrid Edge local DLP and summary-only evidence are not implemented by this runner.</p>}</div>}
      {info && (!info.gateway_url || info.gateway_url_source.includes('local')) && <p className="mt-4 text-xs text-warn">Remote machines need reachable HTTPS addresses. Configure SIGNET_CONTROL_PUBLIC_URL and SIGNET_GATEWAY_PUBLIC_URL on the Signet server.</p>}
      <p className="mt-4 text-sm text-ink-2">3. Send an approved request, then refresh Connection status. A token alone does not mark an agent connected.</p>
    </Card>}
    {method === 'hybrid' && !unsupported && <EdgeRunners />}
  </div>;
}

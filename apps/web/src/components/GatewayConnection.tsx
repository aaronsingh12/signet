import { useState } from 'react';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import type { ConnectionSetupProps } from './ConnectionSetup';
import { CopyCode } from './CopyCode';
import { Card, ErrorNote } from './ui';
import { HostedConnectionSettings } from './HostedConnectionSettings';
import { AgentConfigDownload } from './AgentConfigDownload';

interface GatewayInfo { control_url: string; gateway_url: string | null; models: string[] }
interface DeploymentKey { deployment_credential: string; expires_at: string }
interface ConnectionTest { ok: boolean; status: number; reply?: string; message?: string; hint?: string }

/** Keep server credentials in memory and verify connectivity with an actual approved model call. */
export function GatewayConnection({ agent, certificate, state, onChange }: ConnectionSetupProps) {
  const can = useCan();
  const { data, error: requestError, reload } = useApi<GatewayInfo>('/connect/info');
  const validInfo = data === null || (data && typeof data.control_url === 'string' && /^https?:\/\//.test(data.control_url) && (data.gateway_url === null || typeof data.gateway_url === 'string' && /^https?:\/\//.test(data.gateway_url)) && Array.isArray(data.models) && data.models.every((value) => typeof value === 'string'));
  const info = validInfo ? data : null;
  const infoError = validInfo ? requestError : new TypeError('Connection settings must include a valid Gateway URL and model list');
  const [environment, setEnvironment] = useState(certificate?.environments[0] ?? 'dev');
  const [key, setKey] = useState<DeploymentKey | null>(null);
  const [result, setResult] = useState<ConnectionTest | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [generating, setGenerating] = useState(false);
  const [testing, setTesting] = useState(false);
  const base = info?.gateway_url ? `${info.gateway_url.replace(/\/+$/, '')}/v1` : null;
  const model = certificate?.models?.[0]?.model ?? info?.models[0];
  const permitted = !!certificate && can('identity.bootstrap') && state !== 'revoked' && state !== 'suspended';
  const createKey = async (): Promise<void> => {
    setGenerating(true); setError(null); setResult(null);
    try {
      const value = await api<DeploymentKey>(`/agents/${agent.id}/deployment-credentials`, { method: 'POST', body: { environment } });
      if (!value || typeof value.deployment_credential !== 'string' || !value.deployment_credential.startsWith('sdc_') || !Number.isFinite(Date.parse(value.expires_at))) throw new TypeError('Signet returned an invalid deployment key or expiry');
      setKey({ deployment_credential: value.deployment_credential, expires_at: value.expires_at });
      onChange();
    } catch (cause) {
      if (!(cause instanceof Error)) throw cause;
      setError(cause);
    } finally { setGenerating(false); }
  };
  const testConnection = async (): Promise<void> => {
    if (!key) throw new Error('Create a deployment key before testing the connection');
    setTesting(true); setError(null); setResult(null);
    try {
      const value = await api<ConnectionTest>('/connect/test', { method: 'POST', body: { credential: key.deployment_credential } });
      if (!value || typeof value.ok !== 'boolean' || !Number.isFinite(value.status) || (value.ok ? typeof value.reply !== 'string' : typeof value.message !== 'string') || (value.hint !== undefined && typeof value.hint !== 'string')) throw new TypeError('Signet returned an invalid connection test result');
      setResult(value);
      onChange();
    } catch (cause) {
      if (!(cause instanceof Error)) throw cause;
      setError(cause);
    } finally { setTesting(false); }
  };
  return <Card title="Gateway URL + API key">
    {can('tenant.admin') && <div className="mb-4"><HostedConnectionSettings onSaved={() => { setResult(null); void reload(); }} /></div>}
    <p className="mb-5 text-sm text-ink-2">Copy these into your chatbot's server-side AI settings, then send a test.</p>
    {!certificate && <p className="mb-4 text-sm text-ink-2">Complete the agent's approval first. Your connection settings will be ready here afterwards.</p>}
    {(state === 'connected' || state === 'connected_idle') && <p className="mb-4 text-sm text-ok" data-testid="gateway-connected">Signet has verified traffic from this agent.</p>}
    {base ? <><label className="label">1. Base URL</label><CopyCode testId="gateway-base-url" text={base} /></> : <p className="text-sm text-ink-3">{info ? 'Ask your administrator to configure the public Gateway URL.' : 'Loading connection settings...'}</p>}
    <div className="mt-4"><div className="label">2. API key</div>{key ? <><CopyCode testId="gateway-api-key" text={key.deployment_credential} /><p className="mt-2 text-xs text-ink-3">Shown only in this session. Save it securely. Expires {new Date(key.expires_at).toLocaleString()}.</p><button data-testid="gateway-hide-key" className="mt-2 text-xs text-royal" onClick={() => { setKey(null); setResult(null); }}>Hide key</button></> : <button data-testid="gateway-create-key" className="btn-primary" disabled={!permitted || !base || generating} onClick={() => void createKey()}>{generating ? 'Creating key...' : 'Create API key'}</button>}</div>
    {model && <p className="mt-4 text-sm text-ink-2">Model: <code>{model}</code></p>}
    {key && info?.gateway_url && <AgentConfigDownload agentId={agent.id} controlUrl={info.control_url} gatewayUrl={info.gateway_url} identity={{ kind: 'gateway', credential: key.deployment_credential }} />}
    {(certificate?.environments.length ?? 0) > 1 && <label className="label mt-4">Environment<select data-testid="gateway-environment" className="input" value={environment} disabled={generating || testing} onChange={(event) => { setEnvironment(event.target.value); setKey(null); setResult(null); }}>{certificate!.environments.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>}
    {certificate && !can('identity.bootstrap') && <p className="mt-3 text-sm text-ink-3">Ask the owner or administrator to create the API key.</p>}
    {key && <div className="mt-5 border-t border-line pt-4"><button data-testid="gateway-test" className="btn-primary" disabled={testing || generating || !permitted} onClick={() => void testConnection()}>{testing ? 'Checking connection...' : 'Test connection'}</button><p className="mt-2 text-xs text-ink-3">Sends one real request to the approved model and records it in scan history.</p></div>}
    {result && <div data-testid="gateway-test-result" className={`mt-3 text-sm ${result.ok ? 'text-ok' : 'text-bad'}`} role="status">{result.ok ? 'Connection verified. Your model replied successfully.' : `Connection test failed (${result.status}): ${result.message}`}{!result.ok && result.hint && <p className="mt-1 text-ink-2">{result.hint}</p>}</div>}
    <div className="mt-3"><ErrorNote error={error ?? infoError} /></div>
    <details className="mt-4 border-t border-line pt-3"><summary className="cursor-pointer text-xs text-ink-2">Where do I use these settings?</summary><p className="mt-2 text-xs text-ink-3">Use the Base URL and API key in an OpenAI-compatible client on your server. If your chatbot cannot change its AI endpoint, its backend needs an integration. Keep the key out of browser code. A generated key alone does not establish a connection.</p></details>
  </Card>;
}

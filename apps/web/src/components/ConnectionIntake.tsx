import { useState } from 'react';
import type { ConnectionMethod } from '@signet/core/types';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { CONNECTION_METHODS } from '../lib/connections';
import { AgentLlmPanel } from './AgentLlmPanel';
import { newConnectionDraft } from './ExternalConnections';
import { RestConnectionWizard } from './RestConnectionWizard';
import { PlatformIntake, type PlatformSource } from './PlatformIntake';
import { HostedConnectionSettings } from './HostedConnectionSettings';
import { EdgeRunners } from './EdgeRunners';
import { ErrorNote } from './ui';

type SetupMethod = ConnectionMethod | 'gateway' | 'platform';
export interface IntakeConnection { method: ConnectionMethod; choice: SetupMethod; model: string | null; connection_id: string | null; platform: PlatformSource | null }
interface Props {
  vendorHosted: boolean;
  initialModel: string;
  onVerified: (connection: IntakeConnection) => void;
  onInvalidate: () => void;
}
interface IntakeRunner { id: string; name: string; status: 'online' | 'offline' | 'revoked' }
const METHODS = [{ id: 'gateway' as const, label: 'Gateway URL + API key', description: 'For a chatbot with an OpenAI-compatible AI client.' }, ...CONNECTION_METHODS];

/** Verify the source connection before intake; runtime credentials still require a signed approval. */
export function ConnectionIntake({ vendorHosted, initialModel, onVerified, onInvalidate }: Props) {
  const can = useCan();
  const [method, setMethod] = useState<SetupMethod | null>(null);
  const [model, setModel] = useState(initialModel);
  const [addingModel, setAddingModel] = useState(false);
  const [showPlatforms, setShowPlatforms] = useState(false);
  const [platformWorkload, setPlatformWorkload] = useState<string | null>(null);
  const [runnerId, setRunnerId] = useState('');
  const [verified, setVerified] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const { data, reload, error: requestError } = useApi<{ catalogue: { model: string }[] }>('/catalogue');
  const { data: runners, error: runnerError, reload: reloadRunners } = useApi<{ items: IntakeRunner[] }>(method === 'hybrid' ? '/edge-runners' : null);
  const validCatalogue = data === null || data && Array.isArray(data.catalogue) && data.catalogue.every((item) => typeof item?.model === 'string');
  const catalogueError = validCatalogue ? requestError : new TypeError('The model catalogue response must contain model names');
  const selectedModel = model;
  const select = (value: SetupMethod): void => { setMethod(value); setAddingModel(false); setVerified(null); setError(null); onInvalidate(); };
  const verifyModel = async (): Promise<void> => {
    if (!method) throw new Error('Select a connection method before testing');
    setBusy(true); setError(null); setVerified(null); onInvalidate();
    try {
      if (method === 'hybrid') {
        const current = await api<{ items: IntakeRunner[] }>('/edge-runners');
        if (!current || !Array.isArray(current.items)) throw new TypeError('Runner response must contain an items list');
        if (!current.items.some((runner) => runner.id === runnerId && runner.status === 'online')) throw new Error('Select an online private runner before verifying. Enroll and start it with the downloaded runner file, then refresh runners.');
      }
      const value = await api<{ model: string; verified_at: string }>(`/catalogue/${encodeURIComponent(selectedModel)}/test`, { method: 'POST' });
      if (!value || value.model !== selectedModel || !Number.isFinite(Date.parse(value.verified_at))) throw new TypeError('Invalid model connection verification response');
      setVerified(`Model API verified at ${new Date(value.verified_at).toLocaleString()}`);
      if (method !== 'gateway' && method !== 'bootstrap' && method !== 'hybrid') throw new Error('Select Gateway, Bootstrap or Private network before verifying a model');
      onVerified({ method: method === 'gateway' ? 'rest' : method, choice: method, model: selectedModel, connection_id: null, platform: null });
    } catch (cause) { if (!(cause instanceof Error)) throw cause; setError(cause); }
    finally { setBusy(false); }
  };
  return <div className="space-y-5" data-testid="connection-intake">
    <h1 className="flow-title">How should we connect it?</h1>
    <p className="flow-lead">Choose a method, enter the connection details, and verify it. Safety questions come next.</p>
    {can('tenant.admin') && <HostedConnectionSettings onSaved={() => { setVerified(null); onInvalidate(); }} />}
    <div className="grid gap-3 sm:grid-cols-2" role="group" aria-label="Connection methods">
      {METHODS.map((option) => <button type="button" key={option.id} data-testid={`intake-method-${option.id}`} disabled={busy || vendorHosted && !['oauth', 'rest'].includes(option.id)} aria-pressed={method === option.id} className={`rounded-xl border p-4 text-left ${method === option.id ? 'border-royal bg-royal-50' : 'border-line hover:bg-canvas'} disabled:opacity-50`} onClick={() => select(option.id)}><b className="text-sm">{option.label}</b><p className="mt-1 text-xs text-ink-3">{option.description}</p></button>)}
    </div>
    <div>
      <button type="button" data-testid="intake-show-platforms" className="btn-ghost" aria-expanded={showPlatforms} aria-controls="intake-platforms" onClick={() => { setShowPlatforms(!showPlatforms); if (method === 'platform') { setPlatformWorkload(null); setVerified(null); onInvalidate(); } }}>{showPlatforms ? 'Show less' : 'Show more'}</button>
      <div id="intake-platforms" hidden={!showPlatforms}>
        {showPlatforms && (can('tenant.admin') ? <PlatformIntake activeWorkload={method === 'platform' ? platformWorkload : null} onInvalidate={() => { setPlatformWorkload(null); setVerified(null); onInvalidate(); }} onSelected={(source) => {
          setPlatformWorkload(`${source.connection_id}:${source.workload_id}`);
          setMethod('platform'); setAddingModel(false); setError(null); setVerified(`${source.name}: platform account and source identity verified. Continue to safety questions.`);
          onVerified({ method: source.vendor ? 'oauth' : 'rest', choice: 'platform', model: null, connection_id: null, platform: source });
        }} /> : <p className="mt-3 text-sm text-ink-3">A tenant administrator can connect Vercel, AWS, Azure, Google Cloud, Copilot Studio, OpenAI and Anthropic accounts.</p>)}
      </div>
    </div>
    {vendorHosted && <p className="text-xs text-ink-3">Vendor-hosted agents use OAuth or REST for their company APIs. Their private model calls stay with the vendor.</p>}
    {!vendorHosted && (method === 'gateway' || method === 'bootstrap' || method === 'hybrid') && <section key={method} data-testid={`intake-form-${method}`} className="card p-5 space-y-4">
      <h2 className="font-semibold">{method === 'bootstrap' ? 'Bootstrap / Workload JWT setup' : method === 'hybrid' ? 'Connect a private runner and AI model' : 'Connect its AI model'}</h2>
      {method === 'hybrid' && <>
        <p className="text-sm text-ink-2">Enroll your runner, save its private API settings here, and start it with the downloaded connection file. This step verifies runner availability and the model API. Private tool calls require the agent's later approval.</p>
        <EdgeRunners />
        <label className="label">Private runner<select data-testid="intake-runner" className="input" value={runnerId} onChange={(event) => { setRunnerId(event.target.value); setVerified(null); onInvalidate(); }}><option value="">Choose an online runner</option>{runners?.items.map((runner) => <option key={runner.id} value={runner.id} disabled={runner.status !== 'online'}>{runner.name} ({runner.status})</option>)}</select></label>
        <button type="button" data-testid="intake-refresh-runners" className="btn-ghost" onClick={() => { setVerified(null); onInvalidate(); void reloadRunners(); }}>Refresh runners</button>
        <ErrorNote error={runnerError} />
      </>}
      {method === 'bootstrap' && <p className="text-sm text-ink-2">Choose the model your SDK agent will call. After approval, generate a single-use bootstrap credential and exchange it for a short-lived workload JWT with the Python SDK.</p>}
      <p className="text-sm text-ink-2">Use a configured model, or add your AI provider URL and API key. The test sends one fixed, harmless connection-check request. Your agent is not deployed.</p>
      <label className="label">Your agent's AI model<select data-testid="intake-model" className="input" value={selectedModel} disabled={busy || !data || !!catalogueError} onChange={(event) => { setModel(event.target.value); setVerified(null); onInvalidate(); }}><option value="">Choose the model your agent uses</option>{validCatalogue && data?.catalogue.map((item) => <option key={item.model} value={item.model}>{item.model}</option>)}</select></label>
      {can('tenant.admin') ? <button data-testid="intake-own-model" type="button" className="btn-ghost" onClick={() => { setVerified(null); onInvalidate(); setAddingModel(true); }}>+ Enter my AI provider URL and credentials</button> : <p className="text-xs text-ink-3">Ask a tenant administrator to add a new provider's credentials.</p>}
      <div><button type="button" data-testid="intake-connect" className="btn-primary" disabled={busy || !selectedModel} onClick={() => void verifyModel()}>{busy ? 'Verifying connection...' : 'Connect and verify'}</button></div>
      <p className="text-xs text-ink-3">{method === 'gateway' ? 'Your Signet Gateway URL and API key are issued after approval.' : method === 'bootstrap' ? 'Your SDK bootstrap credential and workload JWT become available after approval.' : 'Private runner and tool bindings are completed at deployment after approval.'}</p>
    </section>}
    {(method === 'oauth' || method === 'rest') && <div data-testid={`intake-form-${method}`} onChangeCapture={() => { setVerified(null); onInvalidate(); }}>
      <RestConnectionWizard key={method} agentId={null} initialDraft={newConnectionDraft(method)} connectionId={null}
        onSaved={() => setVerified(null)} onCancel={() => select(method)}
        onVerified={(connection) => { setVerified('API endpoint and authentication verified. Continue to safety questions.'); onVerified({ method, choice: method, model: null, connection_id: connection.id, platform: null }); }} />
    </div>}
    {verified && <p role="status" data-testid="intake-verified" className="rounded-lg border border-line bg-ok-50 p-3 text-sm text-ok">{verified}</p>}
    <ErrorNote error={error ?? catalogueError} />
    <p className="text-xs text-ink-3">Verification checks the source API. Signet starts governing live agent traffic only after safety review, approval and deployment.</p>
    {addingModel && <AgentLlmPanel onClose={() => setAddingModel(false)} onSaved={(value) => { setModel(value); setAddingModel(false); setVerified(null); onInvalidate(); void reload(); }} />}
  </div>;
}

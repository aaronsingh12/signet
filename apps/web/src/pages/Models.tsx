import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { parseModelProviderDraft, parseModelSettingsDraft, parseModelSettingsView, type ModelProvider, type ModelSettingsDraft, type ModelSettingsView } from '../../../../packages/core/src/model-settings';
import { Card, ErrorNote, PageHeader } from '../components/ui';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';

const providers: { id: ModelProvider; label: string; url: string; help: string }[] = [
  { id: 'ollama_local', label: 'Ollama Local', url: 'http://localhost:11434/v1', help: 'Run Ollama and download a chat model on the machine hosting Signet. The URL is reached from Signet, not from your browser. A remote Signet installation needs a reachable Ollama server.' },
  { id: 'ollama_api', label: 'Ollama API', url: 'https://ollama.com/v1', help: 'Use your Ollama API key and an available cloud model. You can also enter the HTTPS /v1 address of your own hosted Ollama API.' },
  { id: 'openai', label: 'OpenAI API', url: 'https://api.openai.com/v1', help: 'Use an OpenAI API key with access to a chat model. Load your models or enter the exact model ID.' },
  { id: 'claude', label: 'Claude API', url: 'https://api.anthropic.com/v1', help: 'Use a workspace-scoped Anthropic API key and a Claude model ID. Signet uses Claude’s OpenAI-compatible chat endpoint.' },
];

export function Models() {
  const canManage = useCan()('tenant.admin');
  const { data, error, reload } = useApi<ModelSettingsView>(canManage ? '/model-settings' : null);
  return <>
    <PageHeader title="Models" subtitle="Configure the model Signet uses for Guardian, safety reviews and internal evaluations." />
    {!canManage ? <Card><p className="text-sm text-ink-2">A Tenant Admin can configure model providers.</p></Card> : <>
      <ErrorNote error={error} />
      {error && <button type="button" className="btn-ghost mt-3" data-testid="model-settings-reload" onClick={() => void reload()}>Reload model settings</button>}
      {!data && !error && <p role="status">Loading model settings…</p>}
      {data && <ModelSettingsForm initial={parseModelSettingsView(data)} />}
    </>}
  </>;
}

function ModelSettingsForm({ initial }: { initial: ModelSettingsView }) {
  const [saved, setSaved] = useState(initial);
  const [draft, setDraft] = useState<ModelSettingsDraft>({ provider: initial.provider, base_url: initial.base_url, model: initial.model, api_key: '' });
  const [models, setModels] = useState<string[]>([]);
  const [loadingModels, setLoadingModels] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [message, setMessage] = useState('');
  const selected = providers.find(provider => provider.id === draft.provider)!;
  const keepKey = saved.has_api_key && saved.provider === draft.provider && saved.base_url === draft.base_url.replace(/\/+$/, '');
  const changeProvider = (provider: ModelProvider): void => {
    const option = providers.find(item => item.id === provider);
    if (!option) throw new Error(`Unsupported model provider ${provider}`);
    setDraft({ provider, base_url: option.url, model: '', api_key: '' });
    setModels([]); setError(null); setMessage('');
  };
  const loadModels = async (): Promise<void> => {
    setLoadingModels(true); setError(null); setMessage('');
    try {
      const result = await api<{ models: string[] }>('/model-settings/models', { method: 'POST', body: parseModelProviderDraft(draft) });
      if (!result || !Array.isArray(result.models) || result.models.some(model => typeof model !== 'string' || !model)) throw new TypeError('Provider model list must contain model IDs');
      setModels(result.models);
      setMessage(result.models.length ? `${result.models.length} models loaded. Choose a chat model below.` : 'The provider returned no models for this credential.');
    } catch (failure) { setError(failure instanceof Error ? failure : new Error(String(failure))); }
    finally { setLoadingModels(false); }
  };
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault(); setSaving(true); setError(null); setMessage('');
    try {
      const result = parseModelSettingsView(await api<ModelSettingsView>('/model-settings', { method: 'PUT', body: parseModelSettingsDraft(draft) }));
      setSaved(result);
      setDraft({ provider: result.provider, base_url: result.base_url, model: result.model, api_key: '' });
      setMessage('Model verified and saved. Signet will use it automatically for new reviews. Existing agent approvals and tool routing are preserved.');
    } catch (failure) { setError(failure instanceof Error ? failure : new Error(String(failure))); }
    finally { setSaving(false); }
  };
  return <div className="max-w-3xl space-y-4">
    <Card title="Current model">
      <p className="font-semibold" data-testid="model-settings-current">{providers.find(provider => provider.id === saved.provider)!.label} · {saved.model}</p>
      <p className="mt-1 break-all text-sm text-ink-3">{saved.base_url}</p>
      <p className="mt-2 text-xs text-ink-3">{saved.source === 'saved' ? 'Saved in Signet.' : 'Your existing installation configuration is shown. Save below to manage it here.'} API keys are stored encrypted and never shown again.</p>
    </Card>
    <Card title="Model provider">
      <form data-testid="model-settings-form" className="space-y-4" onSubmit={event => void save(event)}>
        <fieldset className="space-y-4" disabled={saving || loadingModels}>
          <div><label htmlFor="model-provider" className="label">Provider</label>
            <select id="model-provider" data-testid="model-provider" className="input" value={draft.provider} onChange={event => changeProvider(event.target.value as ModelProvider)}>
              {providers.map(provider => <option key={provider.id} value={provider.id}>{provider.label}</option>)}
            </select><p className="mt-2 text-xs leading-relaxed text-ink-3">{selected.help}</p></div>
          <div><label htmlFor="model-base-url" className="label">Provider API URL</label>
            <input id="model-base-url" data-testid="model-base-url" className="input" type="url" required value={draft.base_url} readOnly={draft.provider === 'openai' || draft.provider === 'claude'} onChange={event => { setDraft({ ...draft, base_url: event.target.value }); setModels([]); setMessage(''); }} />
            <p className="mt-1 text-xs text-ink-3">Use the API base address ending in /v1.</p></div>
          <div><label htmlFor="model-api-key" className="label">API key{draft.provider === 'ollama_local' ? ' (optional)' : ''}</label>
            <input id="model-api-key" data-testid="model-api-key" className="input" type="password" autoComplete="new-password" maxLength={4096} required={draft.provider !== 'ollama_local' && !keepKey} value={draft.api_key} onChange={event => { setDraft({ ...draft, api_key: event.target.value }); setModels([]); setMessage(''); }} />
            {keepKey && <p className="mt-1 text-xs text-ink-3">A key is available for this provider URL. Leave blank to keep it, or enter a replacement.</p>}</div>
          <div><label htmlFor="model-id" className="label">Model ID</label>
            <div className="flex flex-wrap gap-2"><input id="model-id" data-testid="model-id" className="input min-w-0 flex-1" list="model-options" required maxLength={128} value={draft.model} onChange={event => { setDraft({ ...draft, model: event.target.value }); setMessage(''); }} />
              <button type="button" data-testid="model-load-options" className="btn-ghost" onClick={() => void loadModels()}>Load models</button></div>
            <datalist id="model-options">{models.map(model => <option key={model} value={model} />)}</datalist>
            <p className="mt-1 text-xs text-ink-3">Select a chat model from the loaded list or type its exact provider ID.</p></div>
        </fieldset>
        <ErrorNote error={error} />
        {message && <p role="status" data-testid="model-settings-result" className="text-sm text-ink-2">{message}</p>}
        <button type="submit" data-testid="model-settings-save" className="btn-primary" disabled={saving || loadingModels}>{saving ? 'Verifying and saving…' : loadingModels ? 'Loading models…' : 'Verify and save model'}</button>
        <p className="text-xs text-ink-3">Saving runs a small real safety check before changing the active model. Provider usage charges may apply. Model changes require no environment-file edits or restart.</p>
      </form>
    </Card>
    <p className="text-sm text-ink-3">Set this model’s token prices in <Link className="text-royal" to="/settings/gateway-cost">Gateway cost</Link> for usage accounting. Agent-specific models keep their own connections and approval requirements.</p>
  </div>;
}

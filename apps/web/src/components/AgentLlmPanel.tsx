import { X } from 'lucide-react';
import { useState } from 'react';
import { ErrorNote } from './ui';
import { ApiError, api } from '../lib/api';

// Adds an agent's own LLM to the approved list, so the agent keeps its model and Signet checks each
// call on the way. The key goes straight to the Secrets Broker and is never shown again.
export function AgentLlmPanel({ onClose, onSaved }: { onClose: () => void; onSaved: (model: string) => void }) {
  const [f, setF] = useState({ model: '', base_url: '', api_key: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const save = async () => {
    setBusy(true);
    try {
      await api('/catalogue', { method: 'POST', body: f });
      setF({ ...f, api_key: '' });
      onSaved(f.model.trim());
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="drawer-scrim" onMouseDown={onClose}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Add your agent's LLM" onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between"><h2 className="text-xl font-semibold">Add your agent's LLM</h2><button aria-label="Close" className="icon-button" onClick={onClose}><X size={17} /></button></div>
        <p className="mt-1 text-sm text-ink-2">Your agent keeps its own LLM. Signet checks each call, then sends it there.</p>
        <label className="flow-label" htmlFor="llm-model">Model name</label>
        <input id="llm-model" data-testid="llm-model" className="input mono" value={f.model} onChange={(e) => setF({ ...f, model: e.target.value })} placeholder="beam:cloud" />
        <p className="mt-1 text-xs text-ink-3">Exactly as your agent sends it.</p>
        <label className="flow-label" htmlFor="llm-url">LLM address</label>
        <input id="llm-url" data-testid="llm-url" className="input mono" value={f.base_url} onChange={(e) => setF({ ...f, base_url: e.target.value })} placeholder="https://your-llm.example.com/v1" />
        <p className="mt-1 text-xs text-ink-3">Its OpenAI-compatible address, usually ending in /v1. Ollama provides one.</p>
        <label className="flow-label" htmlFor="llm-key">API key <span className="font-normal text-ink-3">(if it needs one)</span></label>
        <input id="llm-key" data-testid="llm-key" className="input" type="password" autoComplete="new-password" value={f.api_key} onChange={(e) => setF({ ...f, api_key: e.target.value })} />
        <p className="mt-1 text-xs text-ink-3">Stored in the Secrets Broker. Leave blank to keep a saved key. Remove this key from your agent afterwards.</p>
        {error && <div className="mt-4"><ErrorNote error={error} /></div>}
        <button className="btn-primary btn-large mt-6 w-full" data-testid="llm-save" disabled={busy || !f.model.trim() || !f.base_url.trim()} onClick={() => void save()}>{busy ? 'Saving…' : 'Save'}</button>
      </aside>
    </div>
  );
}

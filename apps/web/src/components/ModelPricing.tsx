import { useState, type FormEvent } from 'react';
import type { GatewayModelPrice } from '../../../../packages/core/src/gateway-costs';
import { api } from '../lib/api';

/** One persisted catalogue rate used by every agent that calls this model. */
export function ModelPriceEditor({ model, canEdit, onSaved }: { model: GatewayModelPrice; canEdit: boolean; onSaved: () => Promise<void> }) {
  const [draft, setDraft] = useState<{ input: string; output: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const values = draft ?? { input: String(model.price_per_1k_usd.in * 1000), output: String(model.price_per_1k_usd.out * 1000) };
  const inputId = `model-price-input-${model.model}`;
  const outputId = `model-price-output-${model.model}`;
  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const input = Number(values.input);
    const output = Number(values.output);
    if (!values.input.trim() || !values.output.trim() || ![input, output].every(value => Number.isFinite(value) && value >= 0 && value <= 1_000_000)) {
      setMessage({ ok: false, text: 'Enter input and output prices between 0 and 1,000,000 USD per million tokens.' });
      return;
    }
    setBusy(true); setMessage(null);
    try {
      await api(`/catalogue/${encodeURIComponent(model.model)}/price`, { method: 'PUT', body: { in: input / 1000, out: output / 1000 } });
      await onSaved();
      setDraft(null);
      setMessage({ ok: true, text: 'Saved for new requests. Historical recorded costs are unchanged.' });
    } catch (failure) {
      setMessage({ ok: false, text: failure instanceof Error ? failure.message : String(failure) });
    } finally { setBusy(false); }
  };
  return <form className="border-b border-line py-4 last:border-0" data-testid={`model-price-${model.model}`} onSubmit={event => void save(event)}>
    <div className="grid items-end gap-3 sm:grid-cols-[1fr_10rem_10rem_auto]">
      <div><h3 className="break-all font-medium">{model.model}</h3><p className="mt-1 text-xs text-ink-3">Shared across agents using this model</p></div>
      <div><label className="label" htmlFor={inputId}>Input USD / 1M tokens</label><input id={inputId} data-testid={inputId} className="input" type="number" min="0" max="1000000" step="any" required disabled={!canEdit || busy} value={values.input} onChange={event => { setDraft({ ...values, input: event.target.value }); setMessage(null); }} /></div>
      <div><label className="label" htmlFor={outputId}>Output USD / 1M tokens</label><input id={outputId} data-testid={outputId} className="input" type="number" min="0" max="1000000" step="any" required disabled={!canEdit || busy} value={values.output} onChange={event => { setDraft({ ...values, output: event.target.value }); setMessage(null); }} /></div>
      {canEdit && <button className="btn-primary" data-testid={`model-price-save-${model.model}`} disabled={busy || draft === null}>{busy ? 'Saving…' : 'Save prices'}</button>}
    </div>
    {(model.price_per_1k_usd.in === 0 || model.price_per_1k_usd.out === 0) && <p className="mt-2 text-xs text-warn">A zero rate contributes no cost for that token direction. Set your contracted rate to track spend.</p>}
    {message && <p className={`mt-2 text-sm ${message.ok ? 'text-ok' : 'text-bad'}`} role="status" data-testid={`model-price-status-${model.model}`}>{message.text}</p>}
  </form>;
}

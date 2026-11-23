import { ArrowUp, Bot, MessageCircle, RotateCcw, ShieldCheck, Sparkles, X } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { parseAssistantReply, parseAssistantRequest, type AssistantAction, type AssistantReply } from '../../../../packages/core/src/assistant';
import { api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { LadderModal } from '../pages/Agent360';

interface ChatEntry { id: string; role: 'user' | 'assistant'; content: string; reply: AssistantReply | null }

/** Tab-local conversation; all facts and permitted action proposals come from the signed-in control API. */
export function SignetAssistant() {
  const can = useCan();
  const [open, setOpen] = useState(false);
  const [entries, setEntries] = useState<ChatEntry[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [review, setReview] = useState<{ entry_id: string; action: AssistantAction } | null>(null);
  const [submitted, setSubmitted] = useState<string[]>([]);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const threadRef = useRef<HTMLDivElement>(null);
  const launcherRef = useRef<HTMLButtonElement>(null);
  const status = useApi<{ model: string; provider: string }>(open && can('agents.read') ? '/assistant/status' : null);
  const full = entries.length >= 20;
  useEffect(() => { if (open) inputRef.current?.focus(); }, [open]);
  useEffect(() => { if (threadRef.current) threadRef.current.scrollTop = threadRef.current.scrollHeight; }, [entries, busy, error, open]);
  const close = (): void => { setOpen(false); launcherRef.current?.focus(); };
  const send = async (content: string): Promise<void> => {
    if (busy || !content.trim()) return;
    const next: ChatEntry = { id: crypto.randomUUID(), role: 'user', content: content.trim(), reply: null };
    setError(null);
    setBusy(true);
    try {
      const body = parseAssistantRequest({ messages: [...entries, next].map(entry => ({ role: entry.role, content: entry.content })), time_zone: Intl.DateTimeFormat().resolvedOptions().timeZone });
      const reply = parseAssistantReply(await api<AssistantReply>('/assistant/chat', { method: 'POST', body }));
      setEntries(previous => [...previous, next, { id: crypto.randomUUID(), role: 'assistant', content: reply.message, reply }]);
      setInput('');
    } catch (failure) { setError(failure instanceof Error ? failure.message : String(failure)); }
    finally { setBusy(false); inputRef.current?.focus(); }
  };
  const submit = (event: FormEvent<HTMLFormElement>): void => { event.preventDefault(); void send(input); };
  if (!can('agents.read')) return null;
  return <>
    <button ref={launcherRef} type="button" className="signet-assistant-launcher" data-testid="signet-assistant-toggle" aria-label={open ? 'Close Signet AI assistant' : 'Open Signet AI assistant'} aria-expanded={open} aria-controls="signet-assistant-panel" onClick={() => open ? close() : setOpen(true)}>{open ? <X size={23} /> : <MessageCircle size={23} />}<span>Signet AI</span>{!open && <Sparkles size={15} aria-hidden="true" />}</button>
    {open && <section id="signet-assistant-panel" className="signet-assistant-panel card" role="dialog" aria-label="Signet AI assistant" aria-modal="false" data-testid="signet-assistant-panel" onKeyDown={event => { if (event.key === 'Escape') close(); }}>
      <header className="signet-assistant-header">
        <span className="signet-assistant-avatar"><Bot size={23} /></span>
        <div className="min-w-0 flex-1"><h2 className="font-semibold">Signet AI <Sparkles size={13} className="inline text-royal" /></h2><p className="truncate text-xs text-ink-3" data-testid="signet-assistant-model">{status.error ? 'Model connection needs attention' : status.data ? `Connected · ${entries.at(-1)?.reply?.model ?? status.data.model}` : 'Reading connected model…'}</p></div>
        <button type="button" className="icon-button" data-testid="signet-assistant-reset" aria-label="Start a new chat" disabled={busy} onClick={() => { setEntries([]); setSubmitted([]); setInput(''); setError(null); inputRef.current?.focus(); }}><RotateCcw size={16} /></button>
        <button type="button" className="icon-button" data-testid="signet-assistant-close" aria-label="Close assistant" onClick={close}><X size={18} /></button>
      </header>
      <div ref={threadRef} className="signet-assistant-thread" role="log" aria-live="polite" aria-label="Signet conversation" aria-busy={busy}>
        {entries.length === 0 && <div className="signet-assistant-welcome"><span className="signet-assistant-welcome-icon"><ShieldCheck size={30} /></span><h3 className="text-lg font-semibold">Your Signet workspace,<br />one conversation away.</h3><p className="mt-2 text-sm text-ink-3">Ask about an agent, token usage, costs or safety. Signet AI responds in English using live platform data.</p><div className="mt-5 flex flex-col gap-2">{[{ id: 'agents', label: 'Show my AI agents', prompt: 'Show my Signet AI agents and their current status.' }, { id: 'cost', label: 'Tokens & costs', prompt: 'Show the last 24 hours of input and output tokens and recorded USD cost for my agents.' }, { id: 'blocks', label: 'Explain blocked events', prompt: 'Explain the Signet dashboard blocked events. Separate unavailable checks from detected threats.' }].map(suggestion => <button key={suggestion.id} type="button" className="signet-assistant-suggestion" data-testid={`signet-assistant-suggestion-${suggestion.id}`} disabled={busy} onClick={() => void send(suggestion.prompt)}>{suggestion.label}<ArrowUp size={14} className="rotate-45" /></button>)}</div></div>}
        {entries.map(entry => <article key={entry.id} className={`signet-assistant-message ${entry.role === 'user' ? 'from-user' : 'from-assistant'}`} data-testid={`signet-assistant-message-${entry.role}`}>
          <p className="whitespace-pre-wrap break-words text-sm">{entry.content}</p>
          {entry.reply && <>
            {entry.reply.action && <div className="signet-assistant-action" data-testid="signet-assistant-action"><strong className="text-xs">{entry.reply.action.agent_name}</strong><p className="my-2 text-xs text-ink-3">{entry.reply.action.action === 'kill' ? 'Permanent stop: revokes the seal. Requires typing the agent handle.' : 'Review this safety change in Signet before applying it.'}</p><button type="button" className="btn-primary text-xs" data-testid="signet-assistant-review-action" disabled={submitted.includes(entry.id)} onClick={() => setReview({ entry_id: entry.id, action: entry.reply!.action! })}>{submitted.includes(entry.id) ? 'Request submitted' : 'Review action'}</button></div>}
            <div className="mt-3 flex flex-wrap gap-2">{entry.reply.links.map(link => <Link key={link.href} className="signet-assistant-link" to={link.href}>{link.label}</Link>)}</div>
            {entry.reply.period_days !== null && <p className="mt-2 text-[10px] text-ink-3">Recorded usage · last {entry.reply.period_days === 1 ? '24 hours' : `${entry.reply.period_days} days`}</p>}
          </>}
        </article>)}
        {busy && <div className="signet-assistant-thinking" role="status" data-testid="signet-assistant-thinking"><span className="animate-pulse">● ● ●</span><span>Checking Signet…</span></div>}
        {(error || status.error) && <div className="rounded-xl border border-bad/20 bg-bad-50 p-3 text-xs text-bad" role="alert" data-testid="signet-assistant-error">{error ?? status.error?.message}<Link className="mt-2 block underline" to="/settings/models">Open model settings</Link></div>}
      </div>
      <form className="signet-assistant-composer" onSubmit={submit}>
        {full && <p className="mb-2 text-xs text-warn">Start a new chat to continue; this conversation has reached 10 exchanges.</p>}
        <div className="flex items-end gap-2"><label htmlFor="signet-assistant-input" className="sr-only">Ask Signet AI</label><textarea ref={inputRef} id="signet-assistant-input" data-testid="signet-assistant-input" className="input min-h-12 resize-none" rows={2} maxLength={6000} placeholder="Ask about your agents…" value={input} disabled={busy || full} onChange={event => setInput(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); void send(input); } }} /><button type="submit" className="btn-primary min-w-11 px-3" data-testid="signet-assistant-send" aria-label="Send message" disabled={busy || full || !input.trim()}><ArrowUp size={20} /></button></div>
        <p className="mt-2 text-center text-[10px] text-ink-3">Signet only · live platform data · actions need your review</p>
      </form>
    </section>}
    {review && <LadderModal agent={{ id: review.action.agent_id, handle: review.action.agent_handle }} instances={[]} action={review.action.action} onClose={() => setReview(null)} onDone={() => setSubmitted(previous => [...previous, review.entry_id])} />}
  </>;
}

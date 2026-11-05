import { Check, Plus, Trash2, X } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { RestConnectionWizard } from '../components/RestConnectionWizard';
import { newConnectionDraft } from '../components/ExternalConnections';
import { ErrorNote, PageHeader } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan, useMe } from '../lib/auth';

// Guided onboarding: describe the agent first, then who and what it touches, then what it may do.
// Nothing technical comes first, and nothing is created until the third step is finished. The
// lifecycle, classification and approval rules are the backend's, unchanged.

export const FLOW_STEPS = ['About', 'People & data', 'What it can do', 'Safety check', 'Approval', 'Connect'];

export function FlowFrame({ step, children }: { step: number; children: ReactNode }) {
  return (
    <div className="flow-page">
      <header className="flow-head">
        <strong>Add an agent</strong>
        <ol className="flow-steps" aria-label="Progress">
          {FLOW_STEPS.map((label, i) => <li key={label} aria-current={i === step ? 'step' : undefined} className={i < step ? 'done' : i === step ? 'now' : ''}><i>{i < step ? <Check size={13} /> : i + 1}</i><span>{label}</span></li>)}
        </ol>
        <Link to="/agents" className="flow-exit">Exit</Link>
      </header>
      <div className="flow-body">{children}</div>
    </div>
  );
}

export function Choice({ on, multi, title, hint, onClick, testId }: { on: boolean; multi?: boolean; title: string; hint?: string; onClick: () => void; testId?: string }) {
  return (
    <button type="button" data-testid={testId} role={multi ? 'checkbox' : 'radio'} aria-checked={on} className={`choice ${on ? 'on' : ''}`} onClick={onClick}>
      <span className={`choice-mark ${multi ? 'multi' : ''}`}>{on && multi && <Check size={13} />}</span>
      <span><b>{title}</b>{hint && <small>{hint}</small>}</span>
    </button>
  );
}

// Step zero: three plain goals in place of connection methods.
export function AddAgentStart() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  const [goal, setGoal] = useState('one');
  // Connectors link here with a suggested name; those go straight to the form.
  useEffect(() => { if (params.get('name')) nav(`/agents/new/one?${params}`, { replace: true }); }, [params, nav]);
  const next = () => nav(goal === 'one' ? '/agents/new/one' : goal === 'find' ? '/settings/accounts' : '/agents/new/platform');
  return (
    <div className="flow-page">
      <header className="flow-head"><strong>Add an agent</strong><Link to="/agents" className="flow-exit">Exit</Link></header>
      <div className="flow-body narrow">
        <h1 className="flow-title">What would you like to do?</h1>
        <p className="flow-lead">There's no wrong answer. You can always add more later.</p>
        <div className="mt-7 space-y-3" role="radiogroup">
          <Choice on={goal === 'one'} testId="goal-one" onClick={() => setGoal('one')} title="Add one agent I know about" hint="A chatbot, assistant or automation that you or your team built or bought." />
          <Choice on={goal === 'find'} testId="goal-find" onClick={() => setGoal('find')} title="Find the agents my company already has" hint="Connect a cloud or AI account (AWS, Azure, Google, Vercel, OpenAI…) and pick from what Signet finds." />
          <Choice on={goal === 'platform'} testId="goal-platform" onClick={() => setGoal('platform')} title="Connect a platform that runs many agents" hint="Use a web address and API key to see and monitor every agent on it." />
        </div>
        <div className="flow-actions"><span /><button className="btn-primary btn-large" data-testid="goal-continue" onClick={next}>Continue</button></div>
      </div>
    </div>
  );
}

export function AddPlatform() {
  const nav = useNavigate();
  return (
    <div className="p-6 lg:p-10">
      <PageHeader title="Connect a platform" subtitle="Connect its API, see its agents, and choose which ones to bring into Signet." />
      <RestConnectionWizard agentId={null} initialDraft={newConnectionDraft('rest')} connectionId={null} onSaved={() => nav('/settings/systems')} onCancel={() => nav('/agents/new')} />
    </div>
  );
}

const USERS = [['internal', 'Our employees'], ['customers', 'Our customers'], ['public', 'The public']] as const;
const DATA = [['personal', 'Personal details', 'Names, emails, phone numbers'], ['financial_account', 'Bank or account info', ''], ['payment_card', 'Card numbers', ''], ['special_category', 'Health or other sensitive', ''], ['confidential_doc', 'Confidential documents', ''], ['source_code', 'Source code', '']] as const;
const RESTRICTED = ['payment_card', 'special_category'];
const DOMAINS = [['employment', 'Hiring or jobs'], ['credit', 'Loans or credit'], ['insurance', 'Insurance'], ['healthcare', 'Healthcare'], ['education', 'Education'], ['essential_services', 'Essential services'], ['other', 'Something else']] as const;
const FREEDOM = [['L0', 'Suggests only', 'A person does everything'], ['L1', 'Asks first', 'A person approves each action'], ['L2', 'Acts, within limits', 'People review afterwards'], ['L3', 'Acts on its own', 'Only within what you approve']] as const;
const IMPACT = [['read', 'Only reads information'], ['write', 'Adds or changes everyday records'], ['privileged', 'Sends messages or changes important records'], ['critical', 'Moves money or deletes things']] as const;

interface AppAction { server: string; name: string; label: string; impact: string; ask: boolean }
interface Draft {
  name: string; purpose: string; sponsor: string; vendorHosted: boolean; vendor: string;
  users: string[]; data: string[]; decisions: boolean | null; domains: string[]; undo: string;
  usesApps: boolean | null; actions: AppAction[]; autonomy: string;
}
const EMPTY: Draft = { name: '', purpose: '', sponsor: '', vendorHosted: false, vendor: '', users: [], data: [], decisions: null, domains: [], undo: '', usesApps: null, actions: [], autonomy: 'L1' };
const DRAFT_KEY = 'signet.add-agent-draft';

function loadDraft(): Draft {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    return raw ? { ...EMPTY, ...(JSON.parse(raw) as Partial<Draft>) } : EMPTY;
  } catch {
    return EMPTY;
  }
}
const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
const handleOf = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 58).replace(/-$/, '');

export function AddAgentFlow() {
  const nav = useNavigate();
  const me = useMe();
  const [params] = useSearchParams();
  const [d, setD] = useState<Draft>(() => { const draft = loadDraft(); const name = params.get('name'); return name ? { ...draft, name } : draft; });
  const [step, setStep] = useState(0);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [agentId, setAgentId] = useState<string | null>(null);
  const { data: catalogue } = useApi<{ catalogue: { model: string; region: string }[] }>('/catalogue');
  const { data: info } = useApi<{ environment: string }>('/connect/info');
  // The draft holds no secrets: app keys go straight to the Secrets Broker.
  useEffect(() => { try { localStorage.setItem(DRAFT_KEY, JSON.stringify(d)); } catch { /* the form still works */ } }, [d]);
  const set = (patch: Partial<Draft>) => setD({ ...d, ...patch });

  const ready = [
    d.name.trim().length > 0 && d.purpose.trim().length >= 10 && (!d.vendorHosted || d.vendor.trim().length > 0),
    d.users.length > 0 && d.decisions !== null && !!d.undo && (!d.decisions || d.domains.length > 0),
    d.usesApps === false ? !d.vendorHosted : d.usesApps === true && (d.actions.length > 0 || !d.vendorHosted),
  ];
  const missing = [
    d.name.trim() ? (d.purpose.trim().length < 10 ? 'Describe what it does in a little more detail' : d.vendorHosted && !d.vendor.trim() ? 'Name the vendor' : '') : 'Give it a name',
    !d.users.length ? 'Choose who it affects' : d.decisions === null ? 'Say whether it makes decisions about people' : d.decisions && !d.domains.length ? 'Choose the kind of decisions' : !d.undo ? 'Say whether mistakes can be undone' : '',
    d.usesApps === null ? 'Say whether it uses other apps' : d.vendorHosted && !d.actions.length ? 'A vendor-hosted agent needs at least one company app listed' : '',
  ];

  // Creates the agent, its draft permissions and submits it for the risk rating.
  const finish = async () => {
    setBusy(true);
    try {
      const actions = d.usesApps ? d.actions : [];
      let id = agentId;
      let lifecycleId: string | undefined;
      const body = {
        name: d.name.trim(), purpose: d.purpose.trim(), sponsor: d.sponsor.trim() || me.principal.id, autonomy_level: d.autonomy,
        kind: d.vendorHosted ? 'third_party' : 'self_hosted', vendor: d.vendorHosted ? d.vendor.trim() : undefined, connection_method: d.vendorHosted ? 'oauth' : 'rest',
        intake: { users_affected: d.users, data_touched: d.data, decisions_about_individuals: d.decisions === true, individual_domains: d.domains, reversibility: d.undo, planned_tools: actions.map((a) => `${a.name} (${a.impact})`) },
      };
      if (!id) {
        const base = handleOf(d.name) || 'agent';
        try {
          const a = await api<{ id: string; lifecycle_id: string }>('/agents', { method: 'POST', body: { ...body, handle: base } });
          id = a.id; lifecycleId = a.lifecycle_id;
        } catch (e) {
          if (!(e instanceof ApiError) || e.status !== 409) throw e;
          const a = await api<{ id: string; lifecycle_id: string }>('/agents', { method: 'POST', body: { ...body, handle: `${base}-${crypto.randomUUID().slice(0, 4)}` } });
          id = a.id; lifecycleId = a.lifecycle_id;
        }
        setAgentId(id);
      } else {
        lifecycleId = (await api<any>(`/agents/${id}`)).lifecycle?.lifecycle.id;
      }
      const tools = [...new Set(actions.map((a) => a.server))].map((server) => ({ server, data_scopes: d.data.filter((t) => !RESTRICTED.includes(t)), actions: actions.filter((a) => a.server === server).map((a) => ({ name: a.name, impact: a.impact })) }));
      const model = catalogue?.catalogue[0];
      await api(`/lifecycles/${lifecycleId}/manifest`, {
        method: 'PUT',
        body: {
          models: d.vendorHosted || !model ? [] : [{ model: model.model, region: model.region }],
          tools,
          hitl: actions.filter((a) => a.ask).map((a) => ({ action: `${a.server}.${a.name}`, approver_group: 'owner-approvers' })),
          // Restricted data stays out of prompts unless reviewers add it for a high-risk seal (RB-INV-17).
          data_classes: { prompt: d.data.filter((t) => !RESTRICTED.includes(t)), forbidden: ['payment_card'] },
          limits: { rpm: 60, tokens_per_day: 200_000, usd_per_day: 10 },
          environments: [info?.environment ?? 'dev'],
        },
      });
      await api(`/lifecycles/${lifecycleId}/stages/propose/submit`, { method: 'POST' });
      try { localStorage.removeItem(DRAFT_KEY); } catch { /* nothing to clean */ }
      nav(`/agents/${id}/setup`);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };

  const go = (to: number) => { setError(null); setStep(to); window.scrollTo(0, 0); };
  const actionsRow = (
    <div className="flow-actions">
      {step > 0 ? <button className="btn-ghost btn-large" onClick={() => go(step - 1)}>Back</button> : <span />}
      <div className="flex items-center gap-3">
        {!ready[step] && missing[step] && <span className="text-sm text-ink-3" data-testid="still-needed">{missing[step]}</span>}
        <button className="btn-primary btn-large" data-testid="flow-continue" disabled={!ready[step] || busy || (step === 2 && (!catalogue || !info))} onClick={() => (step === 2 ? void finish() : go(step + 1))}>{step === 2 ? (busy ? 'Working out the risk…' : 'See the risk result') : 'Continue'}</button>
      </div>
    </div>
  );
  const nameRequired = d.vendorHosted;

  return (
    <FlowFrame step={step}>
      <div className="flow-grid">
        <div className="min-w-0">
          {step === 0 && <>
            <h1 className="flow-title">Tell us about your agent</h1>
            <p className="flow-lead">Just the basics. Technical details come later, only if needed.</p>
            <label className="flow-label" htmlFor="flow-name">What do you call it?</label>
            <input id="flow-name" data-testid="flow-name" className="input" value={d.name} onChange={(e) => set({ name: e.target.value })} placeholder="Refund Helper" />
            <label className="flow-label" htmlFor="flow-purpose">What does it do, and for whom?</label>
            <textarea id="flow-purpose" data-testid="flow-purpose" className="input min-h-24" value={d.purpose} onChange={(e) => set({ purpose: e.target.value })} placeholder="Answers customer questions about orders and issues refunds when an order arrives damaged." />
            <label className="flow-label" htmlFor="flow-sponsor">Who else is accountable for it? <span className="font-normal text-ink-3">(optional; you're the owner)</span></label>
            <input id="flow-sponsor" className="input" value={d.sponsor} onChange={(e) => set({ sponsor: e.target.value })} placeholder="Business sponsor's email" />
            <div className="flow-label">Who runs it?</div>
            <div className="grid gap-3 sm:grid-cols-2" role="radiogroup">
              <Choice on={!d.vendorHosted} title="We run it ourselves" hint="Our own code, or a tool like n8n" onClick={() => set({ vendorHosted: false })} />
              <Choice on={d.vendorHosted} title="A vendor hosts it" hint="Such as Copilot or Agentforce" onClick={() => set({ vendorHosted: true })} />
            </div>
            {d.vendorHosted && <><label className="flow-label" htmlFor="flow-vendor">Which vendor?</label><input id="flow-vendor" className="input" value={d.vendor} onChange={(e) => set({ vendor: e.target.value })} placeholder="Microsoft Copilot Studio" /></>}
          </>}

          {step === 1 && <>
            <h1 className="flow-title">Who and what does it touch?</h1>
            <p className="flow-lead">This decides how much review it needs.</p>
            <div className="flow-label">Who will it affect?</div>
            <div className="grid gap-3 sm:grid-cols-3">{USERS.map(([v, l]) => <Choice key={v} multi testId={`flow-user-${v}`} on={d.users.includes(v)} title={l} onClick={() => set({ users: toggle(d.users, v) })} />)}</div>
            <div className="flow-label">What information can it see? <span className="font-normal text-ink-3">(leave empty if none)</span></div>
            <div className="grid gap-3 sm:grid-cols-3">{DATA.map(([v, l, h]) => <Choice key={v} multi on={d.data.includes(v)} title={l} hint={h} onClick={() => set({ data: toggle(d.data, v) })} />)}</div>
            <div className="mt-6 grid gap-6 sm:grid-cols-2">
              <div>
                <div className="flow-label !mt-0">Does it make decisions about people?</div>
                <div className="flex gap-2"><button type="button" data-testid="flow-decides-yes" className={`chip ${d.decisions === true ? 'on' : ''}`} onClick={() => set({ decisions: true })}>Yes</button><button type="button" data-testid="flow-decides-no" className={`chip ${d.decisions === false ? 'on' : ''}`} onClick={() => set({ decisions: false, domains: [] })}>No</button></div>
              </div>
              <div>
                <div className="flow-label !mt-0">Can its mistakes be undone?</div>
                <div className="flex gap-2">{[['yes', 'Yes'], ['partly', 'Partly'], ['no', 'No']].map(([v, l]) => <button key={v} type="button" data-testid={`flow-undo-${v}`} className={`chip ${d.undo === v ? 'on' : ''}`} onClick={() => set({ undo: v! })}>{l}</button>)}</div>
              </div>
            </div>
            {d.decisions && <><div className="flow-label">What kind of decisions?</div><div className="flex flex-wrap gap-2">{DOMAINS.map(([v, l]) => <button key={v} type="button" className={`chip ${d.domains.includes(v) ? 'on' : ''}`} onClick={() => set({ domains: toggle(d.domains, v) })}>{l}</button>)}</div></>}
          </>}

          {step === 2 && <>
            <h1 className="flow-title">What should it be able to do?</h1>
            <p className="flow-lead">Anything not listed here will be blocked.</p>
            <div className="flow-label">Besides talking, does it take actions in other apps?</div>
            <div className="grid gap-3 sm:grid-cols-2" role="radiogroup">
              <Choice on={d.usesApps === false} testId="flow-apps-no" title="No, it only answers" hint="Nothing else to set up." onClick={() => set({ usesApps: false })} />
              <Choice on={d.usesApps === true} testId="flow-apps-yes" title="Yes, it uses other apps" hint="List what it needs below." onClick={() => set({ usesApps: true })} />
            </div>
            {d.usesApps && (
              <div className="card mt-4 p-4">
                {d.actions.map((a, i) => (
                  <div key={`${a.server}.${a.name}`} className="flex flex-wrap items-center justify-between gap-3 border-b border-line py-3 last:border-0">
                    <div><b className="text-sm">{a.label}</b><div className="text-xs text-ink-3">{a.server.replace(/^\w+:\/\//, '')} · {IMPACT.find(([v]) => v === a.impact)?.[1]}</div></div>
                    <div className="flex items-center gap-3">
                      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={a.ask} onChange={() => set({ actions: d.actions.map((x, j) => (j === i ? { ...x, ask: !x.ask } : x)) })} />Always ask a person</label>
                      <button aria-label={`Remove ${a.label}`} className="icon-button" onClick={() => set({ actions: d.actions.filter((_, j) => j !== i) })}><Trash2 size={15} /></button>
                    </div>
                  </div>
                ))}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-3">
                  <button className="btn-ghost" data-testid="flow-add-app" onClick={() => setAdding(true)}><Plus size={15} />Add an action</button>
                  {!nameRequired && !d.actions.length && <span className="text-xs text-ink-3">Don't have the details? Continue, and add them before approval.</span>}
                </div>
              </div>
            )}
            <div className="flow-label">How much freedom should it have?</div>
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" role="radiogroup">{FREEDOM.map(([v, l, h]) => <Choice key={v} testId={`flow-freedom-${v}`} on={d.autonomy === v} title={l} hint={h} onClick={() => set({ autonomy: v })} />)}</div>
          </>}
          {error && <div className="mt-5"><ErrorNote error={error} /></div>}
          {actionsRow}
        </div>
        <aside className="flow-why">
          {step === 0 && <><h3>Why we ask</h3><p>Every agent needs a clear job and a named person responsible. If something goes wrong, Signet knows who to contact.</p></>}
          {step === 1 && <><h3>Nothing is final yet</h3><p>Signet uses these answers to work out the risk level for you. You can go back and correct them before you see the result.</p></>}
          {step === 2 && <><h3>You can skip apps for now</h3><p>No setup is needed to get this far. If you add apps later, the agent's safety check will ask for them before approval.</p></>}
        </aside>
      </div>
      {adding && <AddActionPanel onClose={() => setAdding(false)} onAdd={(a) => { set({ actions: [...d.actions.filter((x) => `${x.server}.${x.name}` !== `${a.server}.${a.name}`), a] }); setAdding(false); }} />}
    </FlowFrame>
  );
}

// Picks an action from an app Signet knows, or connects a new app in place. The key goes straight to
// the Secrets Broker; the agent never sees it, and it is not kept in the draft.
function AddActionPanel({ onClose, onAdd }: { onClose: () => void; onAdd: (a: AppAction) => void }) {
  const can = useCan();
  const { data: tools, reload } = useApi<{ items: { alias: string; kind: string; actions: Record<string, unknown> }[] }>('/tools');
  const canConnect = can('tools.manage') && can('secrets.manage');
  const [mode, setMode] = useState<'pick' | 'new'>('pick');
  const [server, setServer] = useState('');
  const [label, setLabel] = useState('');
  const [impact, setImpact] = useState('read');
  const [ask, setAsk] = useState(false);
  const [app, setApp] = useState({ name: '', url: '', key: '', method: 'POST', path: '/' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const items = tools?.items ?? [];
  const selected = items.find((t) => `${t.kind}://${t.alias}` === server);
  const httpActions = selected?.kind === 'http' ? Object.keys(selected.actions) : null;
  useEffect(() => { if (tools && !items.length) setMode('new'); }, [tools, items.length]);
  const actionName = (httpActions ? label : handleOf(label).replace(/-/g, '_'));

  const connect = async () => {
    setBusy(true);
    try {
      const alias = handleOf(app.name);
      const name = actionName;
      const secret = app.key ? await api<{ id: string }>('/secrets', { method: 'POST', body: { name: `${alias}-key`, kind: 'tool', value: app.key } }) : null;
      await api('/tools', { method: 'POST', body: { alias, kind: 'http', url: app.url.trim(), secret: secret?.id ?? null, actions: { [name]: { method: app.method, path: app.path } } } });
      setApp({ ...app, key: '' });
      await reload();
      onAdd({ server: `http://${alias}`, name, label, impact, ask });
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const actionFields = (
    <>
      <div className="flow-label">What does this action do to your data?</div>
      <select className="input" value={impact} onChange={(e) => setImpact(e.target.value)}>{IMPACT.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
      <label className="mt-4 flex items-center gap-2 text-sm"><input type="checkbox" checked={ask} onChange={(e) => setAsk(e.target.checked)} />Always ask a person before it does this</label>
    </>
  );
  return (
    <div className="drawer-scrim" onMouseDown={onClose}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Add an action" onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between"><h2 className="text-xl font-semibold">{mode === 'new' ? 'Connect an app' : 'Add an action'}</h2><button aria-label="Close" className="icon-button" onClick={onClose}><X size={17} /></button></div>
        {mode === 'pick' ? <>
          <div className="flow-label">Which app?</div>
          <select className="input" data-testid="action-app" value={server} onChange={(e) => { setServer(e.target.value); setLabel(''); }}><option value="">Choose an app…</option>{items.map((t) => <option key={t.alias} value={`${t.kind}://${t.alias}`}>{t.alias}</option>)}</select>
          {canConnect && <button className="mt-2 text-sm font-medium text-royal" onClick={() => setMode('new')}>+ Connect a new app</button>}
          {selected && <>
            <div className="flow-label">Which action?</div>
            {httpActions ? <select className="input" value={label} onChange={(e) => setLabel(e.target.value)}><option value="">Choose…</option>{httpActions.map((a) => <option key={a}>{a}</option>)}</select> : <input className="input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Action name, as the app calls it" />}
            {actionFields}
            <button className="btn-primary btn-large mt-6 w-full" disabled={!label.trim()} onClick={() => onAdd({ server, name: httpActions ? label : label.trim(), label, impact, ask })}>Add</button>
          </>}
        </> : canConnect ? <>
          <p className="mt-1 text-sm text-ink-2">Your agent never sees this key. Signet adds it to each approved action.</p>
          <label className="flow-label" htmlFor="app-name">App name</label><input id="app-name" data-testid="app-name" className="input" value={app.name} onChange={(e) => setApp({ ...app, name: e.target.value })} placeholder="Payments" />
          <label className="flow-label" htmlFor="app-url">Web address</label><input id="app-url" data-testid="app-url" className="input" value={app.url} onChange={(e) => setApp({ ...app, url: e.target.value })} placeholder="https://payments.example.com" />
          <label className="flow-label" htmlFor="app-key">Password or API key <span className="font-normal text-ink-3">(if it needs one)</span></label><input id="app-key" className="input" type="password" autoComplete="off" value={app.key} onChange={(e) => setApp({ ...app, key: e.target.value })} />
          <label className="flow-label" htmlFor="app-action">What can the agent do here?</label><input id="app-action" data-testid="app-action" className="input" value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Issue a refund" />
          <details className="mt-3 text-sm" open><summary className="cursor-pointer text-ink-2">Where the action lives in the app (from its API documentation)</summary><div className="mt-2 grid grid-cols-[110px_1fr] gap-2"><select aria-label="Method" className="input" value={app.method} onChange={(e) => setApp({ ...app, method: e.target.value })}>{['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => <option key={m}>{m}</option>)}</select><input aria-label="Path" data-testid="app-path" className="input mono" value={app.path} onChange={(e) => setApp({ ...app, path: e.target.value })} placeholder="/refunds" /></div></details>
          {actionFields}
          {error && <div className="mt-4"><ErrorNote error={error} /></div>}
          <div className="mt-6 flex items-center justify-between gap-3">{items.length ? <button className="btn-ghost" onClick={() => setMode('pick')}>Back</button> : <span />}<button className="btn-primary btn-large" data-testid="app-save" disabled={busy || !app.name.trim() || !app.url.trim() || !label.trim() || app.path.length < 2} onClick={() => void connect()}>{busy ? 'Saving…' : 'Save and go back'}</button></div>
        </> : <p className="mt-4 text-sm text-ink-2">Connecting a new app needs a platform administrator. Ask them to add it under Settings, or continue without it and add it before approval.</p>}
      </aside>
    </div>
  );
}

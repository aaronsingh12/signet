import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, ErrorNote, PageHeader, TierChip } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useMe } from '../lib/auth';
import { CONNECTION_METHODS } from '../lib/connections';
import type { ConnectionMethod } from '@signet/core/types';

const AUTONOMY = [
  ['L0', 'Suggests only; a human performs every action'],
  ['L1', 'Acts only after a human approves each action'],
  ['L2', 'Acts; a human reviews afterwards'],
  ['L3', 'Acts autonomously within seal limits'],
  ['L4', 'Fully autonomous; can spawn or direct agents'],
];
const USERS = [['internal', 'Employees'], ['customers', 'Customers'], ['public', 'The public']];
const DATA = ['personal', 'financial_account', 'confidential_doc', 'source_code', 'special_category', 'payment_card'];
const DOMAINS = ['credit', 'employment', 'insurance', 'healthcare', 'education', 'essential_services', 'other'];

const KINDS = [
  ['self_hosted', 'Self-hosted', 'Your code on your servers, RunPod, EC2, Docker. Connects with the SDK.'],
  ['framework', 'Framework-based', 'LangChain, LangGraph, CrewAI... Connects with the SDK.'],
  ['no_code', 'No-code hosted', 'n8n, Flowise, Dify. Connects through the Signet sidecar.'],
  ['third_party', 'Third-party / vendor', 'Copilot, Agentforce, ChatGPT, Amazon. Only its calls to company tools are governed.'],
];

const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
const handleOf = (name: string): string => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 63).replace(/-$/, '');

interface TemplateOption {
  id: string; name: string; tier_hint: string; autonomy: string;
  users_affected: string[]; decisions_about_individuals: boolean; data_touched: string[];
  suggested_actions: { name: string; impact: string }[];
}

// Stage 1 Propose (BP 6): purpose, owners, autonomy and the intake questions Classify scores. A
// template pre-fills the intake and a starting manifest; nothing is sealed until the matrix signs.
export function Propose() {
  const me = useMe();
  const nav = useNavigate();
  const { data: tpls } = useApi<{ items: TemplateOption[] }>('/templates');
  const [f, setF] = useState({ name: '', handle: '', purpose: '', sponsor: '', autonomy_level: 'L2', team: '' });
  const [template, setTemplate] = useState<string | null>(null);
  const [kind, setKind] = useState('self_hosted');
  const [rt, setRt] = useState({ runtime: '', framework: '', model_provider: '', vendor: '', contract: '', vendor_contact: '', data_residency: '', documentation: '' });
  const [intake, setIntake] = useState({ users_affected: [] as string[], decisions_about_individuals: false, individual_domains: [] as string[], data_touched: [] as string[], reversibility: 'partly', planned_tools: '', business_value: '' });
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);
  const [method, setMethod] = useState<ConnectionMethod>('oauth');
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const pick = (t: TemplateOption) => {
    setTemplate(t.id);
    setF({ ...f, autonomy_level: t.autonomy });
    setIntake({ ...intake, users_affected: t.users_affected, decisions_about_individuals: t.decisions_about_individuals, data_touched: t.data_touched, planned_tools: t.suggested_actions.map((a) => `${a.name} (${a.impact})`).join(', ') });
  };
  const submit = async () => {
    setBusy(true);
    try {
      const a = await api<{ id: string }>('/agents', {
        method: 'POST',
        body: {
          ...f,
          kind,
          connection_method: method,
          runtime: kind === 'third_party' ? 'vendor' : method === 'hybrid' ? 'on_prem' : rt.runtime || undefined,
          framework: rt.framework || undefined,
          model_provider: rt.model_provider || undefined,
          vendor: kind === 'third_party' ? rt.vendor : undefined,
          vendor_details: kind === 'third_party' ? Object.fromEntries(Object.entries({ contract: rt.contract, vendor_contact: rt.vendor_contact, data_residency: rt.data_residency, documentation: rt.documentation }).filter(([, v]) => v)) : undefined,
          team: f.team.split(',').map((s) => s.trim()).filter(Boolean).map((user) => ({ user, role: 'builder' })),
          intake: { ...intake, template, planned_tools: intake.planned_tools.split(',').map((s) => s.trim()).filter(Boolean) },
        },
      });
      nav(`/agents/${a.id}?tab=connection`);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const gate: [string, boolean][] = [
    ['Owner named (you)', true],
    ['Sponsor named', !!f.sponsor],
    ['Purpose complete', f.purpose.length >= 10],
    ['Autonomy level set', !!f.autonomy_level],
    ['Who it affects', intake.users_affected.length > 0],
    ['Handle is kebab-case', /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(f.handle)],
    ...(kind === 'third_party' ? [['Vendor named', !!rt.vendor.trim()] as [string, boolean]] : []),
  ];
  return (
    <>
      <PageHeader title="Connect an AI agent" subtitle="Choose a connection, add your agent's details, then review its permissions. Credentials become available after approval." />
      <ol className="mb-4 grid grid-cols-3 gap-3" aria-label="Add agent progress">{['Connection', 'Agent details', 'Permissions & review'].map((label, index) => <li key={label} aria-current={step === index ? 'step' : undefined} className={`rounded-lg border p-3 text-sm ${step === index ? 'border-royal bg-royal-50 text-royal' : 'border-line bg-white text-ink-3'}`}><span className="mr-2 font-semibold">{index + 1}</span>{label}</li>)}</ol>
      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <div className="space-y-4">
          {step === 0 && <>
          <Card title="How would you like to connect?">
            <div className="grid gap-3 md:grid-cols-2">{CONNECTION_METHODS.map((item) => <button key={item.id} data-testid={`connect-method-${item.id}`} aria-pressed={method === item.id} disabled={kind === 'third_party' && (item.id === 'bootstrap' || item.id === 'hybrid')} onClick={() => setMethod(item.id)} className={`rounded-lg border p-4 text-left disabled:opacity-40 ${method === item.id ? 'border-royal bg-royal-50' : 'border-line hover:bg-canvas'}`}><div className="font-semibold">{item.label}</div><p className="mt-1 text-sm text-ink-2">{item.description}</p></button>)}</div>
          </Card>
          <Card title="Agent type">
            <select data-testid="agent-kind" aria-label="Agent hosting" className="input" value={kind} onChange={(event) => { setKind(event.target.value); if (event.target.value === 'third_party') setMethod('oauth'); }}>{KINDS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
            <p className="mt-2 text-xs text-ink-3">{KINDS.find(([value]) => value === kind)?.[2]}</p>
            {kind === 'third_party' ? (
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                <div><label className="label">Vendor</label><input className="input" value={rt.vendor} onChange={(e) => setRt({ ...rt, vendor: e.target.value })} placeholder="Microsoft Copilot Studio" /></div>
                <div><label className="label">Contract or agreement</label><input className="input" value={rt.contract} onChange={(e) => setRt({ ...rt, contract: e.target.value })} placeholder="MSA-2026-114" /></div>
                <div><label className="label">Vendor contact</label><input className="input" value={rt.vendor_contact} onChange={(e) => setRt({ ...rt, vendor_contact: e.target.value })} /></div>
                <div><label className="label">Data residency</label><input className="input" value={rt.data_residency} onChange={(e) => setRt({ ...rt, data_residency: e.target.value })} placeholder="EU" /></div>
                <div className="md:col-span-2"><label className="label">Documentation (security whitepaper, DPA link)</label><input className="input" value={rt.documentation} onChange={(e) => setRt({ ...rt, documentation: e.target.value })} /></div>
                <p className="text-xs text-ink-3 md:col-span-2">The vendor's model runs outside Signet and is not intercepted. Signet governs the company tools this agent may call, through the gateway, with OAuth client credentials.</p>
              </div>
            ) : (
              <details className="mt-4"><summary className="cursor-pointer text-sm text-ink-2">Runtime and framework (optional)</summary><div className="mt-3 grid gap-3 md:grid-cols-3">
                <div><label className="label">Runtime</label><input className="input" list="runtimes" value={rt.runtime} onChange={(e) => setRt({ ...rt, runtime: e.target.value })} placeholder="runpod" /></div>
                <div><label className="label">Framework</label><input className="input" list="frameworks" value={rt.framework} onChange={(e) => setRt({ ...rt, framework: e.target.value })} placeholder="langchain" /></div>
                <div><label className="label">Built against (model provider)</label><input className="input" value={rt.model_provider} onChange={(e) => setRt({ ...rt, model_provider: e.target.value })} placeholder="openai-compatible" /></div>
                <datalist id="runtimes">{['runpod', 'aws_ec2', 'aws_ecs', 'docker', 'kubernetes', 'on_prem', 'azure_vm', 'gcp_vm'].map((x) => <option key={x} value={x} />)}</datalist>
                <datalist id="frameworks">{['custom-python', 'langchain', 'langgraph', 'crewai', 'autogen', 'llamaindex', 'n8n', 'flowise', 'dify', 'custom-node'].map((x) => <option key={x} value={x} />)}</datalist>
                <p className="text-xs text-ink-3 md:col-span-3">Its model calls will go to the tenant's one cloud LLM through the gateway, whatever it was built against.</p>
              </div></details>
            )}
          </Card>
          </>}
          {step === 1 && <>
          <details className="rounded-lg border border-line bg-white p-4"><summary className="cursor-pointer text-sm font-medium">Start from a template (optional)</summary>
          <Card>
            <div className="grid gap-2 md:grid-cols-3">
              {(tpls?.items ?? []).map((t) => (
                <button key={t.id} onClick={() => pick(t)} className={`rounded-md border p-2.5 text-left text-xs ${template === t.id ? 'border-royal bg-royal-50' : 'border-line hover:bg-canvas'}`}>
                  <div className="flex items-center gap-2 text-sm font-semibold">{t.name} <TierChip tier={t.tier_hint} /></div>
                  <div className="mt-0.5 text-ink-2">{t.suggested_actions.map((a) => a.name).join(', ')}</div>
                </button>
              ))}
            </div>
          </Card></details>
          <Card title="Purpose, owners, autonomy">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="label">Agent name</label>
                <input data-testid="agent-name" className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value, handle: f.handle === handleOf(f.name) ? handleOf(e.target.value) : f.handle })} placeholder="Refund Concierge" />
              </div>
              <div>
                <label className="label">Handle (kebab-case, unique)</label>
                <input data-testid="agent-handle" className="input mono" value={f.handle} onChange={set('handle')} placeholder="Generated from the agent name" />
              </div>
              <div className="md:col-span-2">
                <label className="label">Business purpose</label>
                <textarea data-testid="agent-purpose" className="input min-h-20" value={f.purpose} onChange={set('purpose')} placeholder="What the agent does, for whom, and why (at least 10 characters)" />
              </div>
              <div>
                <label className="label">Accountable owner</label>
                <input className="input" value={me.principal.id} disabled />
              </div>
              <div>
                <label className="label">Sponsor</label>
                <input data-testid="agent-sponsor" className="input" value={f.sponsor} onChange={set('sponsor')} placeholder="Business sponsor's identity" />
              </div>
              <div className="md:col-span-2">
                <label className="label">Build team (comma-separated emails; they can never approve this agent)</label>
                <input className="input" value={f.team} onChange={set('team')} placeholder="arjun.mehta@northwind.example" />
              </div>
            </div>
            <div className="mt-5">
              <label className="label">Autonomy</label>
              <div className="grid gap-2 md:grid-cols-5">
                {AUTONOMY.map(([l, d]) => (
                  <button key={l} onClick={() => setF({ ...f, autonomy_level: l })} className={`rounded-md border p-2.5 text-left text-xs ${f.autonomy_level === l ? 'border-royal bg-royal-50' : 'border-line hover:bg-canvas'}`}>
                    <div className="text-sm font-semibold">{l}</div>
                    <div className="mt-0.5 text-ink-2">{d}</div>
                  </button>
                ))}
              </div>
            </div>
          </Card>
          </>}
          {step === 2 && <>
          <Card title="Review your agent"><p className="text-sm"><strong>{f.name}</strong> · {CONNECTION_METHODS.find((item) => item.id === method)?.label} · <span className="mono">{f.handle}</span></p><p className="mt-2 text-xs text-ink-3">Registering creates a pending proposal. Complete the approval lifecycle before generating credentials.</p></Card>
          <Card title="Intake (scored at Classify)">
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="label">Who does it affect?</label>
                <div className="flex flex-wrap gap-3 text-sm">
                  {USERS.map(([v, l]) => <label key={v} className="flex items-center gap-1.5"><input data-testid={`agent-audience-${v}`} type="checkbox" checked={intake.users_affected.includes(v)} onChange={() => setIntake({ ...intake, users_affected: toggle(intake.users_affected, v) })} /> {l}</label>)}
                </div>
              </div>
              <div>
                <label className="label">Can its actions be undone?</label>
                <select className="input" value={intake.reversibility} onChange={(e) => setIntake({ ...intake, reversibility: e.target.value })}>
                  <option value="yes">Yes, fully</option><option value="partly">Partly</option><option value="no">No</option>
                </select>
              </div>
              <div className="md:col-span-2">
                <label className="label">What data does it touch?</label>
                <div className="flex flex-wrap gap-3 text-sm">
                  {DATA.map((d) => <label key={d} className="flex items-center gap-1.5"><input type="checkbox" checked={intake.data_touched.includes(d)} onChange={() => setIntake({ ...intake, data_touched: toggle(intake.data_touched, d) })} /> {d.replace('_', ' ')}</label>)}
                </div>
              </div>
              <div className="md:col-span-2">
                <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={intake.decisions_about_individuals} onChange={(e) => setIntake({ ...intake, decisions_about_individuals: e.target.checked })} /> It makes or shapes decisions about individual people</label>
                {intake.decisions_about_individuals && (
                  <div className="mt-2 flex flex-wrap gap-3 text-sm">
                    {DOMAINS.map((d) => <label key={d} className="flex items-center gap-1.5"><input type="checkbox" checked={intake.individual_domains.includes(d)} onChange={() => setIntake({ ...intake, individual_domains: toggle(intake.individual_domains, d) })} /> {d.replace('_', ' ')}</label>)}
                  </div>
                )}
              </div>
              <div className="md:col-span-2">
                <label className="label">Planned tools and actions (comma-separated)</label>
                <input className="input" value={intake.planned_tools} onChange={(e) => setIntake({ ...intake, planned_tools: e.target.value })} placeholder="lookup_order (read), issue_refund (privileged)" />
              </div>
              <div className="md:col-span-2">
                <label className="label">Business value</label>
                <input className="input" value={intake.business_value} onChange={(e) => setIntake({ ...intake, business_value: e.target.value })} />
              </div>
            </div>
          </Card>
          </>}
          <div className="flex items-center gap-3">
            <button data-testid="agent-back" className="btn" disabled={step === 0 || busy} onClick={() => setStep(step - 1)}>Back</button>
            {step < 2 ? <button data-testid="agent-next" className="btn-primary" disabled={step === 0 ? kind === 'third_party' && !rt.vendor.trim() : !f.name.trim() || !f.sponsor.trim() || f.purpose.trim().length < 10 || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(f.handle) || f.handle.length > 63} onClick={() => setStep(step + 1)}>Continue</button> : <button data-testid="agent-create" className="btn-primary" disabled={busy || gate.some(([, ok]) => !ok) || (intake.decisions_about_individuals && !intake.individual_domains.length)} onClick={() => void submit()}>{busy ? 'Registering…' : 'Register agent'}</button>}
            <ErrorNote error={error} />
          </div>
        </div>
        <Card title="Exit gate" className="h-fit">
          <ul className="space-y-2 text-sm">
            {gate.map(([l, ok]) => (
              <li key={l} className="flex items-center gap-2">
                <span className={`flex h-4 w-4 items-center justify-center rounded-full text-[10px] text-white ${ok ? 'bg-ok' : 'bg-slate-300'}`}>✓</span>
                {l}
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-ink-3">Next, on the agent's Lifecycle tab: draft the manifest and submit. Signet scores the risk, you complete the assessments for the tier, tests run, and the approval matrix signs the seal.</p>
        </Card>
      </div>
    </>
  );
}

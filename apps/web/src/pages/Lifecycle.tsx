import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, Empty, ErrorNote, KV, Mono, Pill, TierChip } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useMe } from '../lib/auth';
import { ago, date, hash } from '../lib/format';
import { LifecycleIntake } from '../components/LifecycleIntake';

// The 8-stage lifecycle on Agent 360 (BP 6): where the agent is, what its exit gate still needs, and
// the actions the signed-in person can take at this stage. Every action is an API call and a ledger entry.

const STAGES = ['propose', 'classify', 'assess', 'test', 'approve', 'deploy', 'monitor', 'retire'] as const;
const FACTOR_LABEL: Record<string, string> = { autonomy: 'Autonomy', data_sensitivity: 'Data sensitivity', decision_impact: 'Decision impact', external_exposure: 'External exposure', reversibility: 'Reversibility' };
const WEIGHT: Record<string, number> = { autonomy: 0.25, data_sensitivity: 0.25, decision_impact: 0.25, external_exposure: 0.15, reversibility: 0.1 };

function useAction(onDone: () => void) {
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (path: string, method: string, body?: unknown) => {
    setBusy(true);
    try {
      const r = await api(path, { method, body });
      setError(null);
      onDone();
      return r;
    } catch (e) {
      setError(e as ApiError);
      return null;
    } finally {
      setBusy(false);
    }
  };
  return { error, busy, run, clearError: () => setError(null) };
}

function Gate({ gate }: { gate: Record<string, boolean> | null }) {
  if (!gate) return null;
  return (
    <ul className="space-y-1.5 text-sm">
      {Object.entries(gate).map(([k, ok]) => (
        <li key={k} className="flex items-center gap-2">
          <span className={`flex h-4 w-4 items-center justify-center rounded-full text-[10px] text-white ${ok ? 'bg-ok' : 'bg-slate-300'}`}>✓</span>
          {k.replace(/_/g, ' ')}
        </li>
      ))}
    </ul>
  );
}

export function LifecycleTab({ data, onChange }: { data: any; onChange: () => void }) {
  const v = data.lifecycle;
  if (!v) return <Card><Empty>No lifecycle for this agent.</Empty></Card>;
  const lc = v.lifecycle;
  const at = STAGES.indexOf(lc.stage);
  return (
    <div className="space-y-4">
      <Card pad={false}>
        <ol className="flex overflow-x-auto">
          {STAGES.map((s, i) => {
            const done = i < at || lc.status === 'complete' && i <= at;
            const current = i === at && lc.status === 'in_progress';
            return (
              <li key={s} className={`flex min-w-[110px] flex-1 items-center gap-2 border-r border-line px-3 py-2.5 text-sm last:border-r-0 ${current ? 'bg-royal-50 font-semibold text-royal' : done ? 'text-ok' : 'text-ink-3'}`}>
                <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] ${current ? 'bg-royal text-white' : done ? 'bg-ok text-white' : 'bg-slate-200'}`}>{done ? '✓' : i + 1}</span>
                <span className="capitalize">{s}</span>
              </li>
            );
          })}
        </ol>
        <div className="border-t border-line px-4 py-2 text-xs text-ink-3">
          {lc.kind} lifecycle <Mono>{lc.id}</Mono> · {lc.status.replace('_', ' ')} · in {lc.stage} since {ago(lc.stage_entered_at)}
        </div>
      </Card>
      {lc.status === 'in_progress' && lc.stage === 'propose' && <ProposeStage v={v} onChange={onChange} />}
      {lc.status === 'in_progress' && lc.stage === 'classify' && <ClassifyStage v={v} onChange={onChange} />}
      {lc.status === 'in_progress' && lc.stage === 'assess' && <AssessStage v={v} onChange={onChange} />}
      {lc.status === 'in_progress' && lc.stage === 'test' && <TestStage v={v} onChange={onChange} />}
      {lc.status === 'in_progress' && lc.stage === 'approve' && <ApproveStage v={v} />}
      {lc.status === 'in_progress' && lc.stage === 'deploy' && <DeployStage v={v} onChange={onChange} />}
      {(lc.stage === 'monitor' || lc.status === 'complete') && <MonitorStage data={data} onChange={onChange} />}
      {v.classification && lc.stage !== 'classify' && <ClassificationSummary c={v.classification} />}
      <Card title="Stage history" pad={false}>
        {v.stages.length ? (
          <table className="w-full">
            <thead><tr>{['Stage', 'Outcome', 'By', 'Left'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {v.stages.map((s: any, i: number) => (
                <tr key={i}>
                  <td className="td capitalize">{s.stage}</td>
                  <td className="td"><Pill value={s.outcome === 'passed' ? 'allow' : 'deny'} label={s.outcome} /></td>
                  <td className="td text-xs text-ink-2">{s.actor}</td>
                  <td className="td text-xs text-ink-2">{ago(s.exited_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty>No stage completed yet.</Empty>
        )}
      </Card>
    </div>
  );
}

const MANIFEST_DATA = ['personal', 'financial_account', 'confidential_doc', 'source_code', 'special_category', 'payment_card'];
const IMPACTS = ['read', 'write', 'privileged', 'critical'];

// The everyday manifest fields as a form. It edits the same JSON, so fields it does not show (argument
// constraints, approval rules) are kept.
function ManifestForm({ text, onChange, agentKind }: { text: string; onChange: (text: string) => void; agentKind: string }) {
  const { data: catalogue } = useApi<{ catalogue: { model: string; region: string }[] }>('/catalogue');
  const { data: registered } = useApi<{ items: { alias: string; kind: string }[] }>('/tools');
  let m: any;
  try {
    m = JSON.parse(text);
  } catch {
    return <p className="text-sm text-bad">The JSON below is not valid, so the form is hidden until it is fixed.</p>;
  }
  const update = (fn: (draft: any) => void) => {
    const draft = JSON.parse(text);
    fn(draft);
    if (agentKind !== 'third_party' && !draft.models?.length && catalogue?.catalogue[0]) draft.models = [{ model: catalogue.catalogue[0].model, region: catalogue.catalogue[0].region }];
    onChange(JSON.stringify(draft, null, 2));
  };
  const number = (key: string, label: string) => (
    <label key={key} className="text-xs text-ink-3">{label}<input className="input mt-1" type="number" min="0" value={m.limits?.[key] ?? ''} onChange={(e) => update((d) => { d.limits = { ...d.limits, [key]: Number(e.target.value) }; })} /></label>
  );
  const dataBoxes = (key: 'prompt' | 'forbidden') => (
    <div className="flex flex-wrap gap-3 text-sm">{MANIFEST_DATA.map((tag) => <label key={tag} className="flex items-center gap-1.5"><input type="checkbox" checked={!!m.data_classes?.[key]?.includes(tag)} onChange={() => update((d) => { const list: string[] = d.data_classes?.[key] ?? []; d.data_classes = { ...d.data_classes, [key]: list.includes(tag) ? list.filter((x) => x !== tag) : [...list, tag] }; })} /> {tag.replace('_', ' ')}</label>)}</div>
  );
  return (
    <div className="space-y-4">
      <div><div className="label">Daily and per-minute limits</div><div className="grid gap-3 sm:grid-cols-3">{number('rpm', 'Requests per minute')}{number('tokens_per_day', 'Tokens per day')}{number('usd_per_day', 'USD per day')}</div></div>
      <div><div className="label">Data it may send to the model</div>{dataBoxes('prompt')}</div>
      <div><div className="label">Data that must never be sent</div>{dataBoxes('forbidden')}</div>
      <div><label className="label" htmlFor="lifecycle-1">Environments (comma-separated)</label><input id="lifecycle-1" className="input" value={(m.environments ?? []).join(', ')} onChange={(e) => update((d) => { d.environments = e.target.value.split(',').map((x: string) => x.trim()).filter(Boolean); })} /></div>
      <div>
        <div className="label">Tools it may call</div>
        {(m.tools ?? []).map((tool: any, ti: number) => (
          <div key={ti} className="mb-2 rounded-md border border-line p-3">
            <div className="flex items-center justify-between"><span className="mono text-sm">{tool.server}</span><button className="text-xs text-bad hover:underline" onClick={() => update((d) => { d.tools.splice(ti, 1); })}>Remove tool</button></div>
            {(tool.actions ?? []).map((action: any, ai: number) => (
              <div key={ai} className="mt-2 grid items-center gap-2 sm:grid-cols-[1fr_9rem_auto]">
                <input className="input" aria-label="Action name" placeholder="action name" value={action.name} onChange={(e) => update((d) => { d.tools[ti].actions[ai].name = e.target.value; })} />
                <select className="input" aria-label="Action impact" value={action.impact} onChange={(e) => update((d) => { d.tools[ti].actions[ai].impact = e.target.value; })}>{IMPACTS.map((x) => <option key={x} value={x}>{x}</option>)}</select>
                <button className="text-xs text-bad hover:underline" onClick={() => update((d) => { d.tools[ti].actions.splice(ai, 1); })}>Remove</button>
              </div>
            ))}
            <button className="btn-ghost mt-2 text-xs" onClick={() => update((d) => { d.tools[ti].actions = [...(d.tools[ti].actions ?? []), { name: '', impact: 'read' }]; })}>Add action</button>
          </div>
        ))}
        {registered?.items?.length ? (
          <select className="input" aria-label="Add a tool" value="" onChange={(e) => { const server = e.target.value; if (server) update((d) => { d.tools = [...(d.tools ?? []), { server, data_scopes: [], actions: [{ name: '', impact: 'read' }] }]; }); }}><option value="">Add a registered tool…</option>{registered.items.map((t) => <option key={t.alias} value={`${t.kind}://${t.alias}`}>{t.alias}</option>)}</select>
        ) : <p className="text-xs text-ink-3">No tools registered yet. Add them under Tools & credentials.</p>}
      </div>
    </div>
  );
}

function ManifestEditor({ v, onChange }: { v: any; onChange: () => void }) {
  const [text, setText] = useState(() => JSON.stringify(v.lifecycle.data.manifest ?? {}, null, 2));
  const [parseError, setParseError] = useState<string | null>(null);
  const a = useAction(onChange);
  const save = () => {
    try {
      const body = JSON.parse(text);
      setParseError(null);
      void a.run(`/lifecycles/${v.lifecycle.id}/manifest`, 'PUT', body);
    } catch {
      setParseError('the manifest is not valid JSON');
    }
  };
  return (
    <Card title="Manifest draft" action={<button className="btn-ghost" disabled={a.busy} onClick={save}>Save manifest</button>}>
      <ManifestForm text={text} onChange={setText} agentKind={v.agent.kind} />
      {v.agent.kind === 'third_party' && <p className="mt-2 text-sm text-ink-3">Vendor models run outside Signet. Keep models empty. REST-connected agents can have no company tools; this grants no tool access or control over their internal model calls.</p>}
      <details className="mt-4"><summary className="cursor-pointer text-sm text-ink-2">Edit as JSON (advanced: constraints, approval rules)</summary>
      <textarea className="input mono mt-2 min-h-[300px] text-xs" spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} />
      </details>
      <p className="mt-2 text-xs text-ink-3">Checked on save: the model is the tenant's cloud LLM (RB-INV-19), every action has an impact label (RB-PRIV-01), tool aliases are registered, nothing secret reaches the model (RB-INV-16).</p>
      <div className="mt-2"><ErrorNote error={parseError ? { rule: 'JSON', message: parseError } : a.error} /></div>
    </Card>
  );
}

function ProposeStage({ v, onChange }: { v: any; onChange: () => void }) {
  const a = useAction(onChange);
  const i = v.lifecycle.data.intake;
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
      <div className="space-y-4">
        <LifecycleIntake key={v.lifecycle.id} lifecycleId={v.lifecycle.id} intake={i} onChange={() => { a.clearError(); onChange(); }} />
        <ManifestEditor v={v} onChange={onChange} />
      </div>
      <Card title="Exit gate">
        <Gate gate={v.gate} />
        <button className="btn-primary mt-4 w-full" disabled={a.busy} onClick={() => void a.run(`/lifecycles/${v.lifecycle.id}/stages/propose/submit`, 'POST')}>Submit for classification</button>
        <div className="mt-2"><ErrorNote error={a.error} /></div>
      </Card>
    </div>
  );
}

function ClassificationSummary({ c }: { c: any }) {
  return (
    <Card title="Classification">
      <KV
        rows={[
          ['Tier', <span key="t"><TierChip tier={c.tier} /> score {c.score}{c.confirmed_by ? ` · confirmed by ${c.confirmed_by}` : ' · not confirmed'}</span>],
          ['Regulatory', c.regulatory_category],
          ['Frameworks', c.frameworks.join(', ')],
          ['Factors', Object.entries(c.factors).map(([k, x]) => `${FACTOR_LABEL[k] ?? k} ${x}`).join(' · ')],
          ['Reasons', c.reasons.join('; ')],
        ]}
      />
    </Card>
  );
}

function ClassifyStage({ v, onChange }: { v: any; onChange: () => void }) {
  const me = useMe();
  const c = v.classification;
  const riskTeam = me.principal.roles.some((r) => r === 'risk_officer' || r === 'governance_board');
  const [over, setOver] = useState<Record<string, number>>({});
  const [reason, setReason] = useState('');
  const a = useAction(onChange);
  const factors = { ...c.factors, ...over };
  const score = Math.round(Object.entries(factors).reduce((s, [k, x]) => s + Number(x) * (WEIGHT[k] ?? 0), 0) * 100) / 100;
  const needsRisk = c.tier === 'T1' || c.tier === 'T2';
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
      <Card title="Risk score (BP 6, Stage 2)">
        <table className="w-full">
          <thead><tr>{['Factor', 'Weight', 'Suggested', riskTeam ? 'Override' : ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {Object.keys(WEIGHT).map((k) => (
              <tr key={k}>
                <td className="td">{FACTOR_LABEL[k]}</td>
                <td className="td text-ink-2">{WEIGHT[k]}</td>
                <td className="td">{c.factors[k]}</td>
                <td className="td">
                  {riskTeam && (
                    <select className="input w-20" value={over[k] ?? ''} onChange={(e) => setOver({ ...over, [k]: Number(e.target.value) || undefined } as Record<string, number>)}>
                      <option value="">—</option>
                      {[1, 2, 3, 4, 5].map((n) => <option key={n} value={n}>{n}</option>)}
                    </select>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="mt-3 text-sm">Weighted score <b>{score}</b> → <TierChip tier={score >= 4 ? 'T1' : score >= 3 ? 'T2' : score >= 2 ? 'T3' : 'T4'} /> <span className="text-ink-3">(≥4 T1 · ≥3 T2 · ≥2 T3 · else T4; decisions about individuals floor at T2)</span></div>
        {Object.keys(over).some((k) => over[k]) && (
          <div className="mt-3">
            <label className="label" htmlFor="lifecycle-2">Reason for the override (ledgered)</label>
            <input id="lifecycle-2" className="input" value={reason} onChange={(e) => setReason(e.target.value)} />
            <button className="btn-ghost mt-2" disabled={a.busy || !reason.trim()} onClick={() => void a.run(`/lifecycles/${v.lifecycle.id}/classification`, 'POST', { overrides: Object.fromEntries(Object.entries(over).filter(([, x]) => x)), reason })}>Apply override</button>
          </div>
        )}
      </Card>
      <Card title="Confirm">
        <KV rows={[['Suggested tier', <TierChip key="t" tier={c.tier} />], ['Regulatory', c.regulatory_category], ['Frameworks', c.frameworks.join(', ')]]} />
        <p className="mt-3 text-xs text-ink-3">{needsRisk ? `${c.tier} is confirmed by Risk/Compliance, not the build team.` : 'The owner or the risk team confirms.'}</p>
        <button className="btn-primary mt-3 w-full" disabled={a.busy} onClick={() => void a.run(`/lifecycles/${v.lifecycle.id}/classification`, 'POST', { confirm: true })}>Confirm classification</button>
        <div className="mt-2"><ErrorNote error={a.error} /></div>
      </Card>
    </div>
  );
}

function Questionnaire({ lcId, asm, onChange }: { lcId: string; asm: any; onChange: () => void }) {
  const [answers, setAnswers] = useState<Record<string, { answer: string; note: string }>>(asm.content.answers ?? {});
  const a = useAction(onChange);
  const qs = asm.content.questions ?? [];
  const save = (complete: boolean) => void a.run(`/lifecycles/${lcId}/assessments/questionnaire`, 'PUT', { content: { ...asm.content, answers }, complete });
  return (
    <Card title={<span>Control questionnaire <Pill value={asm.status === 'complete' ? 'allow' : 'require_approval'} label={asm.status} /></span>}>
      <ul className="space-y-3">
        {qs.map((q: any) => (
          <li key={q.id} className="grid gap-2 md:grid-cols-[1fr_120px_200px] md:items-center">
            <div className="text-sm">{q.text} <span className="mono text-[11px] text-ink-3">{q.control} · {q.severity}</span></div>
            <select className="input" value={answers[q.id]?.answer ?? ''} onChange={(e) => setAnswers({ ...answers, [q.id]: { ...answers[q.id], answer: e.target.value, note: answers[q.id]?.note ?? '' } })}>
              <option value="">—</option><option value="yes">Yes</option><option value="partial">Partly</option><option value="no">No</option><option value="na">Not applicable</option>
            </select>
            <input className="input" placeholder="Note" value={answers[q.id]?.note ?? ''} onChange={(e) => setAnswers({ ...answers, [q.id]: { answer: answers[q.id]?.answer ?? '', note: e.target.value } })} />
          </li>
        ))}
      </ul>
      <p className="mt-3 text-xs text-ink-3">A “No” or “Partly” opens a gap against its control, at the question's severity.</p>
      <div className="mt-3 flex gap-2">
        <button className="btn-ghost" disabled={a.busy} onClick={() => save(false)}>Save draft</button>
        <button className="btn-primary" disabled={a.busy} onClick={() => save(true)}>Mark complete</button>
      </div>
      <div className="mt-2"><ErrorNote error={a.error} /></div>
    </Card>
  );
}

function FreeAssessment({ lcId, asm, onChange }: { lcId: string; asm: any; onChange: () => void }) {
  const [summary, setSummary] = useState(String(asm.content.summary ?? ''));
  const [findings, setFindings] = useState(String(asm.content.findings ?? ''));
  const a = useAction(onChange);
  const save = (complete: boolean) => void a.run(`/lifecycles/${lcId}/assessments/${asm.type}`, 'PUT', { content: { ...asm.content, summary, findings }, complete });
  return (
    <Card title={<span className="capitalize">{asm.type.replace('_', ' ')} <Pill value={asm.status === 'complete' ? 'allow' : 'require_approval'} label={asm.status} /></span>}>
      <label className="label" htmlFor="lifecycle-3">Summary</label>
      <textarea id="lifecycle-3" className="input min-h-20" value={summary} onChange={(e) => setSummary(e.target.value)} />
      <label className="label mt-2">Findings</label>
      <textarea className="input min-h-16" value={findings} onChange={(e) => setFindings(e.target.value)} />
      <div className="mt-3 flex gap-2">
        <button className="btn-ghost" disabled={a.busy} onClick={() => save(false)}>Save draft</button>
        <button className="btn-primary" disabled={a.busy || !summary.trim()} onClick={() => save(true)}>Mark complete</button>
      </div>
      <div className="mt-2"><ErrorNote error={a.error} /></div>
    </Card>
  );
}

function Gaps({ v, onChange }: { v: any; onChange: () => void }) {
  const a = useAction(onChange);
  const [f, setF] = useState({ severity: 'medium', title: '', mitigation: '' });
  const [accept, setAccept] = useState<{ id: string; reason: string; until: string } | null>(null);
  return (
    <Card title="Gaps" pad={false}>
      {v.gaps.length ? (
        <table className="w-full">
          <thead><tr>{['Severity', 'Gap', 'Control', 'Status', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {v.gaps.map((g: any) => (
              <tr key={g.id}>
                <td className="td"><Pill value={g.severity === 'critical' || g.severity === 'high' ? 'deny' : 'require_approval'} label={g.severity} /></td>
                <td className="td text-sm">{g.title}{g.mitigation ? <div className="text-xs text-ink-3">{g.mitigation}</div> : null}</td>
                <td className="td"><Mono>{g.control_id ?? '—'}</Mono></td>
                <td className="td text-xs">{g.status}{g.accepted_until ? ` until ${date(g.accepted_until)}` : ''}</td>
                <td className="td whitespace-nowrap text-right">
                  {g.status === 'open' && (
                    <>
                      <button className="btn-ghost text-xs" onClick={() => { const m = prompt('How was it mitigated?'); if (m) void a.run(`/gaps/${g.id}`, 'PATCH', { status: 'mitigated', mitigation: m }); }}>Mitigated</button>
                      <button className="btn-ghost text-xs" onClick={() => setAccept({ id: g.id, reason: '', until: new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10) })}>Accept risk</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <Empty>No gaps.</Empty>
      )}
      {accept && (
        <div className="border-t border-line p-4">
          <div className="text-sm font-medium">Risk acceptance request (Risk and the sponsor decide)</div>
          <div className="mt-2 grid gap-2 md:grid-cols-[1fr_160px_auto]">
            <input className="input" placeholder="Why the risk is acceptable" value={accept.reason} onChange={(e) => setAccept({ ...accept, reason: e.target.value })} />
            <input className="input" type="date" value={accept.until} onChange={(e) => setAccept({ ...accept, until: e.target.value })} />
            <button className="btn-primary" disabled={!accept.reason.trim()} onClick={() => void a.run(`/gaps/${accept.id}/acceptance`, 'POST', { reason: accept.reason, until: accept.until }).then(() => setAccept(null))}>Request</button>
          </div>
        </div>
      )}
      <div className="grid gap-2 border-t border-line p-4 md:grid-cols-[120px_1fr_1fr_auto]">
        <select className="input" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s}>{s}</option>)}</select>
        <input className="input" placeholder="New gap" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} />
        <input className="input" placeholder="Mitigation (optional)" value={f.mitigation} onChange={(e) => setF({ ...f, mitigation: e.target.value })} />
        <button className="btn-ghost" disabled={!f.title.trim()} onClick={() => void a.run(`/lifecycles/${v.lifecycle.id}/gaps`, 'POST', f).then(() => setF({ severity: 'medium', title: '', mitigation: '' }))}>Add gap</button>
      </div>
      <div className="px-4 pb-3"><ErrorNote error={a.error} /></div>
    </Card>
  );
}

export function AssessStage({ v, onChange }: { v: any; onChange: () => void }) {
  const a = useAction(onChange);
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
      <div className="space-y-4">
        {v.assessments.map((asm: any) =>
          asm.type === 'questionnaire' ? <Questionnaire key={asm.id} lcId={v.lifecycle.id} asm={asm} onChange={onChange} /> : <FreeAssessment key={asm.id} lcId={v.lifecycle.id} asm={asm} onChange={onChange} />,
        )}
        <Gaps v={v} onChange={onChange} />
        <ManifestEditor v={v} onChange={onChange} />
      </div>
      <Card title="Exit gate">
        <div className="mb-3 text-xs text-ink-3">Required for {v.agent.tier}: {v.required_assessments.join(', ') || 'none'}</div>
        <Gate gate={v.gate} />
        <button className="btn-primary mt-4 w-full" disabled={a.busy} onClick={() => void a.run(`/lifecycles/${v.lifecycle.id}/stages/assess/submit`, 'POST')}>Continue to tests</button>
        <div className="mt-2"><ErrorNote error={a.error} /></div>
      </Card>
    </div>
  );
}

function Suites({ suites }: { suites: any[] }) {
  return (
    <table className="w-full">
      <thead><tr>{['Suite', 'Required', 'Result', 'Cases', 'Detail'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
      <tbody>
        {suites.map((s) => (
          <tr key={s.suite}>
            <td className="td mono">{s.suite}</td>
            <td className="td text-xs">{s.required ? 'yes' : 'no'}</td>
            <td className="td"><Pill value={s.passed ? 'allow' : s.required ? 'deny' : 'none'} label={s.passed ? 'pass' : 'fail'} /></td>
            <td className="td text-xs">{s.cases}</td>
            <td className="td text-xs text-ink-2">{s.failures?.length ? s.failures.join('; ') : s.value !== undefined && s.value !== null ? `${s.value}${s.threshold ? ` (needs ${s.threshold})` : ''}` : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function TestStage({ v, onChange }: { v: any; onChange: () => void }) {
  const [functional, setFunctional] = useState('');
  const [bias, setBias] = useState('');
  const [redTeam, setRedTeam] = useState('');
  const a = useAction(onChange);
  const last = v.tests[0];
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
      <Card title="Last test run" pad={false}>{last ? <Suites suites={last.suites.suites} /> : <Empty>No run yet.</Empty>}</Card>
      <Card title="Run baseline suites">
        <p className="text-xs text-ink-3">Signet runs tool misuse, argument constraints, data leakage and HITL suites against the compiled policy. Supply the evidence it cannot measure itself.</p>
        <label className="label mt-3">Functional eval score % (T1/T2 need ≥ 85)</label>
        <input className="input" value={functional} onChange={(e) => setFunctional(e.target.value.replace(/[^\d.]/g, ''))} />
        <label className="label mt-2">Bias ratio (if it decides about individuals; 0.8–1.25)</label>
        <input className="input" value={bias} onChange={(e) => setBias(e.target.value.replace(/[^\d.]/g, ''))} />
        {v.agent.tier === 'T1' && (
          <>
            <label className="label mt-2">Red-team report SHA-256 (T1)</label>
            <input className="input mono" value={redTeam} onChange={(e) => setRedTeam(e.target.value.trim())} />
          </>
        )}
        <button
          className="btn-primary mt-3 w-full"
          disabled={a.busy}
          onClick={() => void a.run(`/lifecycles/${v.lifecycle.id}/test-runs`, 'POST', { functional_score: functional ? Number(functional) : undefined, bias_ratio: bias ? Number(bias) : undefined, red_team_report_sha256: redTeam || undefined })}
        >
          Run tests
        </button>
        <p className="mt-2 text-xs text-ink-3">A failing required suite opens gaps and returns the agent to Assess.</p>
        <div className="mt-2"><ErrorNote error={a.error} /></div>
      </Card>
    </div>
  );
}

function ApproveStage({ v }: { v: any }) {
  const r = v.approval;
  if (!r) return <Card><Empty>Waiting for the approval request.</Empty></Card>;
  return (
    <Card title="Approval" action={<Link className="btn-primary" to={`/needs-you?id=${r.id}`}>Open approval</Link>}>
      <KV
        rows={[
          ['Request', <Mono key="r">{r.id}</Mono>],
          ['Status', r.status],
          ['Signatures', r.slots.map((s: any) => `${s.label}: ${(r.decisions ?? []).filter((d: any) => d.slot === s.slot).map((d: any) => `${d.approver} (${d.decision})`).join(', ') || 'open'}`).join(' · ')],
          ['Due', date(r.sla_due)],
          ['Pack hash', <Mono key="h">{hash(r.pack_hash)}</Mono>],
        ]}
      />
    </Card>
  );
}

export function DeployStage({ v, onChange }: { v: any; onChange: () => void }) {
  const d = v.deploy;
  const [reason, setReason] = useState('');
  const [ack, setAck] = useState(false);
  const [override, setOverride] = useState(false);
  const a = useAction(onChange);
  if (!d) return null;
  const next = d.mode === 'shadow' && d.canary ? 'canary' : 'enforce';
  const need = d.mode === 'shadow' ? d.shadow_days : 1;
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
      <Card title={<span>Stage: <span>{d.mode === 'shadow' ? 'Trial' : d.mode === 'canary' ? 'Partial protection' : 'Protected'}</span>{d.mode === 'canary' ? ` (${d.canary_pct}% of sessions enforced)` : ''}</span>}>
        <KV
          rows={[
            ['Path', `Trial for ${d.shadow_days} days${d.canary ? `, then ${d.canary_pct}% of conversations for 1 day` : ''}, then full protection`],
            ['So far', `${d.days_in_mode.toFixed(2)} of ${need} days`],
            ['Requests', d.stats.transactions],
            ['Would have been stopped or held', `${d.stats.would_block} (${d.stats.critical_would_block} critical)`],
            ['Service errors', d.stats.upstream_errors],
            ['Shortened by', d.overrides.length ? d.overrides.join(' · ') : '—'],
          ]}
        />
        <p className="mt-3 text-xs text-ink-3">During the trial, Signet records what it would have stopped and lets the request through; emergency stops, leaked secrets and the one-AI-model rule are enforced from the first call. Look at the would-blocks in the Ledger Explorer before moving on.</p>
        <Link className="mt-1 inline-block text-xs text-royal hover:underline" to={`/ledger?agent=${v.agent.id}`}>Open this agent's records</Link>
      </Card>
      <Card title={next === 'canary' ? 'Protect 10% of conversations' : 'Turn on protection'}>
        {d.stats.critical_would_block > 0 && (
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-1" /> I reviewed the {d.stats.critical_would_block} critical would-block decision(s)</label>
        )}
        {d.days_in_mode < need && (
          <>
            <label className="mt-2 flex items-start gap-2 text-sm"><input type="checkbox" checked={override} onChange={(e) => setOverride(e.target.checked)} className="mt-1" /> End this stage early (dev only, recorded)</label>
            {override && <input className="input mt-2" placeholder="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />}
          </>
        )}
        <button className="btn-primary mt-3 w-full" disabled={a.busy} onClick={() => void a.run(`/lifecycles/${v.lifecycle.id}/deploy`, 'POST', { to: next, acknowledge_would_blocks: ack || undefined, dev_override: override || undefined, reason: reason || undefined })}>
          {next === 'canary' ? 'Start partial protection' : 'Turn on protection'}
        </button>
        <div className="mt-2"><ErrorNote error={a.error} /></div>
      </Card>
    </div>
  );
}

function MonitorStage({ data, onChange }: { data: any; onChange: () => void }) {
  const me = useMe();
  const own = data.agent.owner === me.principal.id;
  const a = useAction(onChange);
  const [checks, setChecks] = useState({ purpose_unchanged: false, manifest_minimal: false, owner_accountable: false });
  const [change, setChange] = useState<{ kind: 'minor' | 'major'; reason: string } | null>(null);
  const [retire, setRetire] = useState('');
  const [result, setResult] = useState<string | null>(null);
  useEffect(() => setResult(null), [data.lifecycle?.lifecycle.id]);
  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Card title="Re-attestation (owner)">
        {[
          ['purpose_unchanged', 'The purpose is unchanged'],
          ['manifest_minimal', 'The manifest is still the least it needs'],
          ['owner_accountable', 'I remain accountable for this agent'],
        ].map(([k, l]) => (
          <label key={k} className="flex items-center gap-2 text-sm"><input type="checkbox" disabled={!own} checked={(checks as any)[k]} onChange={(e) => setChecks({ ...checks, [k]: e.target.checked })} /> {l}</label>
        ))}
        <button className="btn-primary mt-3" disabled={!own || a.busy || !Object.values(checks).every(Boolean)} onClick={() => void a.run(`/agents/${data.agent.id}/attest`, 'POST', checks).then((r: any) => r && setResult(r.renewed_cert_id ? `Attested; seal renewed (${r.renewed_cert_id})` : 'Attested'))}>Sign attestation</button>
        <div className="mt-3 text-xs text-ink-3">{data.attestations.length ? `Last: ${ago(data.attestations[0].signed_at)} by ${data.attestations[0].signer}` : 'No attestation yet.'} Inside 30 days of expiry an attestation renews the seal.</div>
      </Card>
      <Card title="Change request">
        <p className="text-xs text-ink-3">Minor (limits, constraints, same tools): back to Test. Major (new tools, data or purpose): back to Classify. The current seal keeps running until the new one is issued.</p>
        {change ? (
          <div className="mt-2 space-y-2">
            <select className="input" value={change.kind} onChange={(e) => setChange({ ...change, kind: e.target.value as 'minor' | 'major' })}><option value="minor">Minor</option><option value="major">Major</option></select>
            <input className="input" placeholder="What changes and why" value={change.reason} onChange={(e) => setChange({ ...change, reason: e.target.value })} />
            <button className="btn-primary" disabled={!change.reason.trim()} onClick={() => void a.run(`/agents/${data.agent.id}/changes`, 'POST', change).then(() => setChange(null))}>Start change</button>
          </div>
        ) : (
          <button className="btn-ghost mt-2" onClick={() => setChange({ kind: 'minor', reason: '' })}>New change request</button>
        )}
      </Card>
      <Card title="Retire">
        <p className="text-xs text-ink-3">Retirement revokes the seal and tokens once Owner and Security sign the decommission pack.</p>
        <input className="input mt-2" placeholder="Reason" value={retire} onChange={(e) => setRetire(e.target.value)} />
        <button className="btn-ghost mt-2 text-bad" disabled={!retire.trim() || a.busy} onClick={() => void a.run(`/agents/${data.agent.id}/retire`, 'POST', { reason: retire }).then((r: any) => r && setResult(`Retirement request ${r.id} sent for approval`))}>Request retirement</button>
      </Card>
      {(result || a.error) && <div className="xl:col-span-3">{result ? <div className="rounded-md bg-ok-50 px-3 py-2 text-sm text-ok">{result}</div> : <ErrorNote error={a.error} />}</div>}
    </div>
  );
}

import { useState } from 'react';
import { Link, Navigate, useParams } from 'react-router-dom';
import { CopyCode } from '../components/CopyCode';
import { ErrorNote } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useMe } from '../lib/auth';
import { DETECTOR_HOLD_NOTE, RISK_LABEL, isHighRisk, riskReasons } from '../lib/plain';
import { Choice, FlowFrame } from './AddAgent';
import { ApprovalDetail } from './Approvals';
import { ConnectionTab } from './Connection';
import { AssessStage, DeployStage, LifecycleTab, TestStage } from './Lifecycle';

// The rest of the guided path once an agent exists: it always opens on whatever the lifecycle needs
// next, so anyone can leave and come back. Gates and approvals stay in the backend.

const SEVERITY_NOTE = { partial: "We'll note this as something to improve", no: "We'll note this as something to close before approval" };
const stepOf = (stage: string) => (stage === 'approve' ? 4 : stage === 'deploy' || stage === 'monitor' ? 5 : stage === 'propose' ? 2 : 3);

export function AgentSetup() {
  const { id } = useParams();
  const { data, reload, error } = useApi<any>(`/agents/${id}`);
  if (error) return <FlowFrame step={0}><ErrorNote error={error} /></FlowFrame>;
  if (!data) return <FlowFrame step={0}><p className="py-10 text-center text-sm text-ink-3" role="status">Loading…</p></FlowFrame>;
  const v = data.lifecycle;
  if (!v) return <Navigate to={`/agents/${id}`} replace />;
  const lc = v.lifecycle;
  if (lc.status === 'complete') return <Navigate to={`/agents/${id}`} replace />;
  const onChange = () => void reload();
  return (
    <FlowFrame step={stepOf(lc.stage)} back={`/agents/${id}`}>
      {lc.status === 'rejected' && <Rejected v={v} agentId={id!} />}
      {lc.status === 'in_progress' && lc.stage === 'propose' && <Wide title="A few details are still needed"><LifecycleTab data={data} onChange={onChange} /></Wide>}
      {lc.status === 'in_progress' && lc.stage === 'classify' && <RiskResult data={data} onChange={onChange} />}
      {lc.status === 'in_progress' && lc.stage === 'assess' && <Assess v={v} onChange={onChange} />}
      {lc.status === 'in_progress' && lc.stage === 'test' && <Test v={v} onChange={onChange} />}
      {lc.status === 'in_progress' && lc.stage === 'approve' && <Approve v={v} onChange={onChange} />}
      {lc.status === 'in_progress' && lc.stage === 'deploy' && <Connect data={data} onChange={onChange} />}
      {lc.status === 'in_progress' && !['propose', 'classify', 'assess', 'test', 'approve', 'deploy'].includes(lc.stage) && <Navigate to={`/agents/${id}`} replace />}
    </FlowFrame>
  );
}

function Wide({ title, lead, children }: { title: string; lead?: string; children?: React.ReactNode }) {
  return <div className="flow-wide"><h1 className="flow-title">{title}</h1>{lead && <p className="flow-lead">{lead}</p>}<div className="mt-6">{children}</div></div>;
}

function Rejected({ v, agentId }: { v: any; agentId: string }) {
  return <Wide title={`${v.agent.name} wasn't approved`} lead="This agent can't run. The reasons are on its record."><Link className="btn-primary" to={`/agents/${agentId}?tab=lifecycle`}>See its record</Link></Wide>;
}

function RiskResult({ data, onChange }: { data: any; onChange: () => void }) {
  const me = useMe();
  const v = data.lifecycle;
  const c = v.classification;
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const high = isHighRisk(c.tier);
  const riskTeam = me.principal.roles.some((r) => r === 'risk_officer' || r === 'governance_board');
  const canConfirm = high ? riskTeam : riskTeam || data.agent.owner === me.principal.id;
  const reasons = riskReasons(v.lifecycle.data.intake, data.agent.autonomy_level);
  const next = high
    ? [canConfirm ? 'Confirm this rating' : 'Your risk team confirms this rating', 'Answer safety questions and complete the threat and impact reviews', 'Add test results; Signet checks its permissions automatically', c.tier === 'T1' ? 'Owner, Security, Risk and the governance board approve it' : 'Owner, Security and Risk approve it']
    : c.tier === 'T3'
      ? ['Answer a few safety questions', 'Signet checks its permissions automatically', 'You and Security approve it', 'Connect it, and it starts in shadow mode']
      : ['Signet checks its permissions automatically', 'No signature is needed at this risk level', 'Connect it, and it starts in shadow mode'];
  const confirm = async () => {
    setBusy(true);
    try {
      await api(`/lifecycles/${v.lifecycle.id}/classification`, { method: 'POST', body: { confirm: true } });
      onChange();
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flow-wide">
      <div className="risk-scale" role="img" aria-label={`Risk level: ${RISK_LABEL[c.tier]}`}>{['T4', 'T3', 'T2', 'T1'].map((t) => <span key={t} className={t === c.tier ? `on ${t}` : ''}>{RISK_LABEL[t]!.replace(' risk', '')}</span>)}</div>
      <h1 className="flow-title mt-5" data-testid="risk-title">{data.agent.name} is {RISK_LABEL[c.tier]}</h1>
      <p className="flow-lead">{high ? 'It needs a deeper review before it can run.' : c.tier === 'T3' ? 'It needs a short safety check and one approval.' : 'It only needs an automatic check.'}</p>
      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <section className="card p-5"><h2 className="font-semibold">Why this rating</h2><ul className="plain-list">{(reasons.length ? reasons : ['It has limited reach and limited access']).map((r) => <li key={r}>{r}</li>)}</ul><p className="mt-3 text-xs text-ink-3">Scored from your answers: {c.score} out of 5.</p></section>
        <section className="card p-5"><h2 className="font-semibold">What happens next</h2><ol className="plain-list numbered">{next.map((n) => <li key={n}>{n}</li>)}</ol></section>
      </div>
      {high && <p className="note mt-4">{DETECTOR_HOLD_NOTE}</p>}
      {error && <div className="mt-4"><ErrorNote error={error} /></div>}
      <div className="flow-actions">
        <Link className="btn-ghost btn-large" to={`/agents/${data.agent.id}?tab=lifecycle`}>See the full scoring</Link>
        {canConfirm ? <button className="btn-primary btn-large" data-testid="risk-confirm" disabled={busy} onClick={() => void confirm()}>{busy ? 'Saving…' : 'Confirm and continue'}</button> : <span className="note">Your risk team has been asked to confirm this. You'll see it move forward here.</span>}
      </div>
    </div>
  );
}

function Assess({ v, onChange }: { v: any; onChange: () => void }) {
  const questionnaire = v.assessments.find((a: any) => a.type === 'questionnaire');
  const [redo, setRedo] = useState(false);
  if (questionnaire && questionnaire.status !== 'complete' && !redo) return <Questions key={questionnaire.id} lcId={v.lifecycle.id} asm={questionnaire} onChange={onChange} />;
  const asm = v.assessments as any[];
  const openGaps = (v.gaps as any[]).filter((g) => g.status === 'open');
  const blocking = openGaps.filter((g) => g.severity === 'critical' || g.severity === 'high');
  return (
    <Wide title={`${v.agent.name}: what's left before tests`} lead="Finish the items below. Serious to-dos must be closed before it can move on; minor ones can be closed later.">
      <section className="card mb-4 p-5">
        <ul className="task-list">
          {asm.map((a) => <li key={a.id} className={a.status === 'complete' ? 'done' : ''}><i>{a.status === 'complete' ? '✓' : ''}</i>{a.type === 'questionnaire' ? 'Safety questions' : a.type === 'threat_model' ? 'Threat review' : a.type === 'impact' ? 'Impact on people' : a.type === 'dpia' ? 'Data protection assessment' : 'Vendor risk review'}</li>)}
          <li className={blocking.length ? '' : 'done'}><i>{blocking.length ? '' : '✓'}</i>{blocking.length ? `${blocking.length} serious to-do${blocking.length > 1 ? 's' : ''} to close` : 'No serious to-dos open'}</li>
          <li className={v.gate?.manifest_valid ? 'done' : ''}><i>{v.gate?.manifest_valid ? '✓' : ''}</i>Permissions are valid</li>
        </ul>
        {questionnaire?.status === 'complete' && <button className="mt-3 text-sm font-medium text-royal" onClick={() => setRedo(true)}>Review all questions below</button>}
      </section>
      <AssessStage v={v} onChange={onChange} />
    </Wide>
  );
}

// One question at a time. Answers the intake already gave are kept and not asked again.
function Questions({ lcId, asm, onChange }: { lcId: string; asm: any; onChange: () => void }) {
  const all = asm.content.questions as { id: string; text: string }[];
  const [answers, setAnswers] = useState<Record<string, { answer: string; note: string }>>(asm.content.answers ?? {});
  const [queue] = useState(() => all.filter((q) => !asm.content.answers?.[q.id]?.answer));
  const [at, setAt] = useState(0);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const q = queue[at];
  const save = async (complete: boolean) => {
    setBusy(true);
    try {
      await api(`/lifecycles/${lcId}/assessments/questionnaire`, { method: 'PUT', body: { content: { ...asm.content, answers }, complete } });
      onChange();
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const answer = answers[q?.id ?? '']?.answer ?? '';
  const last = at >= queue.length - 1;
  if (!q) return <Wide title="Safety questions"><button className="btn-primary btn-large" disabled={busy} onClick={() => void save(true)}>Continue</button><ErrorNote error={error} /></Wide>;
  return (
    <div className="flow-grid">
      <div className="min-w-0">
        <div className="text-sm text-ink-3">Question {at + 1} of {queue.length}</div>
        <div className="comparison-track mt-2"><div className="comparison-fill bg-royal" style={{ width: `${((at + 1) / queue.length) * 100}%` }} /></div>
        <h1 className="flow-title mt-8" data-testid="question-text">{q.text}</h1>
        <div className="mt-7 space-y-3" role="radiogroup">
          <Choice on={answer === 'yes'} testId="answer-yes" title="Yes" onClick={() => setAnswers({ ...answers, [q.id]: { answer: 'yes', note: '' } })} />
          <Choice on={answer === 'partial'} testId="answer-partial" title="Partly" hint={SEVERITY_NOTE.partial} onClick={() => setAnswers({ ...answers, [q.id]: { answer: 'partial', note: '' } })} />
          <Choice on={answer === 'no'} testId="answer-no" title="No" hint={SEVERITY_NOTE.no} onClick={() => setAnswers({ ...answers, [q.id]: { answer: 'no', note: '' } })} />
          <Choice on={answer === 'na'} testId="answer-na" title="Doesn't apply" onClick={() => setAnswers({ ...answers, [q.id]: { answer: 'na', note: '' } })} />
        </div>
        {error && <div className="mt-4"><ErrorNote error={error} /></div>}
        <div className="flow-actions">
          {at > 0 ? <button className="btn-ghost btn-large" onClick={() => setAt(at - 1)}>Back</button> : <span />}
          <button className="btn-primary btn-large" data-testid="answer-next" disabled={!answer || busy} onClick={() => (last ? void save(true) : setAt(at + 1))}>{last ? 'Finish' : 'Next question'}</button>
        </div>
      </div>
      <aside className="flow-why"><h3>Honest answers are fine</h3><p>"No" doesn't fail the agent. Signet turns it into a clear to-do. Serious items must be closed before approval; minor ones can wait.</p></aside>
    </div>
  );
}

function Test({ v, onChange }: { v: any; onChange: () => void }) {
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  if (isHighRisk(v.agent.tier)) return <Wide title="Test results" lead="Signet checks its permissions automatically. Add the results only your team can measure."><TestStage v={v} onChange={onChange} /></Wide>;
  const run = async () => {
    setBusy(true);
    try {
      await api(`/lifecycles/${v.lifecycle.id}/test-runs`, { method: 'POST', body: {} });
      onChange();
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Wide title="Let Signet test its permissions" lead="Signet tries actions it shouldn't allow and makes sure each one is refused. It only takes a moment and doesn't touch your agent.">
      {error && <div className="mb-4"><ErrorNote error={error} /></div>}
      <button className="btn-primary btn-large" data-testid="run-tests" disabled={busy} onClick={() => void run()}>{busy ? 'Testing…' : 'Run the tests'}</button>
    </Wide>
  );
}

function Approve({ v, onChange }: { v: any; onChange: () => void }) {
  if (!v.approval) return <Wide title="Preparing the approval…" />;
  return <Wide title={`Approval for ${v.agent.name}`} lead="All checks are done. These people need to approve it. Each is notified, and it moves on as soon as they've all signed."><ApprovalDetail id={v.approval.id} compact onDecided={onChange} /></Wide>;
}

function Connect({ data, onChange }: { data: any; onChange: () => void }) {
  const v = data.lifecycle;
  const { agent } = data;
  const { data: info } = useApi<{ gateway_url: string | null; models: string[] }>('/connect/info');
  const environment = data.certificate?.environments?.[0] ?? 'dev';
  const [key, setKey] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; reply?: string; message?: string; hint?: string } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
      setError(null);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  if (agent.kind === 'third_party' || agent.connection_method !== 'rest') return <Wide title={`Deploy ${agent.name}`} lead="Approval is complete. Use your chosen connection method to activate the runtime and verify its first request."><ConnectionTab data={data} onChange={onChange} /><div className="mt-6"><DeployStage v={v} onChange={onChange} /></div></Wide>;
  const base = `${(info?.gateway_url ?? location.origin).replace(/\/+$/, '')}/v1`;
  const create = () => run(async () => { setKey((await api<{ deployment_credential: string }>(`/agents/${agent.id}/deployment-credentials`, { method: 'POST', body: { environment } })).deployment_credential); });
  const send = () => run(async () => { setTest(await api('/connect/test', { method: 'POST', body: { credential: key } })); });
  return (
    <div className="flow-grid">
      <div className="min-w-0">
        <div className="text-sm font-semibold text-ok">✓ Approved</div>
        <h1 className="flow-title mt-1">Deploy {agent.name}</h1>
        <p className="flow-lead">Change two settings where your agent runs. Its code stays the same.</p>
        <section className="card mt-6 space-y-4 p-5">
          <div><div className="flow-label !mt-0">1. Web address (base URL)</div><CopyCode text={base} testId="connect-base" /></div>
          <div><div className="flow-label !mt-0">2. API key</div>{key ? <><CopyCode text={key} testId="connect-key" /><p className="mt-1 text-xs text-ink-3">Shown once. Keep it somewhere safe. You can make a new one any time.</p></> : <button className="btn-primary" data-testid="connect-create-key" disabled={busy || !info} onClick={() => void create()}>Create a key</button>}</div>
        </section>
        {key && <section className="card mt-4 p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><b>Does it work?</b><div className="text-sm text-ink-3">Sends one real request through Signet</div></div><button className="btn-ghost" data-testid="connect-test" disabled={busy} onClick={() => void send()}>{busy ? 'Testing…' : 'Send test'}</button></div>{test && (test.ok ? <p className="note ok mt-3" data-testid="connect-result"><b>Working.</b> The AI replied "{test.reply}".</p> : <p className="note bad mt-3" data-testid="connect-result"><b>{test.message}</b> {test.hint}</p>)}</section>}
        {error && <div className="mt-4"><ErrorNote error={error} /></div>}
        <section className="mt-8"><h2 className="text-lg font-semibold">It starts in shadow mode</h2><p className="mt-1 text-sm text-ink-2">Signet records would-blocks without stopping normal requests. Kill rules and secret-exfiltration blocks are already enforced. When the shadow period ends, review the results and move to enforce.</p><div className="mt-4"><DeployStage v={v} onChange={onChange} /></div></section>
        <div className="flow-actions"><span /><Link className="btn-primary btn-large" data-testid="connect-finish" to={`/agents/${agent.id}`}>Open monitoring</Link></div>
      </div>
      <aside className="flow-why"><h3>Different setup?</h3><p>Python, Docker, n8n or a sidecar: full instructions are on the agent's Connection tab.</p><Link className="btn-ghost mt-3" to={`/agents/${agent.id}?tab=connection`}>See other setups</Link></aside>
    </div>
  );
}

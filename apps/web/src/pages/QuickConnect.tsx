import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, ErrorNote, Mono, TierChip } from '../components/ui';
import { FlowFrame } from './AddAgent';
import { ApiError, api, useApi } from '../lib/api';
import { useMe } from '../lib/auth';

type Result =
  | { state: 'connected'; agent_id: string; lifecycle_id: string; tier: string; deployment_credential: string; expires_at: string; rollout: string; open_gaps: string[] }
  | { state: 'needs_answers'; agent_id: string; lifecycle_id: string; tier: string; questions: { id: string; text: string }[] }
  | { state: 'needs_review' | 'awaiting_approval'; agent_id: string; lifecycle_id: string; tier: string; reason: string };
type TestResult = { ok: boolean; status: number; reply?: string; code?: string; message?: string; hint?: string; record_id?: string };

const USERS = [['internal', 'Employees'], ['customers', 'Customers'], ['public', 'The public']];
const DATA = [['personal', 'Personal data'], ['financial_account', 'Financial accounts'], ['confidential_doc', 'Confidential documents'], ['source_code', 'Source code']];
const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

// One form to a working key for agents that only call the model. Tools, or higher-risk answers,
// lead to the full lifecycle.
export function QuickConnect() {
  const me = useMe();
  const [f, setF] = useState({ name: '', purpose: '', users_affected: [] as string[], data_touched: [] as string[], reversibility: 'partly', decisions_about_individuals: false });
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<Result>) => {
    setBusy(true);
    try {
      setResult(await fn());
      setError(null);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const ready = f.name.trim() && f.purpose.trim().length >= 10 && f.users_affected.length > 0;

  if (result?.state === 'connected') return <Connected r={result} />;
  return (
    <FlowFrame step={result ? 3 : 0} back="/agents/new">
      <h1 className="flow-title">Tell us about your chatbot</h1>
      <p className="flow-lead mb-3">Signet uses these details to choose the right safety review. After approval, you'll get your connection settings.</p>
      <p className="mb-6 text-sm text-ink-3">Does it also use tools or take actions? <Link data-testid="quick-guided-setup" className="text-royal hover:underline" to="/agents/new/one">Use guided setup</Link></p>
      <div className="max-w-3xl space-y-4">
        {!result && (
          <Card title="About your agent">
            <div className="space-y-4">
              <div><label className="label" htmlFor="quick-1">Agent name</label><input id="quick-1" data-testid="quick-name" className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="FAQ Bot" /></div>
              <div><label className="label" htmlFor="quick-2">What does it do?</label><textarea id="quick-2" data-testid="quick-purpose" className="input min-h-20" value={f.purpose} onChange={(e) => setF({ ...f, purpose: e.target.value })} placeholder="What the agent does, for whom, and why (at least 10 characters)" /></div>
              <div><label className="label">Who does it affect?</label><div className="flex flex-wrap gap-3 text-sm">{USERS.map(([v, l]) => <label key={v} className="flex items-center gap-1.5"><input data-testid={`quick-audience-${v}`} type="checkbox" checked={f.users_affected.includes(v!)} onChange={() => setF({ ...f, users_affected: toggle(f.users_affected, v!) })} /> {l}</label>)}</div></div>
              <div><label className="label">What data does it see? (leave empty if none of these)</label><div className="flex flex-wrap gap-3 text-sm">{DATA.map(([v, l]) => <label key={v} className="flex items-center gap-1.5"><input type="checkbox" checked={f.data_touched.includes(v!)} onChange={() => setF({ ...f, data_touched: toggle(f.data_touched, v!) })} /> {l}</label>)}</div></div>
              <div><label className="label" htmlFor="quick-3">Can its actions be undone?</label><select id="quick-3" data-testid="quick-reversibility" className="input" value={f.reversibility} onChange={(e) => setF({ ...f, reversibility: e.target.value })}><option value="yes">Yes, fully</option><option value="partly">Partly</option><option value="no">No</option></select></div>
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.decisions_about_individuals} onChange={(e) => setF({ ...f, decisions_about_individuals: e.target.checked })} /> It makes or shapes decisions about individual people</label>
              <p className="text-xs text-ink-3">{me.single_operator ? 'You are the only administrator, so continuing also records your approval in the ledger, marked as one person approving.' : 'Approvers are asked in My Approvals when the risk level needs them.'}</p>
              <button data-testid="quick-submit" className="btn-primary" disabled={!ready || busy} onClick={() => void run(() => api<Result>('/agents/quick-connect', { method: 'POST', body: f }))}>{busy ? 'Connecting…' : 'Continue'}</button>
            </div>
          </Card>
        )}
        {result?.state === 'needs_answers' && (
          <Card title={<span className="flex items-center gap-2">A few checks for this risk level <TierChip tier={result.tier} /></span>}>
            <p className="mb-3 text-sm text-ink-2">Answer honestly. "No" or "Partly" records a gap. A high or critical gap sends the agent to the full review with no key; a lower one is recorded for you to close later.</p>
            <div className="space-y-3">
              {result.questions.map((q) => (
                <div key={q.id} className="grid items-center gap-2 sm:grid-cols-[1fr_8rem]">
                  <span className="text-sm">{q.text}</span>
                  <select data-testid={`quick-answer-${q.id}`} aria-label={q.text} className="input" value={answers[q.id] ?? ''} onChange={(e) => setAnswers({ ...answers, [q.id]: e.target.value })}><option value="">Choose</option><option value="yes">Yes</option><option value="partial">Partly</option><option value="no">No</option><option value="na">Not applicable</option></select>
                </div>
              ))}
            </div>
            <button data-testid="quick-answers-submit" className="btn-primary mt-4" disabled={busy || result.questions.some((q) => !answers[q.id])} onClick={() => void run(() => api<Result>(`/agents/${result.agent_id}/quick-connect`, { method: 'POST', body: { lifecycle_id: result.lifecycle_id, answers } }))}>{busy ? 'Connecting…' : 'Approve and get key'}</button>
          </Card>
        )}
        {(result?.state === 'needs_review' || result?.state === 'awaiting_approval') && (
          <Card title={<span className="flex items-center gap-2">{result.state === 'awaiting_approval' ? 'Waiting for approval' : 'This agent needs the full review'} <TierChip tier={result.tier} /></span>}>
            <p className="text-sm text-ink-2">{result.reason}. The agent is registered and no key has been issued.</p>
            <Link data-testid="quick-agent-link" className="btn-primary mt-3 inline-block" to={`/agents/${result.agent_id}`}>Continue on the agent page</Link>
          </Card>
        )}
        <ErrorNote error={error} />
      </div>
    </FlowFrame>
  );
}

function Connected({ r }: { r: Extract<Result, { state: 'connected' }> }) {
  const { data: info } = useApi<{ gateway_url: string | null; models: string[] }>('/connect/info');
  const [test, setTest] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<ApiError | null>(null);
  const base = `${(info?.gateway_url ?? location.origin).replace(/\/+$/, '')}/v1`;
  const send = async () => {
    setTesting(true);
    try {
      setTest(await api<TestResult>('/connect/test', { method: 'POST', body: { credential: r.deployment_credential } }));
      setTestError(null);
    } catch (e) {
      setTestError(e as ApiError);
    } finally {
      setTesting(false);
    }
  };
  return (
    <FlowFrame step={5} back="/agents">
      <h1 className="flow-title">Your connection settings are ready</h1>
      <p className="flow-lead mb-6">Use these in your chatbot's server-side AI settings, then send a test to verify the connection.</p>
      <div className="max-w-3xl space-y-4">
        <Card title="Connection details">
          <div className="space-y-3 text-sm">
            <div><div className="label">Base URL</div><div className="break-all"><Mono>{base}</Mono></div></div>
            <div><div className="label">API key (shown once; copy it now)</div><div data-testid="quick-key" className="break-all"><Mono>{r.deployment_credential}</Mono></div><button className="btn mt-2" onClick={() => void navigator.clipboard?.writeText(r.deployment_credential)}>Copy key</button></div>
            <div><div className="label">Model</div><Mono>{info?.models?.[0] ?? '…'}</Mono></div>
            <p className="text-xs text-ink-3">Key expires {r.expires_at.slice(0, 10)}. Risk level {r.tier}.</p>
          </div>
        </Card>
        <Card title="Check it works">
          <p className="mb-3 text-sm text-ink-2">Sends one real request through the gateway. It appears in Live activity like any other.</p>
          <button data-testid="quick-test" className="btn-primary" disabled={testing} onClick={() => void send()}>{testing ? 'Testing…' : 'Send test request'}</button>
          {test?.ok && <p data-testid="quick-test-result" className="mt-3 text-sm text-ok">Working. The model replied: “{test.reply}”</p>}
          {test && !test.ok && <div data-testid="quick-test-result" className="mt-3 text-sm"><p className="text-bad">Failed ({test.code}): {test.message}</p><p className="mt-1 text-ink-2">{test.hint}</p></div>}
          <div className="mt-2"><ErrorNote error={testError} /></div>
        </Card>
        {r.open_gaps.length > 0 && (
          <Card title="Gaps to close">
            <ul className="list-disc pl-5 text-sm text-ink-2">{r.open_gaps.map((g) => <li key={g}>{g}</li>)}</ul>
          </Card>
        )}
        {r.rollout === 'shadow' && (
          <Card title="Your agent starts in shadow mode">
            <p className="text-sm text-ink-2">Limits and key checks apply now. Policy findings are recorded as "would block" without stopping requests, so you can see the effect first. Move it to enforcing on the agent page.</p>
          </Card>
        )}
        <Link className="btn" to={`/agents/${r.agent_id}`}>Open the agent page</Link>
      </div>
    </FlowFrame>
  );
}

import { useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { Card, Empty, ErrorNote, KV, Mono, PageHeader, Pill, Tabs, TierChip } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useMe } from '../lib/auth';
import { ago, date, hash } from '../lib/format';

// My Approvals (BP 7): every request with a slot I can fill, the approval pack I sign over, and the
// decision. T1/T2 decisions need a sign-in within 5 minutes; the console sends me back to the IdP.

const TYPE_LABEL: Record<string, string> = {
  certificate: 'Seal',
  risk_acceptance: 'Risk acceptance',
  runtime_hitl: 'Runtime action',
  quarantine_release: 'Quarantine release',
  retirement: 'Retirement',
};

const STATUS_PILL: Record<string, string> = { pending: 'require_approval', approved: 'allow', rejected: 'deny', sent_back: 'step_up', expired: 'deny', cancelled: 'none' };

function sla(due: string) {
  const ms = Date.parse(due) - Date.now();
  if (ms <= 0) return <span className="text-bad">overdue</span>;
  const m = Math.round(ms / 60_000);
  return <span className={m < 60 ? 'text-warn' : 'text-ink-2'}>{m < 120 ? `${m} min left` : m < 2880 ? `${Math.round(m / 60)} h left` : `${Math.round(m / 1440)} d left`}</span>;
}

export function Approvals() {
  const [params, setParams] = useSearchParams();
  const selected = params.get('id');
  const [tab, setTab] = useState('mine');
  const path = tab === 'mine' ? '/approvals?mine=1' : tab === 'pending' ? '/approvals?status=pending' : '/approvals?limit=100';
  const { data, reload } = useApi<any>(path, [tab]);
  const items = (data?.items ?? []).filter((r: any) => tab !== 'decided' || r.status !== 'pending');
  return (
    <>
      <PageHeader title="My Approvals" subtitle="Each decision is signed over the approval pack's hash and written to the decision ledger. Owners, proposers and build teams never approve their own agents (RB-INV-09)." />
      <Tabs active={tab} onChange={setTab} tabs={[{ id: 'mine', label: 'Waiting for me' }, { id: 'pending', label: 'All pending' }, { id: 'decided', label: 'Decided' }]} />
      <div className="grid gap-4 xl:grid-cols-[420px_1fr]">
        <Card pad={false}>
          {items.length ? (
            <ul className="divide-y divide-line">
              {items.map((r: any) => (
                <li key={r.id}>
                  <button className={`block w-full px-4 py-3 text-left hover:bg-canvas ${selected === r.id ? 'bg-royal-50' : ''}`} onClick={() => setParams({ id: r.id })}>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-semibold uppercase tracking-wide text-ink-3">{TYPE_LABEL[r.type] ?? r.type}</span>
                      {r.tier && <TierChip tier={r.tier} />}
                      <span className="ml-auto text-xs">{r.status === 'pending' ? sla(r.sla_due) : <Pill value={STATUS_PILL[r.status]} label={r.status.replace('_', ' ')} />}</span>
                    </div>
                    <div className="mt-1 text-sm font-medium">{r.title}</div>
                    <div className="mt-0.5 line-clamp-1 text-xs text-ink-2">{r.summary}</div>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty>{tab === 'mine' ? 'Nothing is waiting for you.' : 'No requests.'}</Empty>
          )}
        </Card>
        {selected ? <ApprovalDetail id={selected} onDecided={() => void reload()} /> : <Card><Empty>Select a request to see its approval pack.</Empty></Card>}
      </div>
    </>
  );
}

export function ApprovalDetail({ id, onDecided, compact = false }: { id: string; onDecided?: () => void; compact?: boolean }) {
  const { data: r, reload, error: loadError } = useApi<any>(`/approvals/${id}`, [id]);
  if (loadError) return <ErrorNote error={loadError} />;
  if (!r) return null;
  const filled = (slot: string) => (r.decisions ?? []).filter((d: any) => d.slot === slot);
  return (
    <div className="space-y-4">
      <Card title={<span className="flex items-center gap-2">{r.title} <Pill value={STATUS_PILL[r.status]} label={r.status.replace('_', ' ')} /></span>}>
        <KV
          rows={[
            ['Type', TYPE_LABEL[r.type] ?? r.type],
            ...(r.agent_id ? [['Agent', <Link key="a" className="text-royal hover:underline" to={`/agents/${r.agent_id}`}>{(r.pack.agent as any)?.handle ?? r.agent_id}</Link>] as [string, JSX.Element]] : []),
            ['Summary', r.summary || '—'],
            ['Requested', `${ago(r.created_at)} by ${r.created_by}`],
            ['Due', r.status === 'pending' ? <span key="d">{date(r.sla_due)} · {sla(r.sla_due)}{r.escalation ? ` · escalation level ${r.escalation}` : ''}</span> : date(r.decided_at)],
            ['Pack hash', <Mono key="h" title={r.pack_hash}>{hash(r.pack_hash)}</Mono>],
          ]}
        />
      </Card>
      <Card title="Who must sign" pad={false}>
        <table className="w-full">
          <tbody>
            {r.slots.map((s: any) => (
              <tr key={s.slot}>
                <td className="td font-medium">{s.label}</td>
                <td className="td text-xs text-ink-2">{s.owner_only ? 'the agent owner' : `${s.roles.join(' or ')}${s.owner_allowed ? ' or the owner' : ''}${s.count > 1 ? ` · ${s.count} people` : ''}`}</td>
                <td className="td text-xs">
                  {filled(s.slot).map((d: any) => <div key={d.id}><Pill value={d.decision.startsWith('approve') ? 'allow' : 'deny'} label={d.decision.replace('_', ' ')} /> {d.approver}{d.comment ? ` · “${d.comment}”` : ''}</div>)}
                  {!filled(s.slot).length && (r.my_slots.includes(s.slot) ? <span className="text-royal">you can sign</span> : <span className="text-ink-3">open</span>)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {r.status === 'pending' && r.my_slots.length > 0 && <DecisionForm r={r} onDone={() => (void reload(), onDecided?.())} />}
      <Pack r={r} compact={compact} />
    </div>
  );
}

function DecisionForm({ r, onDone }: { r: any; onDone: () => void }) {
  const solo = useMe().single_operator === true;
  const [slot, setSlot] = useState(r.my_slots[0]);
  const [comment, setComment] = useState('');
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const runtime = r.type === 'runtime_hitl';
  const decide = async (decision: string) => {
    setBusy(true);
    try {
      await api(`/approvals/${r.id}/decisions`, { method: 'POST', body: { decision, slot, comment: comment || undefined } });
      setError(null);
      onDone();
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setBusy(false);
    }
  };
  const reauth = () => location.assign(`/api/v1/auth/login?max_age=0&return_to=${encodeURIComponent(location.pathname + location.search)}`);
  return (
    <Card title="Your decision">
      {solo && <p className="mb-3 rounded-md bg-warn-50 px-3 py-2 text-xs text-warn">Single-administrator workspace: approving signs every open slot ({r.my_slots.join(', ')}) at once. The ledger records that separation of duties was waived.</p>}
      {!solo && r.my_slots.length > 1 && (
        <div className="mb-3">
          <label className="label">Sign as</label>
          <select className="input w-auto" value={slot} onChange={(e) => setSlot(e.target.value)}>
            {r.my_slots.map((s: string) => <option key={s} value={s}>{r.slots.find((x: any) => x.slot === s)?.label ?? s}</option>)}
          </select>
        </div>
      )}
      <label className="label">Comment (required to reject or send back)</label>
      <textarea className="input min-h-16" value={comment} onChange={(e) => setComment(e.target.value)} />
      {(r.tier === 'T1' || r.tier === 'T2') && !runtime && <p className="mt-2 text-xs text-ink-3">{r.tier} decisions need a sign-in within the last 5 minutes (step-up, BP 7.3).</p>}
      <div className="mt-3 flex flex-wrap gap-2">
        <button className="btn-primary" disabled={busy} onClick={() => void decide('approve')}>Approve{runtime ? ' once' : ''}</button>
        {runtime && <button className="btn-ghost" disabled={busy} onClick={() => void decide('approve_session')}>Approve for this session</button>}
        {r.type === 'certificate' && <button className="btn-ghost" disabled={busy || !comment.trim()} onClick={() => void decide('send_back')}>Send back to Assess</button>}
        <button className="btn-ghost text-bad" disabled={busy || !comment.trim()} onClick={() => void decide('reject')}>Reject</button>
        {runtime && <button className="btn-danger" disabled={busy || !comment.trim()} onClick={() => void decide('reject_quarantine')}>Reject and quarantine</button>}
      </div>
      {error && (
        <div className="mt-3 space-y-2">
          <ErrorNote error={error} />
          {error.rule === 'AUTH-STEP-UP' && <button className="btn-primary" onClick={reauth}>Sign in again, then decide</button>}
        </div>
      )}
    </Card>
  );
}

function Pack({ r, compact }: { r: any; compact: boolean }) {
  const p = r.pack ?? {};
  if (r.type === 'runtime_hitl') {
    return (
      <Card title="The action waiting">
        <KV
          rows={[
            ['Action', <Mono key="a">{p.action}</Mono>],
            ['Arguments (masked)', <pre key="g" className="mono whitespace-pre-wrap text-xs">{JSON.stringify(p.args, null, 2)}</pre>],
            ['Why it needs you', (p.reasons ?? []).join('; ') || '—'],
            ['Rules', (p.rules ?? []).join(', ')],
            ['Session', <Mono key="s">{p.session_id}</Mono>],
          ]}
        />
        <p className="mt-3 text-xs text-ink-3">No decision before the hold time ends is a rejection (RB-INV-11). “Approve for this session” lets the same action through for this session for 8 hours.</p>
      </Card>
    );
  }
  if (r.type === 'certificate') {
    const cls = p.classification ?? {};
    return (
      <div className="space-y-4">
        <Card title="Classification">
          <KV
            rows={[
              ['Tier', <span key="t"><TierChip tier={cls.tier ?? r.tier} /> score {cls.score}</span>],
              ['Regulatory', cls.regulatory_category],
              ['Frameworks', (cls.frameworks ?? []).join(', ')],
              ['Reasons', (cls.reasons ?? []).join('; ')],
            ]}
          />
        </Card>
        <Card title="Evidence">
          <KV
            rows={[
              ['Assessments', (p.assessments ?? []).map((a: any) => `${a.type.replace('_', ' ')}: ${a.status}`).join(' · ') || '—'],
              ['Gaps', (p.gaps ?? []).length ? (p.gaps as any[]).map((g) => `${g.severity} ${g.title} (${g.status})`).join(' · ') : 'none'],
              ['Tests', p.test_report ? <span key="t">{(p.test_report.suites as any[]).map((s) => `${s.suite}${s.passed ? ' ✓' : ' ✗'}`).join(' · ')} · <Mono>{hash(p.test_report.sha256)}</Mono></span> : '—'],
              ['Deploy plan', p.deploy_plan ? `shadow ${p.deploy_plan.shadow_days} d${p.deploy_plan.canary ? ` → ${p.deploy_plan.canary_pct}% canary` : ''} → enforce` : '—'],
            ]}
          />
        </Card>
        {!compact && (
          <Card title="Manifest to be sealed">
            <pre className="mono max-h-96 overflow-auto rounded-md bg-canvas p-3 text-xs">{JSON.stringify(p.manifest, null, 2)}</pre>
          </Card>
        )}
      </div>
    );
  }
  return (
    <Card title="Approval pack">
      <pre className="mono max-h-96 overflow-auto rounded-md bg-canvas p-3 text-xs">{JSON.stringify(p, null, 2)}</pre>
    </Card>
  );
}

// Phone-sized page for runtime approvals, opened from a notification link (BP 7.4).
export function MobileApproval() {
  const { id } = useParams();
  const me = useMe();
  return (
    <div className="mx-auto min-h-screen max-w-md bg-canvas p-4">
      <div className="mb-3 flex items-center justify-between text-xs text-ink-3">
        <span className="font-semibold text-ink">Signet approval</span>
        <span>{me.principal.name}</span>
      </div>
      <ApprovalDetail id={id!} compact />
      <Link className="mt-4 block text-center text-xs text-royal" to="/approvals">Open My Approvals</Link>
    </div>
  );
}

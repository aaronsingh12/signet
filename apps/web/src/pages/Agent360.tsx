import { useEffect, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { AgentInsights } from '../components/AgentInsights';
import { Card, Empty, ErrorNote, KV, LEVEL_LABEL, Modal, Mono, PageHeader, Pill, Tabs, TierChip } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan, useMe } from '../lib/auth';
import { ago, date, daysLeft, dlpSummary, time } from '../lib/format';
import { ConnectionPill, ConnectionTab } from './Connection';
import { LifecycleTab } from './Lifecycle';

type Ladder = 'step_up' | 'throttle' | 'quarantine' | 'kill' | 'release';

export function Agent360() {
  const { id } = useParams();
  const me = useMe();
  const can = useCan();
  const { data, reload, error } = useApi<any>(`/agents/${id}`);
  const [params] = useSearchParams();
  const [tab, setTab] = useState(params.get('tab') ?? 'overview');
  useEffect(() => { setTab(params.get('tab') ?? 'overview'); }, [params]);
  const [ladder, setLadder] = useState<Ladder | null>(null);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <p className="py-10 text-center text-sm text-ink-3" role="status">Loading agent…</p>;
  const { agent, certificate: cert, enforcement } = data;
  const own = agent.owner === me.principal.id;
  const ladderAllowed = (a: Ladder) => can(`ladder.${a}`) && (own || !me.principal.roles.every((r) => r === 'agent_owner'));
  const killed = enforcement.level === 'killed' || agent.status === 'killed';
  const left = daysLeft(cert?.valid_to);

  return (
    <>
      <div className="mb-1 text-xs text-ink-3">
        <Link to="/agents" className="hover:underline">AI agents</Link> / <span>{agent.name}</span>
      </div>
      <PageHeader
        title={agent.name}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            {cert ? <Pill value="sealed" label={`Approved until ${date(cert.valid_to)}`} /> : <Pill value={agent.status} />}
            <Pill value={enforcement.level} label={enforcement.level === 'active' ? agent.kind === 'third_party' ? 'Gateway safeguards configured' : 'Safety checks active' : LEVEL_LABEL[enforcement.level] ?? enforcement.level} />
            {cert || data.lifecycle?.classification?.confirmed_by ? <TierChip tier={agent.tier} /> : <Pill value="neutral" label="Risk not classified yet" />}
            {cert && <ConnectionPill state={data.connection.state} />}
            <span className="text-xs text-ink-3">{agent.purpose}</span>
          </span>
        }
        actions={
          !killed && (
            <details className="relative" data-testid="agent-management">
              <summary className="btn-ghost cursor-pointer">Manage agent</summary>
              <div className="absolute right-0 z-30 mt-2 flex w-64 flex-col gap-2 rounded-xl border border-line bg-white p-3 shadow-lg">
              {ladderAllowed('step_up') && <button className="btn-ghost" onClick={() => setLadder('step_up')}>Add extra checks</button>}
              {ladderAllowed('throttle') && <button className="btn-ghost" onClick={() => setLadder('throttle')}>Limit request rate</button>}
              {ladderAllowed('release') && enforcement.level !== 'active' && <button className="btn-ghost" onClick={() => setLadder('release')}>Release</button>}
              {ladderAllowed('quarantine') && <button className="btn-ghost text-bad" onClick={() => setLadder('quarantine')}>Pause agent</button>}
              {ladderAllowed('kill') && <button className="btn-danger" onClick={() => setLadder('kill')}>Permanently stop agent</button>}
              </div>
            </details>
          )
        }
      />
      {killed && <div className="mb-4 rounded-md border border-bad/30 bg-bad-50 px-4 py-2.5 text-sm text-bad">This agent is permanently stopped. It must go through a new approval process before it can return.</div>}
      {data.lifecycle?.lifecycle.status === 'in_progress' && data.lifecycle.lifecycle.kind === 'initial' && <div className="note mb-4 flex flex-wrap items-center justify-between gap-3"><span>{agent.name} isn't finished yet. It's at the {data.lifecycle.lifecycle.stage === 'deploy' ? 'connect and trial' : data.lifecycle.lifecycle.stage} step.</span><Link className="btn-primary" data-testid="continue-setup" to={`/agents/${agent.id}/setup`}>Continue setup</Link></div>}
      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          { id: 'overview', label: 'Summary' },
          { id: 'manifest', label: 'What it can do' },
          { id: 'ledger', label: 'Activity' },
          { id: 'connection', label: 'Connection' },
          { id: 'lifecycle', label: 'Approval & history' },
        ]}
      />
      {tab === 'overview' && (
        <><AgentInsights agentId={agent.id} /><details className="mt-7"><summary className="cursor-pointer text-xs font-medium text-ink-3">Advanced details & safety history</summary><div className="mt-4 grid gap-4 xl:grid-cols-3">
          <Card title="Accountability" className="xl:col-span-1">
            <KV
              rows={[
                ['Owner', agent.owner],
                ['Sponsor', agent.sponsor],
                ['Proposed by', agent.created_by],
                ['Build team', data.team.length ? data.team.map((t: any) => `${t.user} (${t.role})`).join(', ') : '—'],
                ['Separation of duties', 'Owner signs the owner slot; proposer and build team cannot fill independent slots. Administrators can approve the certificate directly.'],
              ]}
            />
          </Card>
          <Card title="Seal">
            {cert ? (
              <KV
                rows={[
                  ['Certificate', <Mono key="c">{cert.cert_id}</Mono>],
                  ['Approved by', cert.approvers.map((a: any) => a.user).join(', ')],
                  ['Validity', `${date(cert.valid_from)} → ${date(cert.valid_to)} (${left} days left)`],
                  ['Policy hash', <Mono key="p">{cert.policy_sha256.slice(0, 24)}…</Mono>],
                  ['Environments', cert.environments.join(', ')],
                ]}
              />
            ) : (
              <Empty>Not sealed yet. The seal is signed when the lifecycle reaches Approve and every slot of the approval matrix has signed.</Empty>
            )}
          </Card>
          <Card title="Ladder state">
            {enforcement.states.length ? (
              <ul className="space-y-2 text-sm">
                {enforcement.states.map((s: any) => (
                  <li key={s.scope_key}>
                    <Pill value={s.level} label={LEVEL_LABEL[s.level]} /> <Mono>{s.scope_key}</Mono>
                    <div className="text-xs text-ink-3">{s.rule_id ? `${s.rule_id} · ` : ''}{s.reason}{s.until_ms ? ` · until ${new Date(s.until_ms).toLocaleTimeString()}` : ''}</div>
                  </li>
                ))}
              </ul>
            ) : (
              <Empty>Active. No ladder level applies.</Empty>
            )}
          </Card>
          <Card title="Recent ladder events" className="xl:col-span-3" pad={false}>
            <EventsTable events={data.events} />
          </Card>
        </div></details></>
      )}
      {tab === 'manifest' && !cert && <Card><Empty>Its permissions are set during the safety check and take effect when it is approved.</Empty></Card>}
      {tab === 'lifecycle' && <SealTab agentId={agent.id} cert={cert} history={data.certificates} />}
      {tab === 'manifest' && cert && <ManifestTab cert={cert} />}
      {tab === 'connection' && data.instances.length > 0 && (
        <Card pad={false}>
          {data.instances.length ? (
            <table className="w-full">
              <thead><tr>{['Instance', 'Version', 'Env', 'Started', 'Last token', 'State'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
              <tbody>
                {data.instances.map((i: any) => (
                  <tr key={i.id}>
                    <td className="td"><Mono>{i.id}</Mono></td><td className="td">{i.version}</td><td className="td">{i.env}</td>
                    <td className="td">{ago(i.first_seen)}</td><td className="td">{ago(i.last_seen)}</td><td className="td"><Pill value={i.state === 'running' ? 'active' : i.state} label={i.state} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>No instances yet. A deployment exchanges a bootstrap credential for a workload token, which starts an instance.</Empty>
          )}
        </Card>
      )}
      {tab === 'ledger' && <AgentLedger agentId={agent.id} />}
      {tab === 'lifecycle' && <LifecycleTab data={data} onChange={() => void reload()} />}
      {tab === 'connection' && <ConnectionTab data={data} onChange={() => void reload()} />}
      {ladder && <LadderModal agent={agent} instances={data.instances} action={ladder} onClose={() => setLadder(null)} onDone={() => void reload()} />}
    </>
  );
}

export function EventsTable({ events }: { events: any[] }) {
  if (!events.length) return <Empty>No ladder events.</Empty>;
  return (
    <table className="w-full">
      <thead><tr>{['Time', 'Level', 'Scope', 'Trigger', 'Actor', 'Propagation'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
      <tbody>
        {events.map((e) => (
          <tr key={e.id}>
            <td className="td whitespace-nowrap text-ink-2">{ago(e.published_at)}</td>
            <td className="td"><Pill value={e.level} label={LEVEL_LABEL[e.level] ?? e.level} /></td>
            <td className="td"><Mono>{e.scope_key.split(':')[0]}</Mono></td>
            <td className="td">{e.rule_id && <Mono>{e.rule_id} </Mono>}<span className="text-ink-2">{e.reason}</span></td>
            <td className="td text-ink-2">{e.actor.startsWith('gateway:') ? 'Auto rule' : e.actor}</td>
            <td className="td whitespace-nowrap text-xs">
              {e.acks?.length ? `${e.acks.length}/${e.nodes_expected} nodes · max ${Math.max(...e.acks.map((a: any) => a.latency_ms))} ms` : e.nodes_expected ? `0/${e.nodes_expected}` : '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SealTab({ agentId, cert, history }: { agentId: string; cert: any; history: any[] }) {
  const [verify, setVerify] = useState<any>(null);
  const doVerify = async () => {
    const { jws } = await api(`/agents/${agentId}/certificate`);
    setVerify(await api('/certificates/verify', { method: 'POST', body: { jws } }));
  };
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
      <Card title="Seal (Agent Certificate) · signed JSON" action={cert && <button className="btn-ghost" onClick={() => void doVerify()}>Verify seal</button>}>
        {verify && (
          <div className={`mb-3 rounded-md px-3 py-2 text-sm ${verify.signature_valid ? 'bg-ok-50 text-ok' : 'bg-bad-50 text-bad'}`}>
            {verify.signature_valid ? `Signature valid · signed by ${verify.signed_by} (Ed25519) · status ${verify.status}` : `Invalid: ${verify.error}`}
          </div>
        )}
        {cert ? <pre className="mono max-h-[560px] overflow-auto rounded-md bg-canvas p-3">{JSON.stringify(cert, null, 2)}</pre> : <Empty>No active seal.</Empty>}
      </Card>
      <Card title="Versions" pad={false}>
        <table className="w-full">
          <tbody>
            {history.map((c) => (
              <tr key={c.id}>
                <td className="td"><div className="font-medium">{c.version}</div><Mono>{c.id}</Mono></td>
                <td className="td"><Pill value={c.status === 'active' ? 'sealed' : c.status === 'revoked' ? 'killed' : 'none'} label={c.status} /></td>
                <td className="td text-xs text-ink-2">{date(c.issued_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function ManifestTab({ cert }: { cert: any }) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="Models">
        {cert.models.map((m: any) => (
          <div key={m.model} className="text-sm"><Mono>{m.model}</Mono> · region {m.region}{m.max_tokens ? ` · max ${m.max_tokens} tokens` : ''}</div>
        ))}
        <p className="mt-2 text-xs text-ink-3">Only the tenant's one cloud LLM can appear here (RB-INV-19).</p>
      </Card>
      <Card title="Data classes">
        <KV rows={[['Allowed in prompts', cert.data_classes.prompt.join(', ') || 'none (personal data is still tokenised)'], ['Forbidden', cert.data_classes.forbidden.join(', ') || '—']]} />
      </Card>
      <Card title="Tools and actions" className="lg:col-span-2" pad={false}>
        <table className="w-full">
          <thead><tr>{['Tool', 'Action', 'Impact', 'Constraints', 'Data scope'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {cert.tools.flatMap((t: any) =>
              t.actions.map((a: any) => (
                <tr key={`${t.server}.${a.name}`}>
                  <td className="td"><Mono>{t.server}</Mono></td>
                  <td className="td"><Mono>{a.name}</Mono></td>
                  <td className="td"><Pill value={a.impact === 'read' ? 'allow' : a.impact === 'write' ? 'allow_with_obligations' : a.impact === 'privileged' ? 'require_approval' : 'deny'} label={a.impact} /></td>
                  <td className="td text-xs text-ink-2">
                    {Object.entries(a.constraints ?? {}).map(([k, c]: any) => `${k}: ${Object.entries(c).map(([ck, cv]) => `${ck} ${JSON.stringify(cv)}`).join(', ')}`).join(' · ') || '—'}
                    {a.value_threshold_usd ? ` · waiver ≤ ${a.value_threshold_usd} on ${a.value_arg}` : ''}
                  </td>
                  <td className="td text-xs">{(t.data_scopes ?? []).join(', ') || '—'}</td>
                </tr>
              )),
            )}
          </tbody>
        </table>
      </Card>
      <Card title="Human in the loop">
        {cert.hitl.length ? cert.hitl.map((h: any, i: number) => <div key={i} className="text-sm"><Mono>{h.action}{h.arg ? ` && ${h.arg} > ${h.gt}` : ''}</Mono> → {h.approver_group} · timeout = reject</div>) : <Empty>No seal-specific rules. Tenant rules RB-PRIV-03/04/07/08 still apply.</Empty>}
      </Card>
      <Card title="Limits">
        <KV rows={[['Requests per minute', cert.limits.rpm], ['Tokens per day', cert.limits.tokens_per_day.toLocaleString()], ['Cost per day', `$${cert.limits.usd_per_day}`], ['Tool calls per session', cert.limits.tool_calls_per_session ?? '—']]} />
      </Card>
    </div>
  );
}

function AgentLedger({ agentId }: { agentId: string }) {
  const { data } = useApi<any>(`/ledger/records?agent=${agentId}&limit=50`);
  return (
    <Card pad={false} title="Recent ledger activity" action={<Link className="text-xs text-royal hover:underline" to={`/ledger?agent=${agentId}`}>Open in Ledger Explorer</Link>}>
      <table className="w-full">
        <thead><tr>{['Time (UTC)', 'Kind', 'Action', 'Target', 'Decision', 'DLP', 'Gateway ms'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
        <tbody>
          {(data?.items ?? []).map((r: any) => (
            <tr key={r.record_id}>
              <td className="td mono whitespace-nowrap">{time(r.ts)}</td>
              <td className="td text-xs">{r.kind}</td>
              <td className="td mono">{r.data.action_type ?? r.data.event}</td>
              <td className="td mono text-xs">{r.data.target ?? r.data.scope_key ?? ''}</td>
              <td className="td"><Pill value={r.data.policy_decision ?? r.data.level} /></td>
              <td className="td text-xs">{dlpSummary(r.data.dlp_actions)}</td>
              <td className="td text-right">{r.data.latency_ms_gateway ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function LadderModal({ agent, instances, action, onClose, onDone }: { agent: any; instances: any[]; action: Ladder; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState('');
  const [scope, setScope] = useState<'agent' | 'version' | 'instance'>('agent');
  const [instance, setInstance] = useState(instances[0]?.id ?? '');
  const [confirm, setConfirm] = useState('');
  const [minutes, setMinutes] = useState('');
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<any>(null);
  const [acks, setAcks] = useState<any>(null);
  const isKill = action === 'kill';
  const scoped = action === 'kill' || action === 'quarantine';
  const submit = async () => {
    try {
      const version = instances.find((i) => i.id === instance)?.version;
      const r = await api(`/agents/${agent.id}/ladder`, {
        method: 'POST',
        body: { action, reason, scope: scoped ? scope : 'agent', version, instance_id: scope === 'instance' ? instance : undefined, confirm_handle: isKill ? confirm : undefined, minutes: minutes ? Number(minutes) : undefined },
      });
      setResult(r);
      onDone();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  useEffect(() => {
    if (!result?.event_id) return;
    const t = setTimeout(() => void api(`/enforcement-events/${result.event_id}`).then(setAcks), 600);
    return () => clearTimeout(t);
  }, [result]);
  const title = { step_up: 'Step-up (level 2)', throttle: 'Throttle (level 3)', quarantine: 'Quarantine (level 4)', kill: `Kill ${agent.handle}?`, release: 'Release' }[action];
  return (
    <Modal title={title} onClose={onClose}>
      {result ? (
        <div className="space-y-2 text-sm">
          {result.type === 'quarantine_release' ? (
            <div className="rounded-md bg-royal-50 px-3 py-2 text-royal">
              Release request sent for approval: {result.slots.map((s: any) => s.label).join(' + ')}. <Link className="underline" to={`/approvals?id=${result.id}`}>Open it</Link>
            </div>
          ) : (
          <div className="rounded-md bg-ok-50 px-3 py-2 text-ok">Applied: {LEVEL_LABEL[result.level] ?? result.level} · {result.tokens_revoked ?? 0} tokens revoked{result.credentials_flagged_for_rotation?.length ? ` · ${result.credentials_flagged_for_rotation.length} credential(s) flagged for rotation` : ''}</div>
          )}
          {acks && (
            <div>
              <div className="font-medium">Propagation: {acks.acks.length}/{acks.event.nodes_expected} gateway nodes acknowledged</div>
              <div className="mt-1 flex flex-wrap gap-2">{acks.acks.map((a: any) => <span key={a.gateway_node_id} className="rounded bg-canvas px-2 py-1 mono">{a.gateway_node_id} · {a.latency_ms} ms</span>)}</div>
            </div>
          )}
          <button className="btn-ghost" onClick={onClose}>Close</button>
        </div>
      ) : (
        <div className="space-y-4">
          {isKill && (
            <ul className="list-disc space-y-1 pl-5 text-sm text-ink-2">
              <li>The seal is revoked and every live workload token for the scope is revoked.</li>
              <li>In-flight model and tool calls are cut on every gateway node now.</li>
              <li>Brokered credentials this agent could use are flagged for rotation.</li>
              <li className="font-medium text-bad">This cannot be undone. Re-entry only through a new seal from Assess.</li>
            </ul>
          )}
          {action === 'release' && <p className="text-sm text-ink-2">Lifting a ladder state is human-only and written to the ledger (RB-INV-10). Releasing a quarantine opens an approval (Owner + Security; T1 adds Risk). The agent's revoked tokens stay revoked; it redeploys with a new bootstrap credential.</p>}
          {scoped && (
            <div>
              <label className="label">Scope</label>
              <div className="space-y-1 text-sm">
                <label className="flex items-center gap-2"><input type="radio" checked={scope === 'agent'} onChange={() => setScope('agent')} /> Whole agent (all versions, all instances)</label>
                <label className="flex items-center gap-2"><input type="radio" checked={scope === 'instance'} disabled={!instances.length} onChange={() => setScope('instance')} /> One instance
                  {scope === 'instance' && <select className="input ml-2 w-auto" value={instance} onChange={(e) => setInstance(e.target.value)}>{instances.map((i) => <option key={i.id} value={i.id}>{i.id}</option>)}</select>}
                </label>
              </div>
            </div>
          )}
          {(action === 'step_up' || action === 'throttle') && (
            <div>
              <label className="label">Window in minutes (blank = tier default)</label>
              <input className="input w-32" value={minutes} onChange={(e) => setMinutes(e.target.value.replace(/\D/g, ''))} />
            </div>
          )}
          <div>
            <label className="label">Reason (required, goes to the ledger)</label>
            <textarea className="input min-h-16" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
          {isKill && (
            <div>
              <label className="label">Type <span className="mono">{agent.handle}</span> to confirm</label>
              <input className="input mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </div>
          )}
          <ErrorNote error={error} />
          <div className="flex justify-end gap-2">
            <button className="btn-ghost" onClick={onClose}>Cancel</button>
            <button className={isKill || action === 'quarantine' ? 'btn-danger' : 'btn-primary'} disabled={!reason.trim() || (isKill && confirm !== agent.handle)} onClick={() => void submit()}>
              {isKill ? 'Kill agent' : action === 'release' ? 'Release' : 'Apply'}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

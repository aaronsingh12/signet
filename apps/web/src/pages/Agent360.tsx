import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Card, Empty, ErrorNote, KV, LEVEL_LABEL, Modal, Mono, PageHeader, Pill, Tabs, TierChip } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan, useMe } from '../lib/auth';
import { ago, date, daysLeft, dlpSummary, time } from '../lib/format';

type Ladder = 'step_up' | 'throttle' | 'quarantine' | 'kill' | 'release';

export function Agent360() {
  const { id } = useParams();
  const me = useMe();
  const can = useCan();
  const { data, reload, error } = useApi<any>(`/agents/${id}`);
  const [tab, setTab] = useState('overview');
  const [ladder, setLadder] = useState<Ladder | null>(null);
  const [boot, setBoot] = useState<any>(null);
  if (error) return <ErrorNote error={error} />;
  if (!data) return null;
  const { agent, certificate: cert, enforcement } = data;
  const own = agent.owner === me.principal.id;
  const ladderAllowed = (a: Ladder) => can(`ladder.${a}`) && (own || !me.principal.roles.every((r) => r === 'agent_owner'));
  const killed = enforcement.level === 'killed' || agent.status === 'killed';
  const left = daysLeft(cert?.valid_to);
  const issueBootstrap = async () => setBoot(await api(`/agents/${agent.id}/bootstrap`, { method: 'POST', body: { environment: 'dev' } }).catch((e) => ({ error: e })));

  return (
    <>
      <div className="mb-1 text-xs text-ink-3">
        <Link to="/agents" className="hover:underline">Agent Registry</Link> / <span className="mono">{agent.handle}</span>
      </div>
      <PageHeader
        title={agent.name}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            {cert ? <Pill value="sealed" label={`Sealed · valid to ${date(cert.valid_to)}`} /> : <Pill value={agent.status} />}
            <Pill value={enforcement.level} label={enforcement.level === 'active' ? 'ladder: active' : LEVEL_LABEL[enforcement.level] ?? enforcement.level} />
            <TierChip tier={agent.tier} />
            <span className="text-xs">{agent.autonomy_level}</span>
            <Mono>{agent.id}</Mono>
            {cert && <span className="text-xs">version {cert.version} · gpt-oss (cloud LLM) · keyless</span>}
          </span>
        }
        actions={
          !killed && (
            <>
              {can('identity.bootstrap') && cert && <button className="btn-ghost" onClick={() => void issueBootstrap()}>Bootstrap credential</button>}
              {ladderAllowed('step_up') && <button className="btn-ghost" onClick={() => setLadder('step_up')}>Step-up</button>}
              {ladderAllowed('throttle') && <button className="btn-ghost" onClick={() => setLadder('throttle')}>Throttle</button>}
              {ladderAllowed('release') && enforcement.level !== 'active' && <button className="btn-ghost" onClick={() => setLadder('release')}>Release</button>}
              {ladderAllowed('quarantine') && <button className="btn-ghost text-bad" onClick={() => setLadder('quarantine')}>Quarantine</button>}
              {ladderAllowed('kill') && <button className="btn-danger" onClick={() => setLadder('kill')}>Kill</button>}
            </>
          )
        }
      />
      {killed && <div className="mb-4 rounded-md border border-bad/30 bg-bad-50 px-4 py-2.5 text-sm text-bad">This agent has been killed. A kill is never lifted; re-entry needs a new seal through Assess (RB-INV-08).</div>}
      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'seal', label: 'Seal' },
          { id: 'manifest', label: 'Manifest' },
          { id: 'instances', label: `Instances ${data.instances.length}` },
          { id: 'ledger', label: 'Ledger' },
          ...(can('certificates.approve') && !killed ? [{ id: 'approve', label: cert ? 'Re-issue seal' : 'Approve & seal' }] : []),
        ]}
      />
      {tab === 'overview' && (
        <div className="grid gap-4 xl:grid-cols-3">
          <Card title="Accountability" className="xl:col-span-1">
            <KV
              rows={[
                ['Owner', agent.owner],
                ['Sponsor', agent.sponsor],
                ['Proposed by', agent.created_by],
                ['Build team', data.team.length ? data.team.map((t: any) => `${t.user} (${t.role})`).join(', ') : '—'],
                ['Separation of duties', 'Owner, proposer and build team can never approve this agent (RB-INV-09)'],
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
              <Empty>Not sealed yet. An approver outside the build team defines the manifest and signs it.</Empty>
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
        </div>
      )}
      {tab === 'seal' && <SealTab agentId={agent.id} cert={cert} history={data.certificates} />}
      {tab === 'manifest' && cert && <ManifestTab cert={cert} />}
      {tab === 'instances' && (
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
      {tab === 'approve' && <SealEditor agent={agent} current={cert} onDone={() => (void reload(), setTab('seal'))} />}
      {ladder && <LadderModal agent={agent} instances={data.instances} action={ladder} onClose={() => setLadder(null)} onDone={() => void reload()} />}
      {boot && (
        <Modal title="Bootstrap credential" onClose={() => setBoot(null)}>
          {boot.error ? (
            <ErrorNote error={boot.error} />
          ) : (
            <>
              <p className="text-sm text-ink-2">Give this to the deployment pipeline. It works once, within 15 minutes, and is exchanged at <Mono>POST /api/v1/identity/token</Mono> for a workload token. It is not shown again.</p>
              <pre className="mono mt-3 break-all rounded-md bg-canvas p-3">{boot.bootstrap_credential}</pre>
              <p className="mt-2 text-xs text-ink-3">Expires {new Date(boot.expires_at).toLocaleTimeString()} · environment {boot.environment}</p>
            </>
          )}
        </Modal>
      )}
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
          <div className="rounded-md bg-ok-50 px-3 py-2 text-ok">Applied: {LEVEL_LABEL[result.level] ?? result.level} · {result.tokens_revoked ?? 0} tokens revoked{result.credentials_flagged_for_rotation?.length ? ` · ${result.credentials_flagged_for_rotation.length} credential(s) flagged for rotation` : ''}</div>
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
          {action === 'release' && <p className="text-sm text-ink-2">Lifting a ladder state is human-only and written to the ledger (RB-INV-10). The agent's revoked tokens stay revoked; it redeploys with a new bootstrap credential.</p>}
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

function SealEditor({ agent, current, onDone }: { agent: any; current: any; onDone: () => void }) {
  const { data: tools } = useApi<any>('/tools');
  const { data: cat } = useApi<any>('/catalogue');
  const [text, setText] = useState('');
  const [error, setError] = useState<ApiError | { rule: string; message: string } | null>(null);
  useEffect(() => {
    if (text || !cat) return;
    const base = current
      ? { models: current.models, tools: current.tools, data_classes: current.data_classes, hitl: current.hitl, limits: current.limits, environments: current.environments, tags: current.tags }
      : {
          models: [{ model: cat.catalogue[0].model, region: cat.catalogue[0].region, max_tokens: 800 }],
          tools: (tools?.items ?? []).map((t: any) => ({ server: `${t.kind}://${t.alias}`, data_scopes: ['personal'], actions: t.kind === 'http' ? Object.keys(t.actions).map((name) => ({ name, impact: 'read' })) : [{ name: 'lookup_order', impact: 'read' }] })),
          data_classes: { prompt: ['personal'], forbidden: ['payment_card', 'special_category'] },
          hitl: [],
          limits: { rpm: 60, tokens_per_day: 200000, usd_per_day: 50, tool_calls_per_session: 40 },
          environments: ['dev'],
          tags: [],
        };
    setText(JSON.stringify(base, null, 2));
  }, [cat, tools, current, text]);
  const submit = async () => {
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return setError({ rule: 'JSON', message: 'the manifest is not valid JSON' });
    }
    try {
      await api(`/agents/${agent.id}/certificates`, { method: 'POST', body });
      onDone();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
      <Card title={`Manifest for ${agent.handle} · ${agent.tier} · ${agent.autonomy_level}`}>
        <textarea className="input mono min-h-[440px]" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
        <div className="mt-3 flex items-center gap-3">
          <button className="btn-primary" onClick={() => void submit()}>Approve and sign seal</button>
          <ErrorNote error={error as any} />
        </div>
      </Card>
      <Card title="What happens when you sign">
        <ul className="list-disc space-y-1.5 pl-5 text-sm text-ink-2">
          <li>Signet checks separation of duties: you are not the owner, proposer or on the build team (RB-INV-09).</li>
          <li>Every check cites its rule: model is the cloud LLM (RB-INV-19), every action has an impact label (RB-PRIV-01), no secrets to models (RB-INV-16), T4 has no privileged actions (RB-INV-17).</li>
          <li>The manifest is compiled into the gateway policy; the seal carries the policy hash and is signed with the tenant CA key (Ed25519).</li>
          <li>Both gateway nodes receive the new bundle within a second. The decision is written to the lifecycle ledger.</li>
        </ul>
        <div className="mt-3 text-xs text-ink-3">Registered tools: {(tools?.items ?? []).map((t: any) => `${t.kind}://${t.alias}`).join(', ') || 'none'}</div>
      </Card>
    </div>
  );
}

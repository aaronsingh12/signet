import { useState } from 'react';
import { Card, Empty, ErrorNote, KV, Mono, Pill, Tabs } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago, time } from '../lib/format';
import { ConnectionSetup } from '../components/ConnectionSetup';

// Agent connectivity on Agent 360: whether the agent's own calls actually reach the gateway, the
// credentials that let it, the runtime diagnostics its SDK reported, how to connect it, and its
// real model and tool traffic. Every figure here comes from identity records and the ledger.

const STATE: Record<string, { pill: string; label: string }> = {
  pending_approval: { pill: 'none', label: 'Pending approval' },
  approved: { pill: 'allow_with_obligations', label: 'Approved' },
  credentials_not_provisioned: { pill: 'require_approval', label: 'Credentials not provisioned' },
  not_connected: { pill: 'require_approval', label: 'Not connected' },
  connected: { pill: 'allow', label: 'Connected' },
  connection_error: { pill: 'deny', label: 'Connection error' },
  suspended: { pill: 'quarantine', label: 'Suspended' },
  revoked: { pill: 'kill', label: 'Revoked' },
};

export function ConnectionPill({ state }: { state: string }) {
  const s = STATE[state] ?? { pill: 'none', label: state };
  return <Pill value={s.pill} label={s.label} />;
}

export function ConnectionTab({ data, onChange }: { data: any; onChange: () => void }) {
  const can = useCan();
  const { agent, connection: c, certificate: cert } = data;
  const thirdParty = agent.kind === 'third_party';
  const [error, setError] = useState<ApiError | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setError(null);
      onChange();
    } catch (e) {
      setError(e as ApiError);
    }
  };
  const revokeInstance = (id: string) => {
    const reason = prompt(`Reason for revoking instance ${id}`);
    if (reason) void act(() => api(`/instances/${id}/revoke`, { method: 'POST', body: { reason } }));
  };
  const revokeClient = (id: string) => {
    const reason = prompt(`Reason for revoking client ${id}`);
    if (reason) void act(() => api(`/clients/${id}/revoke`, { method: 'POST', body: { reason } }));
  };

  if (agent.connection_method === 'rest') return <ConnectionSetup key={agent.id} agent={agent} certificate={cert} state={c.state} onChange={onChange} />;

  return (
    <div className="space-y-4">
      <ConnectionSetup key={agent.id} agent={agent} certificate={cert} state={c.state} onChange={onChange} />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Connection">
          <div className="mb-2"><ConnectionPill state={c.state} /></div>
          <p className="text-sm text-ink-2">{c.reason}</p>
          <div className="mt-3">
            <KV
              rows={[
                ['Last accepted call', c.last_accepted_at ? `${ago(c.last_accepted_at)} (${time(c.last_accepted_at)} UTC)` : 'never'],
                ['Last successful call', c.last_success_at ? ago(c.last_success_at) : 'never'],
                ['Last refused identity', c.last_auth_failure ? `${c.last_auth_failure.code}, ${ago(c.last_auth_failure.at)}` : '—'],
                ['Live tokens', c.identity.live_tokens],
                ['Bootstrap generated', c.identity.bootstrap_credentials.issued > 0 ? 'Yes' : 'No'],
                ['Bootstrap token exchanged', c.identity.bootstrap_credentials.exchanged > 0 ? 'Yes' : 'No'],
                ['Gateway enforcement active', c.gateway_enforcement_active ? 'Recent identity accepted by Gateway' : 'No recent accepted identity'],
                ['Latest Gateway decision', c.last_gateway_decision ? `${c.last_gateway_decision.outcome ?? 'unknown'}${c.last_gateway_decision.error_code ? ` · ${c.last_gateway_decision.error_code}` : ''}` : 'No calls recorded'],
              ]}
            />
          </div>
        </Card>
        <Card title="What Signet governs">
          <KV
            rows={[
              ['Agent type', agent.kind.replace('_', ' ')],
              ['Model calls', c.coverage.model_calls === 'governed' ? <Pill key="m" value="allow" label="through the gateway" /> : <Pill key="m" value="none" label="not intercepted (vendor model)" />],
              ['Tool calls', <Pill key="t" value="allow" label="through the gateway" />],
              ...(thirdParty ? [['Vendor', agent.vendor] as [string, string]] : [['Runtime', agent.runtime ?? '—'] as [string, string], ['Framework', agent.framework ?? '—'] as [string, string]]),
            ]}
          />
          {thirdParty && <p className="mt-3 text-xs text-ink-3">{agent.vendor}'s own model runs outside Signet. Signet governs and records only the company tools this agent calls through the gateway.</p>}
        </Card>

      </div>

      <Card title="Instances" pad={false}>
        {c.identity.instances.length ? (
          <table className="w-full">
            <thead><tr>{['Instance', 'How it proved itself', 'Version', 'Env', 'Started', 'Last token', 'State', ''].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
            <tbody>
              {c.identity.instances.map((i: any) => (
                <tr key={i.id}>
                  <td className="td"><Mono>{i.id}</Mono></td>
                  <td className="td text-xs">{i.auth_kind === 'client_credentials' ? 'OAuth client' : 'bootstrap credential'}</td>
                  <td className="td text-xs">{i.version}</td>
                  <td className="td text-xs">{i.env}</td>
                  <td className="td text-xs">{ago(i.first_seen)}</td>
                  <td className="td text-xs">{ago(i.last_seen)}</td>
                  <td className="td"><Pill value={i.revoked_at ? 'deny' : i.state === 'running' ? 'allow' : 'none'} label={i.revoked_at ? 'revoked' : i.state} /></td>
                  <td className="td">{!i.revoked_at && can('ladder.quarantine') && <button className="text-xs text-bad hover:underline" onClick={() => revokeInstance(i.id)}>Revoke identity</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty>No instance has exchanged a credential yet.</Empty>
        )}
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Runtime diagnostics (reported by the SDK or sidecar)">
          {c.diagnostics.length ? (
            <ul className="space-y-3 text-sm">
              {c.diagnostics.map((d: any) => (
                <li key={d.instance_id}>
                  <div className="flex items-center gap-2">
                    <Pill value={d.bypass_risk ? 'deny' : 'allow'} label={d.bypass_risk ? 'bypass risk detected' : 'no bypass found'} />
                    <span className="text-xs text-ink-3">{d.client} · {ago(d.reported_at)} · <Mono>{d.instance_id}</Mono></span>
                  </div>
                  {(d.report.env_findings ?? []).map((f: any) => <div key={f.name} className="mt-1 text-xs"><Mono>{f.name}</Mono> {f.detail}</div>)}
                  {(d.report.egress_check ?? []).filter((e: any) => e.reachable).map((e: any) => <div key={e.target} className="mt-1 text-xs">direct connection to <Mono>{e.target}</Mono> succeeded</div>)}
                </li>
              ))}
            </ul>
          ) : (
            <Empty>No report yet. The Python SDK reports at start-up; agents connected without the SDK are unverified.</Empty>
          )}
          <p className="mt-3 text-xs text-ink-3">This detects a way around the gateway; it does not stop one. Outbound network rules that allow only the gateway are what enforce it (docs/egress.md).</p>
        </Card>
        <Card title="Recent refusals and failures" pad={false}>
          {c.recent_errors.length ? (
            <table className="w-full">
              <tbody>
                {c.recent_errors.map((e: any, i: number) => (
                  <tr key={i}>
                    <td className="td whitespace-nowrap text-xs">{ago(e.ts)}</td>
                    <td className="td mono text-xs">{e.action_type}</td>
                    <td className="td mono text-xs">{e.target}</td>
                    <td className="td text-xs"><Pill value={e.outcome === 'upstream_error' ? 'require_approval' : 'deny'} label={e.error_code ?? e.outcome} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>None.</Empty>
          )}
        </Card>
      </div>

      <Card title="OAuth connections">
        {(data.clients ?? []).length ? <ul className="space-y-2">{data.clients.map((client: { client_id: string; label: string; revoked_at: string | null }) => <li key={client.client_id} className="flex items-center gap-3 text-sm"><Mono>{client.client_id}</Mono><span>{client.label}</span><span className="text-ink-3">{client.revoked_at ? 'revoked' : 'active'}</span>{!client.revoked_at && can('identity.bootstrap') && <button className="ml-auto text-bad" onClick={() => revokeClient(client.client_id)}>Revoke</button>}</li>)}</ul> : <Empty>No OAuth connection created yet.</Empty>}
      </Card>
      <div><ErrorNote error={error} /></div>
      <Activity agentId={agent.id} />


    </div>
  );
}

function Activity({ agentId }: { agentId: string }) {
  const [kind, setKind] = useState<'llm_call' | 'tool_call'>('llm_call');
  const { data } = useApi<any>(`/ledger/records?agent=${agentId}&kind=transaction&limit=200`, [agentId]);
  const rows = (data?.items ?? []).filter((r: any) => r.data.action_type === kind).slice(0, 50);
  return (
    <Card title="Gateway activity" pad={false} action={<Tabs tabs={[{ id: 'llm_call', label: 'Model calls' }, { id: 'tool_call', label: 'Tool calls' }]} active={kind} onChange={(k) => setKind(k as 'llm_call' | 'tool_call')} />}>
      {rows.length ? (
        <table className="w-full">
          <thead><tr>{['Time (UTC)', 'Target', 'Decision', 'Rules', 'Outcome', 'Instance', 'Gateway ms', 'Upstream ms'].map((h) => <th key={h} className="th">{h}</th>)}</tr></thead>
          <tbody>
            {rows.map((r: any) => (
              <tr key={r.record_id}>
                <td className="td mono whitespace-nowrap text-xs">{time(r.ts)}</td>
                <td className="td mono text-xs">{r.data.target}</td>
                <td className="td"><Pill value={r.data.policy_decision} /></td>
                <td className="td mono text-[11px] text-ink-2">{(r.data.policy_rule_ids ?? []).join(', ') || '—'}</td>
                <td className="td text-xs">{r.data.error_code ?? r.data.outcome}</td>
                <td className="td mono text-[11px]">{r.data.instance_id ?? '—'}</td>
                <td className="td text-right text-xs">{r.data.latency_ms_gateway ?? ''}</td>
                <td className="td text-right text-xs">{r.data.latency_ms_upstream ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <Empty>No {kind === 'llm_call' ? 'model' : 'tool'} calls from this agent have reached a gateway.</Empty>
      )}
    </Card>
  );
}

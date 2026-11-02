import { useState } from 'react';
import { Card, Empty, ErrorNote, KV, Modal, Mono, Pill, Tabs } from '../components/ui';
import { ApiError, api, useApi } from '../lib/api';
import { useCan } from '../lib/auth';
import { ago, time } from '../lib/format';

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

function Code({ children }: { children: string }) {
  return (
    <div className="relative">
      <pre className="mono overflow-x-auto whitespace-pre rounded-md bg-canvas p-3 text-xs">{children}</pre>
      <button className="absolute right-2 top-2 rounded border border-line bg-white px-1.5 py-0.5 text-[10px] text-ink-2 hover:text-ink" onClick={() => void navigator.clipboard?.writeText(children)}>
        Copy
      </button>
    </div>
  );
}

export function ConnectionTab({ data, onChange }: { data: any; onChange: () => void }) {
  const can = useCan();
  const { agent, connection: c, certificate: cert } = data;
  const { data: info } = useApi<any>('/connect/info');
  const thirdParty = agent.kind === 'third_party';
  const [secret, setSecret] = useState<any>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [env, setEnv] = useState(cert?.environments?.[0] ?? 'dev');
  const [label, setLabel] = useState('');
  const act = async (fn: () => Promise<any>, show = false) => {
    try {
      const r = await fn();
      if (show) setSecret(r);
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
  const canProvision = can('identity.bootstrap') && cert && c.state !== 'revoked' && c.state !== 'suspended';

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-3">
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
        <Card title={thirdParty ? 'Client credentials (OAuth)' : 'Bootstrap credential'}>
          {!cert ? (
            <p className="text-sm text-ink-3">Available once the seal is signed.</p>
          ) : thirdParty ? (
            <>
              <p className="text-xs text-ink-3">The vendor platform exchanges these at the token URL (grant_type=client_credentials) for a short-lived token. The secret is shown once.</p>
              {canProvision && (
                <div className="mt-2 flex gap-2">
                  <input className="input" placeholder="Label, e.g. Copilot Studio connector" value={label} onChange={(e) => setLabel(e.target.value)} />
                  <button className="btn-primary whitespace-nowrap" onClick={() => void act(() => api(`/agents/${agent.id}/clients`, { method: 'POST', body: { label } }), true)}>Create</button>
                </div>
              )}
              <ul className="mt-3 space-y-1.5 text-xs">
                {(data.clients ?? []).map((cl: any) => (
                  <li key={cl.client_id} className="flex items-center gap-2">
                    <Mono>{cl.client_id}</Mono>
                    <span className="text-ink-3">{cl.label} · {cl.revoked_at ? 'revoked' : cl.last_used_at ? `used ${ago(cl.last_used_at)}` : 'never used'}</span>
                    {!cl.revoked_at && can('identity.bootstrap') && <button className="ml-auto text-bad hover:underline" onClick={() => revokeClient(cl.client_id)}>Revoke</button>}
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <>
              <p className="text-xs text-ink-3">For the deployment pipeline: works once, within 15 minutes, and is never shown again. {c.identity.bootstrap_credentials.issued} issued, {c.identity.bootstrap_credentials.exchanged} exchanged.</p>
              {canProvision && (
                <div className="mt-2 flex gap-2">
                  <select className="input w-auto" value={env} onChange={(e) => setEnv(e.target.value)}>{cert.environments.map((e: string) => <option key={e}>{e}</option>)}</select>
                  <button className="btn-primary" onClick={() => void act(() => api(`/agents/${agent.id}/bootstrap`, { method: 'POST', body: { environment: env } }), true)}>Issue bootstrap credential</button>
                </div>
              )}
            </>
          )}
          <div className="mt-2"><ErrorNote error={error} /></div>
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

      <Instructions agent={agent} info={info} />
      <Activity agentId={agent.id} />

      {secret && (
        <Modal title={secret.client_secret ? 'Client credentials' : 'Bootstrap credential'} onClose={() => setSecret(null)}>
          <p className="text-sm text-ink-2">Copy it now. Signet stores only a hash and will not show it again.</p>
          <div className="mt-3 space-y-2">
            {secret.client_secret ? (
              <>
                <KV rows={[['Token URL', <Mono key="u">{`${info?.control_url ?? ''}/api/v1/identity/token`}</Mono>], ['Grant type', 'client_credentials'], ['Client ID', <Mono key="i">{secret.client_id}</Mono>]]} />
                <Code>{secret.client_secret}</Code>
              </>
            ) : (
              <>
                <Code>{secret.bootstrap_credential}</Code>
                <p className="text-xs text-ink-3">Expires {new Date(secret.expires_at).toLocaleTimeString()} · environment {secret.environment}. Put it in the agent's SIGNET_BOOTSTRAP_CREDENTIAL (or a mounted file for SIGNET_BOOTSTRAP_FILE).</p>
              </>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}

function Instructions({ agent, info }: { agent: any; info: any }) {
  const thirdParty = agent.kind === 'third_party';
  const [tab, setTab] = useState(thirdParty ? 'vendor' : agent.kind === 'no_code' ? 'sidecar' : 'python');
  const gw = info?.gateway_url ?? '<gateway-url>';
  const cp = info?.control_url ?? '<control-url>';
  const model = info?.models?.[0] ?? 'gpt-oss:120b-cloud';
  const mcp = (info?.tools ?? []).filter((t: any) => t.kind === 'mcp');
  const http = (info?.tools ?? []).filter((t: any) => t.kind === 'http');
  const envBlock = `SIGNET_GATEWAY_URL=${gw}\nSIGNET_CONTROL_URL=${cp}\nSIGNET_BOOTSTRAP_CREDENTIAL=<from the pipeline, single use>\n# or: SIGNET_BOOTSTRAP_FILE=/run/secrets/signet-bootstrap\n# Remove direct provider keys (OPENAI_API_KEY, OLLAMA_API_KEY, ...) from the agent.`;
  const tabs = thirdParty
    ? [{ id: 'vendor', label: 'Vendor platform (OAuth)' }, { id: 'tools', label: 'Tool endpoints' }]
    : [{ id: 'python', label: 'Python SDK' }, { id: 'sidecar', label: 'Sidecar (n8n, Flowise, Dify, any language)' }, { id: 'tools', label: 'Tool endpoints' }, { id: 'deploy', label: 'Docker / RunPod / AWS' }, { id: 'verify', label: 'Verify' }];
  return (
    <Card title="Connect this agent">
      {(info?.gateway_url_source ?? '').includes('local') && <p className="mb-3 rounded-md bg-warn-50 px-3 py-2 text-xs text-warn">Gateway URL is {info.gateway_url_source}. Agents on other machines (RunPod, EC2) need a reachable URL.</p>}
      <Tabs tabs={tabs} active={tab} onChange={setTab} />
      {tab === 'python' && (
        <div className="space-y-3">
          <Code>{`pip install ./sdk/python[openai]    # from the Signet repository; package signet-sdk`}</Code>
          <Code>{envBlock}</Code>
          <Code>{`from signet_sdk import SignetAgent

agent = SignetAgent.from_env()          # exchanges the bootstrap credential, refreshes tokens
client = agent.openai_client()          # openai.OpenAI pointed at the Signet gateway

reply = client.chat.completions.create(
    model="${model}",
    messages=[{"role": "user", "content": "Hello"}],
)
${mcp[0] ? `\nagent.mcp_call("${mcp[0].alias}", "<tool>", {...})      # MCP through the gateway` : ''}${http[0] ? `\nagent.http_tool("${http[0].alias}", "${http[0].actions[0] ?? '<action>'}", ...)  # HTTP tool through the gateway` : ''}
# LangChain / LangGraph / CrewAI (OpenAI-compatible model classes):
#   import httpx; from signet_sdk import SignetAuth
#   ChatOpenAI(model="${model}", base_url=agent.openai_base_url, api_key="unused",
#              http_client=httpx.Client(auth=SignetAuth(agent.tokens)))`}</Code>
        </div>
      )}
      {tab === 'sidecar' && (
        <div className="space-y-3">
          <p className="text-sm text-ink-2">Run the sidecar next to the agent on a private network. Point the framework's OpenAI base URL at it; whatever API key the framework asks for is discarded.</p>
          <Code>{`docker build --target sidecar -t signet/sidecar .
docker run -d --name signet-sidecar --network agent-net \\
  -e SIGNET_GATEWAY_URL=${gw} -e SIGNET_CONTROL_URL=${cp} \\
  -e SIGNET_BOOTSTRAP_CREDENTIAL=<single use> -e SIGNET_SIDECAR_BIND=0.0.0.0 \\
  signet/sidecar`}</Code>
          <Code>{`# In n8n / Flowise / Dify (OpenAI-compatible model node):
Base URL:  http://signet-sidecar:8300/v1
API key:   anything (ignored)
Model:     ${model}
${mcp.map((t: any) => `MCP server ${t.alias}: http://signet-sidecar:8300/v1/mcp/${t.alias}`).join('\n')}`}</Code>
          <p className="text-xs text-ink-3">Anyone who can reach the sidecar acts as this agent: never publish its port.</p>
        </div>
      )}
      {tab === 'tools' && (
        <div className="space-y-2 text-sm">
          {mcp.map((t: any) => <div key={t.alias}>MCP <Mono>{`${gw}/v1/mcp/${t.alias}`}</Mono></div>)}
          {http.map((t: any) => t.actions.map((a: string) => <div key={`${t.alias}.${a}`}>HTTP <Mono>{`${gw}/v1/tools/http/${t.alias}/${a}`}</Mono></div>))}
          {!mcp.length && !http.length && <p className="text-ink-3">No tools registered yet (Tools & secrets).</p>}
          <p className="text-xs text-ink-3">Each call needs <Mono>Authorization: Bearer &lt;workload token&gt;</Mono>; only actions in this agent's seal are allowed, and the gateway injects the tool's credential.</p>
        </div>
      )}
      {tab === 'vendor' && (
        <div className="space-y-3 text-sm text-ink-2">
          <p>Configure the company tools in {agent.vendor ?? 'the vendor platform'} as custom connectors (OpenAPI or MCP) that point at the Signet gateway, with OAuth 2.0 client credentials:</p>
          <Code>{`Token URL:      ${cp}/api/v1/identity/token
Grant type:     client_credentials
Client ID/secret: create them in the Bootstrap / Client credentials card above
Tool base URL:  ${gw}/v1/tools/http/<alias>/<action>
MCP server URL: ${gw}/v1/mcp/<alias>`}</Code>
          <p className="text-xs text-ink-3">Signet then decides and records every tool call. The vendor's own model and any tools the vendor hosts itself remain outside Signet; do not give the vendor direct credentials to these systems.</p>
        </div>
      )}
      {tab === 'deploy' && (
        <div className="space-y-3 text-sm text-ink-2">
          <p>Give the pipeline the bootstrap credential at deploy time, as a secret, not in the image. Then restrict outbound traffic so the agent can reach only the gateway:</p>
          <ul className="list-disc space-y-1 pl-5 text-xs">
            <li>Docker: put the agent on an <Mono>internal: true</Mono> network with the gateway (or sidecar) as its only route out.</li>
            <li>AWS EC2/ECS: security group egress only to the gateway's address on 443; no NAT route to the internet.</li>
            <li>Kubernetes: a NetworkPolicy allowing egress only to the gateway service (and DNS).</li>
            <li>RunPod: pods have open outbound internet and no egress firewall, so Signet can only detect a bypass there (SDK diagnostics). Keep provider keys out of the pod; use a VPC provider for enforcement.</li>
          </ul>
          <p className="text-xs text-ink-3">Full guide: docs/egress.md and docs/connect-agents.md in the repository.</p>
        </div>
      )}
      {tab === 'verify' && (
        <div className="space-y-3">
          <Code>{`signet-doctor --model ${model}${mcp[0] ? ` --mcp ${mcp[0].alias}` : ''}`}</Code>
          <p className="text-xs text-ink-3">Checks configuration, reaches the gateway and control plane, exchanges the credential, reports diagnostics and sends one model call. The connection state above changes to Connected once the gateway accepts a call. A bootstrap credential is single use: run the doctor with SIGNET_TOKEN_CACHE set if the agent should continue from the same identity.</p>
        </div>
      )}
    </Card>
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

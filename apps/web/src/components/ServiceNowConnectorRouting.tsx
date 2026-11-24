// Connector feature disabled at user request. Original code is preserved below.
// import { useEffect, useState } from 'react';
// import { ArrowRight, CheckCircle2, Clock, ShieldCheck } from 'lucide-react';
// import { Link } from 'react-router-dom';
// import type { ServiceNowRoutingView, ServiceNowRoutingAgent } from '@signet/core/servicenow-connector';
// import { api, useApi } from '../lib/api';
// import { useCan } from '../lib/auth';
// import { Card, ErrorNote, Modal, Pill } from './ui';
// import { CopyCode } from './CopyCode';
// import { ConnectionSetup, type ConnectionSetupProps } from './ConnectionSetup';
//
// function routingResponse(value: ServiceNowRoutingView): ServiceNowRoutingView {
//   if (!value || typeof value.connection_id !== 'string' || typeof value.authorization_url !== 'string' || typeof value.token_url !== 'string' || !Array.isArray(value.agents) || (value.route !== null && (typeof value.route.alias !== 'string' || typeof value.route.url !== 'string'))) throw new TypeError('ServiceNow routing status is missing connection, route or OAuth endpoints');
//   for (const agent of value.agents) {
//     if (!agent || typeof agent.id !== 'string' || typeof agent.name !== 'string' || typeof agent.routing_verified !== 'boolean' || !Array.isArray(agent.environments) || agent.environments.some(environment => typeof environment !== 'string') || !Array.isArray(agent.allowed_actions) || agent.allowed_actions.some(action => typeof action !== 'string') || !['shadow', 'canary', 'enforce'].includes(agent.rollout) || typeof agent.runtime_state !== 'string') throw new TypeError('ServiceNow routing status contains invalid agent approval or verification evidence');
//     for (const at of [agent.last_call_at, agent.last_block_at]) if (at !== null && !Number.isFinite(Date.parse(at))) throw new TypeError('ServiceNow routing evidence contains an invalid timestamp');
//   }
//   return value;
// }
//
// export function ServiceNowConnectorRouting({ connectionId }: { connectionId: string }) {
//   const path = `/plugins/servicenow/connections/${encodeURIComponent(connectionId)}`;
//   const can = useCan();
//   const [data, setData] = useState<ServiceNowRoutingView | null>(null);
//   const [error, setError] = useState<Error | null>(null);
//   const [busy, setBusy] = useState(false);
//   const [credentialsFor, setCredentialsFor] = useState<string | null>(null);
//   useEffect(() => {
//     let active = true;
//     const load = async (): Promise<void> => {
//       try { const value = routingResponse(await api<ServiceNowRoutingView>(path + '/routing')); if (active) { setData(value); setError(null); } }
//       catch (failure) { if (active) setError(failure as Error); }
//     };
//     void load(); const timer = window.setInterval(() => void load(), 15000);
//     return () => { active = false; window.clearInterval(timer); };
//   }, [path]);
//   const prepare = async (): Promise<void> => {
//     setBusy(true); setError(null);
//     try {
//       await api(path + '/gateway', { method: 'POST', body: { alias: `servicenow-${connectionId.slice(-12).toLowerCase()}` } });
//       setData(routingResponse(await api<ServiceNowRoutingView>(path + '/routing')));
//     } catch (failure) { setError(failure as Error); }
//     finally { setBusy(false); }
//   };
//   return <div className="space-y-4" data-testid="connector-routing">
//     <Card title="Route ServiceNow tool calls through Signet"><div className="mb-4 flex flex-wrap items-center gap-2 text-sm"><span>ServiceNow agent</span><ArrowRight size={15} /><strong>Signet checks / approval</strong><ArrowRight size={15} /><span>ServiceNow MCP</span></div><p className="mb-3 text-sm text-ink-2">Use Signet’s MCP URL as the agent’s outbound tool endpoint. Signet keeps the ServiceNow credential server-side and checks each tool call before forwarding it.</p><ErrorNote error={error} />
//       {!data && !error && <p role="status" className="text-sm">Loading routing and approval status…</p>}
//       {data && !data.route && <div className="mt-3"><p className="mb-3 text-sm text-ink-2">Authorize ServiceNow and discover its tools first. Preparing a route does not approve tools or create an agent credential.</p>{can('tools.manage') && <button className="btn-primary" data-testid="connector-prepare-route" disabled={busy} onClick={() => void prepare()}>{busy ? 'Preparing…' : 'Prepare Signet MCP route'}</button>}</div>}
//       {data?.route && <><label className="label">Signet MCP URL — configure this in ServiceNow</label><CopyCode testId="connector-signet-mcp-url" text={data.route.url} /><div className="mt-3"><CopyCode testId="connector-oauth-endpoints" text={`Authorization URL: ${data.authorization_url}\nToken URL: ${data.token_url}\nSupported grants: client_credentials or authorization_code with PKCE S256\nScope: mcp`} /></div><p className="mt-3 text-xs text-ink-3">For browser OAuth, save ServiceNow’s exact outbound callback URL in the agent credential setup. Use the agent’s approved environment. Direct tool connections that bypass Signet are outside this route.</p></>}
//     </Card>
//     {data?.agents.length === 0 && <Card><p className="text-sm text-ink-2">Select and link an existing ServiceNow agent in step 2 before configuring its approval and identity.</p></Card>}
//     {data?.agents.map(agent => <RoutingAgent key={agent.id} agent={agent} onCredentials={() => setCredentialsFor(agent.id)} />)}
//     <Card><div className="flex items-start gap-3"><ShieldCheck size={22} className="shrink-0 text-royal" /><div><h3 className="font-semibold">Verify from the real ServiceNow agent</h3><ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-ink-2"><li>Approve only the required MCP tools through the existing agent approval screen.</li><li>Create the agent’s OAuth credentials below, then configure the Signet MCP URL in ServiceNow’s outbound MCP connection.</li><li>Run an approved tool action from ServiceNow, then refresh this page to see its authenticated route evidence.</li><li>Enforcement must be active for policy refusals to block. Shadow mode only records what would be blocked. For a controlled denial test, use a non-destructive input that violates an approved constraint.</li></ol><p className="mt-3 text-xs text-ink-3">A successful OAuth login, a discovered tool list or an activity sync alone is not proof that an agent is routed through Signet. This connector does not automatically replace ServiceNow’s internal model or native chat provider.</p></div></div></Card>
//     {credentialsFor && <Modal title="Agent credentials and OAuth setup" width="max-w-5xl" onClose={() => setCredentialsFor(null)}><ConnectorIdentity agentId={credentialsFor} /></Modal>}
//   </div>;
// }
//
// function RoutingAgent({ agent, onCredentials }: { agent: ServiceNowRoutingAgent; onCredentials: () => void }) {
//   const enforced = agent.routing_verified && agent.rollout === 'enforce';
//   return <Card title={agent.name} action={<Pill value={enforced ? 'active' : 'require_approval'} label={enforced ? 'Routing verified · enforcement active' : agent.routing_verified ? `Routing verified · ${agent.rollout}` : 'Routing not verified'} />}>
//     <div className="grid gap-4 text-sm sm:grid-cols-3"><div><span className="text-ink-3">Approval</span><p className="mt-1 font-medium">{agent.allowed_actions.length ? `${agent.allowed_actions.length} approved MCP actions` : 'Approve this route and its tools'}</p></div><div><span className="text-ink-3">Routed traffic</span><p className="mt-1 font-medium">{agent.last_call_at ? new Date(agent.last_call_at).toLocaleString() : 'Waiting for actual agent traffic'}</p></div><div><span className="text-ink-3">Recorded block</span><p className="mt-1 font-medium">{agent.last_block_at ? new Date(agent.last_block_at).toLocaleString() : 'No confirmed block on this route'}</p></div></div>
//     <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-ink-3">{agent.last_block_at ? <CheckCircle2 size={14} /> : <Clock size={14} />}<span>Runtime: {agent.runtime_state} · rollout: {agent.rollout}</span></div>
//     {agent.allowed_actions.length > 0 && <details className="mt-3 text-xs"><summary className="cursor-pointer">Approved actions</summary><ul className="mt-2 space-y-1">{agent.allowed_actions.map(action => <li className="mono" key={action}>{action}</li>)}</ul></details>}
//     <div className="mt-4 flex flex-wrap gap-2"><Link className="btn-ghost" data-testid={`connector-agent-approval-${agent.id}`} to={`/agents/${agent.id}?tab=lifecycle`}>Review and approval</Link><button className="btn-primary" data-testid={`connector-agent-credentials-${agent.id}`} disabled={!agent.certificate_id} onClick={onCredentials}>Configure agent credentials</button><Link className="btn-ghost" to={`/agents/${agent.id}?tab=scans`}>Scan history</Link>{agent.last_record_id && <Link className="btn-ghost" to={`/activity?tab=history&record=${encodeURIComponent(agent.last_record_id)}`}>View route evidence</Link>}</div>
//   </Card>;
// }
//
// function ConnectorIdentity({ agentId }: { agentId: string }) {
//   const { data, error, reload } = useApi<{ agent: ConnectionSetupProps['agent']; certificate: ConnectionSetupProps['certificate']; connection: { state: string } }>(`/agents/${encodeURIComponent(agentId)}`);
//   if (error) return <ErrorNote error={error} />;
//   if (!data) return <p role="status">Loading the agent’s current approval and identity…</p>;
//   return <ConnectionSetup agent={data.agent} certificate={data.certificate} state={data.connection.state} onChange={() => void reload()} />;
// }

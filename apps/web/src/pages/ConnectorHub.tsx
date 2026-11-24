// Connector feature disabled at user request. Original code is preserved below.
// import { useState } from 'react';
// import { ArrowRight, Plug, Settings2 } from 'lucide-react';
// import { useSearchParams } from 'react-router-dom';
// import { api, useApi } from '../lib/api';
// import { useCan } from '../lib/auth';
// import { Card, ErrorNote, Modal, PageHeader, Pill } from '../components/ui';
// import { ServiceNowConnectorRouting } from '../components/ServiceNowConnectorRouting';
// import { ConnectorAdminSetup, ConnectorAgentSelection, ConnectorLogin } from '../components/ServiceNowConnectorOnboarding';
//
// interface Session { id: string; name: string; authorized: boolean }
//
// /** Connector onboarding is separate from the manual company-system setup. */
// export function ConnectorHub() {
//   const can = useCan();
//   const [params, setParams] = useSearchParams();
//   const [adding, setAdding] = useState(false);
//   const [admin, setAdmin] = useState(false);
//   const id = params.get('connection');
//   const manage = can('tenant.admin');
//   const { data, error, reload } = useApi<{ items: Session[] }>(manage ? '/connector/servicenow/sessions' : null);
//   const invalidSessions = data !== null && (!Array.isArray(data.items) || data.items.some(session => typeof session.id !== 'string' || typeof session.name !== 'string' || typeof session.authorized !== 'boolean'));
//   const sessions = data && !invalidSessions ? data.items : [];
//   const selected = sessions.find(session => session.id === id);
//   const [readyConnection, setReadyConnection] = useState<string | null>(null);
//   const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
//   return <>
//     <PageHeader title="Connectors" subtitle="Sign in to a platform, select an agent and verify its Signet route." />
//     <div className="settings-grid mb-6" data-testid="connector-catalog"><Card className="aspect-square border border-line [&>div]:flex [&>div]:h-full [&>div]:flex-col">
//       <div className="flex items-center justify-between gap-3"><span className="rounded-xl bg-royal-50 p-2.5 text-royal"><Plug size={22} /></span><Pill value="active" label="MCP connector" /></div>
//       <h2 className="mt-3 text-base font-semibold">ServiceNow</h2><p className="mt-1 text-xs leading-relaxed text-ink-2">Sign in, discover agents and govern their MCP tools through Signet.</p>
//       <div className="my-3 flex items-center gap-2 text-xs text-ink-2"><span>Login</span><ArrowRight size={13} /><span>Select agent</span><ArrowRight size={13} /><span>Route</span></div>
//       {manage && <button className="btn-primary mt-auto w-full justify-center" data-testid="connector-add-servicenow" onClick={() => setAdding(true)}>Connect ServiceNow<ArrowRight size={16} /></button>}
//     </Card></div>
//     <ErrorNote error={error ?? (invalidSessions ? new TypeError("Connector sessions response contains invalid connection metadata") : null)} />
//     {!manage && <Card><p className="text-sm text-ink-2">A Tenant Admin can connect ServiceNow here.</p></Card>}
//     {manage && <button className="btn-ghost mb-5" data-testid="connector-admin-setup" onClick={() => setAdmin(true)}><Settings2 size={15} />Connector admin setup</button>}
//     {sessions.length > 0 && <div className="mb-5"><label className="label" htmlFor="connector-session-select">Connector connections</label><select id="connector-session-select" className="input max-w-md" value={id ?? ''} onChange={event => { setSelectedAgent(null); setParams(event.target.value ? { connection: event.target.value } : {}); }}><option value="">Select a connector connection</option>{sessions.map(session => <option key={session.id} value={session.id}>{session.name}</option>)}</select></div>}
//     {id && data && !selected && <ErrorNote error={new Error('Connector session not found. Manual connections are managed separately. Start a new connector connection.')} />}
//     {selected && !selected.authorized && <Card title="Complete ServiceNow sign-in"><p className="mb-3 text-sm text-ink-2">Continue to ServiceNow to log in and allow access.</p><a className="btn-primary" data-testid="connector-resume-login" href={`/api/v1/connector/servicenow/sessions/${encodeURIComponent(selected.id)}/authorize`}>Continue to ServiceNow</a></Card>}
//     {selected?.authorized && <><ConnectorAgentSelection key={selected.id} connectionId={selected.id} onReady={setReadyConnection} onSelected={agentId => setSelectedAgent(agentId)} />{selectedAgent && <p role="status" className="my-3 text-sm text-royal">Agent selected. Complete approval and verify its route below.</p>}{readyConnection === selected.id && <div className="mt-5"><ServiceNowConnectorRouting key={`${selected.id}:${selectedAgent ?? "initial"}`} connectionId={selected.id} /></div>}</>}
//     {adding && <Modal title="Connect ServiceNow" onClose={() => setAdding(false)}><ConnectorLogin /></Modal>}
//     {admin && <Modal title="One-time connector admin setup" onClose={() => setAdmin(false)}><ConnectorAdminSetup onSaved={() => { setAdmin(false); void reload(); }} /></Modal>}
//   </>;
// }

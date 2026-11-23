// Connector feature disabled at user request. Original code is preserved below.
// import { useEffect, useState, type FormEvent } from 'react';
// import { api } from '../lib/api';
// import { Card, ErrorNote } from './ui';
// import { CopyCode } from './CopyCode';
//
// export function ConnectorLogin() {
//   const [instance, setInstance] = useState('');
//   const [error, setError] = useState<Error | null>(null);
//   const [busy, setBusy] = useState(false);
//   const connect = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
//     event.preventDefault(); setBusy(true); setError(null);
//     try {
//       const result = await api<{ authorize_url: string }>('/connector/servicenow/start', { method: 'POST', body: { instance_url: instance } });
//       if (typeof result.authorize_url !== 'string' || !/^\/api\/v1\/connector\/servicenow\/sessions\/[a-zA-Z0-9_]+\/authorize$/.test(result.authorize_url)) throw new TypeError('Connector did not return a valid ServiceNow authorization URL');
//       window.location.assign(result.authorize_url);
//     } catch (failure) { setError(failure as Error); setBusy(false); }
//   };
//   return <form onSubmit={event => void connect(event)} className="space-y-4" data-testid="connector-login-form">
//     <p className="text-sm text-ink-2">Continue to ServiceNow to enter your password and allow access. Signet does not collect your ServiceNow password.</p>
//     <div><label className="label" htmlFor="connector-instance-url">ServiceNow URL</label><input className="input" id="connector-instance-url" type="url" required placeholder="https://your-instance.service-now.com" value={instance} onChange={event => setInstance(event.target.value)} /></div>
//     <ErrorNote error={error} /><button className="btn-primary" data-testid="connector-login-continue" disabled={busy}>{busy ? 'Opening ServiceNow…' : 'Continue to ServiceNow'}</button>
//   </form>;
// }
//
// /** Registers the OAuth application once; this form never creates a manual connection. */
// export function ConnectorAdminSetup({ onSaved }: { onSaved: () => void }) {
//   const [draft, setDraft] = useState({ instance_url: '', gateway_url: window.location.protocol === 'https:' ? window.location.origin : '', mcp_url: '', client_id: '', client_secret: '' });
//   const [busy, setBusy] = useState(false);
//   const [error, setError] = useState<Error | null>(null);
//   const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
//     event.preventDefault(); setBusy(true); setError(null);
//     try { await api('/connector/servicenow/apps', { method: 'PUT', body: { ...draft, name: 'ServiceNow connector application' } }); onSaved(); }
//     catch (failure) { setError(failure as Error); }
//     finally { setBusy(false); }
//   };
//   const fields: { key: keyof typeof draft; label: string; type: string }[] = [
//     { key: 'instance_url', label: 'ServiceNow instance URL', type: 'url' }, { key: 'gateway_url', label: 'Public Signet URL', type: 'url' },
//     { key: 'mcp_url', label: 'ServiceNow MCP server URL', type: 'url' }, { key: 'client_id', label: 'OAuth application client ID', type: 'text' }, { key: 'client_secret', label: 'OAuth application secret', type: 'password' },
//   ];
//   return <form onSubmit={event => void save(event)} className="space-y-4" data-testid="connector-admin-form">
//     <p className="text-sm text-ink-2">An administrator registers the OAuth app for each ServiceNow instance once. Users then connect with only their instance URL and ServiceNow sign-in. These settings are independent of manual connections.</p>
//     {fields.map(field => <div key={field.key}><label className="label" htmlFor={`connector-app-${field.key}`}>{field.label}</label><input id={`connector-app-${field.key}`} className="input" type={field.type} required={field.key !== 'client_secret'} autoComplete={field.key === 'client_secret' ? 'new-password' : 'off'} value={draft[field.key]} onChange={event => setDraft({ ...draft, [field.key]: event.target.value })} />{field.key === 'client_secret' && <p className="mt-1 text-xs text-ink-3">Required initially. Leave blank to keep the registered secret when updating.</p>}</div>)}
//     <div><label className="label">Register this redirect URL in ServiceNow with authorization-code grant and PKCE S256</label><CopyCode testId="connector-app-callback" text={`${draft.gateway_url.replace(/\/+$/, '')}/api/v1/plugins/servicenow/callback`} /></div>
//     <ErrorNote error={error} /><button className="btn-primary" data-testid="connector-app-save" disabled={busy}>{busy ? 'Saving…' : 'Save connector application'}</button>
//   </form>;
// }
//
// interface Discovery {
//   tools: { name: string; title: string; description: string }[];
//   agents: { id: string; name: string; description: string }[];
//   linked: { agent_id: string; external_id: string }[];
//   route: { alias: string; url: string };
// }
//
// function validateDiscovery(result: Discovery): Discovery {
//   if (!result || !Array.isArray(result.agents) || !Array.isArray(result.tools) || !Array.isArray(result.linked) || typeof result.route?.url !== 'string') throw new TypeError('Connector discovery must return agents, tools, linked identities and a prepared route');
//   for (const agent of result.agents) if (typeof agent.id !== 'string' || typeof agent.name !== 'string' || typeof agent.description !== 'string') throw new TypeError('ServiceNow discovery returned invalid agent metadata');
//   for (const tool of result.tools) if (typeof tool.name !== 'string' || typeof tool.title !== 'string') throw new TypeError('ServiceNow discovery returned invalid tool metadata');
//   return result;
// }
//
// /** Automatically discovers authorized agents/tools; selection has no manual identity fields. */
// export function ConnectorAgentSelection({ connectionId, onSelected, onReady }: { connectionId: string; onSelected: (id: string) => void; onReady: (id: string) => void }) {
//   const path = `/connector/servicenow/sessions/${encodeURIComponent(connectionId)}`;
//   const [data, setData] = useState<Discovery | null>(null);
//   const [error, setError] = useState<Error | null>(null);
//   const [busy, setBusy] = useState(false);
//   const [attempt, setAttempt] = useState(0);
//   useEffect(() => {
//     let active = true;
//     setData(null); setError(null);
//     void api<Discovery>(path + '/discover', { method: 'POST', body: {} }).then(result => { const parsed = validateDiscovery(result); if (active) { setData(parsed); onReady(connectionId); } }).catch((failure: Error) => { if (active) setError(failure); });
//     return () => { active = false; };
//   }, [path, attempt, connectionId, onReady]);
//   const select = async (externalId: string): Promise<void> => {
//     setBusy(true); setError(null);
//     try {
//       const result = await api<{ agent_id: string }>(path + '/agents', { method: 'POST', body: { external_id: externalId } });
//       if (typeof result.agent_id !== 'string') throw new TypeError('Connector selection did not return a registered agent ID');
//       setData(current => current ? { ...current, linked: [...current.linked, { external_id: externalId, agent_id: result.agent_id }] } : null);
//       onSelected(result.agent_id);
//     } catch (failure) { setError(failure as Error); }
//     finally { setBusy(false); }
//   };
//   return <Card title="Discover and select agents"><ErrorNote error={error} />
//     {!data && !error && <p role="status" className="text-sm text-ink-2">Discovering ServiceNow agents and MCP tools, and preparing the Signet route…</p>}
//     {error && <button className="btn-ghost mt-3" data-testid="connector-discovery-retry" onClick={() => setAttempt(value => value + 1)}>Retry discovery</button>}
//     {data && <><p className="mb-4 text-sm text-ink-2">{data.agents.length} agents · {data.tools.length} tools discovered. Select an agent to register it for approval.</p><div className="space-y-3">{data.agents.map(agent => <div key={agent.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line p-3"><div className="min-w-0 flex-1"><h3 className="text-sm font-semibold">{agent.name}</h3><p className="mt-1 line-clamp-2 text-xs text-ink-2">{agent.description}</p></div><button className="btn-primary" data-testid={`connector-select-agent-${agent.id}`} disabled={busy || data.linked.some(link => link.external_id === agent.id)} onClick={() => void select(agent.id)}>{data.linked.some(link => link.external_id === agent.id) ? 'Selected' : 'Select agent'}</button></div>)}</div>{!data.agents.length && <p className="text-sm text-ink-2">ServiceNow returned no active agents for this user's access permissions.</p>}<details className="mt-4"><summary className="cursor-pointer text-sm">Discovered tools</summary><ul className="mt-2 space-y-1 text-xs">{data.tools.map(tool => <li key={tool.name}>{tool.title} · {tool.name}</li>)}</ul></details></>}
//   </Card>;
// }

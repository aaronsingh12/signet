// Connector feature disabled at user request. Original code is preserved below.
// import { db, tx } from './db';
// import { PolicyError } from './errors';
// import { tenant } from './tenant';
// import type { Principal } from './rbac';
// import { putSecret, revealPlatformCredential, rotateSecret } from './secrets';
// import { createServiceNowSettings, validatedSettings, type ServiceNowSettingsInput } from './servicenow-mcp-settings';
// import { serviceNowConnection } from './servicenow-mcp';
// import { availableServiceNowAgents, linkedServiceNowAgents, linkServiceNowAgent } from './servicenow-agents';
// import { discoverServiceNowTools } from './servicenow-mcp-discovery';
// import { prepareServiceNowGateway, serviceNowGatewayRoute } from './servicenow-gateway';
//
// interface ConnectorApp { instance_url: string; gateway_url: string; mcp_url: string; client_id: string; secret_id: string }
//
// function instanceOrigin(value: string): string {
//   if (typeof value !== 'string') throw new PolicyError('SERVICENOW_CONNECTOR', 'ServiceNow instance URL is required', 400);
//   let url: URL;
//   try { url = new URL(value.trim()); } catch { throw new PolicyError('SERVICENOW_CONNECTOR', 'Enter a valid HTTPS ServiceNow instance URL', 400); }
//   if (url.protocol !== 'https:' || !url.hostname.endsWith('.service-now.com') || url.port || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new PolicyError('SERVICENOW_CONNECTOR', 'Instance URL must be an HTTPS service-now.com origin without a path, port or credentials', 400);
//   return url.origin;
// }
//
// /** One-time application registration is independent of manual connections and delegated user sessions. */
// export async function saveConnectorApp(input: ServiceNowSettingsInput, actor: Principal): Promise<{ instance_url: string }> {
//   const urls = validatedSettings(input);
//   return tx(async () => {
//     const existing = await db.prepare('SELECT secret_id FROM servicenow_connector_app WHERE tenant_id = ? AND instance_url = ?').get(tenant.id, urls.instance.origin) as { secret_id: string } | undefined;
//     if (!existing && !input.client_secret) throw new PolicyError('SERVICENOW_CONNECTOR', 'OAuth client secret is required for the initial admin registration', 400);
//     const secret = existing ? input.client_secret ? await rotateSecret(existing.secret_id, input.client_secret, actor) : { id: existing.secret_id }
//       : await putSecret({ name: `sn-connector-app-${Date.now().toString(36)}`, kind: 'platform', value: input.client_secret }, actor);
//     await db.prepare('INSERT INTO servicenow_connector_app (tenant_id, instance_url, gateway_url, mcp_url, client_id, secret_id) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, instance_url) DO UPDATE SET gateway_url = excluded.gateway_url, mcp_url = excluded.mcp_url, client_id = excluded.client_id, secret_id = excluded.secret_id')
//       .run(tenant.id, urls.instance.origin, urls.gateway.origin, urls.endpoint.href, input.client_id.trim(), secret.id);
//     return { instance_url: urls.instance.origin };
//   });
// }
//
// export async function connectorApps(): Promise<{ instance_url: string; callback_url: string }[]> {
//   const apps = await db.prepare('SELECT instance_url, gateway_url FROM servicenow_connector_app WHERE tenant_id = ? ORDER BY instance_url').all(tenant.id) as { instance_url: string; gateway_url: string }[];
//   return apps.map(app => ({ instance_url: app.instance_url, callback_url: `${app.gateway_url}/api/v1/plugins/servicenow/callback` }));
// }
//
// /** Creates a fresh delegated connector session from a registered instance, never from a manual account. */
// export async function startConnector(instanceUrl: string, actor: Principal): Promise<{ connection_id: string; authorize_url: string }> {
//   const origin = instanceOrigin(instanceUrl);
//   const app = await db.prepare('SELECT instance_url, gateway_url, mcp_url, client_id, secret_id FROM servicenow_connector_app WHERE tenant_id = ? AND instance_url = ?').get(tenant.id, origin) as ConnectorApp | undefined;
//   if (!app) throw new PolicyError('SERVICENOW_CONNECTOR_APP_REQUIRED', `No connector OAuth application is registered for ${origin}. Ask an administrator to complete Connector admin setup once. Manual connections are not reused.`, 409);
//   const clientSecret = await revealPlatformCredential(app.secret_id);
//   return tx(async () => {
//     const settings = await createServiceNowSettings({ name: `ServiceNow · ${new URL(origin).hostname}`, gateway_url: app.gateway_url, instance_url: origin, mcp_url: app.mcp_url, client_id: app.client_id, client_secret: clientSecret }, actor);
//     await db.prepare('INSERT INTO servicenow_connector_session (connection_id, tenant_id) VALUES (?, ?)').run(settings.id, tenant.id);
//     return { connection_id: settings.id, authorize_url: `/api/v1/connector/servicenow/sessions/${encodeURIComponent(settings.id)}/authorize` };
//   });
// }
//
// export async function requireConnectorSession(id: string): Promise<void> {
//   const session = await db.prepare('SELECT connection_id FROM servicenow_connector_session WHERE tenant_id = ? AND connection_id = ?').get(tenant.id, id);
//   if (!session) throw new PolicyError('SERVICENOW_CONNECTOR_SESSION', 'Connector session not found. Start from Connect ServiceNow; manual connections cannot be opened in this flow.', 404);
// }
//
// export async function connectorSessions(): Promise<Awaited<ReturnType<typeof serviceNowConnection>>[]> {
//   const rows = await db.prepare('SELECT connection_id FROM servicenow_connector_session WHERE tenant_id = ?').all(tenant.id) as { connection_id: string }[];
//   return Promise.all(rows.map(row => serviceNowConnection(row.connection_id)));
// }
//
// /** Read-only discovery and route registration do not grant agent approval or prove routed traffic. */
// export async function discoverConnector(id: string, actor: Principal): Promise<{ tools: Awaited<ReturnType<typeof discoverServiceNowTools>>; agents: Awaited<ReturnType<typeof availableServiceNowAgents>>; route: { alias: string; url: string }; linked: Awaited<ReturnType<typeof linkedServiceNowAgents>> }> {
//   await requireConnectorSession(id);
//   const [tools, agents] = await Promise.all([discoverServiceNowTools(id), availableServiceNowAgents(id)]);
//   const existingRoute = await serviceNowGatewayRoute(id);
//   const route = await prepareServiceNowGateway(id, existingRoute?.alias ?? `sn-connector-${id.slice(-12).toLowerCase()}`, actor);
//   return { tools, agents, route, linked: await linkedServiceNowAgents(id) };
// }
//
// /** Only an agent returned by the user's ServiceNow ACLs can be selected; no free-text identity intake. */
// export async function selectConnectorAgent(id: string, externalId: string, actor: Principal): Promise<{ agent_id: string }> {
//   await requireConnectorSession(id);
//   if (typeof externalId !== 'string' || !/^[a-f0-9]{32}$/i.test(externalId)) throw new PolicyError('SERVICENOW_CONNECTOR_AGENT', 'Select a valid agent returned by ServiceNow discovery', 400);
//   const available = await availableServiceNowAgents(id);
//   const selected = available.find(agent => agent.id === externalId);
//   if (!selected) throw new PolicyError('SERVICENOW_CONNECTOR_AGENT', 'Selected agent was not returned by ServiceNow discovery for the authorized user', 400);
//   return linkServiceNowAgent(id, { external_id: selected.id, name: selected.name, purpose: `Govern MCP tool calls for ServiceNow agent ${selected.name}` }, actor);
// }

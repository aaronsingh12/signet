// Connector feature disabled at user request. Original code is preserved below.
// import { strict as assert } from 'node:assert';
// import { spawn, type ChildProcess } from 'node:child_process';
// import { mkdtempSync } from 'node:fs';
// import { createServer } from 'node:http';
// import { tmpdir } from 'node:os';
// import { join, resolve } from 'node:path';
// import { setTimeout } from 'node:timers/promises';
// import { after, test } from 'node:test';
// import type { Principal } from '../src/rbac';
// import { dropTestDatabase } from './database';
//
// process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-sn-connector-'));
// process.env.MONGODB_DATABASE = 'test_sn_connector_' + Date.now().toString(36);
// process.env.SIGNET_TOOL_PRIVATE_DESTINATIONS = 'allow';
// process.env.SIGNET_DET_RUNTIME = 'off';
// after(dropTestDatabase);
//
// async function port(): Promise<number> {
//   const socket = createServer();
//   await new Promise<void>(done => socket.listen(0, '127.0.0.1', done));
//   const address = socket.address();
//   assert(address && typeof address === 'object');
//   await new Promise<void>((done, reject) => socket.close(error => error ? reject(error) : done()));
//   return address.port;
// }
//
// /** Exercise the real control API, OAuth identity, gateway and an isolated HTTP MCP upstream. */
// test('ServiceNow connector routes allowed calls, blocks a disallowed argument before forwarding and verifies only its own route', { timeout: 180000 }, async context => {
//   const { db } = await import('../src/db');
//   const { permissionsFor } = await import('../src/rbac');
//   const { createServiceNowSettings } = await import('../src/servicenow-mcp-settings');
//   const { saveServiceNowAuthorization } = await import('../src/servicenow-mcp');
//   const { linkServiceNowAgent } = await import('../src/servicenow-agents');
//   const { prepareServiceNowGateway } = await import('../src/servicenow-gateway');
//   const { serviceNowRouting } = await import('../src/servicenow-connector');
//   const { saveConnectorApp, startConnector, requireConnectorSession, connectorSessions, connectorApps } = await import('../src/servicenow-connector-onboarding');
//   const { listServiceNowConnections } = await import('../src/servicenow-mcp');
//   const { serviceNowConfiguration } = await import('../src/servicenow-mcp-settings');
//   const { signSeal } = await import('../src/registry');
//   const { createClient, exchangeClientCredentials } = await import('../src/identity');
//   const actor: Principal = { id: 'connector-admin@example.test', name: 'Connector admin', kind: 'human', roles: ['tenant_admin', 'platform_admin', 'agent_owner'], permissions: permissionsFor(['tenant_admin', 'platform_admin', 'agent_owner']), groups: [], mfa: true, auth: 'session', auth_time: null };
//   const application = { name: 'Connector HTTP contract', gateway_url: 'https://signet.example.test', instance_url: 'https://techsnitchpvtltddemo2.service-now.com', mcp_url: 'https://techsnitchpvtltddemo2.service-now.com/sncapps/mcp-server/mcp/connector-contract', client_id: 'connector-client', client_secret: 'connector-contract-secret' };
//   const manual = await createServiceNowSettings(application, actor);
//   await assert.rejects(startConnector(application.instance_url, actor), /No connector OAuth application/);
//   await assert.rejects(requireConnectorSession(manual.id), /manual connections cannot be opened/);
//   await saveConnectorApp(application, actor);
//   assert.equal((await connectorApps()).length, 1);
//   assert(!JSON.stringify(await connectorApps()).includes(application.client_secret));
//   assert.equal((await listServiceNowConnections()).length, 1, 'application registration must not create a manual connection');
//   const started = await startConnector(application.instance_url, actor);
//   assert.match(started.authorize_url, /^\/api\/v1\/connector\/servicenow\/sessions\/.+\/authorize$/);
//   const settings = { id: started.connection_id };
//   assert.notEqual(settings.id, manual.id);
//   assert.equal((await listServiceNowConnections()).length, 1, 'connector sessions must not enter manual connection lists');
//   assert.equal((await connectorSessions()).length, 1);
//   assert.equal((await serviceNowConfiguration(settings.id)).clientSecret, application.client_secret);
//   await requireConnectorSession(settings.id);
//   await assert.rejects(startConnector('https://unregistered.service-now.com', actor), /No connector OAuth application/);
//   await assert.rejects(startConnector('http://127.0.0.1', actor), /HTTPS service-now.com origin/);
//   const agent = await linkServiceNowAgent(settings.id, { external_id: '1234567890abcdef1234567890abcdef', name: 'Connector contract agent', purpose: 'Verify governed ServiceNow MCP routing with real HTTP calls' }, actor);
//   assert.equal((await serviceNowRouting(settings.id)).route, null);
//   await saveServiceNowAuthorization(settings.id, JSON.stringify({ access_token: 'isolated-upstream-token', refresh_token: 'isolated-refresh-token' }), Date.now() + 600000, actor);
//   await db.prepare('UPDATE servicenow_mcp_account SET tools_json = ? WHERE id = ?').run(JSON.stringify([{ name: 'read_record', title: 'Read record', description: 'Read an incident record' }]), settings.id);
//   const route = await prepareServiceNowGateway(settings.id, 'sn-connector-contract', actor);
//   assert.equal((await serviceNowRouting(settings.id)).agents[0]!.routing_verified, false);
//   let forwarded = 0;
//   const upstream = createServer((req, res) => {
//     let body = '';
//     req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
//     req.on('end', () => {
//       assert.equal(req.headers.authorization, 'Bearer isolated-upstream-token');
//       const message = JSON.parse(body) as { id: number; params: { name: string; arguments: { number: string } } };
//       assert.equal(message.params.name, 'read_record');
//       assert.equal(message.params.arguments.number, 'INC001');
//       forwarded++;
//       res.setHeader('content-type', 'application/json');
//       res.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: 'Read-only incident response' }] } }));
//     });
//   });
//   await new Promise<void>(done => upstream.listen(0, '127.0.0.1', done));
//   const address = upstream.address();
//   assert(address && typeof address === 'object');
//   context.after(() => new Promise<void>((done, reject) => upstream.close(error => error ? reject(error) : done())));
//   // Only the isolated test database replaces the vendor endpoint with this local contract service.
//   await db.prepare('UPDATE tool SET url = ? WHERE alias = ?').run(`http://127.0.0.1:${address.port}/mcp`, route.alias);
//   const seal = await signSeal(agent.agent_id, {
//     models: [], tools: [{ server: `mcp://${route.alias}`, actions: [{ name: 'read_record', impact: 'read', constraints: { number: { pattern: '^INC[0-9]+$' } } }], data_scopes: [] }],
//     limits: { rpm: 100, tokens_per_day: 10000, usd_per_day: 5 }, environments: ['dev'],
//   }, { approvers: [{ user: 'reviewer@example.test', at: new Date().toISOString() }], evidence_refs: {}, regulatory_category: 'test', minor: false, actor: 'reviewer@example.test' });
//   const client = await createClient(agent.agent_id, actor, 'ServiceNow MCP contract', 'dev');
//   const credential = await exchangeClientCredentials(client.client_id, client.client_secret);
//   assert.equal((await serviceNowRouting(settings.id)).agents[0]!.routing_verified, false, 'approval and credentials do not prove routing');
//   const controlPort = await port(); const gatewayPort = await port();
//   const control = `http://127.0.0.1:${controlPort}`; const gateway = `http://127.0.0.1:${gatewayPort}`;
//   const children: ChildProcess[] = [];
//   let logs = '';
//   context.after(async () => { await Promise.all(children.map(async child => { if (child.exitCode !== null || child.signalCode !== null) return; await new Promise<void>(done => { child.once('exit', done); child.kill(); }); })); });
//   const env = { ...process.env, PORT: undefined, SIGNET_ADMIN_ID: 'connector-admin@example.test', SIGNET_ADMIN_PASSWORD: 'connector-contract-password', SIGNET_CONTROL_PORT: String(controlPort), SIGNET_GATEWAY_PORT: String(gatewayPort), SIGNET_CONTROL_URL: control, SIGNET_PUBLIC_URL: control, SIGNET_NODE_ID: 'connector-contract', SIGNET_POLICY_ENGINE: 'typescript', SIGNET_ENV: 'dev' };
//   const start = async (entry: string, origin: string): Promise<void> => {
//     const child = spawn(process.execPath, ['--max-old-space-size=256', '--import', 'tsx', resolve(entry)], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
//     children.push(child);
//     child.stdout?.on('data', (chunk: Buffer) => { logs = (logs + chunk.toString()).slice(-12000); });
//     child.stderr?.on('data', (chunk: Buffer) => { logs = (logs + chunk.toString()).slice(-12000); });
//     for (let attempt = 0; attempt < 240; attempt++) {
//       assert.equal(child.exitCode, null, logs);
//       try { if ((await fetch(origin + '/healthz', { signal: AbortSignal.timeout(1000) })).ok) return; }
//       catch (error) { if (!(error instanceof TypeError) && !(error instanceof Error && error.name === 'TimeoutError')) throw error; }
//       await setTimeout(250);
//     }
//     throw new Error(`Connector test service did not start: ${origin}\n${logs}`);
//   };
//   await start('apps/control/src/index.ts', control); await start('apps/gateway/src/index.ts', gateway);
//   const login = await fetch(control + '/api/v1/auth/local-login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: env.SIGNET_ADMIN_ID, password: env.SIGNET_ADMIN_PASSWORD }) });
//   assert.equal(login.status, 200, logs);
//   const cookie = login.headers.get('set-cookie')!.split(';')[0]!;
//   const headers = { cookie, 'content-type': 'application/json' };
//   assert.equal((await fetch(control + '/api/v1/connector/servicenow/sessions')).status, 401);
//   const listed = await fetch(control + '/api/v1/connector/servicenow/sessions', { headers });
//   assert.equal(listed.status, 200);
//   assert.deepEqual((await listed.json() as { items: { id: string }[] }).items.map(item => item.id), [settings.id]);
//   const manualList = await fetch(control + '/api/v1/plugins/servicenow', { headers });
//   assert.deepEqual((await manualList.json() as { items: { id: string }[] }).items.map(item => item.id), [manual.id]);
//   const missingApp = await fetch(control + '/api/v1/connector/servicenow/start', { method: 'POST', headers, body: JSON.stringify({ instance_url: 'https://not-registered.service-now.com' }) });
//   assert.equal(missingApp.status, 409);
//   assert.equal((await fetch(`${control}/api/v1/connector/servicenow/sessions/${manual.id}/authorize`, { headers, redirect: 'manual' })).status, 404);
//   const authorize = await fetch(`${control}/api/v1/connector/servicenow/sessions/${settings.id}/authorize`, { headers, redirect: 'manual' });
//   assert.equal(authorize.status, 302);
//   const consent = new URL(authorize.headers.get('location')!);
//   assert.equal(consent.origin, application.instance_url);
//   assert.equal(consent.pathname, '/oauth_auth.do');
//   assert.equal(consent.searchParams.get('code_challenge_method'), 'S256');
//   assert(!consent.href.includes(application.client_secret));
//   assert.equal((await fetch(`${control}/api/v1/connector/servicenow/sessions/${manual.id}/discover`, { method: 'POST', headers, body: '{}' })).status, 404);
//   assert.equal((await fetch(`${control}/api/v1/connector/servicenow/sessions/${manual.id}/agents`, { method: 'POST', headers, body: JSON.stringify({ external_id: '1234567890abcdef1234567890abcdef' }) })).status, 404);
//   const call = async (number: string): Promise<{ result: { isError?: boolean; content: { text: string }[] } }> => {
//     const response = await fetch(`${gateway}/v1/mcp/${route.alias}`, { method: 'POST', headers: { authorization: `Bearer ${credential.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_record', arguments: { number } } }) });
//     assert.equal(response.status, 200, logs);
//     return response.json() as Promise<{ result: { isError?: boolean; content: { text: string }[] } }>;
//   };
//   assert.equal((await call('INC001')).result.isError, undefined);
//   assert.equal(forwarded, 1);
//   assert.equal((await serviceNowRouting(settings.id)).agents[0]!.routing_verified, true);
//   const denied = await call('INVALID');
//   assert.equal(denied.result.isError, true);
//   assert.match(denied.result.content[0]!.text, /blocked by Signet/i);
//   assert.equal(forwarded, 1, 'Denied arguments must never reach the upstream MCP server');
//   assert((await serviceNowRouting(settings.id)).agents[0]!.last_block_at);
//   await db.prepare('UPDATE servicenow_gateway_route SET alias = ? WHERE connection_id = ?').run('different-route', settings.id);
//   assert.equal((await serviceNowRouting(settings.id)).agents[0]!.routing_verified, false, 'another alias must never verify this connector');
//   await db.prepare('UPDATE servicenow_gateway_route SET alias = ? WHERE connection_id = ?').run(route.alias, settings.id);
//   await db.prepare('UPDATE agent_instance SET revoked_at = ? WHERE agent_id = ?').run(new Date().toISOString(), agent.agent_id);
//   assert.equal((await serviceNowRouting(settings.id)).agents[0]!.routing_verified, false, 'revoked runtime identity must not remain verified');
//   assert(seal.certificate.cert_id);
// });

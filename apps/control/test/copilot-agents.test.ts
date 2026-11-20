import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';

// Copilot Studio onboarding against a local stand-in for Microsoft sign-in and the Dataverse Web API.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-copilot-'));
process.env.MONGODB_DATABASE = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);

const BOT = '6d1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b';
const OTHER = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';
const ENV_HOST = 'contoso.crm8.dynamics.com';
const fakeState = { signInFails: false, listForbidden: false };
const bots = [
  { botid: BOT.toUpperCase(), name: 'Signet Test Agent', statecode: 0, schemaname: 'cr123_signetTestAgent' },
  { botid: OTHER, name: 'Old helper', statecode: 1, schemaname: 'cr123_oldHelper' },
];

const fake = createServer((req, res) => {
  const [, host, ...rest] = req.url!.split('/');
  const url = new URL(`https://${host}/${rest.join('/')}`);
  const json = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (host === 'login.microsoftonline.com') return fakeState.signInFails ? json(401, { error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret provided' }) : json(200, { access_token: 'dataverse-token' });
  if (host === ENV_HOST) {
    assert.equal(req.headers.authorization, 'Bearer dataverse-token');
    const p = decodeURIComponent(url.pathname);
    if (p === '/api/data/v9.2/WhoAmI') return json(200, { OrganizationId: 'org-contoso' });
    if (p === '/api/data/v9.2/bots') return fakeState.listForbidden ? json(403, { error: { message: 'Principal user is missing prvReadbot privilege' } }) : json(200, { value: bots });
    const one = p.match(/^\/api\/data\/v9\.2\/bots\(([^)]+)\)$/);
    if (one) {
      const bot = bots.find((b) => b.botid.toLowerCase() === one[1]!.toLowerCase());
      return bot ? json(200, bot) : json(404, { error: { message: 'bot With Id = ' + one[1] + ' Does Not Exist' } });
    }
  }
  json(404, { error: { message: `unexpected ${req.method} ${host}${url.pathname}` } });
});
await new Promise<void>((resolve) => fake.listen(0, '127.0.0.1', resolve));
process.env.SIGNET_PLATFORM_API_OVERRIDE = `http://127.0.0.1:${(fake.address() as { port: number }).port}`;

after(async () => {
  fake.close();
  await dropTestDatabase();
});

const { permissionsFor } = await import('../src/rbac');
const copilot = await import('../src/copilot-agents');
const platforms = await import('../src/platforms');
const { getAgent } = await import('../src/registry');
const { db } = await import('../src/db');
const admin: Principal = { id: 'copilot-admin@example.test', name: 'Admin', kind: 'human', roles: ['tenant_admin', 'platform_admin', 'agent_owner'], permissions: permissionsFor(['tenant_admin', 'platform_admin', 'agent_owner']), groups: [], mfa: true, auth: 'session', auth_time: null };
const credentials = { tenant_id: 'tenant-1', client_id: 'client-1', client_secret: 'copilot-client-secret', environment_url: `https://${ENV_HOST}/` };

test('Copilot Studio agents: connect, list, link once, and report coverage from evidence', async () => {
  fakeState.signInFails = true;
  await assert.rejects(copilot.createCopilotConnection({ ...credentials, label: 'Bad secret' }, admin), /Invalid client secret/, 'the sign-in is proved before anything is stored');
  fakeState.signInFails = false;
  assert.deepEqual(await copilot.listCopilotConnections(), []);

  const connection = await copilot.createCopilotConnection({ ...credentials, label: 'Copilot Studio – Test' }, admin);
  assert.equal(connection.environment_url, `https://${ENV_HOST}`);
  assert.equal(connection.status, 'connected');
  assert.equal(connection.linked_agents, 0);
  assert.equal((await copilot.listCopilotConnections()).length, 1);
  const stored = await db.prepare('SELECT scope, status_detail FROM platform_connection WHERE id = ?').get(connection.id) as { scope: string; status_detail: string };
  assert.ok(!JSON.stringify(stored).includes(credentials.client_secret), 'the client secret is never kept in the connection row');

  const available = await copilot.availableCopilotAgents(connection.id);
  assert.deepEqual(available.map((bot) => [bot.id, bot.name, bot.active]), [[BOT, 'Signet Test Agent', true], [OTHER, 'Old helper', false]]);

  const input = { bot_id: BOT.toUpperCase(), name: 'Signet Test Agent', purpose: 'Answers employee questions in Microsoft Teams' };
  await assert.rejects(copilot.linkCopilotAgent(connection.id, input, { ...admin, permissions: [] }), /agents.write/);
  await assert.rejects(copilot.linkCopilotAgent(connection.id, { ...input, bot_id: 'not-a-guid' }, admin), /GUID/);
  await assert.rejects(copilot.linkCopilotAgent(connection.id, { ...input, purpose: 'short' }, admin), /10–4000/);
  await assert.rejects(copilot.linkCopilotAgent(connection.id, { ...input, bot_id: '00000000-0000-4000-8000-000000000000' }, admin), /No Copilot Studio agent/);

  const linked = await copilot.linkCopilotAgent(connection.id, input, admin);
  assert.equal((await copilot.linkCopilotAgent(connection.id, { ...input, bot_id: BOT }, admin)).agent_id, linked.agent_id, 'linking again reuses the identity');
  const agent = await getAgent(linked.agent_id);
  assert.equal(agent.kind, 'third_party');
  assert.equal(agent.vendor, copilot.COPILOT_VENDOR);
  assert.equal(agent.connection_method, 'oauth');
  assert.deepEqual(JSON.parse(String((await db.prepare('SELECT vendor_details FROM agent WHERE id = ?').get(agent.id) as { vendor_details: string }).vendor_details)),
    { environment_url: `https://${ENV_HOST}`, bot_id: BOT, schema_name: 'cr123_signetTestAgent' });

  const rows = await copilot.linkedCopilotAgents(connection.id);
  assert.deepEqual(rows.map((row) => [row.agent_id, row.bot_id, row.gateway_enforcement]), [[linked.agent_id, BOT, false]], 'a link alone never claims gateway enforcement');
  assert.equal((await copilot.copilotConnection(connection.id)).linked_agents, 1);
  const workload = (await platforms.workloads(connection.id)).find((w) => w.id === `copilot:${BOT}`)!;
  assert.equal(workload.registered_agent_id, linked.agent_id, 'platform scans treat the linked agent as registered, not as a new finding');
  const ledgerRows = await db.prepare("SELECT data FROM ledger_record WHERE agent_id = ? AND kind = 'lifecycle'").all(linked.agent_id) as { data: string }[];
  assert.equal(ledgerRows.filter((row) => JSON.parse(row.data).event === 'copilot.agent_linked').length, 1);

  // A second connection to the same environment links the same Copilot agent to the same Signet identity.
  const second = await copilot.createCopilotConnection({ ...credentials, label: 'Same environment' }, admin);
  assert.equal((await copilot.linkCopilotAgent(second.id, input, admin)).agent_id, linked.agent_id);
});

test('Copilot Studio connection test and permission errors are explained', async () => {
  const connection = await copilot.createCopilotConnection({ ...credentials, label: 'Checks' }, admin);
  fakeState.listForbidden = true;
  await assert.rejects(copilot.availableCopilotAgents(connection.id), (error: Error & { rule?: string }) => error.rule === 'COPILOT_PERMISSIONS' && /application user/.test(error.message));
  fakeState.listForbidden = false;

  fakeState.signInFails = true;
  const failed = await copilot.testCopilotConnection(connection.id, admin);
  assert.equal(failed.status, 'error');
  assert.match(failed.status_detail ?? '', /Invalid client secret/);
  fakeState.signInFails = false;
  assert.equal((await copilot.testCopilotConnection(connection.id, admin)).status, 'connected');

  await copilot.removeCopilotConnection(connection.id, admin);
  assert.ok(!(await copilot.listCopilotConnections()).some((item) => item.id === connection.id));
  await assert.rejects(copilot.availableCopilotAgents(connection.id), /not found/i);
});

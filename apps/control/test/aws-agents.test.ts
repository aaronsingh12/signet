import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';
import type { Principal } from '../src/rbac';

// Amazon Bedrock onboarding against local stand-ins for AWS STS, AgentCore control, Bedrock Agents and Lambda.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-aws-'));
process.env.MONGODB_DATABASE = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);

const fakeState = { signInFails: false, classicForbidden: false, agentCoreForbidden: false };

const fake = createServer((req, res) => {
  const [, host, ...rest] = req.url!.split('/');
  const p = decodeURIComponent('/' + rest.join('/').split('?')[0]);
  const json = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (host === 'sts.amazonaws.com') {
    if (fakeState.signInFails) return res.writeHead(403, { 'content-type': 'text/xml' }).end('<ErrorResponse><Error><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>');
    return res.writeHead(200, { 'content-type': 'text/xml' }).end('<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::111122223333:user/signet-reader</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>');
  }
  if (host === 'bedrock-agentcore-control.us-east-1.amazonaws.com') {
    assert.match(String(req.headers.authorization), /\/us-east-1\/bedrock-agentcore\/aws4_request/, 'AgentCore calls are signed for the bedrock-agentcore service');
    if (fakeState.agentCoreForbidden) return json(403, { message: 'User is not authorized to perform: bedrock-agentcore:ListHarnesses' });
    if (req.method === 'GET' && p === '/harnesses') return json(200, { harnesses: [{ harnessId: 'signet_test_agent2-AbC123xyz', harnessName: 'signet_test_agent2', status: 'READY' }, { harnessId: 'signet_test_agent-aLpQCrbZYY', harnessName: 'signet_test_agent', status: 'CREATE_FAILED' }] });
    if (req.method === 'POST' && p === '/runtimes/') return json(200, { agentRuntimes: [{ agentRuntimeId: 'claims_rt-9QwErTy', agentRuntimeName: 'claims_rt', status: 'READY' }] });
  }
  if (host === 'bedrock-agent.us-east-1.amazonaws.com' && p === '/agents/') {
    if (fakeState.classicForbidden) return json(403, { message: 'User is not authorized to perform: bedrock:ListAgents' });
    return json(200, { agentSummaries: [{ agentId: 'ABCDE12345', agentName: 'claims-bot', agentStatus: 'PREPARED' }] });
  }
  if (host === 'lambda.us-east-1.amazonaws.com' && p === '/2015-03-31/functions/') return json(200, { Functions: [{ FunctionName: 'triage-fn', Runtime: 'python3.12', Environment: { Variables: {} } }] });
  json(404, { message: `unexpected ${req.method} ${host}${p}` });
});
await new Promise<void>((resolve) => fake.listen(0, '127.0.0.1', resolve));
process.env.SIGNET_PLATFORM_API_OVERRIDE = `http://127.0.0.1:${(fake.address() as { port: number }).port}`;

after(async () => {
  fake.close();
  await dropTestDatabase();
});

const { permissionsFor } = await import('../src/rbac');
const aws = await import('../src/aws-agents');
const platforms = await import('../src/platforms');
const { getAgent } = await import('../src/registry');
const { db } = await import('../src/db');
const admin: Principal = { id: 'aws-admin@example.test', name: 'Admin', kind: 'human', roles: ['tenant_admin', 'platform_admin', 'agent_owner'], permissions: permissionsFor(['tenant_admin', 'platform_admin', 'agent_owner']), groups: [], mfa: true, auth: 'session', auth_time: null };
const credentials = { access_key_id: 'AKIAEXAMPLE0000', secret_access_key: 'aws-secret-access-key-value', regions: 'us-east-1' };
const purpose = 'Answers short questions about IT support tickets';
const HARNESS = 'agentcore-harness:us-east-1:signet_test_agent2-AbC123xyz';

test('Amazon Bedrock agents: connect, list every kind, link once, and report coverage from evidence', async () => {
  fakeState.signInFails = true;
  await assert.rejects(aws.createAwsConnection({ ...credentials, label: 'Bad key' }, admin), /security token included in the request is invalid/, 'the sign-in is proved before anything is stored');
  fakeState.signInFails = false;
  assert.deepEqual(await aws.listAwsConnections(), []);

  const connection = await aws.createAwsConnection({ ...credentials, label: 'AWS – Test' }, admin);
  assert.equal(connection.account_id, '111122223333');
  assert.equal(connection.regions, 'us-east-1');
  assert.equal(connection.status, 'connected');
  const stored = await db.prepare('SELECT scope, status_detail FROM platform_connection WHERE id = ?').get(connection.id) as { scope: string; status_detail: string };
  assert.ok(!JSON.stringify(stored).includes(credentials.secret_access_key), 'the secret key is never kept in the connection row');

  assert.deepEqual((await aws.availableAwsAgents(connection.id)).map((a) => [a.ref, a.name, a.kind_label, a.active]), [
    [HARNESS, 'signet_test_agent2', 'AgentCore harness', true],
    ['agentcore-harness:us-east-1:signet_test_agent-aLpQCrbZYY', 'signet_test_agent', 'AgentCore harness', false],
    ['agentcore-runtime:us-east-1:claims_rt-9QwErTy', 'claims_rt', 'AgentCore runtime', true],
    ['bedrock:us-east-1:ABCDE12345', 'claims-bot', 'Agents Classic', true],
  ], 'Lambda functions are not offered as agents');

  const input = { agent_ref: HARNESS, name: 'signet_test_agent2', purpose };
  await assert.rejects(aws.linkAwsAgent(connection.id, input, { ...admin, permissions: [] }), /agents.write/);
  await assert.rejects(aws.linkAwsAgent(connection.id, { ...input, agent_ref: 'signet_test_agent2' }, admin), /agent reference/);
  await assert.rejects(aws.linkAwsAgent(connection.id, { ...input, agent_ref: 'bedrock:us-east-1:short' }, admin), /10 capital letters/);
  await assert.rejects(aws.linkAwsAgent(connection.id, { ...input, agent_ref: 'agentcore-harness:eu-west-1:x-1' }, admin), /not eu-west-1/);
  await assert.rejects(aws.linkAwsAgent(connection.id, { ...input, agent_ref: 'agentcore-harness:us-east-1:missing-1' }, admin), /No AgentCore harness/);
  await assert.rejects(aws.linkAwsAgent(connection.id, { ...input, purpose: 'short' }, admin), /10–4000/);

  const linked = await aws.linkAwsAgent(connection.id, input, admin);
  assert.equal((await aws.linkAwsAgent(connection.id, input, admin)).agent_id, linked.agent_id, 'linking again reuses the identity');
  const agent = await getAgent(linked.agent_id);
  assert.equal(agent.kind, 'third_party');
  assert.equal(agent.vendor, aws.AWS_VENDOR);
  assert.equal(agent.connection_method, 'oauth');
  assert.deepEqual(JSON.parse(String((await db.prepare('SELECT vendor_details FROM agent WHERE id = ?').get(agent.id) as { vendor_details: string }).vendor_details)),
    { account_id: '111122223333', region: 'us-east-1', agent_id: 'signet_test_agent2-AbC123xyz', agent_type: 'AgentCore harness' });

  const classic = await aws.linkAwsAgent(connection.id, { agent_ref: 'us-east-1:ABCDE12345', name: 'claims-bot', purpose }, admin);
  assert.notEqual(classic.agent_id, linked.agent_id);
  const workload = (await platforms.workloads(connection.id)).find((w) => w.id === 'bedrock:us-east-1:ABCDE12345')!;
  assert.equal(workload.registered_agent_id, classic.agent_id, 'platform scans treat the linked agent as registered, not as a new finding');

  const rows = await aws.linkedAwsAgents(connection.id);
  assert.deepEqual(rows.map((row) => [row.agent_ref, row.kind_label, row.gateway_enforcement]).sort(), [
    [HARNESS, 'AgentCore harness', false],
    ['bedrock:us-east-1:ABCDE12345', 'Agents Classic', false],
  ], 'a link alone never claims gateway enforcement');
  assert.equal((await aws.awsConnection(connection.id)).linked_agents, 2);
  const ledgerRows = await db.prepare("SELECT data FROM ledger_record WHERE agent_id = ? AND kind = 'lifecycle'").all(linked.agent_id) as { data: string }[];
  assert.equal(ledgerRows.filter((row) => JSON.parse(row.data).event === 'aws.agent_linked').length, 1);

  // A second connection to the same account links the same AWS agent to the same Signet identity.
  const second = await aws.createAwsConnection({ ...credentials, label: 'Same account' }, admin);
  assert.equal((await aws.linkAwsAgent(second.id, input, admin)).agent_id, linked.agent_id);
});

test('Amazon Bedrock: partial permissions, connection test and removal are explained', async () => {
  const connection = await aws.createAwsConnection({ ...credentials, label: 'Checks' }, admin);
  fakeState.classicForbidden = true;
  assert.deepEqual((await aws.availableAwsAgents(connection.id)).map((a) => a.name), ['signet_test_agent2', 'signet_test_agent', 'claims_rt'], 'a missing Agents Classic permission does not hide AgentCore agents');
  fakeState.agentCoreForbidden = true;
  await assert.rejects(aws.availableAwsAgents(connection.id), (error: Error & { rule?: string }) => error.rule === 'AWS_PERMISSIONS' && /bedrock-agentcore:ListHarnesses/.test(error.message));
  fakeState.classicForbidden = false;
  fakeState.agentCoreForbidden = false;

  fakeState.signInFails = true;
  const failed = await aws.testAwsConnection(connection.id, admin);
  assert.equal(failed.status, 'error');
  assert.equal(failed.account_id, '111122223333', 'an error message does not change the account');
  fakeState.signInFails = false;
  assert.equal((await aws.testAwsConnection(connection.id, admin)).status, 'connected');

  await aws.removeAwsConnection(connection.id, admin);
  assert.ok(!(await aws.listAwsConnections()).some((item) => item.id === connection.id));
  await assert.rejects(aws.availableAwsAgents(connection.id), /not found/i);
});

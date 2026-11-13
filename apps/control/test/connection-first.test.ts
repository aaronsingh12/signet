import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import type { ExternalConnectionConfig } from '@signet/core/types';
import type { Principal } from '../src/rbac';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-connect-first-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
after(dropTestDatabase);

test('a real public API can be verified before registration and attached without issuing runtime approval', async () => {
  const connections = await import('../src/external-connections');
  const { registerAgent, activeCertificate } = await import('../src/registry');
  const { permissionsFor } = await import('../src/rbac');
  const { testModelConnection } = await import('../src/model-connection');
  const roles: Principal['roles'] = ['tenant_admin', 'platform_admin', 'agent_owner'];
  const admin: Principal = { id: 'admin', name: 'Admin', kind: 'human', roles, permissions: permissionsFor(roles), groups: [], mfa: true, auth: 'session', auth_time: Math.floor(Date.now() / 1000) };
  const config: ExternalConnectionConfig = { name: 'Public provider model list', base_url: 'https://ollama.com/v1', method: 'rest', auth: 'none', header: '', client_id: '', token_url: '', scopes: '', token_auth: 'client_secret_basic', timeout_ms: 10000, sync_interval_seconds: 300, remote_management: false, endpoints: { test: { method: 'GET', path: '/models' } }, agents_mapping: null, executions_mapping: null, tracking_pointer: '', execution_pagination: null, private_connector: null };
  const profile = await connections.create(null, { config, credential: '' }, admin);
  const agent = await registerAgent({ handle: 'connect-first', name: 'Connect First', purpose: 'Checks the connection before governance intake', sponsor: admin.id, autonomy_level: 'L0', connection_method: 'rest' }, admin);
  await assert.rejects(connections.attachToAgent(profile.id, agent.id, admin), /Verify the endpoint and authentication/);
  const tested = await connections.testConnection(profile.id, admin);
  assert.equal(tested.health.endpoint_verified, true);
  assert.equal(tested.health.authentication, 'not_required');
  assert.equal((await connections.attachToAgent(profile.id, agent.id, admin)).agent_id, agent.id);
  assert.equal((await connections.attachToAgent(profile.id, agent.id, admin)).agent_id, agent.id, 'retry must not create another connection');
  assert.equal(await activeCertificate(agent.id), null, 'verification must not create an approval');
  const other = await registerAgent({ handle: 'other-connect-first', name: 'Other Agent', purpose: 'Checks that a bound connection cannot be reassigned', sponsor: admin.id, autonomy_level: 'L0' }, admin);
  await assert.rejects(connections.attachToAgent(profile.id, other.id, admin), /already belongs to another agent/);
  await assert.rejects(testModelConnection('missing-model', admin.id), /catalogue model missing-model/);
});

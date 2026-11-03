import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import type { Principal } from '../src/rbac';

const dir = mkdtempSync(join(tmpdir(), 'signet-deployment-'));
process.env.SIGNET_DATA_DIR = dir;
process.env.SIGNET_DB = join(dir, 'test.db');

test('deployment identity issues fresh scoped tokens and enforces ownership, seal changes, expiry and revocation', async () => {
  const { permissionsFor } = await import('../src/rbac');
  const { db } = await import('../src/db');
  const { registerAgent, issueSeal } = await import('../src/registry');
  const { createDeploymentCredential, exchangeDeploymentCredential, revokeDeploymentCredential } = await import('../src/deployment-identity');
  const owner: Principal = { id: 'owner@example.test', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const security: Principal = { id: 'security@example.test', name: 'Security', kind: 'human', roles: ['security_officer'], permissions: permissionsFor(['security_officer']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const agent = registerAgent({ handle: 'deployment-test', name: 'Deployment test', purpose: 'Verify scoped identity', sponsor: 'sponsor@example.test', tier: 'T1', autonomy_level: 'L0' }, owner);
  const seal = { models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }], tools: [], limits: { rpm: 30, tokens_per_day: 1000, usd_per_day: 1 }, environments: ['dev'] };
  issueSeal(agent.id, seal, security);
  assert.throws(() => createDeploymentCredential(agent.id, { ...owner, id: 'other@example.test' }, 'dev'), /does not own/);
  assert.throws(() => createDeploymentCredential(agent.id, owner, 'production'), /does not cover/);
  const credential = createDeploymentCredential(agent.id, owner, 'dev');
  const first = exchangeDeploymentCredential(credential.deployment_credential);
  const second = exchangeDeploymentCredential(credential.deployment_credential);
  assert.equal(first.claims.agent_id, agent.id);
  assert.equal(first.agent_handle, agent.handle);
  assert.equal(first.claims.ins, second.claims.ins);
  assert.notEqual(first.token, second.token);
  assert.equal(first.expires_in, 600);
  assert.throws(() => exchangeDeploymentCredential('invalid'), /unknown or revoked/);
  const expired = createDeploymentCredential(agent.id, owner, 'dev');
  db.prepare('UPDATE deployment_credential SET expires_at = ? WHERE id = ?').run('2000-01-01T00:00:00Z', expired.id);
  assert.throws(() => exchangeDeploymentCredential(expired.deployment_credential), /expired/);
  revokeDeploymentCredential(agent.id, credential.id, owner);
  assert.throws(() => exchangeDeploymentCredential(credential.deployment_credential), /revoked/);
  const superseded = createDeploymentCredential(agent.id, owner, 'dev');
  issueSeal(agent.id, seal, security);
  assert.throws(() => exchangeDeploymentCredential(superseded.deployment_credential), /seal changed/);
});

test('four hospital identities keep independent seals, instances and enforcement', async () => {
  const { permissionsFor } = await import('../src/rbac');
  const { registerAgent, issueSeal } = await import('../src/registry');
  const { createDeploymentCredential, exchangeDeploymentCredential } = await import('../src/deployment-identity');
  const { applyLadder } = await import('../src/enforcement');
  const owner: Principal = { id: 'hospital-owner@example.test', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'bearer', auth_time: null };
  const security: Principal = { ...owner, id: 'hospital-security@example.test', roles: ['security_officer'], permissions: permissionsFor(['security_officer']) };
  const deployments = ['appointment', 'records', 'lab', 'care'].map((key) => {
    const agent = registerAgent({ handle: `hospital-${key}-agent`, name: key, purpose: 'Independent hospital governance', sponsor: owner.id, tier: 'T1', autonomy_level: 'L0' }, owner);
    issueSeal(agent.id, { models: [{ model: 'gpt-oss:120b-cloud', region: 'unverified' }], tools: [], limits: { rpm: 30, tokens_per_day: 1000, usd_per_day: 1 }, environments: ['dev'] }, security);
    return createDeploymentCredential(agent.id, owner, 'dev');
  });
  const identities = deployments.map((deployment) => exchangeDeploymentCredential(deployment.deployment_credential));
  for (const field of ['agent_id', 'cert_id', 'ins', 'sub'] as const) assert.equal(new Set(identities.map((identity) => identity.claims[field])).size, 4);
  applyLadder({ agentId: deployments[0]!.agent_id }, 'kill', { actor: security.id, reason: 'Verify hospital agent isolation' });
  assert.throws(() => exchangeDeploymentCredential(deployments[0]!.deployment_credential), /killed/);
  for (const deployment of deployments.slice(1)) assert.equal(exchangeDeploymentCredential(deployment.deployment_credential).claims.agent_id, deployment.agent_id);
});

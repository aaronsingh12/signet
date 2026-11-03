import { randomBytes } from 'node:crypto';
import { newId, sha256 } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError } from './errors';
import { mintToken, usableCertificate } from './identity';
import { assertCan, getAgent } from './registry';
import type { Principal } from './rbac';
import { tenant } from './tenant';
import * as ledger from './ledger';

db.exec(`CREATE TABLE IF NOT EXISTS deployment_credential (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenant(id),
  secret_hash TEXT NOT NULL UNIQUE,
  agent_id TEXT NOT NULL REFERENCES agent(id),
  cert_id TEXT NOT NULL REFERENCES certificate(id),
  instance_id TEXT NOT NULL REFERENCES agent_instance(id),
  environment TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
)`);

interface DeploymentCredential {
  id: string;
  agent_id: string;
  cert_id: string;
  instance_id: string;
  environment: string;
  expires_at: string;
  revoked_at: string | null;
}

/** Issue an agent-, seal- and environment-bound server credential; never an administrator token. */
export function createDeploymentCredential(agentRef: string, actor: Principal, environment: string): {
  id: string; deployment_credential: string; expires_at: string; agent_id: string;
} {
  const agent = getAgent(agentRef);
  assertCan(actor, 'identity.bootstrap', agent);
  const cert = usableCertificate(agent.id, undefined);
  if (!cert.environments.includes(environment)) throw new PolicyError('BP-5.2-4', `seal does not cover environment ${environment}`, 403);
  const secret = `sdc_${randomBytes(32).toString('base64url')}`;
  const id = newId('sec');
  const instanceId = newId('ins');
  const expires = new Date(Math.min(Date.parse(cert.valid_to), Date.now() + 30 * 86_400_000)).toISOString();
  return tx(() => {
    db.prepare('INSERT INTO agent_instance (id, agent_id, cert_id, version, env, first_seen, last_seen, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(instanceId, agent.id, cert.cert_id, cert.version, environment, nowIso(), nowIso(), 'running');
    db.prepare('INSERT INTO deployment_credential (id, tenant_id, secret_hash, agent_id, cert_id, instance_id, environment, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, tenant.id, sha256(secret), agent.id, cert.cert_id, instanceId, environment, expires);
    ledger.append({ kind: 'lifecycle', agent_id: agent.id, cert_id: cert.cert_id, data: { event: 'deployment_credential.issued', credential_id: id, actor: actor.id, environment, expires_at: expires } });
    return { id, deployment_credential: secret, expires_at: expires, agent_id: agent.id };
  });
}

/** Recheck seal, environment, expiry and kill state whenever a server obtains a short-lived token. */
export function exchangeDeploymentCredential(secret: string): ReturnType<typeof mintToken> & { agent_handle: string; detector_unavailability: 'hold' | 'audit' } {
  return tx(() => {
    const row = db.prepare('SELECT * FROM deployment_credential WHERE tenant_id = ? AND secret_hash = ?')
      .get(tenant.id, sha256(secret)) as DeploymentCredential | undefined;
    if (!row || row.revoked_at) throw new PolicyError('BP-4.2', 'deployment credential is unknown or revoked', 401);
    if (Date.parse(row.expires_at) <= Date.now()) throw new PolicyError('BP-4.2', 'deployment credential expired; issue and configure a new deployment credential', 401);
    const cert = usableCertificate(row.agent_id, row.instance_id);
    if (cert.cert_id !== row.cert_id) throw new PolicyError('BP-4.2', 'seal changed; issue and configure a new deployment credential', 401);
    if (!cert.environments.includes(row.environment)) throw new PolicyError('BP-5.2-4', `seal does not cover environment ${row.environment}`, 403);
    return { ...mintToken(cert, row.instance_id), agent_handle: getAgent(row.agent_id).handle, detector_unavailability: cert.detector_unavailability ?? 'hold' };
  });
}

export function revokeDeploymentCredential(agentRef: string, credentialId: string, actor: Principal): { revoked: true } {
  const agent = getAgent(agentRef);
  assertCan(actor, 'identity.bootstrap', agent);
  const result = db.prepare('UPDATE deployment_credential SET revoked_at = ? WHERE id = ? AND agent_id = ? AND tenant_id = ?')
    .run(nowIso(), credentialId, agent.id, tenant.id);
  if (!result.changes) throw new PolicyError('NOT_FOUND', `deployment credential ${credentialId} not found for agent ${agent.id}`, 404);
  ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'deployment_credential.revoked', credential_id: credentialId, actor: actor.id } });
  return { revoked: true };
}

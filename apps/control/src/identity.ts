import { randomBytes } from 'node:crypto';
import { newId, sha256, signJws, spiffeId, verifyJws, type CertificateBody, type WorkloadClaims } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError } from './errors';
import { keys } from './keys';
import { activeCertificate, assertCan, getAgent } from './registry';
import { agentBlocked } from './enforcement';
import type { Principal } from './rbac';

const BOOTSTRAP_TTL_MS = 15 * 60_000; // BP 4.2: valid 15 minutes, single use
const tokenTtlSeconds = (tier: string) => (tier === 'T1' || tier === 'T2' ? 600 : 1800);

function mintToken(cert: CertificateBody, instanceId: string) {
  const now = Math.floor(Date.now() / 1000);
  const claims: WorkloadClaims = {
    sub: spiffeId(cert.tenant, cert.agent_id, cert.version),
    agent_id: cert.agent_id,
    ver: cert.version,
    cert_id: cert.cert_id,
    ins: instanceId,
    tier: cert.tier,
    tenant: cert.tenant,
    iat: now,
    exp: now + tokenTtlSeconds(cert.tier),
    jti: newId('jti'),
  };
  db.prepare('INSERT INTO issued_token (jti, agent_id, instance_id, exp) VALUES (?, ?, ?, ?)').run(claims.jti, cert.agent_id, instanceId, claims.exp);
  db.prepare('UPDATE agent_instance SET last_seen = ? WHERE id = ?').run(nowIso(), instanceId);
  return { token: signJws(claims, keys.token, 'JWT'), token_type: 'Bearer', expires_in: claims.exp - now, claims };
}

function usableCertificate(agentId: string, instanceId?: string) {
  const blocked = agentBlocked(agentId, instanceId);
  if (blocked) throw new PolicyError(blocked === 'killed' ? 'RB-INV-08' : 'BP-5.4', `agent is ${blocked}; new tokens are refused`, 403);
  const active = activeCertificate(agentId);
  if (!active) throw new PolicyError('RB-INV-01', 'agent has no active seal', 403);
  if (Date.parse(active.certificate.valid_to) < Date.now()) throw new PolicyError('RB-KILL-11', 'seal has expired', 403);
  return active.certificate;
}

// Issued to the deployment pipeline at Deploy; exchanged once for a workload token.
export function createBootstrap(agentRef: string, p: Principal, env = 'dev') {
  const agent = getAgent(agentRef);
  assertCan(p, 'identity.bootstrap', agent);
  const cert = usableCertificate(agent.id);
  if (!cert.environments.includes(env)) throw new PolicyError('BP-5.2-4', `the seal does not cover environment ${env}`, 403);
  const secret = `sbc_${randomBytes(32).toString('base64url')}`;
  const expires = new Date(Date.now() + BOOTSTRAP_TTL_MS).toISOString();
  db.prepare('INSERT INTO bootstrap_credential (id, secret_hash, agent_id, cert_id, issued_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)').run(
    `${newId('boot')}:${env}`, sha256(secret), agent.id, cert.cert_id, p.id, expires,
  );
  return { bootstrap_credential: secret, expires_at: expires, agent_id: agent.id, environment: env };
}

// Each exchange starts a new instance (BP 4.1), so a kill can target one replica.
export function exchangeBootstrap(secret: string) {
  return tx(() => {
    const row = db.prepare('SELECT * FROM bootstrap_credential WHERE secret_hash = ?').get(sha256(secret ?? '')) as
      | { id: string; agent_id: string; expires_at: string; used_at: string | null }
      | undefined;
    if (!row) throw new PolicyError('BP-4.2', 'unknown bootstrap credential', 401);
    if (row.used_at) throw new PolicyError('BP-4.2', 'bootstrap credential already used', 401);
    if (Date.parse(row.expires_at) < Date.now()) throw new PolicyError('BP-4.2', 'bootstrap credential expired', 401);
    db.prepare('UPDATE bootstrap_credential SET used_at = ? WHERE id = ?').run(nowIso(), row.id);
    const cert = usableCertificate(row.agent_id);
    const instanceId = newId('ins');
    db.prepare('INSERT INTO agent_instance (id, agent_id, cert_id, version, env, first_seen, last_seen, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      instanceId, cert.agent_id, cert.cert_id, cert.version, row.id.split(':')[1] ?? 'dev', nowIso(), nowIso(), 'running',
    );
    return mintToken(cert, instanceId);
  });
}

// A still-valid workload token can be swapped for a fresh one; seal and ladder state are rechecked.
export function refreshToken(token: string) {
  let claims: WorkloadClaims;
  try {
    claims = verifyJws<WorkloadClaims>(token, new Map([[keys.token.kid, keys.token.publicKey]]), 'JWT').payload;
  } catch {
    throw new PolicyError('BP-4.2', 'invalid workload token', 401);
  }
  if (claims.exp * 1000 < Date.now()) throw new PolicyError('BP-4.2', 'workload token expired; use a new bootstrap credential', 401);
  if (db.prepare('SELECT 1 FROM revoked_jti WHERE jti = ?').get(claims.jti)) throw new PolicyError('BP-4.2', 'workload token revoked', 401);
  const cert = usableCertificate(claims.agent_id, claims.ins);
  if (cert.cert_id !== claims.cert_id) throw new PolicyError('BP-4.2', 'the seal changed; redeploy with a new bootstrap credential', 401);
  return mintToken(cert, claims.ins);
}

export const instancesOf = (agentId: string) =>
  db.prepare('SELECT id, version, env, first_seen, last_seen, state FROM agent_instance WHERE agent_id = ? ORDER BY first_seen DESC').all(agentId) as {
    id: string; version: string; env: string; first_seen: string; last_seen: string; state: string;
  }[];

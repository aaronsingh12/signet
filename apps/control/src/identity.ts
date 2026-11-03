import { randomBytes, timingSafeEqual } from 'node:crypto';
import { TOKEN_AUDIENCE, newId, sha256, signJws, spiffeId, tokenIssuer, verifyJws, type CertificateBody, type WorkloadClaims } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError } from './errors';
import { keys } from './keys';
import { activeCertificate, assertCan, getAgent } from './registry';
import { agentBlocked, revokeTokensFor } from './enforcement';
import * as hub from './hub';
import * as ledger from './ledger';
import { can, type Principal } from './rbac';

// Revoking an identity is a security action: Security (who may quarantine) or whoever manages the
// agent's identities may do it.
const assertCanRevoke = (p: Principal, agentId: string) => (can(p, 'ladder.quarantine') && !p.roles.every((r) => r === 'agent_owner') ? undefined : assertCan(p, 'identity.bootstrap', getAgent(agentId)));

const BOOTSTRAP_TTL_MS = 15 * 60_000; // BP 4.2: valid 15 minutes, single use
const tokenTtlSeconds = (tier: string) => (tier === 'T1' || tier === 'T2' ? 600 : 1800);

export function mintToken(cert: CertificateBody, instanceId: string, kind: WorkloadClaims['kind']) {
  const now = Math.floor(Date.now() / 1000);
  const claims: WorkloadClaims = {
    iss: tokenIssuer(cert.tenant),
    aud: TOKEN_AUDIENCE,
    sub: spiffeId(cert.tenant, cert.agent_id, cert.version),
    agent_id: cert.agent_id,
    ver: cert.version,
    cert_id: cert.cert_id,
    ins: instanceId,
    tier: cert.tier,
    tenant: cert.tenant,
    kind,
    iat: now,
    exp: now + tokenTtlSeconds(cert.tier),
    jti: newId('jti'),
  };
  db.prepare('INSERT INTO issued_token (jti, agent_id, instance_id, exp) VALUES (?, ?, ?, ?)').run(claims.jti, cert.agent_id, instanceId, claims.exp);
  db.prepare('UPDATE agent_instance SET last_seen = ? WHERE id = ?').run(nowIso(), instanceId);
  return { token: signJws(claims, keys.token, 'JWT'), token_type: 'Bearer', expires_in: claims.exp - now, claims };
}

export function usableCertificate(agentId: string, instanceId?: string) {
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
  if (agent.kind === 'third_party') throw new PolicyError('VALIDATION', 'third-party agents connect with client credentials, not a bootstrap credential', 409);
  const cert = usableCertificate(agent.id);
  if (!cert.environments.includes(env)) throw new PolicyError('BP-5.2-4', `the seal does not cover environment ${env}`, 403);
  const secret = `sbc_${randomBytes(32).toString('base64url')}`;
  const expires = new Date(Date.now() + BOOTSTRAP_TTL_MS).toISOString();
  db.prepare('INSERT INTO bootstrap_credential (id, secret_hash, agent_id, cert_id, issued_by, expires_at, environment) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    `${newId('boot')}:${env}`, sha256(secret), agent.id, cert.cert_id, p.id, expires, env,
  );
  ledger.append({ kind: 'admin', agent_id: agent.id, data: { event: 'identity.bootstrap_issued', environment: env, expires_at: expires, actor: p.id } });
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
    return mintToken(cert, instanceId, 'bootstrap');
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
  if (claims.aud !== TOKEN_AUDIENCE || claims.iss !== tokenIssuer(claims.tenant)) throw new PolicyError('BP-4.2', 'workload token was not issued by this control plane', 401);
  if (claims.exp * 1000 < Date.now()) throw new PolicyError('BP-4.2', 'workload token expired; use a new bootstrap credential', 401);
  if (db.prepare('SELECT 1 FROM revoked_jti WHERE jti = ?').get(claims.jti)) throw new PolicyError('BP-4.2', 'workload token revoked', 401);
  const cert = usableCertificate(claims.agent_id, claims.ins);
  if (cert.cert_id !== claims.cert_id) throw new PolicyError('BP-4.2', 'the seal changed; redeploy with a new bootstrap credential', 401);
  const inst = db.prepare('SELECT revoked_at FROM agent_instance WHERE id = ?').get(claims.ins) as { revoked_at: string | null } | undefined;
  if (!inst || inst.revoked_at) throw new PolicyError('BP-4.2', 'this instance identity has been revoked', 401);
  return mintToken(cert, claims.ins, claims.kind ?? 'bootstrap');
}

export const instancesOf = (agentId: string) =>
  db.prepare('SELECT id, version, env, first_seen, last_seen, state FROM agent_instance WHERE agent_id = ? ORDER BY first_seen DESC').all(agentId) as {
    id: string; version: string; env: string; first_seen: string; last_seen: string; state: string;
  }[];

// Revoking one instance's identity (BP 4.1) without touching the agent's ladder level: its tokens go on
// the revocation list every gateway node receives, and refresh is refused from now on.
export function revokeInstance(instanceId: string, p: Principal, reason: string) {
  const inst = db.prepare('SELECT agent_id, revoked_at FROM agent_instance WHERE id = ?').get(instanceId) as { agent_id: string; revoked_at: string | null } | undefined;
  if (!inst) throw new PolicyError('VALIDATION', `unknown instance ${instanceId}`, 404);
  assertCanRevoke(p, inst.agent_id);
  if (!reason?.trim()) throw new PolicyError('VALIDATION', 'a reason is required', 400);
  if (inst.revoked_at) return { instance_id: instanceId, tokens_revoked: 0, already_revoked: true };
  const n = tx(() => {
    db.prepare("UPDATE agent_instance SET revoked_at = ?, state = 'revoked' WHERE id = ?").run(nowIso(), instanceId);
    const count = revokeTokensFor(inst.agent_id, 'instance', { agentId: inst.agent_id, instanceId });
    ledger.append({ kind: 'admin', agent_id: inst.agent_id, data: { event: 'identity.instance_revoked', instance_id: instanceId, tokens_revoked: count, reason, actor: p.id } });
    return count;
  });
  hub.publish('bundle', { reason: 'identity.revoked', agent_id: inst.agent_id });
  return { instance_id: instanceId, tokens_revoked: n, already_revoked: false };
}

// --- Third-party agents: OAuth 2.0 client credentials (RFC 6749 section 4.4) ----------------------
// A vendor-hosted agent (Copilot Studio, Agentforce, a ChatGPT action, ...) cannot run our SDK or hold a
// bootstrap credential, but such platforms can call a tool with OAuth client credentials. The client
// exchanges them at /identity/token for the same short-lived workload token, bound to its agent.

export function createClient(agentRef: string, p: Principal, label: string) {
  const agent = getAgent(agentRef);
  assertCan(p, 'identity.bootstrap', agent);
  if (agent.kind !== 'third_party') throw new PolicyError('VALIDATION', 'client credentials are for third-party agents; self-hosted agents use a bootstrap credential', 409);
  usableCertificate(agent.id);
  const clientId = `scl_${randomBytes(12).toString('hex')}`;
  const secret = `scs_${randomBytes(32).toString('base64url')}`;
  db.prepare('INSERT INTO agent_client (client_id, agent_id, secret_hash, label, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(clientId, agent.id, sha256(secret), label?.trim() || 'vendor platform', p.id, nowIso());
  ledger.append({ kind: 'admin', agent_id: agent.id, data: { event: 'identity.client_created', client_id: clientId, label, actor: p.id } });
  return { client_id: clientId, client_secret: secret, token_url: '/api/v1/identity/token', grant_type: 'client_credentials' };
}

export const clientsOf = (agentId: string) =>
  db.prepare('SELECT client_id, label, created_by, created_at, last_used_at, revoked_at FROM agent_client WHERE agent_id = ? ORDER BY created_at DESC').all(agentId);

// One stable instance per client, so a kill or revocation can target that vendor connection alone.
const clientInstanceId = (clientId: string) => `ins_${sha256(clientId).slice(0, 26).toUpperCase()}`;

export function revokeClient(clientId: string, p: Principal, reason: string) {
  const c = db.prepare('SELECT agent_id, revoked_at FROM agent_client WHERE client_id = ?').get(clientId) as { agent_id: string; revoked_at: string | null } | undefined;
  if (!c) throw new PolicyError('VALIDATION', `unknown client ${clientId}`, 404);
  assertCanRevoke(p, c.agent_id);
  if (!reason?.trim()) throw new PolicyError('VALIDATION', 'a reason is required', 400);
  tx(() => {
    db.prepare('UPDATE agent_client SET revoked_at = ?, revoked_by = ? WHERE client_id = ?').run(nowIso(), p.id, clientId);
    const instanceId = clientInstanceId(clientId);
    if (db.prepare('SELECT 1 FROM agent_instance WHERE id = ?').get(instanceId)) {
      db.prepare("UPDATE agent_instance SET revoked_at = ?, state = 'revoked' WHERE id = ?").run(nowIso(), instanceId);
      revokeTokensFor(c.agent_id, 'instance', { agentId: c.agent_id, instanceId });
    }
    ledger.append({ kind: 'admin', agent_id: c.agent_id, data: { event: 'identity.client_revoked', client_id: clientId, reason, actor: p.id } });
  });
  hub.publish('bundle', { reason: 'identity.revoked', agent_id: c.agent_id });
  return { client_id: clientId, revoked: true };
}

export function exchangeClientCredentials(clientId: string, secret: string) {
  return tx(() => {
    const c = db.prepare('SELECT * FROM agent_client WHERE client_id = ?').get(clientId ?? '') as { client_id: string; agent_id: string; secret_hash: string; revoked_at: string | null } | undefined;
    // Same answer for an unknown client and a wrong secret; hashes compared in constant time.
    const ok = !!c && timingSafeEqual(Buffer.from(c.secret_hash), Buffer.from(sha256(secret ?? '')));
    if (!c || !ok) throw new PolicyError('BP-4.2', 'invalid client credentials', 401);
    if (c.revoked_at) throw new PolicyError('BP-4.2', 'client credentials have been revoked', 401);
    const cert = usableCertificate(c.agent_id);
    const instanceId = clientInstanceId(c.client_id);
    const inst = db.prepare('SELECT revoked_at FROM agent_instance WHERE id = ?').get(instanceId) as { revoked_at: string | null } | undefined;
    if (inst?.revoked_at) throw new PolicyError('BP-4.2', 'this client connection has been revoked', 401);
    if (!inst) {
      db.prepare("INSERT INTO agent_instance (id, agent_id, cert_id, version, env, first_seen, last_seen, state, auth_kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'client_credentials')").run(
        instanceId, cert.agent_id, cert.cert_id, cert.version, cert.environments[0] ?? 'dev', nowIso(), nowIso(), 'running',
      );
    } else db.prepare('UPDATE agent_instance SET cert_id = ?, version = ? WHERE id = ?').run(cert.cert_id, cert.version, instanceId);
    db.prepare('UPDATE agent_client SET last_used_at = ? WHERE client_id = ?').run(nowIso(), c.client_id);
    return mintToken(cert, instanceId, 'client_credentials');
  });
}

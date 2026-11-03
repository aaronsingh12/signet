import { randomBytes, timingSafeEqual } from 'node:crypto';
import { newId, sha256, type EdgeTask } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, invalid } from './errors';
import { verifyWorkloadToken } from './connectivity';
import { usableCertificate } from './identity';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';
import { getTool } from './tools';


interface Runner {
  id: string; name: string; created_at: string; last_seen_at: string | null; revoked_at: string | null;
}

interface Job {
  id: string; runner_id: string; agent_id: string; cert_id: string; instance_id: string; jti: string;
  token_exp: number; alias: string; action: string; args_json: string;
  state: string; result_json: string | null; error: string | null; expires_at: string;
}

function parseJson(text: string, field: string): unknown {
  try { return JSON.parse(text); }
  catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    throw invalid(`${field} is not valid JSON: ${error.message}`);
  }
}

export async function listRunners(): Promise<(Runner & { status: 'online' | 'offline' | 'revoked' })[]> {
  const rows = (await db.prepare('SELECT id, name, created_at, last_seen_at, revoked_at FROM edge_runner WHERE tenant_id = ? ORDER BY created_at DESC').all(tenant.id)) as unknown as Runner[];
  return rows.map((row) => ({ ...row, status: row.revoked_at ? 'revoked' : row.last_seen_at && Date.now() - Date.parse(row.last_seen_at) < 15_000 ? 'online' : 'offline' }));
}

/** Enroll an outbound-only connector worker; the enrollment secret is shown once and stored hashed. */
export async function createRunner(name: string, actor: Principal): Promise<{ id: string; runner_secret: string }> {
  if (typeof name !== 'string' || !name.trim() || name.length > 120) throw invalid('runner name must contain 1–120 characters');
  const id = newId('edge');
  const secret = `ser_${randomBytes(32).toString('base64url')}`;
  return (await tx(async () => {
    (await db.prepare('INSERT INTO edge_runner (id, tenant_id, name, secret_hash, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, tenant.id, name.trim(), sha256(secret), actor.id, nowIso()));
    (await ledger.append({ kind: 'admin', data: { event: 'edge.enrolled', runner_id: id, name: name.trim(), actor: actor.id } }));
    return { id, runner_secret: secret };
  }));
}

export async function requireRunner(id: string): Promise<void> {
  const row = (await db.prepare('SELECT revoked_at FROM edge_runner WHERE tenant_id = ? AND id = ?').get(tenant.id, id)) as { revoked_at: string | null } | undefined;
  if (!row || row.revoked_at) throw new PolicyError('EDGE_RUNNER', `runner ${id} is unknown or revoked`, 403);
}

export async function authenticateRunner(id: string, bearer: string): Promise<void> {
  const row = (await db.prepare('SELECT secret_hash, revoked_at FROM edge_runner WHERE tenant_id = ? AND id = ?').get(tenant.id, id)) as { secret_hash: string; revoked_at: string | null } | undefined;
  const digest = sha256(bearer.replace(/^Bearer\s+/i, ''));
  if (!row || row.revoked_at || !timingSafeEqual(Buffer.from(row.secret_hash), Buffer.from(digest))) throw new PolicyError('EDGE_AUTH', 'runner credentials are invalid or revoked', 401);
}

export async function revokeRunner(id: string, actor: Principal): Promise<{ revoked: true }> {
  (await requireRunner(id));
  return (await tx(async () => {
    (await db.prepare('UPDATE edge_runner SET revoked_at = ? WHERE id = ?').run(nowIso(), id));
    (await db.prepare("UPDATE edge_job SET state = 'cancelled', error = 'runner revoked', args_json = '{}', result_json = NULL WHERE runner_id = ?").run(id));
    (await ledger.append({ kind: 'admin', data: { event: 'edge.revoked', runner_id: id, actor: actor.id } }));
    return { revoked: true };
  }));
}

async function getJob(id: string): Promise<Job> {
  const row = (await db.prepare('SELECT * FROM edge_job WHERE id = ?').get(id)) as Job | undefined;
  if (!row) throw new PolicyError('EDGE_JOB', `connector job ${id} not found or expired`, 404);
  return row;
}

async function assertActive(job: Job): Promise<void> {
  (await requireRunner(job.runner_id));
  if (Date.parse(job.expires_at) <= Date.now() || job.token_exp * 1000 <= Date.now()) throw new PolicyError('EDGE_EXPIRED', `connector job ${job.id} or its workload token expired; it will not be replayed`, 410);
  if (job.state === 'cancelled') throw new PolicyError('EDGE_CANCELLED', `connector job ${job.id} was cancelled`, 409);
  const cert = (await usableCertificate(job.agent_id, job.instance_id));
  const instance = (await db.prepare('SELECT revoked_at, env FROM agent_instance WHERE id = ? AND agent_id = ?').get(job.instance_id, job.agent_id)) as { revoked_at: string | null; env: string } | undefined;
  if (cert.cert_id !== job.cert_id || !instance || instance.revoked_at || !cert.environments.includes(instance.env) || (await db.prepare('SELECT 1 FROM revoked_jti WHERE jti = ?').get(job.jti))) throw new PolicyError('EDGE_IDENTITY', `connector job ${job.id}: agent identity, seal or environment is no longer valid`, 403);
}

export async function enqueue(input: { alias: string; action: string; args_json: string; workload_token: string }): Promise<{ id: string }> {
  if (!input || typeof input.alias !== 'string' || typeof input.action !== 'string' || typeof input.args_json !== 'string' || typeof input.workload_token !== 'string') throw invalid('connector jobs require alias, action, args_json and workload_token strings');
  const args = parseJson(input.args_json, 'connector args_json');
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw invalid('connector job args_json must encode an object');
  const tool = (await getTool(input.alias));
  if (!tool?.runner_id || tool.kind !== 'http' || !tool.actions[input.action]) throw invalid('connector job must name a registered runner HTTP action');
  (await requireRunner(tool.runner_id));
  const runnerId = tool.runner_id;
  const runner = (await db.prepare('SELECT last_seen_at FROM edge_runner WHERE id = ?').get(runnerId)) as { last_seen_at: string | null };
  if (!runner.last_seen_at || Date.now() - Date.parse(runner.last_seen_at) >= 15_000) throw new PolicyError('EDGE_OFFLINE', `connector runner ${runnerId} is offline; start it and verify outbound connectivity before retrying`, 503);
  const claims = (await verifyWorkloadToken(input.workload_token));
  const id = newId('job');
  const expires = new Date(Date.now() + 25_000).toISOString();
  return (await tx(async () => {
    (await db.prepare('INSERT INTO edge_job (id, runner_id, agent_id, cert_id, instance_id, jti, token_exp, alias, action, args_json, state, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, runnerId, claims.agent_id, claims.cert_id, claims.ins, claims.jti, claims.exp, input.alias, input.action, input.args_json, 'queued', expires));
    (await assertActive((await getJob(id))));
    return { id };
  }));
}

/** Claim each job once. Expired or interrupted writes are never automatically replayed. */
export async function poll(id: string): Promise<{ task: EdgeTask | null }> {
  (await requireRunner(id));
  return (await tx(async () => {
    (await db.prepare('UPDATE edge_runner SET last_seen_at = ? WHERE id = ?').run(nowIso(), id));
    (await db.prepare('DELETE FROM edge_job WHERE expires_at < ?').run(new Date(Date.now() - 60_000).toISOString()));
    const job = (await db.prepare("SELECT * FROM edge_job WHERE runner_id = ? AND state = 'queued' AND expires_at > ? ORDER BY id LIMIT 1").get(id, nowIso())) as Job | undefined;
    if (!job) return { task: null };
    try {
      (await assertActive(job));
    } catch (error) {
      if (!(error instanceof PolicyError)) throw error;
      (await db.prepare("UPDATE edge_job SET state = 'failed', error = ?, args_json = '{}' WHERE id = ?").run(error.message, job.id));
      return { task: null };
    }
    (await db.prepare("UPDATE edge_job SET state = 'claimed' WHERE id = ?").run(job.id));
    const tool = (await getTool(job.alias));
    const action = tool?.actions[job.action];
    if (!tool || tool.runner_id !== id || !action) throw new PolicyError('EDGE_TOOL', `job ${job.id}: registered tool configuration changed`, 409);
    return { task: { id: job.id, alias: job.alias, action: job.action, args_json: job.args_json, expires_at: job.expires_at, target: { url: tool.url, method: action.method, path: action.path } } };
  }));
}

export async function lease(runnerId: string, jobId: string): Promise<{ active: true }> {
  const job = (await getJob(jobId));
  if (job.runner_id !== runnerId || job.state !== 'claimed') throw new PolicyError('EDGE_JOB', `runner ${runnerId} has no active lease on job ${jobId}`, 403);
  (await assertActive(job));
  (await db.prepare('UPDATE edge_runner SET last_seen_at = ? WHERE id = ?').run(nowIso(), runnerId));
  return { active: true };
}

export async function complete(runnerId: string, jobId: string, input: { result_json?: string; error?: string }): Promise<{ recorded: true }> {
  const job = (await getJob(jobId));
  if (job.runner_id === runnerId && (job.state === 'completed' || job.state === 'failed') && job.result_json === (input?.result_json ?? null) && job.error === (input?.error ?? null)) return { recorded: true };
  (await lease(runnerId, jobId));
  if (!input || (typeof input.result_json === 'string') === (typeof input.error === 'string')) throw invalid('provide exactly one of result_json or error');
  if (typeof input.result_json === 'string') parseJson(input.result_json, 'connector result_json');
  (await db.prepare("UPDATE edge_job SET state = ?, result_json = ?, error = ?, args_json = '{}' WHERE id = ?")
    .run(input.error === undefined ? 'completed' : 'failed', input.result_json ?? null, input.error ?? null, jobId));
  return { recorded: true };
}

export async function sweep(): Promise<void> {
  (await db.prepare('DELETE FROM edge_job WHERE expires_at < ?').run(new Date(Date.now() - 60_000).toISOString()));
}

export async function result(id: string): Promise<{ state: string; result_json: string | null; error: string | null }> {
  const job = (await getJob(id));
  (await assertActive(job));
  return { state: job.state, result_json: job.result_json, error: job.error };
}

export async function discard(id: string): Promise<{ cancelled: true }> {
  (await db.prepare("UPDATE edge_job SET state = 'cancelled', args_json = '{}', result_json = NULL WHERE id = ?").run(id));
  return { cancelled: true };
}

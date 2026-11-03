import { TOKEN_AUDIENCE, sha256, tokenIssuer, verifyJws, type WorkloadClaims } from '@signet/core';
import { db, nowIso, tx } from './db';
import * as enforcement from './enforcement';
import { PolicyError, invalid } from './errors';
import { clientsOf } from './identity';
import { keys } from './keys';
import * as ledger from './ledger';
import { activeCertificate, getAgent } from './registry';
import { tenant } from './tenant';
import * as workflow from './workflow';

// Agent connectivity (BP 4, 5): an agent is connected only when its own calls reach a gateway with a
// valid workload identity. Registration or approval alone never counts. Everything here is derived
// from identity records and the gateway's ledger records; nothing is inferred or assumed.

export type ConnectionState =
  | 'pending_approval'
  | 'approved'
  | 'credentials_not_provisioned'
  | 'not_connected'
  | 'connected'
  | 'connection_error'
  | 'suspended'
  | 'revoked';

const CONNECTED_WINDOW_MS = 15 * 60_000; // an accepted call within 15 minutes means "connected"
const AUTH_ERRORS = ['invalid_token', 'token_expired', 'token_revoked', 'no_active_seal', 'agent_killed', 'agent_quarantined', 'seal_mismatch', 'seal_expired', 'wrong_environment'];

interface Tx { ts: string; outcome: string | null; error_code: string | null; action_type: string | null; target: string | null; instance_id: string | null; node_id: string | null }

async function recent(agentId: string, limit = 200): Promise<Tx[]> {
  return (await db
    .prepare(
      `SELECT ts, jsonb_extract_path_text(data::jsonb, 'outcome') AS outcome, jsonb_extract_path_text(data::jsonb, 'error_code') AS error_code, jsonb_extract_path_text(data::jsonb, 'action_type') AS action_type,
              jsonb_extract_path_text(data::jsonb, 'target') AS target, jsonb_extract_path_text(data::jsonb, 'instance_id') AS instance_id, jsonb_extract_path_text(data::jsonb, 'node_id') AS node_id
       FROM ledger_record WHERE agent_id = ? AND kind = 'transaction' AND jsonb_extract_path_text(data::jsonb, 'action_type') IN ('llm_call', 'tool_call') ORDER BY seq DESC LIMIT ?`,
    )
    .all(agentId, limit)) as unknown as Tx[];
}

export async function status(agentRef: string) {
  const agent = (await getAgent(agentRef));
  const level = (await enforcement.agentLevel(agent.id));
  const cert = (await activeCertificate(agent.id))?.certificate ?? null;
  const lc = (await workflow.forAgent(agent.id))[0] ?? null;
  const thirdParty = agent.kind === 'third_party';
  const bootstraps = (await db.prepare('SELECT COUNT(*) AS n, SUM(CASE WHEN used_at IS NOT NULL THEN 1 ELSE 0 END) AS used, MAX(expires_at) AS last_expiry FROM bootstrap_credential WHERE agent_id = ?').get(agent.id)) as { n: number; used: number | null; last_expiry: string | null };
  const clients = (await clientsOf(agent.id)) as { revoked_at: string | null; last_used_at: string | null }[];
  const instances = (await db.prepare('SELECT id, version, env, auth_kind, first_seen, last_seen, state, revoked_at FROM agent_instance WHERE agent_id = ? ORDER BY last_seen DESC').all(agent.id)) as { id: string; revoked_at: string | null; last_seen: string }[];
  const liveTokens = ((await db.prepare('SELECT COUNT(*) AS n FROM issued_token t WHERE t.agent_id = ? AND t.exp > ? AND t.jti NOT IN (SELECT jti FROM revoked_jti)').get(agent.id, Math.floor(Date.now() / 1000))) as { n: number }).n;
  const txs = (await recent(agent.id));
  const lastOk = txs.find((t) => t.outcome === 'success' || t.outcome === 'pending');
  const lastAccepted = txs.find((t) => t.error_code === null || !AUTH_ERRORS.includes(t.error_code)); // reached policy, whatever the policy decided
  const lastAuthFail = txs.find((t) => t.error_code !== null && AUTH_ERRORS.includes(t.error_code));
  const errors = txs.filter((t) => t.outcome !== 'success' && t.outcome !== 'pending').slice(0, 10);
  const diagnostics = (await db.prepare('SELECT instance_id, client, report, bypass_risk, reported_at FROM agent_diagnostic WHERE agent_id = ? ORDER BY reported_at DESC LIMIT 5').all(agent.id)).map((d) => {
    const r = d as { report: string; bypass_risk: number };
    return { ...(d as object), report: JSON.parse(r.report), bypass_risk: !!r.bypass_risk };
  });

  const recentMs = (t?: Tx) => (t ? Date.now() - Date.parse(t.ts) : Infinity);
  let state: ConnectionState;
  let reason: string;
  if (level === 'killed' || agent.status === 'killed' || agent.status === 'retired') {
    state = 'revoked';
    reason = agent.status === 'retired' ? 'the agent is retired; its seal and tokens are revoked' : 'the agent was killed; its seal and tokens are revoked (RB-INV-08)';
  } else if (level === 'quarantined') {
    state = 'suspended';
    reason = 'the agent is quarantined; its tokens are revoked until a release is approved';
  } else if (!cert) {
    state = 'pending_approval';
    reason = lc ? `the lifecycle is at ${lc.stage}; no seal has been signed yet` : 'no seal has been signed';
  } else if (!clients.some((c) => !c.revoked_at) && !bootstraps.n && !instances.length) {
    state = 'credentials_not_provisioned';
    reason = thirdParty ? 'approved, but no client credentials have been created for the vendor platform' : 'approved, but no bootstrap credential has been issued to a deployment';
  } else if (lastAuthFail && recentMs(lastAuthFail) < CONNECTED_WINDOW_MS && Date.parse(lastAuthFail.ts) > Date.parse(lastAccepted?.ts ?? '1970')) {
    state = 'connection_error';
    reason = `the latest call was refused at authentication (${lastAuthFail.error_code})`;
  } else if (lastAccepted && recentMs(lastAccepted) < CONNECTED_WINDOW_MS) {
    state = 'connected';
    reason = `the gateway accepted a ${lastAccepted.action_type?.replace('_', ' ')} from this agent ${Math.round(recentMs(lastAccepted) / 1000)} s ago`;
  } else {
    state = 'not_connected';
    reason = lastAccepted ? 'no accepted call in the last 15 minutes' : thirdParty ? 'credentials exist, but the vendor platform has not called a Signet tool yet' : 'credentials were issued, but the agent has not called the gateway yet';
  }
  return {
    agent_id: agent.id,
    kind: agent.kind,
    state,
    reason,
    level,
    // What Signet can see for this agent. Third-party agents keep their vendor's model, which Signet does not route.
    coverage: thirdParty ? { model_calls: 'not_intercepted', tool_calls: 'governed' } : { model_calls: 'governed', tool_calls: 'governed' },
    last_success_at: lastOk?.ts ?? null,
    last_accepted_at: lastAccepted?.ts ?? null,
    last_auth_failure: lastAuthFail ? { at: lastAuthFail.ts, code: lastAuthFail.error_code } : null,
    identity: {
      bootstrap_credentials: { issued: bootstraps.n, exchanged: bootstraps.used ?? 0 },
      clients,
      instances: instances.slice(0, 20),
      live_tokens: liveTokens,
    },
    recent_errors: errors,
    diagnostics,
  };
}

// --- Runtime diagnostics from the SDK or sidecar -------------------------------------------------
// At start-up the SDK reports what it found in the agent's environment: variable NAMES that look like
// direct provider credentials and base URLs that point at a provider instead of the gateway. Values
// never leave the agent. This is detection of a bypass risk, not enforcement; egress rules enforce.

export interface DiagnosticReport {
  client: string;
  runtime?: string;
  framework?: string;
  language?: string;
  gateway_url?: string;
  env_findings?: { name: string; kind: 'provider_key' | 'provider_url'; provider?: string; detail?: string }[];
  egress_check?: { target: string; reachable: boolean }[]; // optional: did a direct connection to a provider succeed?
}

const short = (v: unknown, n = 120) => (typeof v === 'string' ? v.slice(0, n) : undefined);

export async function verifyWorkloadToken(token: string): Promise<WorkloadClaims> {
  let claims: WorkloadClaims;
  try {
    claims = verifyJws<WorkloadClaims>(token, new Map([[keys.token.kid, keys.token.publicKey]]), 'JWT').payload;
  } catch {
    throw new PolicyError('BP-4.2', 'invalid workload token', 401);
  }
  if (claims.exp * 1000 < Date.now()) throw new PolicyError('BP-4.2', 'workload token expired', 401);
  if ((await db.prepare('SELECT 1 FROM revoked_jti WHERE jti = ?').get(claims.jti))) throw new PolicyError('BP-4.2', 'workload token revoked', 401);
  if (claims.tenant !== tenant.id) throw new PolicyError('BP-4.2', 'workload token is for another tenant', 401);
  if (claims.iss !== tokenIssuer(tenant.id) || claims.aud !== TOKEN_AUDIENCE) throw new PolicyError('BP-4.2', 'workload token has an invalid issuer or audience', 401);
  return claims;
}

export async function report(token: string, input: DiagnosticReport) {
  const claims = (await verifyWorkloadToken(token));
  if (!input || typeof input.client !== 'string') throw invalid('client is required');
  const findings = (Array.isArray(input.env_findings) ? input.env_findings : []).slice(0, 50).map((f) => ({
    name: short(f.name, 80) ?? '',
    kind: f.kind === 'provider_url' ? 'provider_url' : 'provider_key',
    provider: short(f.provider, 40),
    detail: short(f.detail, 200),
  }));
  const egress = (Array.isArray(input.egress_check) ? input.egress_check : []).slice(0, 20).map((e) => ({ target: short(e.target, 120) ?? '', reachable: !!e.reachable }));
  const clean = { client: short(input.client, 60)!, runtime: short(input.runtime, 60), framework: short(input.framework, 60), language: short(input.language, 60), gateway_url: short(input.gateway_url, 200), env_findings: findings, egress_check: egress };
  const bypass = findings.length > 0 || egress.some((e) => e.reachable);
  (await tx(async () => {
    (await db.prepare('INSERT INTO agent_diagnostic (instance_id, agent_id, client, report, bypass_risk, reported_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(instance_id) DO UPDATE SET client = excluded.client, report = excluded.report, bypass_risk = excluded.bypass_risk, reported_at = excluded.reported_at').run(
      claims.ins, claims.agent_id, clean.client, JSON.stringify(clean), bypass ? 1 : 0, nowIso(),
    ));
    (await db.prepare("UPDATE discovery_source SET last_ingest_at = ?, last_count = 1, total = total + 1 WHERE id = 'sdk-diagnostics'").run(nowIso()));
    if (bypass) {
      const what = [...findings.map((f) => `${f.kind === 'provider_key' ? 'credential variable' : 'provider URL'} ${f.name}${f.provider ? ` (${f.provider})` : ''}`), ...egress.filter((e) => e.reachable).map((e) => `direct connection to ${e.target} succeeded`)];
      const fingerprint = sha256(`${claims.agent_id}|${what.join('|')}`).slice(0, 16);
      const location = `agent ${claims.agent_id} instance ${claims.ins}`;
      const existing = (await db.prepare('SELECT id FROM discovered_asset WHERE tenant_id = ? AND fingerprint = ? AND location = ?').get(tenant.id, fingerprint, location));
      if (existing) (await db.prepare('UPDATE discovered_asset SET last_seen = ? WHERE id = (SELECT id FROM discovered_asset WHERE tenant_id = ? AND fingerprint = ? AND location = ?)').run(nowIso(), tenant.id, fingerprint, location));
      else {
        (await db.prepare('INSERT INTO discovered_asset (id, tenant_id, source, type, summary, location, fingerprint, status, first_seen, last_seen, evidence, agent_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
          `fnd_${fingerprint}${claims.ins.slice(-6)}`, tenant.id, 'sdk-diagnostics', 'bypass_risk', `Possible gateway bypass: ${what.join('; ')}`, location, fingerprint, 'open', nowIso(), nowIso(), JSON.stringify({ ...clean, detected_not_enforced: true }), claims.agent_id,
        ));
      }
    }
    (await ledger.append({ kind: 'admin', agent_id: claims.agent_id, data: { event: 'identity.diagnostics', instance_id: claims.ins, client: clean.client, bypass_risk: bypass, env_finding_names: findings.map((f) => f.name) } }));
  }));
  return { recorded: true, bypass_risk: bypass, note: bypass ? 'Signet detected a possible bypass in this runtime. Remove the direct provider credentials and restrict outbound traffic to the gateway; Signet does not enforce network egress itself.' : 'no direct provider configuration detected in this runtime' };
}

export const diagnosticsFor = async (agentId: string) => (await db.prepare('SELECT * FROM agent_diagnostic WHERE agent_id = ? ORDER BY reported_at DESC').all(agentId));

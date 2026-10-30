import {
  newId, scopeKey, signJws,
  type CertificateBody, type DetectorConfig, type EnforcementLevel, type PolicyBundle, type ScopeState, type Tier,
} from '@signet/core';
import { compilePolicy, policyHash } from './compile';
import { db, nowIso, tx } from './db';
import { PolicyError, forbidden, invalid } from './errors';
import * as hub from './hub';
import { keys } from './keys';
import * as ledger from './ledger';
import type { Principal } from './rbac';
import { tenant } from './tenant';
import { listTools } from './tools';

const BUNDLE_TTL_MS = 24 * 3_600_000; // BP 3: gateways enforce on the last bundle until it expires

// Ladder parameters (Rulebook: response ladder parameters).
const STEP_UP_MIN: Record<Tier, number> = { T1: 60, T2: 60, T3: 30, T4: 30 };
const THROTTLE: Record<Tier, { factor: number; minutes: number }> = { T1: { factor: 0.25, minutes: 60 }, T2: { factor: 0.25, minutes: 60 }, T3: { factor: 0.5, minutes: 30 }, T4: { factor: 0.5, minutes: 30 } };
const RANK: Record<EnforcementLevel, number> = { active: 0, step_up: 1, throttled: 2, quarantined: 3, killed: 4 };

interface StateRow {
  scope_key: string;
  agent_id: string;
  level: EnforcementLevel;
  rule_id: string | null;
  reason: string | null;
  until_ms: number | null;
  params: string | null;
  updated_at: string;
}

const live = (r: StateRow) => r.level === 'killed' || r.level === 'quarantined' || !r.until_ms || r.until_ms > Date.now();

export function statesFor(agentId: string): StateRow[] {
  return (db.prepare('SELECT * FROM enforcement_state WHERE agent_id = ?').all(agentId) as unknown as StateRow[]).filter(live);
}

// The strictest blocking level that applies to an agent, or to one instance of it.
export function agentBlocked(agentId: string, instanceId?: string): 'killed' | 'quarantined' | null {
  const keys = [scopeKey.agent(agentId)];
  if (instanceId) {
    keys.push(scopeKey.instance(instanceId));
    const inst = db.prepare('SELECT version FROM agent_instance WHERE id = ?').get(instanceId) as { version: string } | undefined;
    if (inst) keys.push(scopeKey.version(agentId, inst.version));
  }
  let worst: 'killed' | 'quarantined' | null = null;
  for (const k of keys) {
    const r = db.prepare('SELECT level FROM enforcement_state WHERE scope_key = ?').get(k) as { level: EnforcementLevel } | undefined;
    if (r?.level === 'killed') return 'killed';
    if (r?.level === 'quarantined') worst = 'quarantined';
  }
  return worst;
}

export function agentLevel(agentId: string): EnforcementLevel {
  const r = db.prepare('SELECT level, until_ms FROM enforcement_state WHERE scope_key = ?').get(scopeKey.agent(agentId)) as { level: EnforcementLevel; until_ms: number | null } | undefined;
  if (!r) return 'active';
  return live({ level: r.level, until_ms: r.until_ms } as StateRow) ? r.level : 'active';
}

function currentCert(agentId: string): CertificateBody | null {
  const row = db.prepare("SELECT body FROM certificate WHERE agent_id = ? AND status = 'active'").get(agentId) as { body: string } | undefined;
  return row ? (JSON.parse(row.body) as CertificateBody) : null;
}

export function buildBundle(): string {
  const now = Date.now();
  const enforcement: Record<string, ScopeState> = {};
  for (const r of (db.prepare("SELECT * FROM enforcement_state WHERE level != 'active'").all() as unknown as StateRow[]).filter(live)) {
    const params = r.params ? (JSON.parse(r.params) as { factor?: number }) : {};
    enforcement[r.scope_key] = { level: r.level, until_ms: r.until_ms, ...(params.factor ? { factor: params.factor } : {}) };
  }
  const rows = db.prepare("SELECT body, jws FROM certificate WHERE status = 'active'").all() as { body: string; jws: string }[];
  const policies: PolicyBundle['policies'] = {};
  for (const r of rows) {
    const cert = JSON.parse(r.body) as CertificateBody;
    const { policy_sha256, ...draft } = cert;
    const compiled = compilePolicy(draft, tenant.settings.baseline);
    if (policyHash(compiled) !== policy_sha256) {
      // The compiler changed since this seal was signed; the gateway would refuse the mismatch anyway.
      console.error(`[control] policy hash mismatch for ${cert.cert_id}; seal left out of the bundle`);
      continue;
    }
    policies[cert.cert_id] = compiled;
  }
  const bundle: PolicyBundle = {
    bundle_id: newId('bnd'),
    version: now,
    tenant: tenant.id,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + BUNDLE_TTL_MS).toISOString(),
    certificates: rows.filter((r) => policies[(JSON.parse(r.body) as CertificateBody).cert_id]).map((r) => r.jws),
    policies,
    enforcement,
    revoked_jti: (db.prepare('SELECT jti FROM revoked_jti WHERE exp > ?').all(Math.floor(now / 1000)) as { jti: string }[]).map((r) => r.jti),
    catalogue: tenant.settings.catalogue,
    tools: listTools(),
    detectors: db.prepare('SELECT id, version, mode FROM detector').all() as unknown as DetectorConfig[],
  };
  return signJws(bundle, keys.ca, 'signet-bundle');
}

export type LadderAction = 'step_up' | 'throttle' | 'quarantine' | 'kill' | 'release';

export interface LadderTarget {
  agentId: string;
  scope?: 'agent' | 'version' | 'instance';
  version?: string;
  instanceId?: string;
}

export interface LadderOptions {
  actor: string;
  reason: string;
  rule_id?: string;
  automatic?: boolean;
  evidence?: Record<string, unknown>;
  minutes?: number;
  factor?: number;
}

// Response ladder levels 2-5 (BP 5.4). Automatic triggers must cite a deterministic rule (RB-INV-05);
// release is human-only (RB-INV-10); a kill is never lifted (RB-INV-08).
export function applyLadder(target: LadderTarget, action: LadderAction, opts: LadderOptions) {
  if (!opts.reason?.trim()) throw invalid('a reason is required');
  if (opts.automatic && !opts.rule_id) throw new PolicyError('RB-INV-05', 'automatic enforcement must reference a rule ID', 400);
  if (action === 'release' && opts.automatic) throw forbidden('RB-INV-10', 'lifting a ladder state is human-only');
  const agent = db.prepare('SELECT id, tier, status FROM agent WHERE id = ?').get(target.agentId) as { id: string; tier: Tier; status: string } | undefined;
  if (!agent) throw new PolicyError('NOT_FOUND', `agent ${target.agentId} not found`, 404);
  const scope = target.scope ?? 'agent';
  if (scope === 'version' && !target.version) throw invalid('version scope needs a version');
  if (scope === 'instance' && !target.instanceId) throw invalid('instance scope needs an instance id');
  if ((action === 'step_up' || action === 'throttle') && scope !== 'agent') throw invalid(`${action} applies to the whole agent`);
  const key = scope === 'agent' ? scopeKey.agent(agent.id) : scope === 'version' ? scopeKey.version(agent.id, target.version!) : scopeKey.instance(target.instanceId!);

  const existing = db.prepare('SELECT * FROM enforcement_state WHERE scope_key = ?').get(key) as StateRow | undefined;
  const current: EnforcementLevel = existing && live(existing) ? existing.level : 'active';
  if (agentLevel(agent.id) === 'killed' || current === 'killed') {
    if (action === 'kill') return { event_id: null, scope_key: key, level: 'killed' as const, already: true };
    throw new PolicyError('RB-INV-08', 'a kill is never lifted; the agent needs a new seal through Assess', 409);
  }
  if (action === 'release' && current === 'active') throw new PolicyError('BP-5.4', 'nothing to release at this scope', 409);

  const level: EnforcementLevel =
    action === 'kill' ? 'killed' : action === 'quarantine' ? 'quarantined' : action === 'throttle' ? 'throttled' : action === 'step_up' ? 'step_up' : 'active';
  // Never weaken a stricter state by applying a milder one; release is the only way down.
  if (action !== 'release' && RANK[level] < RANK[current]) return { event_id: null, scope_key: key, level: current, already: true };
  if (action !== 'release' && level === current && level === 'quarantined') return { event_id: null, scope_key: key, level, already: true };

  const minutes = action === 'step_up' ? (opts.minutes ?? STEP_UP_MIN[agent.tier]) : action === 'throttle' ? (opts.minutes ?? THROTTLE[agent.tier].minutes) : null;
  const params = action === 'throttle' ? { factor: opts.factor ?? THROTTLE[agent.tier].factor } : {};
  const until = minutes ? Date.now() + minutes * 60_000 : null;
  const eventId = newId('evt');
  const ts = Date.now();
  const nodes = hub.connectedNodes().length;
  let tokensRevoked = 0;
  let rotation: string[] = [];

  tx(() => {
    if (level === 'active') db.prepare('DELETE FROM enforcement_state WHERE scope_key = ?').run(key);
    else {
      db.prepare(
        `INSERT INTO enforcement_state (scope_key, agent_id, level, rule_id, reason, until_ms, params, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(scope_key) DO UPDATE SET level = excluded.level, rule_id = excluded.rule_id, reason = excluded.reason, until_ms = excluded.until_ms, params = excluded.params, updated_at = excluded.updated_at`,
      ).run(key, agent.id, level, opts.rule_id ?? null, opts.reason, until, JSON.stringify(params), nowIso());
    }
    if (level === 'killed' || level === 'quarantined') {
      tokensRevoked = revokeTokensFor(agent.id, scope, target);
      if (scope === 'instance') db.prepare('UPDATE agent_instance SET state = ? WHERE id = ?').run(level, target.instanceId!);
    }
    if (level === 'killed') {
      const cert = currentCert(agent.id);
      if (scope === 'agent' || (scope === 'version' && cert?.version === target.version)) {
        db.prepare("UPDATE certificate SET status = 'revoked' WHERE agent_id = ? AND status = 'active'").run(agent.id);
      }
      if (scope === 'agent') db.prepare("UPDATE agent SET status = 'killed' WHERE id = ?").run(agent.id);
      // BP 5.4: credentials the agent could use are rotated.
      rotation = credentialsOf(cert);
      if (rotation.length) db.prepare(`UPDATE secret SET rotation_due = ? WHERE id IN (${rotation.map(() => '?').join(',')}) AND rotation_due IS NULL`).run(`${nowIso()} · kill ${eventId}`, ...rotation);
    } else if (scope === 'agent') {
      db.prepare('UPDATE agent SET status = ? WHERE id = ?').run(level === 'quarantined' ? 'quarantined' : 'sealed', agent.id);
    }
    db.prepare('INSERT INTO enforcement_event (id, agent_id, scope_key, level, rule_id, actor, reason, published_at, published_ms, nodes_expected) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      eventId, agent.id, key, level, opts.rule_id ?? null, opts.actor, opts.reason, new Date(ts).toISOString(), ts, nodes,
    );
    ledger.append({
      kind: 'enforcement',
      agent_id: agent.id,
      data: {
        event: `ladder.${action}`, event_id: eventId, scope_key: key, level, previous_level: current, rule_id: opts.rule_id ?? null,
        actor: opts.actor, automatic: !!opts.automatic, reason: opts.reason, until: until ? new Date(until).toISOString() : null,
        params, tokens_revoked: tokensRevoked, credentials_flagged_for_rotation: rotation, nodes_expected: nodes, evidence: opts.evidence ?? {},
      },
    });
  });
  hub.publish('enforcement', { event_id: eventId, scope_key: key, agent_id: agent.id, state: { level, until_ms: until, ...params }, published_ms: ts });
  return { event_id: eventId, scope_key: key, level, previous_level: current, until: until ? new Date(until).toISOString() : null, nodes_expected: nodes, tokens_revoked: tokensRevoked, credentials_flagged_for_rotation: rotation };
}

function revokeTokensFor(agentId: string, scope: string, t: LadderTarget): number {
  const now = Math.floor(Date.now() / 1000);
  const rows = (
    scope === 'instance'
      ? db.prepare('SELECT jti, exp FROM issued_token WHERE instance_id = ? AND exp > ?').all(t.instanceId!, now)
      : scope === 'version'
        ? db.prepare('SELECT t.jti, t.exp FROM issued_token t JOIN agent_instance i ON i.id = t.instance_id WHERE t.agent_id = ? AND i.version = ? AND t.exp > ?').all(agentId, t.version!, now)
        : db.prepare('SELECT jti, exp FROM issued_token WHERE agent_id = ? AND exp > ?').all(agentId, now)
  ) as { jti: string; exp: number }[];
  for (const r of rows) db.prepare('INSERT OR IGNORE INTO revoked_jti (jti, exp) VALUES (?, ?)').run(r.jti, r.exp);
  return rows.length;
}

function credentialsOf(cert: CertificateBody | null): string[] {
  if (!cert) return [];
  const aliases = cert.tools.map((t) => t.server.replace(/^(mcp|http):\/\//, ''));
  const ids = new Set<string>();
  for (const a of aliases) {
    const r = db.prepare('SELECT secret_id FROM tool WHERE alias = ?').get(a) as { secret_id: string | null } | undefined;
    if (r?.secret_id) ids.add(r.secret_id);
  }
  for (const r of db.prepare("SELECT id FROM secret WHERE kind = 'llm_provider'").all() as { id: string }[]) ids.add(r.id);
  return [...ids];
}

// Windows that ran out (step-up, throttle) are cleared and recorded; gateways also ignore them.
export function sweepExpired() {
  const rows = db.prepare("SELECT * FROM enforcement_state WHERE level IN ('step_up', 'throttled') AND until_ms IS NOT NULL AND until_ms <= ?").all(Date.now()) as unknown as StateRow[];
  for (const r of rows) {
    tx(() => {
      db.prepare('DELETE FROM enforcement_state WHERE scope_key = ?').run(r.scope_key);
      ledger.append({ kind: 'enforcement', agent_id: r.agent_id, data: { event: 'ladder.expired', scope_key: r.scope_key, level: r.level, rule_id: r.rule_id } });
      db.prepare("UPDATE agent SET status = 'sealed' WHERE id = ? AND status = 'quarantined'").run(r.agent_id);
    });
    hub.publish('bundle', { reason: 'ladder.expired', scope_key: r.scope_key });
  }
}

// Level 6 (BP 5.4): every agent matching a selector at once. Human-only, never from a detector
// (RB-KILL-13), and there is no provider selector because one cloud LLM would match every agent (D-20).
export interface Selector {
  model?: string;
  tool?: string;
  tag?: string;
  tier?: Tier;
}

export function matchSelector(sel: Selector) {
  if (!sel.model && !sel.tool && !sel.tag && !sel.tier) throw invalid('a circuit breaker needs at least one condition');
  if ('provider' in sel) throw new PolicyError('D-20', 'there is no provider selector: with one cloud LLM it would stop every agent (use a Tenant stop)', 400);
  const rows = db.prepare("SELECT body FROM certificate WHERE status = 'active'").all() as { body: string }[];
  const glob = (g: string, v: string) => new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`).test(v);
  return rows
    .map((r) => JSON.parse(r.body) as CertificateBody)
    .filter((c) => (!sel.model || c.models.some((m) => glob(sel.model!, m.model) || glob(m.model, sel.model!))) && (!sel.tool || c.tools.some((t) => glob(sel.tool!, t.server))) && (!sel.tag || c.tags.includes(sel.tag)) && (!sel.tier || c.tier === sel.tier))
    .map((c) => c.agent_id);
}

export function armBreaker(sel: Selector, action: 'quarantine' | 'kill', reason: string, p: Principal) {
  if (p.kind !== 'human') throw forbidden('RB-KILL-13', 'circuit breakers are armed by people only');
  const matched = matchSelector(sel);
  const id = newId('cbk');
  db.prepare('INSERT INTO circuit_breaker (id, selector, action, armed_by, reason, matched, armed_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, JSON.stringify(sel), action, p.id, reason, JSON.stringify(matched), nowIso());
  ledger.append({ kind: 'enforcement', data: { event: 'circuit_breaker.armed', breaker_id: id, selector: sel, action, matched, actor: p.id, reason } });
  const results = matched.map((agentId) => applyLadder({ agentId }, action, { actor: p.id, reason: `circuit breaker ${id}: ${reason}`, rule_id: 'BP-5.4-L6' }));
  return { breaker_id: id, matched: matched.length, results };
}

export function recordAck(eventId: string, nodeId: string) {
  const ev = db.prepare('SELECT published_ms FROM enforcement_event WHERE id = ?').get(eventId) as { published_ms: number } | undefined;
  if (!ev) return;
  db.prepare('INSERT OR IGNORE INTO kill_ack (event_id, gateway_node_id, acked_at, latency_ms) VALUES (?, ?, ?, ?)').run(eventId, nodeId, nowIso(), Date.now() - ev.published_ms);
}

export function eventStatus(eventId: string) {
  const ev = db.prepare('SELECT * FROM enforcement_event WHERE id = ?').get(eventId);
  if (!ev) throw new PolicyError('NOT_FOUND', 'event not found', 404);
  const acks = db.prepare('SELECT gateway_node_id, acked_at, latency_ms FROM kill_ack WHERE event_id = ? ORDER BY latency_ms').all(eventId);
  return { event: ev, acks };
}

export function recentEvents(limit: number, agentId?: string) {
  const rows = (agentId
    ? db.prepare('SELECT * FROM enforcement_event WHERE agent_id = ? ORDER BY published_ms DESC LIMIT ?').all(agentId, limit)
    : db.prepare('SELECT * FROM enforcement_event ORDER BY published_ms DESC LIMIT ?').all(limit)) as { id: string }[];
  return rows.map((e) => ({ ...e, acks: db.prepare('SELECT gateway_node_id, latency_ms FROM kill_ack WHERE event_id = ? ORDER BY latency_ms').all(e.id) }));
}

export const breakers = () => db.prepare('SELECT * FROM circuit_breaker ORDER BY armed_at DESC LIMIT 20').all();

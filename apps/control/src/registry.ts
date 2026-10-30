import {
  DATA_TAGS, RESTRICTED_TAGS, canonicalize, newId, sha256, signJws,
  type Autonomy, type CertificateBody, type DataTag, type HitlRule, type Impact, type Limits, type ModelGrant, type Tier, type ToolGrant,
} from '@signet/core';
import { compilePolicy, policyHash } from './compile';
import { db, nowIso, tx } from './db';
import { PolicyError, forbidden, invalid, notFound } from './errors';
import { keys } from './keys';
import * as ledger from './ledger';
import { can, type Permission, type Principal } from './rbac';
import { tenant } from './tenant';
import { getTool } from './tools';

export interface AgentRow {
  id: string;
  tenant_id: string;
  handle: string;
  name: string;
  purpose: string;
  owner: string;
  sponsor: string;
  tier: Tier;
  autonomy_level: Autonomy;
  status: string;
  created_at: string;
  created_by: string;
}

const TIERS: Tier[] = ['T1', 'T2', 'T3', 'T4'];
const AUTONOMY: Autonomy[] = ['L0', 'L1', 'L2', 'L3', 'L4'];
const IMPACTS: Impact[] = ['read', 'write', 'privileged', 'critical'];
const VALIDITY_DAYS: Record<Tier, number> = { T1: 90, T2: 180, T3: 365, T4: 365 }; // BP 4.3

export function getAgent(ref: string): AgentRow {
  const row = db.prepare('SELECT * FROM agent WHERE tenant_id = ? AND (id = ? OR handle = ?)').get(tenant.id, ref, ref) as AgentRow | undefined;
  if (!row) throw notFound(`agent ${ref}`);
  return row;
}

export const teamOf = (agentId: string) =>
  db.prepare('SELECT user, role FROM agent_team_member WHERE agent_id = ?').all(agentId) as { user: string; role: string }[];

// Owners may act on their own agents with owner-scoped permissions; everyone else needs the role.
export function assertCan(p: Principal, perm: Permission, agent: AgentRow) {
  if (!can(p, perm)) throw forbidden('RBAC', `needs permission ${perm}`);
  const ownerOnly = p.roles.every((r) => r === 'agent_owner' || r === 'builder' || r === 'viewer');
  if (ownerOnly && agent.owner !== p.id) throw forbidden('RBAC', `${p.id} does not own ${agent.handle}`);
}

export interface RegisterInput {
  handle: string;
  name: string;
  purpose: string;
  owner?: string;
  sponsor: string;
  tier: Tier;
  autonomy_level: Autonomy;
  team?: { user: string; role: 'builder' | 'operator' }[];
}

// Phase 1 registry: the proposer states the tier. The Classify stage (risk score) replaces this in Phase 2.
export function registerAgent(input: RegisterInput, p: Principal): AgentRow {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(input.handle ?? '') || input.handle.length > 63) throw invalid('handle must be kebab-case, at most 63 characters');
  for (const f of ['name', 'purpose', 'sponsor'] as const) if (!String(input[f] ?? '').trim()) throw invalid(`${f} is required`);
  if (!TIERS.includes(input.tier)) throw invalid('tier must be T1-T4');
  if (!AUTONOMY.includes(input.autonomy_level)) throw invalid('autonomy_level must be L0-L4');
  const owner = (input.owner ?? p.id).toLowerCase();
  if (p.kind === 'human' && !can(p, 'certificates.approve') && owner !== p.id) throw forbidden('RBAC', 'agent owners can only propose agents they own');
  const id = newId('agt');
  return tx(() => {
    if (db.prepare('SELECT 1 FROM agent WHERE tenant_id = ? AND handle = ?').get(tenant.id, input.handle)) {
      throw new PolicyError('VALIDATION', `handle ${input.handle} is taken`, 409);
    }
    db.prepare(
      'INSERT INTO agent (id, tenant_id, handle, name, purpose, owner, sponsor, tier, autonomy_level, status, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(id, tenant.id, input.handle, input.name.trim(), input.purpose.trim(), owner, input.sponsor.toLowerCase(), input.tier, input.autonomy_level, 'proposed', nowIso(), p.id);
    for (const m of input.team ?? []) db.prepare('INSERT INTO agent_team_member (agent_id, user, role) VALUES (?, ?, ?)').run(id, m.user.toLowerCase(), m.role);
    ledger.append({ kind: 'lifecycle', agent_id: id, data: { event: 'agent.registered', handle: input.handle, tier: input.tier, autonomy_level: input.autonomy_level, owner, actor: p.id } });
    return getAgent(id);
  });
}

const globToRegex = (glob: string) => new RegExp(`^${glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`);
export const globMatch = (glob: string, value: string) => globToRegex(glob).test(value);

export interface SealInput {
  models: ModelGrant[];
  tools?: ToolGrant[];
  data_classes?: { prompt?: DataTag[]; forbidden?: DataTag[] };
  hitl?: HitlRule[];
  limits: Limits;
  environments: string[];
  tags?: string[];
  ai_disclosure?: boolean;
}

// Seal validation: every check cites the rule it enforces.
function validateSeal(agent: AgentRow, input: SealInput) {
  if (!input.models?.length) throw new PolicyError('RB-BL-01', 'a seal needs at least one model');
  for (const m of input.models) {
    if (!tenant.settings.catalogue.some((c) => globMatch(m.model, c.model))) {
      throw new PolicyError('RB-INV-19', `model ${m.model} is not the tenant's cloud LLM (${tenant.settings.catalogue.map((c) => c.model).join(', ')})`);
    }
  }
  const actionKeys = new Set<string>();
  for (const t of input.tools ?? []) {
    const m = t.server.match(/^(mcp|http):\/\/([a-z0-9-]+)$/);
    if (!m) throw invalid(`tool server ${t.server} must look like mcp://<alias> or http://<alias>`);
    const alias = getTool(m[2]!);
    if (!alias) throw new PolicyError('BP-5.1', `tool alias ${m[2]} is not registered`);
    if (alias.kind !== m[1]) throw invalid(`tool alias ${m[2]} is a ${alias.kind} tool, not ${m[1]}`);
    for (const tag of t.data_scopes ?? []) {
      if (!DATA_TAGS.includes(tag)) throw invalid(`unknown data tag ${tag}`);
      if (tag === 'secrets') throw new PolicyError('RB-INV-16', 'secrets can never be passed in tool arguments; the gateway injects credentials');
    }
    for (const a of t.actions ?? []) {
      if (!IMPACTS.includes(a.impact)) throw new PolicyError('RB-PRIV-01', `action ${t.server}.${a.name} has no impact label`);
      if (agent.tier === 'T4' && (a.impact === 'privileged' || a.impact === 'critical')) {
        throw new PolicyError('RB-INV-17', `T4 seals cannot contain ${a.impact} action ${t.server}.${a.name}`);
      }
      if (alias.kind === 'http' && !alias.actions[a.name]) throw invalid(`http tool ${m[2]} has no action ${a.name}`);
      for (const [arg, c] of Object.entries(a.constraints ?? {})) {
        if (c.pattern) {
          try {
            new RegExp(c.pattern);
          } catch {
            throw invalid(`constraint pattern for ${a.name}.${arg} is not a valid regular expression`);
          }
        }
      }
      actionKeys.add(`${t.server}.${a.name}`);
    }
  }
  for (const h of input.hitl ?? []) {
    if (!actionKeys.has(h.action)) throw invalid(`hitl rule references ${h.action}, which is not in the manifest`);
    if (!h.approver_group) throw invalid('hitl rules need an approver_group');
  }
  const prompt = input.data_classes?.prompt ?? [];
  for (const tag of [...prompt, ...(input.data_classes?.forbidden ?? [])]) if (!DATA_TAGS.includes(tag)) throw invalid(`unknown data tag ${tag}`);
  if (prompt.includes('secrets')) throw new PolicyError('RB-INV-16', 'credentials and secrets can never be allowed to reach a model');
  const restricted = prompt.filter((t) => RESTRICTED_TAGS.includes(t));
  if (restricted.length && agent.tier !== 'T1' && agent.tier !== 'T2') {
    throw new PolicyError('RB-INV-17', `only T1/T2 seals may allow Restricted tags (${restricted.join(', ')})`);
  }
  const l = input.limits;
  if (!(l?.rpm > 0 && l.tokens_per_day > 0 && l.usd_per_day >= 0)) throw invalid('limits need rpm, tokens_per_day and usd_per_day');
  if (!input.environments?.length) throw invalid('environments[] is required');
}

// Simplified approve-and-certify (Phase 1, BP 20.2). The 8-stage lifecycle and approval matrix
// replace it in Phase 2; separation of duties already applies (RB-INV-09).
export function issueSeal(agentRef: string, input: SealInput, p: Principal) {
  const agent = getAgent(agentRef);
  if (!can(p, 'certificates.approve')) throw forbidden('RBAC', 'needs permission certificates.approve');
  if (p.kind !== 'human') throw forbidden('RB-INV-10', 'seals are approved by people, not service accounts');
  if (agent.status === 'killed') throw new PolicyError('RB-INV-08', 'a killed agent re-enters only through a new lifecycle from Assess', 409);
  if (agent.status === 'retired') throw new PolicyError('VALIDATION', 'agent is retired', 409);
  const team = teamOf(agent.id).map((m) => m.user);
  if ([agent.created_by, agent.owner, ...team].includes(p.id)) {
    throw forbidden('RB-INV-09', `${p.id} proposed, owns or builds this agent and cannot approve it`);
  }
  validateSeal(agent, input);

  const issued = new Date();
  const count = (db.prepare('SELECT COUNT(*) AS n FROM certificate WHERE agent_id = ?').get(agent.id) as { n: number }).n;
  const draft: Omit<CertificateBody, 'policy_sha256'> = {
    cert_id: newId('crt'),
    agent_id: agent.id,
    version: `v${count + 1}.0`,
    tenant: tenant.id,
    owner: agent.owner,
    approvers: [{ user: p.id, at: issued.toISOString() }],
    tier: agent.tier,
    autonomy_level: agent.autonomy_level,
    models: input.models,
    tools: input.tools ?? [],
    data_classes: { prompt: input.data_classes?.prompt ?? [], forbidden: input.data_classes?.forbidden ?? [] },
    hitl: input.hitl ?? [],
    limits: input.limits,
    environments: input.environments,
    tags: input.tags ?? [],
    ai_disclosure: input.ai_disclosure ?? true,
    valid_from: issued.toISOString(),
    valid_to: new Date(issued.getTime() + VALIDITY_DAYS[agent.tier] * 86_400_000).toISOString(),
    issued_at: issued.toISOString(),
  };
  const policy = compilePolicy(draft, tenant.settings.baseline);
  const body: CertificateBody = { ...draft, policy_sha256: policyHash(policy) };
  const jws = signJws(body, keys.ca, 'signet-seal');
  tx(() => {
    db.prepare("UPDATE certificate SET status = 'superseded' WHERE agent_id = ? AND status = 'active'").run(agent.id);
    db.prepare('INSERT INTO certificate (id, agent_id, version, body, jws, policy_hash, status, valid_from, valid_to, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      body.cert_id, agent.id, body.version, JSON.stringify(body), jws, body.policy_sha256, 'active', body.valid_from, body.valid_to, body.issued_at,
    );
    db.prepare("UPDATE agent SET status = 'sealed' WHERE id = ?").run(agent.id);
    ledger.append({
      kind: 'lifecycle',
      agent_id: agent.id,
      cert_id: body.cert_id,
      data: { event: 'certificate.issued', version: body.version, cert_sha256: sha256(canonicalize(body)), policy_sha256: body.policy_sha256, approver: p.id, valid_to: body.valid_to },
    });
  });
  return { certificate: body, jws, policy };
}

export function activeCertificate(agentId: string) {
  const row = db.prepare("SELECT body, jws FROM certificate WHERE agent_id = ? AND status = 'active'").get(agentId) as { body: string; jws: string } | undefined;
  return row ? { certificate: JSON.parse(row.body) as CertificateBody, jws: row.jws } : null;
}

export function certificates(agentId: string) {
  return (db.prepare('SELECT id, version, status, valid_from, valid_to, issued_at FROM certificate WHERE agent_id = ? ORDER BY issued_at DESC').all(agentId)) as {
    id: string; version: string; status: string; valid_from: string; valid_to: string; issued_at: string;
  }[];
}

export function listAgents(opts: { tier?: string; status?: string; q?: string; cursor?: string | null; limit: number }) {
  const where = ['a.tenant_id = ?'];
  const args: (string | number)[] = [tenant.id];
  if (opts.tier) (where.push('a.tier = ?'), args.push(opts.tier));
  if (opts.status) (where.push('a.status = ?'), args.push(opts.status));
  if (opts.q) (where.push('(a.handle LIKE ? OR a.name LIKE ? OR a.owner LIKE ?)'), args.push(`%${opts.q}%`, `%${opts.q}%`, `%${opts.q}%`));
  if (opts.cursor) (where.push('a.id < ?'), args.push(opts.cursor));
  args.push(opts.limit + 1);
  const rows = db
    .prepare(
      `SELECT a.*, c.id AS cert_id, c.version, c.valid_to,
              (SELECT MAX(ts) FROM ledger_record l WHERE l.agent_id = a.id AND l.kind = 'transaction') AS last_activity
       FROM agent a LEFT JOIN certificate c ON c.agent_id = a.id AND c.status = 'active'
       WHERE ${where.join(' AND ')} ORDER BY a.id DESC LIMIT ?`,
    )
    .all(...args) as unknown as (AgentRow & { cert_id: string | null; version: string | null; valid_to: string | null; last_activity: string | null })[];
  const more = rows.length > opts.limit;
  const items = rows.slice(0, opts.limit);
  return { items, next_cursor: more ? items[items.length - 1]!.id : null };
}

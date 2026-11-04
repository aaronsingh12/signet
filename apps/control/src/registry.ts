import {
  DATA_TAGS, RESTRICTED_TAGS, canonicalize, newId, sha256, signJws,
  type Autonomy, type CertificateBody, type ConnectionMethod, type DataTag, type HitlRule, type Impact, type Limits, type ModelGrant, type Tier, type ToolGrant,
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
  kind: AgentKind;
  runtime: string | null;
  framework: string | null;
  model_provider: string | null;
  vendor: string | null;
  vendor_details: string; // JSON
  connection_method: ConnectionMethod | null;
}

// How an agent reaches Signet. Self-hosted, framework and no-code agents send their model and tool
// calls through the gateway. Third-party (vendor-hosted) agents keep their vendor's model, which
// Signet cannot see; only the company tools they call through the gateway are governed.
export type AgentKind = 'self_hosted' | 'framework' | 'no_code' | 'third_party';
export const AGENT_KINDS: AgentKind[] = ['self_hosted', 'framework', 'no_code', 'third_party'];
const shortText = (v: unknown, max = 80) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);

const TIERS: Tier[] = ['T1', 'T2', 'T3', 'T4'];
const AUTONOMY: Autonomy[] = ['L0', 'L1', 'L2', 'L3', 'L4'];
const IMPACTS: Impact[] = ['read', 'write', 'privileged', 'critical'];
const VALIDITY_DAYS: Record<Tier, number> = { T1: 90, T2: 180, T3: 365, T4: 365 }; // BP 4.3

export async function getAgent(ref: string): Promise<AgentRow> {
  const row = (await db.prepare('SELECT * FROM agent WHERE tenant_id = ? AND (id = ? OR handle = ?)').get(tenant.id, ref, ref)) as AgentRow | undefined;
  if (!row) throw notFound(`agent ${ref}`);
  return row;
}

export const teamOf = async (agentId: string) =>
  (await db.prepare('SELECT "user", role FROM agent_team_member WHERE agent_id = ?').all(agentId)) as { user: string; role: string }[];

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
  tier?: Tier; // provisional; the Classify stage sets the real tier
  autonomy_level: Autonomy;
  team?: { user: string; role: 'builder' | 'operator' }[];
  kind?: AgentKind;
  runtime?: string;
  framework?: string;
  model_provider?: string;
  vendor?: string;
  vendor_details?: Record<string, string>;
  connection_method?: ConnectionMethod;
}

// Stage 1 Propose: the agent gets its permanent ID; the tier is provisional until Classify (BP 6).
export async function registerAgent(input: RegisterInput, p: Principal): Promise<AgentRow> {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(input.handle ?? '') || input.handle.length > 63) throw invalid('handle must be kebab-case, at most 63 characters');
  for (const f of ['name', 'purpose', 'sponsor'] as const) if (typeof input[f] !== 'string' || !input[f].trim()) throw invalid(`${f} must be a non-empty string`);
  if (input.name.length > 200 || input.sponsor.length > 200) throw invalid('name and sponsor must be at most 200 characters');
  if (input.purpose.trim().length < 10 || input.purpose.length > 4000) throw invalid('purpose must be 10 to 4000 characters');
  if (input.team !== undefined && (!Array.isArray(input.team) || input.team.some((m) => typeof m?.user !== 'string' || !m.user.trim() || !['builder', 'operator'].includes(m.role)))) throw invalid('team must be a list of members, each with a user and the role builder or operator');
  if (input.connection_method !== undefined && !['oauth', 'rest', 'bootstrap', 'hybrid'].includes(input.connection_method)) throw invalid('connection_method must be oauth, rest, bootstrap or hybrid');
  const tier: Tier = input.tier ?? 'T3';
  if (!TIERS.includes(tier)) throw invalid('tier must be T1-T4');
  if (!AUTONOMY.includes(input.autonomy_level)) throw invalid('autonomy_level must be L0-L4');
  const kind: AgentKind = input.kind ?? 'self_hosted';
  if (!AGENT_KINDS.includes(kind)) throw invalid(`kind must be one of ${AGENT_KINDS.join(', ')}`);
  if (kind === 'third_party' && (input.connection_method === 'bootstrap' || input.connection_method === 'hybrid')) throw invalid('vendor-hosted agents connect through OAuth or REST for company tools');
  if (kind === 'third_party' && !shortText(input.vendor)) throw invalid('a third-party agent needs its vendor');
  const vendorDetails = Object.fromEntries(Object.entries(input.vendor_details ?? {}).filter(([k, v]) => /^[a-z_]{1,40}$/.test(k) && typeof v === 'string').map(([k, v]) => [k, String(v).slice(0, 500)]));
  const owner = (input.owner ?? p.id).toLowerCase();
  if (p.kind === 'human' && !can(p, 'certificates.approve') && owner !== p.id) throw forbidden('RBAC', 'agent owners can only propose agents they own');
  const id = newId('agt');
  return (await tx(async () => {
    if ((await db.prepare('SELECT 1 FROM agent WHERE tenant_id = ? AND handle = ?').get(tenant.id, input.handle))) {
      throw new PolicyError('VALIDATION', `handle ${input.handle} is taken`, 409);
    }
    (await db.prepare(
      'INSERT INTO agent (id, tenant_id, handle, name, purpose, owner, sponsor, tier, autonomy_level, status, created_at, created_by, kind, runtime, framework, model_provider, vendor, vendor_details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(
      id, tenant.id, input.handle, input.name.trim(), input.purpose.trim(), owner, input.sponsor.toLowerCase(), tier, input.autonomy_level, 'proposed', nowIso(), p.id,
      kind, shortText(input.runtime), shortText(input.framework), shortText(input.model_provider), kind === 'third_party' ? shortText(input.vendor) : null, JSON.stringify(vendorDetails),
    ));
    (await db.prepare('UPDATE agent SET connection_method = ? WHERE id = ?').run(input.connection_method ?? (kind === 'third_party' ? 'oauth' : 'bootstrap'), id));
    for (const m of input.team ?? []) (await db.prepare('INSERT INTO agent_team_member (agent_id, "user", role) VALUES (?, ?, ?)').run(id, m.user.toLowerCase(), m.role));
    (await ledger.append({ kind: 'lifecycle', agent_id: id, data: { event: 'agent.registered', handle: input.handle, agent_kind: kind, vendor: input.vendor ?? null, provisional_tier: tier, autonomy_level: input.autonomy_level, owner, actor: p.id } }));
    return (await getAgent(id));
  }));
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
  detector_unavailability?: 'hold' | 'audit';
}

// Seal validation: every check cites the rule it enforces.
export async function validateSeal(agent: Pick<AgentRow, 'tier'> & { id?: string; kind?: AgentKind }, input: SealInput) {
  if (input.models !== undefined && !Array.isArray(input.models)) throw invalid('models must be a list');
  if (input.tools !== undefined && !Array.isArray(input.tools)) throw invalid('tools must be a list');
  if (agent.kind === 'third_party') {
    // The vendor's model runs outside Signet; a model grant would claim coverage Signet does not have.
    if (input.models?.length) throw new PolicyError('VALIDATION', 'a third-party agent uses its vendor\'s model, which Signet cannot route; list no models, only the company tools it may call');
    if (!input.tools?.length) {
      const externalIdentity = agent.id ? await db.prepare('SELECT 1 FROM external_agent_mapping m JOIN external_connection c ON c.id = m.connection_id WHERE m.agent_id = ? AND c.tenant_id = ?').get(agent.id, tenant.id) : undefined;
      if (!externalIdentity) throw new PolicyError('VALIDATION', 'a third-party agent needs a mapped REST platform connection or at least one company tool');
    }
  } else if (!input.models?.length) throw new PolicyError('RB-BL-01', 'a seal needs at least one model');
  if (input.detector_unavailability !== undefined && !['hold', 'audit'].includes(input.detector_unavailability)) throw invalid('detector_unavailability must be hold or audit');
  for (const m of input.models) {
    if (!tenant.settings.catalogue.some((c) => globMatch(m.model, c.model))) {
      throw new PolicyError('RB-INV-19', `model ${m.model} is not the tenant's cloud LLM (${tenant.settings.catalogue.map((c) => c.model).join(', ')})`);
    }
  }
  const actionKeys = new Set<string>();
  for (const t of input.tools ?? []) {
    const m = t.server.match(/^(mcp|http):\/\/([a-z0-9-]+)$/);
    if (!m) throw invalid(`tool server ${t.server} must look like mcp://<alias> or http://<alias>`);
    const alias = (await getTool(m[2]!));
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
  if (!Array.isArray(input.environments) || !input.environments.length) throw invalid('environments[] is required');
  const knownEnvironments = new Set(['dev', 'test', 'staging', 'prod', 'production', process.env.SIGNET_ENV ?? 'dev']);
  for (const e of input.environments) if (!knownEnvironments.has(e)) throw invalid(`unknown environment ${e}; use one of ${[...knownEnvironments].join(', ')}`);
  const contradictory = prompt.filter((t) => input.data_classes?.forbidden?.includes(t));
  if (contradictory.length) throw invalid(`${contradictory.join(', ')} cannot be both allowed and forbidden`);
}

// Seal signing (BP 4.3, 6 Stage 5). Called only by the lifecycle once the approval matrix is
// satisfied (or automatically for T4 on passing tests); approvers and evidence go into the seal.
export interface SealContext {
  approvers: { user: string; at: string }[];
  evidence_refs: Record<string, string>;
  regulatory_category: string;
  minor: boolean;
  actor: string;
}

/** Preserve approvals for agents registered before lifecycle onboarding was introduced. */
export async function issueSeal(agentRef: string, input: SealInput, actor: Principal): Promise<Awaited<ReturnType<typeof signSeal>>> {
  const agent = (await getAgent(agentRef));
  if (!can(actor, 'certificates.approve') || actor.kind !== 'human') throw forbidden('RBAC', 'a human certificate approver is required');
  if ([agent.owner, agent.created_by, ...(await teamOf(agent.id)).map((member) => member.user)].includes(actor.id)) throw forbidden('RB-INV-09', 'owners, proposers and builders cannot approve their own agent');
  if ((await db.prepare('SELECT 1 FROM lifecycle WHERE agent_id = ?').get(agent.id))) throw new PolicyError('BP-6', 'Complete this agent’s lifecycle approval matrix before issuing its seal', 409);
  return (await signSeal(agent.id, input, { approvers: [{ user: actor.id, at: nowIso() }], evidence_refs: {}, regulatory_category: 'legacy', minor: false, actor: actor.id }));
}

export async function signSeal(agentRef: string, input: SealInput, ctx: SealContext) {
  const agent = (await getAgent(agentRef));
  if (agent.status === 'killed') throw new PolicyError('RB-INV-08', 'a killed agent re-enters only through a new lifecycle from Assess', 409);
  if (agent.status === 'retired') throw new PolicyError('VALIDATION', 'agent is retired', 409);
  (await validateSeal(agent, input));
  const issued = new Date();
  const prev = (await db.prepare("SELECT version FROM certificate WHERE agent_id = ? ORDER BY issued_at DESC LIMIT 1").get(agent.id)) as { version: string } | undefined;
  const [maj, min] = (prev?.version ?? 'v0.0').slice(1).split('.').map(Number) as [number, number];
  const version = !prev ? 'v1.0' : ctx.minor ? `v${maj}.${min + 1}` : `v${maj + 1}.0`;
  const draft: Omit<CertificateBody, 'policy_sha256'> = {
    cert_id: newId('crt'),
    agent_id: agent.id,
    version,
    tenant: tenant.id,
    owner: agent.owner,
    approvers: ctx.approvers,
    tier: agent.tier,
    autonomy_level: agent.autonomy_level,
    regulatory_category: ctx.regulatory_category,
    models: input.models,
    tools: input.tools ?? [],
    data_classes: { prompt: input.data_classes?.prompt ?? [], forbidden: input.data_classes?.forbidden ?? [] },
    hitl: input.hitl ?? [],
    limits: input.limits,
    environments: input.environments,
    tags: input.tags ?? [],
    ai_disclosure: input.ai_disclosure ?? true,
    evidence_refs: ctx.evidence_refs,
    detector_unavailability: input.detector_unavailability ?? 'hold',
    valid_from: issued.toISOString(),
    valid_to: new Date(issued.getTime() + VALIDITY_DAYS[agent.tier] * 86_400_000).toISOString(),
    issued_at: issued.toISOString(),
  };
  const policy = compilePolicy(draft, tenant.settings.baseline);
  const body: CertificateBody = { ...draft, policy_sha256: policyHash(policy) };
  const jws = signJws(body, keys.ca, 'signet-seal');
  (await tx(async () => {
    (await db.prepare("UPDATE certificate SET status = 'superseded' WHERE agent_id = ? AND status = 'active'").run(agent.id));
    (await db.prepare('INSERT INTO certificate (id, agent_id, version, body, jws, policy_hash, status, valid_from, valid_to, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
      body.cert_id, agent.id, body.version, JSON.stringify(body), jws, body.policy_sha256, 'active', body.valid_from, body.valid_to, body.issued_at,
    ));
    (await db.prepare("UPDATE agent SET status = 'sealed' WHERE id = ?").run(agent.id));
    (await ledger.append({
      kind: 'lifecycle',
      agent_id: agent.id,
      cert_id: body.cert_id,
      data: { event: 'certificate.issued', version: body.version, cert_sha256: sha256(canonicalize(body)), policy_sha256: body.policy_sha256, approvers: ctx.approvers.map((a) => a.user), evidence_refs: ctx.evidence_refs, valid_to: body.valid_to, actor: ctx.actor },
    }));
  }));
  return { certificate: body, jws, policy };
}

export async function activeCertificate(agentId: string) {
  const row = (await db.prepare("SELECT body, jws FROM certificate WHERE agent_id = ? AND status = 'active'").get(agentId)) as { body: string; jws: string } | undefined;
  return row ? { certificate: JSON.parse(row.body) as CertificateBody, jws: row.jws } : null;
}

export async function certificates(agentId: string) {
  return ((await db.prepare('SELECT id, version, status, valid_from, valid_to, issued_at FROM certificate WHERE agent_id = ? ORDER BY issued_at DESC').all(agentId))) as {
    id: string; version: string; status: string; valid_from: string; valid_to: string; issued_at: string;
  }[];
}

export async function listAgents(opts: { tier?: string; status?: string; q?: string; cursor?: string | null; limit: number }) {
  const where = ['a.tenant_id = ?'];
  const args: (string | number)[] = [tenant.id];
  if (opts.tier) (where.push('a.tier = ?'), args.push(opts.tier));
  if (opts.status) (where.push('a.status = ?'), args.push(opts.status));
  if (opts.q) (where.push('(a.handle LIKE ? OR a.name LIKE ? OR a.owner LIKE ?)'), args.push(`%${opts.q}%`, `%${opts.q}%`, `%${opts.q}%`));
  if (opts.cursor) (where.push('a.id < ?'), args.push(opts.cursor));
  args.push(opts.limit + 1);
  const rows = (await db
    .prepare(
      `SELECT a.*, c.id AS cert_id, c.version, c.valid_to,
              (SELECT MAX(ts) FROM ledger_record l WHERE l.agent_id = a.id AND l.kind = 'transaction') AS last_activity
       FROM agent a LEFT JOIN certificate c ON c.agent_id = a.id AND c.status = 'active'
       WHERE ${where.join(' AND ')} ORDER BY a.id DESC LIMIT ?`,
    )
    .all(...args)) as unknown as (AgentRow & { cert_id: string | null; version: string | null; valid_to: string | null; last_activity: string | null })[];
  const more = rows.length > opts.limit;
  const items = rows.slice(0, opts.limit);
  return { items, next_cursor: more ? items[items.length - 1]!.id : null };
}

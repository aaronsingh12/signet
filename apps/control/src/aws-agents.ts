import { newId, sha256 } from '@signet/core';
import { status } from './connectivity';
import { db, nowIso, tx } from './db';
import { PolicyError, invalid, notFound } from './errors';
import * as ledger from './ledger';
import * as platforms from './platforms';
import { DRIVERS, awsCall } from './platform-drivers';
import type { Principal } from './rbac';
import { getAgent, registerAgent } from './registry';
import { revealPlatformCredential } from './secrets';
import { tenant } from './tenant';
import * as workflow from './workflow';

// Amazon Bedrock agents. An admin connects an AWS account once with a read-only IAM user. Signet lists the
// account's agents in the chosen regions and links a chosen one as a vendor-hosted agent; review, approval,
// seal and gateway credentials then follow the normal lifecycle. Linking registers identity only: it never
// creates or changes the agent in AWS. Three kinds of agent exist:
//   - AgentCore harness: a managed agent (model + prompt + tools) built in the AgentCore console.
//   - AgentCore runtime: an agent built with any framework and deployed to AgentCore.
//   - Agents Classic: the older Bedrock Agents, closed to new AWS customers since July 2026.
// AgentCore agents reach Signet through an AgentCore Gateway with an MCP server target and an OAuth client;
// Agents Classic can only call tools through a Lambda action group.

export const AWS_VENDOR = 'Amazon Bedrock';

export type AwsAgentKind = 'agentcore_harness' | 'agentcore_runtime' | 'agents_classic';
const PREFIX: Record<AwsAgentKind, string> = { agentcore_harness: 'agentcore-harness', agentcore_runtime: 'agentcore-runtime', agents_classic: 'bedrock' };
export const AWS_KIND_LABEL: Record<AwsAgentKind, string> = { agentcore_harness: 'AgentCore harness', agentcore_runtime: 'AgentCore runtime', agents_classic: 'Agents Classic' };
const REGION = '[a-z]{2}(?:-[a-z]+)+-\\d';
const AGENT_REF = new RegExp(`^(agentcore-harness|agentcore-runtime|bedrock):(${REGION}):([A-Za-z0-9_-]{1,100})$`);
const CLASSIC_SHORT_REF = new RegExp(`^(${REGION}):([A-Z0-9]{10})$`);
const READY = new Set(['READY', 'PREPARED', 'ACTIVE']);

interface AwsConnectionRow { id: string; label: string; secret_id: string; scope: string; status: string; status_detail: string | null; created_at: string }
interface AwsConnection extends Omit<AwsConnectionRow, 'scope'> { secret: string; scope: Record<string, string> }

export interface AwsConnectionView {
  id: string; label: string; account_id: string | null; regions: string; status: string; status_detail: string | null; created_at: string; linked_agents: number;
}

export interface AwsAgent { ref: string; kind: AwsAgentKind; kind_label: string; id: string; name: string; region: string; status: string; active: boolean }

export interface LinkedAwsAgent {
  agent_id: string; agent_ref: string; kind_label: string; connection_id: string; name: string; handle: string; purpose: string; gateway_enforcement: boolean;
}

const accountInArn = (text: string | null) => text?.match(/arn:aws[a-z-]*:[a-z0-9-]+::(\d{12}):/)?.[1] ?? null;
// The account is saved in the connection scope when it is created, so a later error message cannot change it.
const accountOf = (c: AwsConnection) => c.scope.account_id ?? accountInArn(c.status_detail);
const regionsOf = (c: AwsConnection) => (c.scope.regions ?? 'us-east-1').split(',').map((r) => r.trim()).filter(Boolean);
const control = (region: string, path: string) => new URL(`https://bedrock-agentcore-control.${region}.amazonaws.com${path}`);

async function connectionRow(id: string): Promise<AwsConnection> {
  const row = await db.prepare("SELECT id, label, secret_id, scope, status, status_detail, created_at FROM platform_connection WHERE tenant_id = ? AND id = ? AND platform = 'aws' AND revoked_at IS NULL").get(tenant.id, id) as AwsConnectionRow | undefined;
  if (!row) throw notFound(`AWS connection ${id}`);
  return { ...row, scope: JSON.parse(row.scope) as Record<string, string>, secret: await revealPlatformCredential(row.secret_id) };
}

async function view(c: AwsConnection): Promise<AwsConnectionView> {
  const linked = await db.prepare('SELECT COUNT(*) AS n FROM platform_link WHERE tenant_id = ? AND connection_id = ?').get(tenant.id, c.id) as { n: number };
  return { id: c.id, label: c.label, account_id: accountOf(c), regions: regionsOf(c).join(','), status: c.status, status_detail: c.status_detail, created_at: c.created_at, linked_agents: Number(linked.n) };
}

export async function listAwsConnections(): Promise<AwsConnectionView[]> {
  const rows = await db.prepare("SELECT id FROM platform_connection WHERE tenant_id = ? AND platform = 'aws' AND revoked_at IS NULL ORDER BY created_at DESC").all(tenant.id) as { id: string }[];
  return Promise.all(rows.map(async (row) => view(await connectionRow(row.id))));
}

export async function awsConnection(id: string): Promise<AwsConnectionView> {
  return view(await connectionRow(id));
}

/** Proves the access key can sign in (STS GetCallerIdentity) before anything is stored. */
export async function createAwsConnection(input: platforms.CreateInput, actor: Principal): Promise<AwsConnectionView> {
  const created = await platforms.create({ ...input, platform: 'aws' }, actor);
  const account = accountInArn(created.status_detail);
  if (account) await db.prepare('UPDATE platform_connection SET scope = ? WHERE tenant_id = ? AND id = ?').run(JSON.stringify({ ...created.scope, account_id: account }), tenant.id, created.id);
  return awsConnection(created.id);
}

/** Signs in to AWS again with the stored access key and records the result. */
export async function testAwsConnection(id: string, actor: Principal): Promise<AwsConnectionView> {
  const c = await connectionRow(id);
  let state = 'connected';
  let detail: string;
  try { detail = await DRIVERS.aws.validate(c.secret, c.scope); }
  catch (error) {
    if (!(error instanceof PolicyError)) throw error;
    state = 'error';
    detail = error.message;
  }
  const account = state === 'connected' && !c.scope.account_id ? accountInArn(detail) : null;
  await db.prepare('UPDATE platform_connection SET status = ?, status_detail = ?, scope = ? WHERE tenant_id = ? AND id = ?')
    .run(state, detail, JSON.stringify(account ? { ...c.scope, account_id: account } : c.scope), tenant.id, id);
  await ledger.append({ kind: 'admin', data: { event: 'aws.connection_tested', connection_id: id, status: state, actor: actor.id } });
  return awsConnection(id);
}

export async function removeAwsConnection(id: string, actor: Principal): Promise<{ disconnected: true }> {
  await connectionRow(id);
  await platforms.remove(id, actor);
  return { disconnected: true };
}

const agentOf = (kind: AwsAgentKind, region: string, id: string, name: string | undefined, state: string | undefined): AwsAgent =>
  ({ ref: `${PREFIX[kind]}:${region}:${id}`, kind, kind_label: AWS_KIND_LABEL[kind], id, name: name || id, region, status: state ?? 'unknown', active: READY.has(state ?? '') });

async function agentCoreAgents(c: AwsConnection, region: string): Promise<AwsAgent[]> {
  const harnesses = await awsCall<{ harnesses?: { harnessId: string; harnessName?: string; status?: string }[] }>(c.secret, region, 'bedrock-agentcore', 'GET', control(region, '/harnesses?maxResults=100'));
  const runtimes = await awsCall<{ agentRuntimes?: { agentRuntimeId: string; agentRuntimeName?: string; status?: string }[] }>(c.secret, region, 'bedrock-agentcore', 'POST', control(region, '/runtimes/?maxResults=100'), {});
  return [
    ...(harnesses.harnesses ?? []).map((h) => agentOf('agentcore_harness', region, h.harnessId, h.harnessName, h.status)),
    ...(runtimes.agentRuntimes ?? []).map((r) => agentOf('agentcore_runtime', region, r.agentRuntimeId, r.agentRuntimeName, r.status)),
  ];
}

async function classicAgents(c: AwsConnection): Promise<AwsAgent[]> {
  return (await DRIVERS.aws.workloads(c.secret, c.scope)).filter((w) => w.kind === 'bedrock_agent')
    .map((w) => agentOf('agents_classic', w.region!, w.id.split(':')[2]!, w.name, w.framework ?? undefined));
}

/** Reads every kind of agent separately: a missing permission for one kind must not hide the others. */
export async function availableAwsAgents(id: string): Promise<AwsAgent[]> {
  const c = await connectionRow(id);
  const found: AwsAgent[] = [];
  const failures: PolicyError[] = [];
  const read = async (source: () => Promise<AwsAgent[]>) => {
    try { found.push(...await source()); }
    catch (error) { if (error instanceof PolicyError) failures.push(error); else throw error; }
  };
  for (const region of regionsOf(c)) await read(() => agentCoreAgents(c, region));
  await read(() => classicAgents(c));
  if (failures.length && !found.length) {
    const first = failures[0]!;
    if (first.rule === 'PLATFORM_AUTH') throw new PolicyError('AWS_PERMISSIONS', `AWS refused to list agents (${first.message}). Check that the IAM user's policy allows bedrock-agentcore:ListHarnesses, bedrock-agentcore:ListAgentRuntimes, bedrock:ListAgents and lambda:ListFunctions, then load again`, 403);
    throw first;
  }
  if (failures.length) console.warn('Some AWS agent lists could not be read', { connection_id: id, failures: failures.map((f) => f.message) });
  return found;
}

/** Accepts the reference Signet shows (kind:region:id) or region:ID for an Agents Classic agent. */
export function parseAgentRef(raw: unknown): { ref: string; kind: AwsAgentKind; region: string; id: string } {
  if (typeof raw !== 'string') throw invalid('Choose an agent with Load agents, or enter its reference');
  const text = raw.trim();
  const short = text.match(CLASSIC_SHORT_REF);
  if (short) return { ref: `bedrock:${short[1]}:${short[2]}`, kind: 'agents_classic', region: short[1]!, id: short[2]! };
  const match = text.match(AGENT_REF);
  if (!match) throw invalid('Enter the agent reference: agentcore-harness:<region>:<harness ID>, agentcore-runtime:<region>:<runtime ID>, or <region>:<agent ID> for Agents Classic');
  const kind = (Object.keys(PREFIX) as AwsAgentKind[]).find((k) => PREFIX[k] === match[1])!;
  if (kind === 'agents_classic' && !/^[A-Z0-9]{10}$/.test(match[3]!)) throw invalid('An Agents Classic ID has 10 capital letters or digits, e.g. us-east-1:ABCDE12345');
  return { ref: text, kind, region: match[2]!, id: match[3]! };
}

/** Links one existing Bedrock agent as a vendor-hosted agent; it is never created or changed in AWS. */
export async function linkAwsAgent(connectionId: string, input: { agent_ref?: unknown; name?: unknown; purpose?: unknown }, actor: Principal): Promise<{ agent_id: string }> {
  if (!actor.permissions.includes('agents.write')) throw new PolicyError('RBAC', 'Linking an Amazon Bedrock agent requires agents.write', 403);
  const ref = parseAgentRef(input.agent_ref);
  if (typeof input.name !== 'string' || !input.name.trim() || input.name.length > 200) throw invalid('Agent name is required and must not exceed 200 characters');
  if (typeof input.purpose !== 'string' || input.purpose.trim().length < 10 || input.purpose.length > 4000) throw invalid('Agent purpose must contain 10–4000 characters');
  const name = input.name.trim();
  const purpose = input.purpose.trim();
  const c = await connectionRow(connectionId);
  const account = accountOf(c);
  if (!account) throw new PolicyError('AWS_CONFIG', 'Signet does not know the AWS account of this connection yet. Use Test connection, then link the agent again', 409);
  if (!regionsOf(c).includes(ref.region)) throw invalid(`This connection reads ${regionsOf(c).join(', ')}, not ${ref.region}. Add the region to a connection first`);
  // The agent must exist in this account: a typo must not register an identity nobody can govern.
  const agent = (await availableAwsAgents(connectionId)).find((a) => a.ref === ref.ref);
  if (!agent) throw new PolicyError('AWS_AGENT_NOT_FOUND', `No ${AWS_KIND_LABEL[ref.kind]} ${ref.id} exists in account ${account}, region ${ref.region}. Use Load agents, or copy the ID from the AgentCore or Bedrock console`, 404);
  const details = { account_id: account, region: ref.region, agent_id: ref.id, agent_type: AWS_KIND_LABEL[ref.kind] };
  return tx(async () => {
    await db.prepare('SELECT id FROM platform_connection WHERE tenant_id = ? AND id = ? FOR UPDATE').get(tenant.id, connectionId);
    const viaLink = await db.prepare('SELECT agent_id FROM platform_link WHERE tenant_id = ? AND connection_id = ? AND workload_id = ?').get(tenant.id, connectionId, ref.ref) as { agent_id: string } | undefined;
    const viaVendor = viaLink ? undefined : await db.prepare(`SELECT id AS agent_id FROM agent WHERE tenant_id = ? AND vendor = ?
      AND jsonb_extract_path_text(vendor_details::jsonb, 'account_id') = ?
      AND jsonb_extract_path_text(vendor_details::jsonb, 'region') = ?
      AND jsonb_extract_path_text(vendor_details::jsonb, 'agent_id') = ?
      AND jsonb_extract_path_text(vendor_details::jsonb, 'agent_type') = ? LIMIT 1`).get(tenant.id, AWS_VENDOR, account, ref.region, ref.id, details.agent_type) as { agent_id: string } | undefined;
    const prior = viaLink ?? viaVendor;
    const registered = prior ? await getAgent(prior.agent_id) : await registerAgent({
      handle: `bedrock-${sha256(`${account}:${ref.ref}`).slice(0, 24)}`,
      name, purpose, sponsor: actor.id, owner: actor.id,
      autonomy_level: 'L0', kind: 'third_party', vendor: AWS_VENDOR, connection_method: 'oauth', vendor_details: details,
    }, actor);
    if (!prior) await workflow.start(registered, {}, actor, 'initial', null);
    const now = nowIso();
    const inserted = await db.prepare('INSERT INTO platform_link (id, tenant_id, connection_id, workload_id, workload_name, agent_id, settings, state, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (connection_id, workload_id) DO NOTHING')
      .run(newId('pll'), tenant.id, connectionId, ref.ref, agent.name, registered.id, '{}', 'registered', actor.id, now, now);
    if (inserted.changes) await ledger.append({ kind: 'lifecycle', agent_id: registered.id, data: { event: 'aws.agent_linked', connection_id: connectionId, ...details, agent_name: agent.name, actor: actor.id } });
    return { agent_id: registered.id };
  });
}

/** Linked agents with gateway coverage taken from real gateway evidence, not from the link itself. */
export async function linkedAwsAgents(connectionId: string): Promise<LinkedAwsAgent[]> {
  await connectionRow(connectionId);
  const rows = await db.prepare(`SELECT l.agent_id, l.workload_id, l.connection_id, a.name, a.handle, a.purpose
    FROM platform_link l JOIN agent a ON a.id = l.agent_id WHERE l.tenant_id = ? AND a.tenant_id = ? AND l.connection_id = ? ORDER BY a.name`)
    .all(tenant.id, tenant.id, connectionId) as { agent_id: string; workload_id: string; connection_id: string; name: string; handle: string; purpose: string }[];
  return Promise.all(rows.filter((row) => AGENT_REF.test(row.workload_id)).map(async (row) => {
    const kind = (Object.keys(PREFIX) as AwsAgentKind[]).find((k) => row.workload_id.startsWith(`${PREFIX[k]}:`))!;
    return {
      agent_id: row.agent_id, agent_ref: row.workload_id, kind_label: AWS_KIND_LABEL[kind], connection_id: row.connection_id,
      name: row.name, handle: row.handle, purpose: row.purpose,
      gateway_enforcement: (await status(row.agent_id)).gateway_enforcement_active,
    };
  }));
}

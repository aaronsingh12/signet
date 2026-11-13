import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { newId } from '@signet/core';
import { db, nowIso, tx } from './db';
import { PolicyError, forbidden, invalid, notFound } from './errors';
import * as ledger from './ledger';
import { notify } from './notify';
import { can, type Principal } from './rbac';

// SCIM 2.0 provisioning (RFC 7643 / 7644; BP 4, 6 Stage 7, 11.4). The identity provider (Microsoft Entra
// ID, Okta, Ping, Keycloak with a SCIM plug-in ...) pushes people and groups to Signet. What Signet does
// with them:
//   - Leavers: when a person is deactivated or deleted, every agent they own is flagged; the sponsor
//     must name a new owner within 10 business days (14 calendar days), or the agent is quarantined.
//   - A deactivated person cannot use Signet, even before their sign-in session expires.
// Roles still come from the groups in the sign-in token, so SCIM never grants access by itself.
//
// Base URL for the identity provider: <control>/api/v1/scim/v2, with a bearer token from POST /scim/token.

const SCHEMA = {
  user: 'urn:ietf:params:scim:schemas:core:2.0:User',
  group: 'urn:ietf:params:scim:schemas:core:2.0:Group',
  list: 'urn:ietf:params:scim:api:messages:2.0:ListResponse',
  patch: 'urn:ietf:params:scim:api:messages:2.0:PatchOp',
  error: 'urn:ietf:params:scim:api:messages:2.0:Error',
};
export const OWNER_GRACE_DAYS = 14; // 10 business days
const MAX_PAGE = 200;

export class ScimError extends Error {
  constructor(readonly status: number, message: string, readonly scimType?: string) { super(message); }
  body() { return { schemas: [SCHEMA.error], status: String(this.status), detail: this.message, ...(this.scimType ? { scimType: this.scimType } : {}) }; }
}

// --- Token -------------------------------------------------------------------------------------------
const hash = (s: string) => createHash('sha256').update(s).digest('hex');

/** Create a new SCIM token (shown once); earlier tokens stop working. */
export async function issueToken(p: Principal) {
  const token = `scim_${randomBytes(32).toString('base64url')}`;
  await tx(async () => {
    await db.prepare('UPDATE scim_token SET revoked_at = ? WHERE revoked_at IS NULL').run(nowIso());
    await db.prepare('INSERT INTO scim_token (id, token_sha256, created_by, created_at) VALUES (?, ?, ?, ?)').run(newId('evt').replace('evt_', 'sct_'), hash(token), p.id, nowIso());
    await ledger.append({ kind: 'admin', data: { event: 'scim.token_issued', actor: p.id } });
  });
  return { token, base_path: '/api/v1/scim/v2' };
}

export async function checkToken(header: string | undefined) {
  const token = /^Bearer\s+(\S+)$/i.exec(header ?? '')?.[1];
  if (!token) throw new ScimError(401, 'a bearer token is required');
  const rows = (await db.prepare('SELECT token_sha256 FROM scim_token WHERE revoked_at IS NULL').all()) as { token_sha256: string }[];
  const given = Buffer.from(hash(token), 'hex');
  if (!rows.some((r) => timingSafeEqual(Buffer.from(r.token_sha256, 'hex'), given))) throw new ScimError(401, 'invalid SCIM token');
}

// --- Users -------------------------------------------------------------------------------------------
interface UserRow { id: string; external_id: string | null; user_name: string; display_name: string | null; emails: string; active: number; created_at: string; updated_at: string }
const toBool = (v: unknown) => (typeof v === 'string' ? v.toLowerCase() === 'true' : v === true);
const emailsOf = (body: Record<string, unknown>): string[] => (Array.isArray(body.emails) ? body.emails : []).map((e: { value?: unknown }) => String(e?.value ?? '').toLowerCase()).filter(Boolean);

function userView(u: UserRow, base: string) {
  return {
    schemas: [SCHEMA.user], id: u.id, ...(u.external_id ? { externalId: u.external_id } : {}), userName: u.user_name,
    ...(u.display_name ? { displayName: u.display_name, name: { formatted: u.display_name } } : {}),
    emails: (JSON.parse(u.emails) as string[]).map((value, i) => ({ value, primary: i === 0, type: 'work' })),
    active: !!u.active,
    meta: { resourceType: 'User', created: u.created_at, lastModified: u.updated_at, location: `${base}/Users/${u.id}` },
  };
}

async function getUserRow(id: string) {
  const u = (await db.prepare('SELECT * FROM scim_user WHERE id = ? AND deleted = 0').get(id)) as UserRow | undefined;
  if (!u) throw new ScimError(404, `user ${id} not found`);
  return u;
}

function parseFilter(filter: string | undefined): { attr: string; value: string } | null {
  if (!filter) return null;
  const m = /^\s*([A-Za-z.]+)\s+eq\s+"([^"]*)"\s*$/.exec(filter);
  if (!m) throw new ScimError(400, 'only "<attribute> eq \"value\"" filters are supported', 'invalidFilter');
  return { attr: m[1]!.toLowerCase(), value: m[2]! };
}

export async function listUsers(q: { filter?: string; startIndex?: string; count?: string }, base: string) {
  const f = parseFilter(q.filter);
  const col = f ? ({ username: 'user_name', externalid: 'external_id', id: 'id' } as Record<string, string>)[f.attr] : null;
  if (f && !col && f.attr !== 'emails.value') throw new ScimError(400, `filtering on ${f.attr} is not supported`, 'invalidFilter');
  let rows = (await db.prepare('SELECT * FROM scim_user WHERE deleted = 0 ORDER BY created_at').all()) as unknown as UserRow[];
  if (f) rows = rows.filter((u) => (f.attr === 'emails.value' ? (JSON.parse(u.emails) as string[]).includes(f.value.toLowerCase()) : f.attr === 'username' ? u.user_name.toLowerCase() === f.value.toLowerCase() : (u as unknown as Record<string, unknown>)[col!] === f.value));
  return page(rows.map((u) => userView(u, base)), q);
}

function page<T>(items: T[], q: { startIndex?: string; count?: string }) {
  const start = Math.max(1, Number(q.startIndex) || 1);
  const count = Math.min(MAX_PAGE, Math.max(0, q.count === undefined ? MAX_PAGE : Number(q.count) || 0));
  return { schemas: [SCHEMA.list], totalResults: items.length, startIndex: start, itemsPerPage: Math.min(count, Math.max(0, items.length - start + 1)), Resources: items.slice(start - 1, start - 1 + count) };
}

export const getUser = async (id: string, base: string) => userView(await getUserRow(id), base);

export async function createUser(body: Record<string, unknown>, base: string) {
  const userName = String(body.userName ?? '').trim().toLowerCase();
  if (!userName) throw new ScimError(400, 'userName is required', 'invalidValue');
  if (await db.prepare('SELECT id FROM scim_user WHERE user_name = ? AND deleted = 0').get(userName)) throw new ScimError(409, `user ${userName} already exists`, 'uniqueness');
  const id = newId('evt').replace('evt_', 'usr_');
  const now = nowIso();
  const active = body.active === undefined ? true : toBool(body.active);
  await tx(async () => {
    await db.prepare('INSERT INTO scim_user (id, external_id, user_name, display_name, emails, active, deleted, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)')
      .run(id, body.externalId ? String(body.externalId) : null, userName, displayNameOf(body), JSON.stringify(emailsOf(body)), active ? 1 : 0, now, now);
    await ledger.append({ kind: 'admin', data: { event: 'scim.user_created', user_id: id, user_name: userName, active, actor: 'scim' } });
  });
  return userView(await getUserRow(id), base);
}

const displayNameOf = (body: Record<string, unknown>) => (typeof body.displayName === 'string' ? body.displayName : (body.name as { formatted?: string; givenName?: string; familyName?: string } | undefined)?.formatted ?? ([((body.name as { givenName?: string }) ?? {}).givenName, ((body.name as { familyName?: string }) ?? {}).familyName].filter(Boolean).join(' ') || null));

export async function replaceUser(id: string, body: Record<string, unknown>, base: string) {
  const u = await getUserRow(id);
  const active = body.active === undefined ? !!u.active : toBool(body.active);
  await saveUser(u, { user_name: String(body.userName ?? u.user_name).toLowerCase(), display_name: displayNameOf(body) ?? u.display_name, emails: body.emails ? emailsOf(body) : JSON.parse(u.emails), external_id: body.externalId ? String(body.externalId) : u.external_id, active });
  return userView(await getUserRow(id), base);
}

/** PATCH as sent by Entra ID and Okta: replace/add on active, displayName, userName, emails, externalId. */
export async function patchUser(id: string, body: { Operations?: { op?: string; path?: string; value?: unknown }[] }, base: string) {
  const u = await getUserRow(id);
  const next = { user_name: u.user_name, display_name: u.display_name, emails: JSON.parse(u.emails) as string[], external_id: u.external_id, active: !!u.active };
  for (const o of body.Operations ?? []) {
    const op = String(o.op ?? '').toLowerCase();
    if (!['replace', 'add', 'remove'].includes(op)) throw new ScimError(400, `unsupported op ${o.op}`, 'invalidSyntax');
    const apply = (path: string, v: unknown) => {
      const p = path.toLowerCase();
      if (p === 'active') next.active = op === 'remove' ? false : toBool(v);
      else if (p === 'displayname') next.display_name = op === 'remove' ? null : String(v);
      else if (p === 'username') next.user_name = String(v).toLowerCase();
      else if (p === 'externalid') next.external_id = op === 'remove' ? null : String(v);
      else if (p.startsWith('emails')) next.emails = op === 'remove' ? [] : Array.isArray(v) ? v.map((e: { value?: unknown }) => String(e?.value ?? e).toLowerCase()) : [String(v).toLowerCase()];
      // Other attributes (name parts, title, department ...) are accepted and ignored.
    };
    if (o.path) apply(o.path, o.value);
    else if (o.value && typeof o.value === 'object') for (const [k, v] of Object.entries(o.value as Record<string, unknown>)) apply(k, v);
  }
  await saveUser(u, next);
  return userView(await getUserRow(id), base);
}

export async function deleteUser(id: string) {
  const u = await getUserRow(id);
  await saveUser(u, { user_name: u.user_name, display_name: u.display_name, emails: JSON.parse(u.emails), external_id: u.external_id, active: false });
  await db.prepare('UPDATE scim_user SET deleted = 1 WHERE id = ?').run(id);
  await db.prepare('DELETE FROM scim_group_member WHERE user_id = ?').run(id);
}

async function saveUser(u: UserRow, next: { user_name: string; display_name: string | null; emails: string[]; external_id: string | null; active: boolean }) {
  await tx(async () => {
    await db.prepare('UPDATE scim_user SET user_name = ?, display_name = ?, emails = ?, external_id = ?, active = ?, updated_at = ? WHERE id = ?')
      .run(next.user_name, next.display_name, JSON.stringify(next.emails), next.external_id, next.active ? 1 : 0, nowIso(), u.id);
    if (!!u.active && !next.active) await ownerLeft([u.user_name, ...next.emails], u.id);
    if (!u.active && next.active) await ownerReturned([next.user_name, ...next.emails], u.id);
    if (!!u.active !== next.active) await ledger.append({ kind: 'admin', data: { event: next.active ? 'scim.user_reactivated' : 'scim.user_deactivated', user_id: u.id, user_name: next.user_name, actor: 'scim' } });
  });
  inactiveCache.clear();
}

// --- Leavers (BP 6 Stage 7: "sponsor must reassign within 10 business days or agent suspended") -------
async function ownerLeft(identities: string[], userId: string) {
  const ids = [...new Set(identities.map((x) => x.toLowerCase()))];
  const agents = (await db.prepare(`SELECT id, handle, sponsor FROM agent WHERE status != 'retired' AND owner_left_at IS NULL AND lower(owner) IN (${ids.map(() => '?').join(',')})`).all(...ids)) as { id: string; handle: string; sponsor: string }[];
  const due = new Date(Date.now() + OWNER_GRACE_DAYS * 86_400_000).toISOString();
  for (const a of agents) {
    await db.prepare('UPDATE agent SET owner_left_at = ? WHERE id = ?').run(nowIso(), a.id);
    await ledger.append({ kind: 'lifecycle', agent_id: a.id, data: { event: 'agent.owner_left', handle: a.handle, user_id: userId, reassign_by: due, actor: 'scim' } });
    await notify(a.sponsor.toLowerCase(), 'owner_left', `The owner of ${a.handle} has left. Name a new owner by ${due.slice(0, 10)}, or the agent will be quarantined.`, `/agents/${a.id}`);
  }
}

async function ownerReturned(identities: string[], userId: string) {
  const ids = [...new Set(identities.map((x) => x.toLowerCase()))];
  const agents = (await db.prepare(`SELECT id, handle FROM agent WHERE owner_left_at IS NOT NULL AND lower(owner) IN (${ids.map(() => '?').join(',')})`).all(...ids)) as { id: string; handle: string }[];
  for (const a of agents) {
    await db.prepare('UPDATE agent SET owner_left_at = NULL WHERE id = ?').run(a.id);
    await ledger.append({ kind: 'lifecycle', agent_id: a.id, data: { event: 'agent.owner_returned', handle: a.handle, user_id: userId, actor: 'scim' } });
  }
}

/** Name a new owner for an agent. The sponsor, or someone who can approve agents, may do this. */
export async function reassignOwner(agentId: string, input: { owner?: string; reason?: string }, p: Principal) {
  const agent = (await db.prepare('SELECT id, handle, owner, sponsor, status FROM agent WHERE id = ?').get(agentId)) as { id: string; handle: string; owner: string; sponsor: string; status: string } | undefined;
  if (!agent) throw notFound(`agent ${agentId}`);
  if (p.id !== agent.sponsor.toLowerCase() && !can(p, 'certificates.approve')) throw forbidden('BP-6-S7', 'only the sponsor or an approver can name a new owner');
  const owner = String(input.owner ?? '').trim().toLowerCase();
  if (!owner || owner.length > 200) throw invalid('owner must be a person (email or user name)');
  if (!input.reason?.trim()) throw invalid('a reason is required');
  if (await isDeactivated(owner)) throw new PolicyError('BP-6-S7', `${owner} is deactivated in the identity provider`, 409);
  await tx(async () => {
    await db.prepare('UPDATE agent SET owner = ?, owner_left_at = NULL WHERE id = ?').run(owner, agent.id);
    await ledger.append({ kind: 'lifecycle', agent_id: agent.id, data: { event: 'agent.owner_reassigned', handle: agent.handle, from: agent.owner, to: owner, reason: input.reason, actor: p.id } });
  });
  return { agent_id: agent.id, owner };
}

/** Agents whose owner left more than the grace period ago and still have no new owner. */
export async function overdueOwnerless(): Promise<{ id: string; handle: string; owner_left_at: string }[]> {
  const cutoff = new Date(Date.now() - OWNER_GRACE_DAYS * 86_400_000).toISOString();
  return (await db.prepare("SELECT id, handle, owner_left_at FROM agent WHERE owner_left_at IS NOT NULL AND owner_left_at < ? AND status != 'retired'").all(cutoff)) as { id: string; handle: string; owner_left_at: string }[];
}

// --- Deactivated people cannot use Signet -----------------------------------------------------------
const inactiveCache = new Map<string, { inactive: boolean; at: number }>();
export async function isDeactivated(identity: string): Promise<boolean> {
  const id = identity.toLowerCase();
  const hit = inactiveCache.get(id);
  if (hit && Date.now() - hit.at < 60_000) return hit.inactive;
  const rows = (await db.prepare('SELECT user_name, emails, active, deleted FROM scim_user WHERE user_name = ? OR emails LIKE ?').all(id, `%"${id.replace(/[%_"]/g, '')}"%`)) as { user_name: string; emails: string; active: number; deleted: number }[];
  const match = rows.filter((r) => r.user_name === id || (JSON.parse(r.emails) as string[]).includes(id));
  // Known to SCIM and none of the matching records is active: deactivated.
  const inactive = match.length > 0 && match.every((r) => !r.active || r.deleted);
  if (inactiveCache.size > 5000) inactiveCache.clear();
  inactiveCache.set(id, { inactive, at: Date.now() });
  return inactive;
}

// --- Groups (kept in step with the identity provider; roles still come from the sign-in token) --------
interface GroupRow { id: string; external_id: string | null; display_name: string; created_at: string; updated_at: string }
async function groupView(g: GroupRow, base: string) {
  const members = (await db.prepare('SELECT m.user_id, u.user_name FROM scim_group_member m JOIN scim_user u ON u.id = m.user_id WHERE m.group_id = ?').all(g.id)) as { user_id: string; user_name: string }[];
  return { schemas: [SCHEMA.group], id: g.id, ...(g.external_id ? { externalId: g.external_id } : {}), displayName: g.display_name, members: members.map((m) => ({ value: m.user_id, display: m.user_name, $ref: `${base}/Users/${m.user_id}` })), meta: { resourceType: 'Group', created: g.created_at, lastModified: g.updated_at, location: `${base}/Groups/${g.id}` } };
}
async function getGroupRow(id: string) {
  const g = (await db.prepare('SELECT * FROM scim_group WHERE id = ?').get(id)) as GroupRow | undefined;
  if (!g) throw new ScimError(404, `group ${id} not found`);
  return g;
}
export async function listGroups(q: { filter?: string; startIndex?: string; count?: string; excludedAttributes?: string }, base: string) {
  const f = parseFilter(q.filter);
  if (f && !['displayname', 'externalid', 'id'].includes(f.attr)) throw new ScimError(400, `filtering on ${f.attr} is not supported`, 'invalidFilter');
  let rows = (await db.prepare('SELECT * FROM scim_group ORDER BY created_at').all()) as unknown as GroupRow[];
  if (f) rows = rows.filter((g) => (f.attr === 'displayname' ? g.display_name.toLowerCase() === f.value.toLowerCase() : f.attr === 'externalid' ? g.external_id === f.value : g.id === f.value));
  const views = await Promise.all(rows.map((g) => groupView(g, base)));
  return page(q.excludedAttributes?.includes('members') ? views.map(({ members: _m, ...v }) => v) : views, q);
}
export const getGroup = async (id: string, base: string) => groupView(await getGroupRow(id), base);
async function setMembers(groupId: string, ids: string[], mode: 'replace' | 'add' | 'remove') {
  if (mode === 'replace') await db.prepare('DELETE FROM scim_group_member WHERE group_id = ?').run(groupId);
  for (const userId of ids) {
    if (mode === 'remove') await db.prepare('DELETE FROM scim_group_member WHERE group_id = ? AND user_id = ?').run(groupId, userId);
    else if (await db.prepare('SELECT id FROM scim_user WHERE id = ? AND deleted = 0').get(userId)) await db.prepare('INSERT INTO scim_group_member (group_id, user_id) VALUES (?, ?) ON CONFLICT DO NOTHING').run(groupId, userId);
  }
}
const memberIds = (v: unknown) => (Array.isArray(v) ? v : v ? [v] : []).map((m: { value?: unknown }) => String(m?.value ?? '')).filter(Boolean);
export async function createGroup(body: Record<string, unknown>, base: string) {
  const name = String(body.displayName ?? '').trim();
  if (!name) throw new ScimError(400, 'displayName is required', 'invalidValue');
  if (await db.prepare('SELECT id FROM scim_group WHERE lower(display_name) = ?').get(name.toLowerCase())) throw new ScimError(409, `group ${name} already exists`, 'uniqueness');
  const id = newId('evt').replace('evt_', 'grp_');
  await tx(async () => {
    await db.prepare('INSERT INTO scim_group (id, external_id, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)').run(id, body.externalId ? String(body.externalId) : null, name, nowIso(), nowIso());
    await setMembers(id, memberIds(body.members), 'add');
    await ledger.append({ kind: 'admin', data: { event: 'scim.group_created', group_id: id, name, actor: 'scim' } });
  });
  return getGroup(id, base);
}
export async function replaceGroup(id: string, body: Record<string, unknown>, base: string) {
  const g = await getGroupRow(id);
  await tx(async () => {
    await db.prepare('UPDATE scim_group SET display_name = ?, updated_at = ? WHERE id = ?').run(String(body.displayName ?? g.display_name), nowIso(), id);
    await setMembers(id, memberIds(body.members), 'replace');
  });
  return getGroup(id, base);
}
export async function patchGroup(id: string, body: { Operations?: { op?: string; path?: string; value?: unknown }[] }, base: string) {
  await getGroupRow(id);
  await tx(async () => {
    for (const o of body.Operations ?? []) {
      const op = String(o.op ?? '').toLowerCase();
      const path = (o.path ?? '').toLowerCase();
      const filtered = /^members\[value eq "([^"]+)"\]$/i.exec(o.path ?? '');
      if (filtered && op === 'remove') await setMembers(id, [filtered[1]!], 'remove');
      else if (path === 'members' || (!o.path && o.value && typeof o.value === 'object' && 'members' in (o.value as object))) {
        const value = o.path ? o.value : (o.value as { members: unknown }).members;
        await setMembers(id, memberIds(value), op === 'replace' ? 'replace' : op === 'remove' ? 'remove' : 'add');
      } else if (path === 'displayname' || (!o.path && o.value && typeof o.value === 'object' && 'displayName' in (o.value as object))) {
        await db.prepare('UPDATE scim_group SET display_name = ? WHERE id = ?').run(String(o.path ? o.value : (o.value as { displayName: unknown }).displayName), id);
      } else if (!['add', 'replace', 'remove'].includes(op)) throw new ScimError(400, `unsupported op ${o.op}`, 'invalidSyntax');
    }
    await db.prepare('UPDATE scim_group SET updated_at = ? WHERE id = ?').run(nowIso(), id);
  });
  return getGroup(id, base);
}
export async function deleteGroup(id: string) {
  await getGroupRow(id);
  await db.prepare('DELETE FROM scim_group_member WHERE group_id = ?').run(id);
  await db.prepare('DELETE FROM scim_group WHERE id = ?').run(id);
}

// --- Discovery documents ----------------------------------------------------------------------------
export const serviceProviderConfig = () => ({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
  patch: { supported: true }, bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
  filter: { supported: true, maxResults: MAX_PAGE }, changePassword: { supported: false }, sort: { supported: false }, etag: { supported: false },
  authenticationSchemes: [{ type: 'oauthbearertoken', name: 'Bearer token', description: 'Token from Signet (Settings, People & roles)' }],
});
export const resourceTypes = () => ({ schemas: [SCHEMA.list], totalResults: 2, Resources: [
  { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'User', name: 'User', endpoint: '/Users', schema: SCHEMA.user },
  { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'Group', name: 'Group', endpoint: '/Groups', schema: SCHEMA.group },
] });

/** Summary for the console. */
export async function status() {
  const users = (await db.prepare('SELECT COUNT(*) AS n, SUM(active) AS active FROM scim_user WHERE deleted = 0').get()) as { n: number; active: number | null };
  const token = (await db.prepare('SELECT created_at, created_by FROM scim_token WHERE revoked_at IS NULL ORDER BY created_at DESC LIMIT 1').get()) as { created_at: string; created_by: string } | undefined;
  const flagged = (await db.prepare("SELECT id, handle, owner, sponsor, owner_left_at FROM agent WHERE owner_left_at IS NOT NULL AND status != 'retired' ORDER BY owner_left_at").all()) as { owner_left_at: string }[];
  return {
    token: token ?? null, base_path: '/api/v1/scim/v2',
    users: Number(users.n), active_users: Number(users.active ?? 0),
    groups: Number(((await db.prepare('SELECT COUNT(*) AS n FROM scim_group').get()) as { n: number }).n),
    agents_without_owner: flagged.map((a) => ({ ...a, reassign_by: new Date(Date.parse(a.owner_left_at) + OWNER_GRACE_DAYS * 86_400_000).toISOString() })),
  };
}

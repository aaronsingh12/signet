import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// SCIM 2.0 provisioning (BP 11.4) and owner leavers (BP 6 Stage 7).
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-scim-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
process.env.SIGNET_SINGLE_OPERATOR = 'false';
const { db } = await import('../src/db');
const scim = await import('../src/scim');
const registry = await import('../src/registry');
const { permissionsFor } = await import('../src/rbac');
after(dropTestDatabase);
type Role = Parameters<typeof permissionsFor>[0][number];
const person = (id: string, roles: Role[]) => ({ id, name: id, kind: 'human' as const, roles, permissions: permissionsFor(roles), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) });
const admin = person('admin@x.example', ['tenant_admin']);
const base = 'https://signet.example/api/v1/scim/v2';

test('token: issued once, checked by hash, a new token replaces the old one', async () => {
  const a = await scim.issueToken(admin);
  await scim.checkToken(`Bearer ${a.token}`);
  const b = await scim.issueToken(admin);
  await assert.rejects(scim.checkToken(`Bearer ${a.token}`), /invalid SCIM token/);
  await scim.checkToken(`Bearer ${b.token}`);
  await assert.rejects(scim.checkToken(undefined), /bearer token is required/);
});

test('users: create, filter by userName, Entra-style PATCH, duplicate refused', async () => {
  const u = await scim.createUser({ userName: 'Priya.Menon@Northwind.example', name: { givenName: 'Priya', familyName: 'Menon' }, emails: [{ value: 'priya.menon@northwind.example', primary: true }], externalId: 'e-1' }, base);
  assert.equal(u.userName, 'priya.menon@northwind.example');
  assert.equal(u.displayName, 'Priya Menon');
  assert.equal(u.active, true);
  const list = await scim.listUsers({ filter: 'userName eq "priya.menon@northwind.example"' }, base);
  assert.deepEqual([list.totalResults, list.Resources[0]!.id], [1, u.id]);
  assert.equal((await scim.listUsers({ filter: 'userName eq "nobody"' }, base)).totalResults, 0);
  await assert.rejects(scim.listUsers({ filter: 'title co "x"' }, base), /eq/);
  await assert.rejects(scim.createUser({ userName: 'priya.menon@northwind.example' }, base), /already exists/);
  const patched = await scim.patchUser(u.id, { Operations: [{ op: 'Replace', path: 'displayName', value: 'Priya M.' }] }, base);
  assert.equal(patched.displayName, 'Priya M.');
});

test('leaver: deactivation flags owned agents, blocks sign-in; a new owner clears the flag; overdue agents are found', async () => {
  const owner = person('jonas.weber@northwind.example', ['agent_owner']);
  const agent = await registry.registerAgent({ handle: 'leaver-agent', name: 'Leaver agent', purpose: 'Answers order questions', sponsor: 'sponsor@northwind.example', autonomy_level: 'L2' } as never, owner);
  const u = await scim.createUser({ userName: 'jonas', emails: [{ value: 'jonas.weber@northwind.example' }] }, base);
  assert.equal(await scim.isDeactivated('jonas.weber@northwind.example'), false);
  await scim.patchUser(u.id, { Operations: [{ op: 'Replace', path: 'active', value: 'False' }] }, base); // Entra sends text
  assert.equal(await scim.isDeactivated('jonas.weber@northwind.example'), true);
  const flagged = (await db.prepare('SELECT owner_left_at FROM agent WHERE id = ?').get(agent.id)) as { owner_left_at: string | null };
  assert.ok(flagged.owner_left_at);
  const status = await scim.status();
  assert.equal(status.agents_without_owner.length, 1);
  assert.ok(Date.parse(status.agents_without_owner[0]!.reassign_by) - Date.now() > 13 * 86_400_000);
  const note = await db.prepare("SELECT recipient FROM notification WHERE kind = 'owner_left'").get();
  assert.deepEqual(note, { recipient: 'sponsor@northwind.example' });

  // Nothing overdue yet; after the grace period the agent is due for quarantine.
  assert.equal((await scim.overdueOwnerless()).length, 0);
  await db.prepare('UPDATE agent SET owner_left_at = ? WHERE id = ?').run(new Date(Date.now() - 15 * 86_400_000).toISOString(), agent.id);
  assert.deepEqual((await scim.overdueOwnerless()).map((a) => a.id), [agent.id]);

  // Only the sponsor or an approver can name a new owner, and not a deactivated person.
  await assert.rejects(scim.reassignOwner(agent.id, { owner: 'x@northwind.example', reason: 'r' }, person('someone@northwind.example', ['agent_owner'])), /sponsor or an approver/);
  const sponsor = person('sponsor@northwind.example', ['viewer']);
  await assert.rejects(scim.reassignOwner(agent.id, { owner: 'jonas.weber@northwind.example', reason: 'r' }, sponsor), /deactivated/);
  await scim.reassignOwner(agent.id, { owner: 'Ananya.Rao@northwind.example', reason: 'Jonas left; Ananya runs support now' }, sponsor);
  assert.deepEqual(await db.prepare('SELECT owner, owner_left_at FROM agent WHERE id = ?').get(agent.id), { owner: 'ananya.rao@northwind.example', owner_left_at: null });
  assert.equal((await scim.overdueOwnerless()).length, 0);

  // Reactivation of a returning owner clears flags on agents they still own.
  const agent2 = await registry.registerAgent({ handle: 'leaver-agent-2', name: 'Second', purpose: 'Answers order questions', sponsor: 'sponsor@northwind.example', autonomy_level: 'L2' } as never, owner);
  await scim.deleteUser(u.id).catch(() => undefined); // already inactive: deleting keeps it inactive
  const u2 = await scim.createUser({ userName: 'jonas2', emails: [{ value: 'jonas.weber@northwind.example' }], active: false }, base);
  await scim.replaceUser(u2.id, { userName: 'jonas2', active: true, emails: [{ value: 'jonas.weber@northwind.example' }] }, base);
  assert.equal(await scim.isDeactivated('jonas.weber@northwind.example'), false, 'an active record for the same person counts');
  assert.equal(((await db.prepare('SELECT owner_left_at FROM agent WHERE id = ?').get(agent2.id)) as { owner_left_at: string | null }).owner_left_at, null);
});

test('groups: create with members, Okta/Entra PATCH add and remove, filter, delete', async () => {
  const a = await scim.createUser({ userName: 'a@x' }, base);
  const b = await scim.createUser({ userName: 'b@x' }, base);
  const g = await scim.createGroup({ displayName: 'signet-risk-officers', members: [{ value: a.id }] }, base);
  assert.deepEqual(g.members.map((m) => m.value), [a.id]);
  await scim.patchGroup(g.id, { Operations: [{ op: 'add', path: 'members', value: [{ value: b.id }] }] }, base);
  await scim.patchGroup(g.id, { Operations: [{ op: 'remove', path: `members[value eq "${a.id}"]` }] }, base);
  assert.deepEqual((await scim.getGroup(g.id, base)).members.map((m) => m.value), [b.id]);
  const found = await scim.listGroups({ filter: 'displayName eq "signet-risk-officers"', excludedAttributes: 'members' }, base);
  assert.equal(found.totalResults, 1);
  assert.equal('members' in found.Resources[0]!, false);
  await scim.deleteGroup(g.id);
  await assert.rejects(scim.getGroup(g.id, base), /not found/);
});

import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import type { CustomRulebookInput } from '@signet/core/rulebook';
import type { Principal } from '../src/rbac';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-rulebooks-'));
process.env.MONGODB_DATABASE = 'test_rulebooks_' + Date.now().toString(36);
after(dropTestDatabase);

test('rulebooks persist audited edits through the authenticated HTTP API without changing policy', async context => {
  const { defaultRules, importRulebook, listRulebooks, updateRule } = await import('../src/rulebooks');
  const { db } = await import('../src/db');
  const { tenant } = await import('../src/tenant');
  const actor: Principal = { id: 'admin@example.test', name: 'Admin', kind: 'human', roles: ['tenant_admin'], permissions: ['tenant.admin', 'agents.read'], groups: [], mfa: true, auth: 'session', auth_time: null };
  const input: CustomRulebookInput = { name: 'Internal rules', rules: [{ id: 'CUSTOM-01', area: 'Data', text: 'Require approval before export.', note: 'Company policy' }] };
  const before = await db.prepare('SELECT settings FROM tenant WHERE id = ?').get(tenant.id);
  const saved = await importRulebook(input, actor);
  assert.deepEqual((await listRulebooks()), [saved]);
  assert.deepEqual(input.rules, saved.rules);
  assert.equal(saved.created_by, actor.id);
  const audit = await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin' ORDER BY seq DESC LIMIT 1").get() as { data: string };
  assert.equal(JSON.parse(audit.data).rulebook_id, saved.id);
  await assert.rejects(importRulebook({ ...input, rules: [input.rules[0]!, { ...input.rules[0]!, id: 'custom-01' }] }, actor), /appears more than once/);
  await assert.rejects(importRulebook({ ...input, rules: [{ ...input.rules[0]!, text: ' ' }] }, actor), /validation/);
  await assert.rejects(importRulebook({ ...input, rules: [] }, actor), /validation/);
  assert.equal((await listRulebooks()).length, 1);
  const customEdit = { area: 'Privacy', text: 'Updated export approval rule.', note: 'Reviewed' };
  await updateRule(saved.id, 'CUSTOM-01', customEdit, actor);
  assert.deepEqual((await listRulebooks())[0]!.rules, [{ id: 'CUSTOM-01', ...customEdit }]);
  const original = (await defaultRules())[0]!;
  const defaultEdit = { area: original.area, text: 'Tenant reference text.', note: 'Local clarification' };
  await updateRule('default', original.id, defaultEdit, actor);
  assert.deepEqual((await defaultRules())[0], { ...original, ...defaultEdit });
  await updateRule('default', original.id, { ...defaultEdit, text: 'Second edit.' }, actor);
  assert.equal((await defaultRules())[0]!.text, 'Second edit.');
  await assert.rejects(updateRule('default', 'missing', defaultEdit, actor), /not found/);
  await assert.rejects(updateRule(saved.id, 'missing', customEdit, actor), /not found/);
  await assert.rejects(updateRule('default', original.id, { ...defaultEdit, text: ' ' }, actor), /validation/);
  await assert.rejects(updateRule('default', original.id, { ...defaultEdit, area: 'missing' }, actor), /Unknown default rule area/);
  const edits = await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin' ORDER BY seq DESC LIMIT 1").get() as { data: string };
  assert.equal(JSON.parse(edits.data).event, 'rulebook.rule_updated');
  const socket = createServer();
  await new Promise<void>(resolve => socket.listen(0, '127.0.0.1', resolve));
  const address = socket.address();
  assert(address && typeof address === 'object');
  await new Promise<void>((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  const origin = `http://127.0.0.1:${address.port}`;
  const child = spawn(process.execPath, ['--max-old-space-size=256', '--import', 'tsx', 'apps/control/src/index.ts'], {
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PORT: String(address.port), SIGNET_CONTROL_PORT: String(address.port), SIGNET_PUBLIC_URL: origin, SIGNET_AUTH_MODE: 'local', SIGNET_ADMIN_ID: 'rulebook-admin', SIGNET_ADMIN_PASSWORD: 'isolated-rulebook-test-password' },
  });
  context.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise<void>(resolve => { child.once('exit', resolve); child.kill(); });
  });
  let logs = '';
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Rulebook HTTP server did not start: ${logs}`)), 90000);
    const collect = (chunk: Buffer): void => {
      logs = (logs + chunk.toString()).slice(-10000);
      if (logs.includes('Signet control plane on')) { clearTimeout(timer); resolve(); }
    };
    child.stdout?.on('data', collect);
    child.stderr?.on('data', collect);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Rulebook server exited with ${code}: ${logs}`)); });
  });
  const login = await fetch(origin + '/api/v1/auth/local-login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'rulebook-admin', password: 'isolated-rulebook-test-password' }) });
  assert.equal(login.status, 200, logs);
  const cookie = login.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  const headers = { cookie, 'content-type': 'application/json' };
  for (const bookId of ['default', saved.id]) {
    const ruleId = bookId === 'default' ? original.id : 'CUSTOM-01';
    const edit = bookId === 'default' ? { ...defaultEdit, text: 'Saved through HTTP.' } : { ...customEdit, text: 'Custom saved through HTTP.' };
    const response = await fetch(`${origin}/api/v1/rulebooks/${bookId}/rules/${ruleId}`, { method: 'PUT', headers, body: JSON.stringify(edit) });
    assert.equal(response.status, 200, await response.clone().text());
    const reloaded = await fetch(origin + '/api/v1/rulebooks', { headers });
    assert.equal(reloaded.status, 200);
    const body = await reloaded.json() as { default_rules: { id: string; text: string }[]; items: { id: string; rules: { id: string; text: string }[] }[] };
    const rules = bookId === 'default' ? body.default_rules : body.items.find(book => book.id === bookId)!.rules;
    assert.equal(rules.find(rule => rule.id === ruleId)!.text, edit.text);
  }
  assert.deepEqual(await db.prepare('SELECT settings FROM tenant WHERE id = ?').get(tenant.id), before);
});

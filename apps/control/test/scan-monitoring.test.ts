import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { GENESIS_HASH, hashRecord, newId, type LedgerRecord } from '@signet/core';
import type { Principal } from '../src/rbac';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-scans-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
process.env.SIGNET_SINGLE_OPERATOR = 'true';
process.env.SIGNET_ENV = 'dev';
after(dropTestDatabase);

test('verified idle workloads enter monitoring without promoting rollout, and scan history exposes only dated metadata', async () => {
  const { db } = await import('../src/db');
  const { tenant } = await import('../src/tenant');
  const { permissionsFor } = await import('../src/rbac');
  const { seed } = await import('../src/controls');
  const quick = await import('../src/quick-connect');
  const workflow = await import('../src/workflow');
  const { status } = await import('../src/connectivity');
  const { scanHistory } = await import('../src/scan-history');
  const { append } = await import('../src/ledger');
  const { revokeInstance } = await import('../src/identity');
  await seed();
  const roles: Principal['roles'] = ['tenant_admin', 'platform_admin', 'governance_board', 'risk_officer', 'security_officer', 'agent_owner'];
  const admin: Principal = { id: 'admin', name: 'Admin', kind: 'human', roles, permissions: permissionsFor(roles), groups: [], mfa: true, auth: 'session', auth_time: Math.floor(Date.now() / 1000) };
  const setup = await quick.start({ name: 'Private Scan History', purpose: 'Answers internal policy questions', users_affected: ['internal'], data_touched: [], reversibility: 'yes' }, admin);
  assert.equal(setup.state, 'connected');
  const lc = await workflow.get(setup.lifecycle_id);
  assert.equal(lc.stage, 'deploy');
  await workflow.monitorConnectedAgent(setup.agent_id);
  assert.equal((await workflow.get(lc.id)).stage, 'deploy', 'credentials alone must not establish monitoring');
  const instance = await db.prepare('SELECT id FROM agent_instance WHERE agent_id = ?').get(setup.agent_id);
  assert.ok(instance && typeof instance.id === 'string');
  const head = await db.prepare('SELECT seq, record_hash FROM ledger_record ORDER BY seq DESC LIMIT 1').get();
  const historical: Omit<LedgerRecord, 'record_hash'> = {
    seq: Number(head?.seq ?? 0) + 1, record_id: newId('rec'), tenant_id: tenant.id, kind: 'transaction',
    ts: new Date(Date.now() - 20 * 60_000).toISOString(), agent_id: setup.agent_id, cert_id: lc.data.cert_id!,
    data: { action_type: 'llm_call', instance_id: instance.id, outcome: 'success', error_code: null, policy_decision: 'allow', input_safety: { category: 'allow' }, output_safety: { category: 'allow' }, prompt: 'PRIVATE USER CHAT', response: 'PRIVATE AI REPLY', session_id: 'PRIVATE SESSION' },
    prev_hash: typeof head?.record_hash === 'string' ? head.record_hash : GENESIS_HASH,
  };
  await db.prepare('INSERT INTO ledger_record (seq, record_id, tenant_id, kind, ts, agent_id, cert_id, data, prev_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(historical.seq, historical.record_id, historical.tenant_id, historical.kind, historical.ts, historical.agent_id, historical.cert_id, JSON.stringify(historical.data), historical.prev_hash, hashRecord(historical));
  assert.equal((await status(setup.agent_id)).state, 'connected_idle');
  await Promise.all([workflow.monitorConnectedAgent(setup.agent_id), workflow.monitorConnectedAgent(setup.agent_id)]);
  assert.equal((await workflow.get(lc.id)).stage, 'monitor');
  assert.equal((await workflow.rollouts())[lc.data.cert_id!]?.mode, 'shadow');
  assert.equal((await db.prepare("SELECT COUNT(*) AS n FROM stage_record WHERE lifecycle_id = ? AND stage = 'deploy'").get(lc.id))?.n, 1);
  await assert.rejects(workflow.advanceDeploy(lc.id, admin, { to: 'enforce' }), /shadow has run/);
  await append({ kind: 'transaction', agent_id: setup.agent_id, cert_id: lc.data.cert_id, data: { action_type: 'llm_call', instance_id: instance.id, outcome: 'blocked', error_code: 'unsafe_content', policy_decision: 'deny', input_safety: { category: 'weapons' }, prompt: 'PRIVATE BLOCKED CHAT' } });
  const first = await scanHistory(setup.agent_id, null, 1);
  assert.equal(first.items[0]?.result, 'blocked');
  assert.equal(first.items[0]?.input_check, 'blocked');
  assert.equal(first.items[0]?.output_check, 'not_run');
  assert.ok(first.next_cursor);
  const older = await scanHistory(setup.agent_id, first.next_cursor, 1);
  assert.equal(older.items[0]?.record_id, historical.record_id);
  assert.equal(older.items[0]?.scanned_at, historical.ts);
  assert.equal(older.items[0]?.output_check, 'passed');
  assert.equal(older.next_cursor, null);
  assert.ok(!JSON.stringify([first, older]).includes('PRIVATE'));
  assert.deepEqual(Object.keys(first.items[0]!).sort(), ['record_id', 'scanned_at', 'result', 'input_check', 'output_check'].sort());
  assert.equal((await status(setup.agent_id)).state, 'connected');
  await workflow.advanceDeploy(lc.id, admin, { to: 'enforce', dev_override: true, reason: 'Verify rollout promotion remains available during monitoring in the isolated integration test' });
  assert.equal((await workflow.get(lc.id)).stage, 'monitor');
  assert.equal((await workflow.get(lc.id)).status, 'complete');
  assert.equal((await workflow.rollouts())[lc.data.cert_id!], undefined);
  await revokeInstance(instance.id, admin, 'Integration test revocation');
  assert.equal((await status(setup.agent_id)).state, 'not_connected', 'revoked identities must never remain connected');
});

import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import type { Principal } from '../src/rbac';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-assistant-'));
process.env.MONGODB_DATABASE = 'test_assistant_' + Date.now().toString(36);
after(dropTestDatabase);

test('assistant proposals enforce tenant ownership and permissions without executing safety actions or retaining conversation text', async () => {
  const { proposeAssistantAction, chatWithSignet } = await import('../src/assistant');
  const { registerAgent } = await import('../src/registry');
  const { agentLevel } = await import('../src/enforcement');
  const { permissionsFor } = await import('../src/rbac');
  const { db } = await import('../src/db');
  const owner: Principal = { id: 'assistant-owner', name: 'Owner', kind: 'human', roles: ['agent_owner'], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'session', auth_time: null };
  const agent = await registerAgent({ handle: 'assistant-owned-agent', name: 'Assistant owned agent', purpose: 'Verify that an assistant proposal never applies an enforcement change', sponsor: owner.id, autonomy_level: 'L0' }, owner);
  const proposal = await proposeAssistantAction(agent.id, 'quarantine', owner, 'connected-test-model');
  assert.equal(proposal.action?.agent_id, agent.id);
  assert.equal(proposal.action?.action, 'quarantine');
  assert.match(proposal.message, /proposal is ready/);
  assert.doesNotMatch(proposal.message, /ka proposal|Abhi koi|Neeche Review/);
  assert.equal(await agentLevel(agent.id), 'active');
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM enforcement_event WHERE agent_id = ?').get(agent.id))?.n, 0);
  await assert.rejects(proposeAssistantAction(agent.id, 'quarantine', { ...owner, id: 'other-owner' }, 'connected-test-model'), /does not own/);
  await assert.rejects(proposeAssistantAction(agent.id, 'kill', { ...owner, roles: ['viewer'], permissions: permissionsFor(['viewer']) }, 'connected-test-model'), /ladder.kill/);
  await assert.rejects(proposeAssistantAction('agt_missing', 'kill', owner, 'connected-test-model'), /not found/);
  await assert.rejects(chatWithSignet({ messages: [{ role: 'user', content: 'Private chat text must not be recorded' }], time_zone: 'Asia/Calcutta' }, { ...owner, kind: 'service' }), /signed-in person/);
  const records = await db.prepare("SELECT data FROM ledger_record WHERE kind = 'admin' AND agent_id = ?").all(agent.id) as { data: string }[];
  const proposals = records.map(row => JSON.parse(row.data) as { event: string; action?: string; message?: string }).filter(row => row.event === 'assistant.action_proposed');
  assert.equal(proposals.length, 1);
  assert.equal(proposals[0]?.action, 'quarantine');
  assert(!records.some(row => row.data.includes('Private chat text')));
});

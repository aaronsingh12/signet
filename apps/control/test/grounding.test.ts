import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// DET-GROUND (DA 3 Tier 2): sampled answers are judged against their sources, the text is deleted once
// judged, and an ungrounded answer is a finding for the owner only when the detector is active.
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-ground-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const grounding = await import('../src/grounding');
await import('../src/detectors'); // seeds DET-GROUND
const registry = await import('../src/registry');
const { db } = await import('../src/db');
const { permissionsFor } = await import('../src/rbac');
const owner = { id: 'owner@x.example', name: 'o', kind: 'human' as const, roles: ['agent_owner' as const], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };
after(dropTestDatabase);

// Stand-in judge: grounded when every number in the answer appears in a source.
let calls = 0;
grounding.setJudge(async ({ sources, answer }) => {
  calls++;
  const missing = (answer.match(/\d+/g) ?? []).filter((n) => !sources.some((s) => s.includes(n)));
  return { score: missing.length ? 0.1 : 0.95, unsupported: missing, rationale: missing.length ? `numbers not in the sources: ${missing.join(', ')}` : 'all claims supported' };
});

test('samples without sources are skipped; judged text is deleted; findings follow the detector mode', async () => {
  const agent = await registry.registerAgent({ handle: 'ground-agent', name: 'ground-agent', purpose: 'Answers order questions', sponsor: 's@x.example', autonomy_level: 'L2' } as never, owner);
  const source = 'Order 4411 shipped on 3 November and arrives in 5 working days.';
  assert.deepEqual(await grounding.sample({ agent_id: agent.id, request_id: 'r0', tier: 'T2', question: 'q', sources: [], answer: 'a' }), { skipped: 'no sources to ground against' });
  await grounding.sample({ agent_id: agent.id, request_id: 'r1', tier: 'T2', question: 'When does order 4411 arrive?', sources: [source], answer: 'Order 4411 arrives in 5 working days.' });
  await grounding.sample({ agent_id: agent.id, request_id: 'r2', tier: 'T2', question: 'When does order 4411 arrive?', sources: [source], answer: 'Order 4411 arrives tomorrow with a 20% discount.' });

  await db.prepare("UPDATE detector SET mode = 'shadow' WHERE id = 'DET-GROUND'").run();
  assert.deepEqual(await grounding.work(), { judged: 2, inconclusive: 0 });
  const r = await grounding.forAgent(agent.id);
  assert.equal(r.judged, 2);
  assert.equal(r.grounded_rate, 0.5);
  const bad = r.items.find((i) => i.request_id === 'r2')!;
  assert.equal(bad.verdict, 'ungrounded');
  assert.deepEqual(bad.unsupported, ['20']);
  const left = (await db.prepare("SELECT COUNT(*) AS n FROM ground_eval WHERE payload != ''").get()) as { n: number };
  assert.equal(Number(left.n), 0, 'sampled text is deleted once judged');
  const notes = async () => Number(((await db.prepare("SELECT COUNT(*) AS n FROM notification WHERE kind = 'groundedness'").get()) as { n: number }).n);
  assert.equal(await notes(), 0, 'shadow: recorded, nobody notified');

  await db.prepare("UPDATE detector SET mode = 'active' WHERE id = 'DET-GROUND'").run();
  await grounding.sample({ agent_id: agent.id, request_id: 'r3', tier: 'T2', question: 'q', sources: [source], answer: 'It ships in 99 days.' });
  await grounding.work();
  assert.equal(await notes(), 1, 'active: the owner gets a finding');
});

test('a judge that never answers leaves the sample inconclusive after 3 tries, text deleted', async () => {
  const agent = await registry.registerAgent({ handle: 'ground-agent-2', name: 'ground-agent-2', purpose: 'Answers order questions', sponsor: 's@x.example', autonomy_level: 'L2' } as never, owner);
  grounding.setJudge(async () => null);
  await grounding.sample({ agent_id: agent.id, request_id: 'r9', tier: 'T1', question: 'q', sources: ['a source document of some length'], answer: 'an answer' });
  for (let i = 0; i < 3; i++) await grounding.work();
  const row = (await db.prepare('SELECT status, payload FROM ground_eval WHERE request_id = ?').get('r9')) as { status: string; payload: string };
  assert.deepEqual([row.status, row.payload], ['inconclusive', '']);
});

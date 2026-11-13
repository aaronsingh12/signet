import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { dropTestDatabase } from './database';

// DET-ANOM baselines from the ledger and live scoring from shared counters (DA 3, SGC-MON-004).
process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-anom-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
const anomaly = await import('../src/anomaly');
const registry = await import('../src/registry');
const ledger = await import('../src/ledger');
const core = await import('@signet/core');
const { db, nowIso } = await import('../src/db');
const { permissionsFor } = await import('../src/rbac');
const owner = { id: 'o@x.example', name: 'o', kind: 'human' as const, roles: ['agent_owner' as const], permissions: permissionsFor(['agent_owner']), groups: [], mfa: true, auth: 'session' as const, auth_time: Math.floor(Date.now() / 1000) };
after(dropTestDatabase);
const DAY = 86_400_000;

test('baseline: built from llm and tool transactions only; under the floor it is learning', async () => {
  const agent = await registry.registerAgent({ handle: 'anom-new', name: 'anom-new', purpose: 'Answers order questions', sponsor: 's@x.example', autonomy_level: 'L2' } as never, owner);
  for (const action_type of ['llm_call', 'tool_call', 'tool_call', 'detector_score']) {
    await ledger.append({ kind: 'transaction', agent_id: agent.id, data: { action_type, target: action_type === 'tool_call' ? 'crm.lookup' : 'gpt-oss', cost_usd: 0.02, outcome: 'success' } });
  }
  const b = await anomaly.computeBaseline(agent.id, new Date(Date.now() + DAY));
  assert.equal(b.records, 3, 'the detector_score record is not traffic');
  assert.deepEqual(b.tool_share, { 'crm.lookup': 1 });
  assert.equal((await anomaly.live(agent.id, 'T2')).status, 'learning');
});

test('live: normal traffic is low, a burst goes High and the High run is timed across calls', async () => {
  const agent = await registry.registerAgent({ handle: 'anom-steady', name: 'anom-steady', purpose: 'Answers order questions', sponsor: 's@x.example', autonomy_level: 'L2' } as never, owner);
  const to = new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate()));
  const hour = new Date().getUTCHours();
  // 10 days with 5 requests in this hour of day each day.
  const rows = Array.from({ length: 50 * 3 }, (_, i) => ({ ts: new Date(to.getTime() - (1 + (i % 10)) * DAY + hour * 3_600_000 + (i % 50) * 1000).toISOString(), cost_usd: 0.01, ok: true }));
  const b = core.buildBaseline(rows, new Date(to.getTime() - 14 * DAY), to);
  await db.prepare('INSERT INTO agent_baseline (agent_id, data, computed_at) VALUES (?, ?, ?)').run(agent.id, JSON.stringify(b), nowIso());
  for (let i = 0; i < 10; i++) await anomaly.countRequest(agent.id);
  const normal = await anomaly.live(agent.id, 'T2');
  assert.equal(normal.status, 'ready');
  assert.equal(normal.band, 'low');
  for (let i = 0; i < 150; i++) await anomaly.countRequest(agent.id);
  const t0 = Date.now();
  const burst = await anomaly.live(agent.id, 'T2', undefined, t0);
  assert.equal(burst.band, 'high');
  assert.equal(burst.feature, 'volume');
  const later = await anomaly.live(agent.id, 'T2', undefined, t0 + 4 * 60_000);
  assert.ok(later.high_for_ms! >= 3 * 60_000, 'the High run started at the first High score');
  await anomaly.countOutcome(agent.id, 0, true);
  await anomaly.eraseAgent(agent.id);
  assert.equal((await anomaly.live(agent.id, 'T2')).status, 'learning', 'erased with the agent');
});

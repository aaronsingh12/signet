import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { decodeJwt } from '@signet/core';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-pricing-'));
process.env.SIGNET_DB_SCHEMA = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);

after(async () => {
  await dropTestDatabase();
});

const { tenant, setModelPrice, reloadSettings } = await import('../src/tenant');
const { db } = await import('../src/db');
const { buildBundle } = await import('../src/enforcement');

test('a model price is saved, survives a reload and reaches the gateway bundle', async () => {
  const model = tenant.settings.catalogue[0]!.model;
  await setModelPrice(model, { in: 0.15, out: 0.6 });
  tenant.settings.catalogue[0]!.price_per_1k_usd = { in: 0, out: 0 }; // as another instance would still see it
  await reloadSettings();
  assert.deepEqual(tenant.settings.catalogue[0]!.price_per_1k_usd, { in: 0.15, out: 0.6 });
  const stored = JSON.parse(((await db.prepare('SELECT settings FROM tenant WHERE id = ?').get(tenant.id)) as { settings: string }).settings);
  assert.deepEqual(stored.catalogue[0].price_per_1k_usd, { in: 0.15, out: 0.6 });
  const bundle = decodeJwt<{ catalogue: { price_per_1k_usd: { in: number; out: number } }[] }>(await buildBundle()).payload;
  assert.deepEqual(bundle.catalogue[0]!.price_per_1k_usd, { in: 0.15, out: 0.6 });
});

import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { decodeJwt } from '@signet/core';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-pricing-'));
process.env.MONGODB_DATABASE = 'test_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);

after(async () => {
  await dropTestDatabase();
});

const { tenant, setModelPrice, setAgentModel, reloadSettings } = await import('../src/tenant');
const { modelPriceQuote } = await import('../src/model-pricing');
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
  assert.equal(stored.catalogue[0].price_source, 'manual');
  const bundle = decodeJwt<{ catalogue: { price_per_1k_usd: { in: number; out: number } }[] }>(await buildBundle()).payload;
  assert.deepEqual(bundle.catalogue[0]!.price_per_1k_usd, { in: 0.15, out: 0.6 });
});

test('live public pricing matches the connected provider, preserves manual rates and never assigns API prices to local models', async () => {
  const model = 'claude-haiku-5-5';
  await setAgentModel(model, { base_url: 'https://api.anthropic.com/v1', provider: 'claude', secret_id: null });
  const quote = await modelPriceQuote(model);
  assert(quote.available, 'The live catalogue must publish an exact Anthropic Haiku price');
  assert(quote.input_per_million > 0);
  assert(quote.output_per_million > 0);
  assert.equal(quote.source_url, 'https://models.dev');
  assert(Number.isFinite(Date.parse(quote.fetched_at)));
  await setModelPrice(model, { in: 0, out: 0.0007 });
  await modelPriceQuote(model);
  const saved = (await reloadSettings()).catalogue.find(entry => entry.model === model)!;
  assert.deepEqual(saved.price_per_1k_usd, { in: 0, out: 0.0007 });
  assert.equal(saved.price_source, 'manual');
  await setAgentModel('local-pricing-test', { base_url: 'http://localhost:11434/v1', provider: 'ollama_local', secret_id: null });
  const local = await modelPriceQuote('local-pricing-test');
  assert.equal(local.available, false);
  await setAgentModel('missing-pricing-model', { base_url: 'https://api.anthropic.com/v1', provider: 'claude', secret_id: null });
  assert.equal((await modelPriceQuote('missing-pricing-model')).available, false);
  await assert.rejects(modelPriceQuote('unregistered-model'), /not in the tenant catalogue/);
});

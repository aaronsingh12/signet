import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import type { ModelSettingsDraft, PolicyBundle } from '@signet/core';
import type { Principal } from '../src/rbac';
import { dropTestDatabase } from './database';

process.env.SIGNET_DATA_DIR = mkdtempSync(join(tmpdir(), 'signet-model-settings-'));
process.env.MONGODB_DATABASE = 'test_models_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 8);
after(dropTestDatabase);

test('real model settings verify inference, encrypt keys, survive environment removal and preserve existing model routes', { timeout: 180000, skip: process.env.SIGNET_TEST_MODEL_SETTINGS !== '1' ? 'set SIGNET_TEST_MODEL_SETTINGS=1 with a working provider or local model' : false }, async () => {
  const { decodeJwt } = await import('@signet/core');
  const models = await import('../src/model-settings');
  const { db } = await import('../src/db');
  const { reloadSettings, tenant } = await import('../src/tenant');
  const { buildBundle } = await import('../src/enforcement');
  const { permissionsFor } = await import('../src/rbac');
  const { askTenantModel } = await import('../src/tenant-model');
  const actor: Principal = { id: 'model-admin@example.test', name: 'Model admin', kind: 'human', roles: ['tenant_admin'], permissions: permissionsFor(['tenant_admin']), groups: [], mfa: true, auth: 'session', auth_time: null };
  const before = await models.modelSettings();
  const connection = await models.runtimeModelConnection();
  const originalKey = await models.runtimeModelKey(connection);
  const key = before.provider === 'ollama_local' ? 'local-ollama-encrypted-key-test' : originalKey;
  const draft: ModelSettingsDraft = { provider: before.provider, base_url: before.base_url, model: before.model, api_key: before.provider === 'ollama_local' ? key! : '' };
  const options = await models.listModelOptions(draft);
  assert(options.models.length > 0, 'Configured real provider must list its actual models');
  const selected = before.provider === 'ollama_local'
    ? options.models.find(model => model !== before.model && !model.endsWith(':cloud'))
    : options.models.find(model => model === draft.model || model === process.env.SIGNET_LLM_UPSTREAM_MODEL);
  assert(selected, 'The configured model or its upstream ID must be available');
  const saved = await models.saveModelSettings({ ...draft, model: selected }, actor);
  assert.equal(saved.source, 'saved');
  assert.equal(saved.model, selected);
  assert.equal(saved.has_api_key, Boolean(key));
  assert(!JSON.stringify(saved).includes('secret_id'));
  if (key) assert(!JSON.stringify(saved).includes(key));
  const runtime = await models.runtimeModelConnection();
  assert.equal(await models.runtimeModelKey(runtime), key);
  if (key) {
    assert(runtime.secret_id);
    const row = await db.prepare('SELECT sealed FROM secret WHERE id = ?').get(runtime.secret_id);
    assert.equal(typeof row?.sealed, 'string');
    assert(!String(row?.sealed).includes(key));
  }
  const settings = await reloadSettings();
  const previous = settings.catalogue.find(entry => entry.model === before.model);
  if (before.model !== selected) {
    assert.equal(previous?.upstream?.base_url, before.base_url);
    assert.equal(previous?.upstream?.provider, before.provider);
    assert(previous?.upstream?.secret_id || !originalKey, 'Existing approved routes retain their own credentials');
  }
  const oldUrl = process.env.SIGNET_LLM_BASE_URL;
  const oldKey = process.env.SIGNET_LLM_API_KEY;
  const oldModel = process.env.SIGNET_LLM_MODEL;
  try {
    delete process.env.SIGNET_LLM_BASE_URL;
    delete process.env.SIGNET_LLM_API_KEY;
    delete process.env.SIGNET_LLM_MODEL;
    assert.equal((await models.modelSettings()).model, selected);
    const answer = await askTenantModel([{ role: 'user', content: 'Reply with OK only.' }], 1024);
    assert(answer?.text.trim(), 'Saved provider must serve a real request without model environment variables');
    const bundle = decodeJwt<PolicyBundle>(await buildBundle()).payload;
    assert.equal(bundle.model_connection?.model, selected);
    assert.equal(bundle.model_connection?.secret_id, runtime.secret_id);
    assert.equal(bundle.model_connection_saved, true);
    assert.equal(bundle.catalogue[0]?.model, selected);
    if (key) assert(!JSON.stringify(bundle).includes(key), 'Signed gateway bundles contain secret references only');
  } finally {
    if (oldUrl === undefined) delete process.env.SIGNET_LLM_BASE_URL; else process.env.SIGNET_LLM_BASE_URL = oldUrl;
    if (oldKey === undefined) delete process.env.SIGNET_LLM_API_KEY; else process.env.SIGNET_LLM_API_KEY = oldKey;
    if (oldModel === undefined) delete process.env.SIGNET_LLM_MODEL; else process.env.SIGNET_LLM_MODEL = oldModel;
  }
  await assert.rejects(models.saveModelSettings({ ...draft, provider: 'openai', base_url: 'https://api.openai.com/v1', model: 'test-model', api_key: '' }, actor), /Enter the API key/);
  assert.equal((await models.modelSettings()).model, selected, 'Rejected configurations must not replace the saved connection');
  assert.equal(tenant.id.length > 0, true);
});

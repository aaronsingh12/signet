import { db, nowIso } from './db';
import { PolicyError, notFound } from './errors';
import { readJson, requestJson } from './external-http';
import * as ledger from './ledger';
import { revealForGateway } from './secrets';
import { reloadSettings, tenant } from './tenant';
import { setTimeout } from 'node:timers/promises';

/** Verify stored model credentials using a fixed probe, without issuing an agent identity or seal. */
export async function testModelConnection(model: string, actorId: string): Promise<{ model: string; verified_at: string }> {
  const entry = (await reloadSettings()).catalogue.find((item) => item.model === model);
  if (!entry) throw notFound(`catalogue model ${model}`);
  const base = entry.upstream?.base_url ?? process.env.SIGNET_LLM_BASE_URL;
  if (!base) throw new PolicyError('MODEL_CONNECTION', 'Configure SIGNET_LLM_BASE_URL or add the model provider URL before connecting', 422);
  const secret = entry.upstream ? entry.upstream.secret_id : (await db.prepare("SELECT id FROM secret WHERE tenant_id = ? AND kind = 'llm_provider' ORDER BY created_at LIMIT 1").get(tenant.id))?.id;
  const key = typeof secret === 'string' ? (await revealForGateway(secret)).value : entry.upstream ? null : process.env.SIGNET_LLM_API_KEY;
  const url = new URL(`${base.replace(/\/+$/, '')}/models`);
  const response = await readJson({ url, method: 'GET', headers: key ? { authorization: `Bearer ${key}` } : {}, body: null, timeout: 10000 });
  if (!response || typeof response !== 'object' || Array.isArray(response) || !Array.isArray(response.data)) throw new PolicyError('MODEL_CONNECTION', `GET ${url} did not return an OpenAI-compatible model list`, 502);
  const expected = entry.upstream_model;
  const listed = response.data.some((item) => item !== null && typeof item === 'object' && !Array.isArray(item) && typeof item.id === 'string' && (item.id === entry.model || item.id === expected));
  if (!listed) throw new PolicyError('MODEL_CONNECTION', `GET ${url} succeeded but did not list model ${entry.model} (upstream ${expected})`, 422);
  const probeUrl = new URL(`${base.replace(/\/+$/, '')}/chat/completions`);
  for (let attempt = 1; ; attempt++) {
    try {
      const probe = await requestJson({ url: probeUrl, method: 'POST', headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) }, body: JSON.stringify({ model: entry.model, messages: [{ role: 'user', content: 'Connection verification: reply with OK only.' }], max_tokens: 32, stream: false }), timeout: 30000 });
      if (!probe || typeof probe !== 'object' || Array.isArray(probe) || !Array.isArray(probe.choices) || !probe.choices.length) throw new PolicyError('MODEL_CONNECTION', `POST ${probeUrl} did not return a chat completion for ${entry.model}`, 502);
      const assistant = probe.choices.some((choice) => choice !== null && typeof choice === 'object' && !Array.isArray(choice) && choice.message !== null && typeof choice.message === 'object' && !Array.isArray(choice.message) && choice.message.role === 'assistant' && (choice.message.content === null || typeof choice.message.content === 'string'));
      if (!assistant) throw new PolicyError('MODEL_CONNECTION', `POST ${probeUrl} returned no valid assistant message for ${entry.model}`, 502);
      break;
    } catch (error) {
      if (!(error instanceof PolicyError) || !['EXTERNAL_TIMEOUT', 'EXTERNAL_NETWORK', 'EXTERNAL_RATE_LIMIT', 'EXTERNAL_HTTP'].includes(error.rule) || (error.extra.upstream_status !== undefined && ![429, 502, 503, 504].includes(Number(error.extra.upstream_status))) || attempt === 3) throw error;
      console.warn('Model connection probe failed; retrying', { model, attempt, rule: error.rule });
      await setTimeout(200 * 2 ** (attempt - 1));
    }
  }
  const verifiedAt = nowIso();
  await ledger.append({ kind: 'admin', data: { event: 'model.connection_verified', model: entry.model, actor: actorId, verified_at: verifiedAt } });
  return { model: entry.model, verified_at: verifiedAt };
}

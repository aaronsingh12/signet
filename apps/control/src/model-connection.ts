import { modelRequest, modelRequestBody, type ModelConnection } from '@signet/core';
import { nowIso } from './db';
import { PolicyError, notFound } from './errors';
import * as ledger from './ledger';
import { revealForGateway } from './secrets';
import { reloadSettings } from './tenant';
import { runtimeModelConnection, runtimeModelKey } from './model-settings';

/** Verify stored model credentials using a fixed probe, without issuing an agent identity or seal. */
export async function testModelConnection(model: string, actorId: string): Promise<{ model: string; verified_at: string }> {
  const entry = (await reloadSettings()).catalogue.find((item) => item.model === model);
  if (!entry) throw notFound(`catalogue model ${model}`);
  const connection: ModelConnection = entry.upstream ? { provider: entry.upstream.provider ?? 'ollama_api', base_url: entry.upstream.base_url, model, secret_id: entry.upstream.secret_id } : await runtimeModelConnection();
  const key = entry.upstream ? (connection.secret_id ? (await revealForGateway(connection.secret_id)).value : null) : await runtimeModelKey(connection);
  const url = `${connection.base_url}/models`;
  const response = (await modelRequest(connection, key, '/models', null, AbortSignal.timeout(30_000), 10_000)).json<{ data: { id: string }[] }>();
  if (!response || !Array.isArray(response.data) || response.data.some(item => !item || typeof item.id !== 'string')) throw new PolicyError('MODEL_CONNECTION', `GET ${url} did not return a valid model list`, 502);
  const expected = entry.upstream_model;
  const listed = response.data.some((item) => item !== null && typeof item === 'object' && !Array.isArray(item) && typeof item.id === 'string' && (item.id === entry.model || item.id === expected));
  if (!listed) throw new PolicyError('MODEL_CONNECTION', `GET ${url} succeeded but did not list model ${entry.model} (upstream ${expected})`, 422);
  const probe = (await modelRequest(connection, key, '/chat/completions', modelRequestBody(connection, { model: entry.model, messages: [{ role: 'user', content: 'Connection verification: reply with OK only.' }], max_tokens: 1024 }), AbortSignal.timeout(60_000), 30_000)).json<{ choices: { message: { role: string; content: string | null } }[] }>();
  if (!probe || !Array.isArray(probe.choices) || probe.choices[0]?.message?.role !== 'assistant' || typeof probe.choices[0].message.content !== 'string') throw new PolicyError('MODEL_CONNECTION', `POST ${connection.base_url}/chat/completions returned no assistant text for ${model}`, 502);
  const verifiedAt = nowIso();
  await ledger.append({ kind: 'admin', data: { event: 'model.connection_verified', model: entry.model, actor: actorId, verified_at: verifiedAt } });
  return { model: entry.model, verified_at: verifiedAt };
}

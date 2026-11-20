import { request, parseModelPriceQuote, type HttpResponse, type ModelPriceQuote } from '@signet/core';
import { setTimeout } from 'node:timers/promises';
import { PolicyError, invalid } from './errors';
import { object, type Json } from './external-contract';
import { reloadSettings } from './tenant';
import { runtimeModelConnection } from './model-settings';

const PRICING_URL = 'https://models.dev/api.json';

/** Fetch public rates without sending model credentials or using another provider's prices. */
async function pricingCatalogue(): Promise<HttpResponse> {
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await request(PRICING_URL, { method: 'GET', headers: { accept: 'application/json' }, timeoutMs: 15000, signal: AbortSignal.timeout(20000), maxBytes: 16 * 1024 * 1024, destination: { allowPrivate: false } });
      if (!response.ok) throw new PolicyError('MODEL_PRICING', `GET ${PRICING_URL} failed: HTTP ${response.status}; response: ${response.text().slice(0, 1000)}`, 502, { upstream_status: response.status });
      return response;
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      if (error instanceof PolicyError && Number(error.extra.upstream_status) < 500 && error.extra.upstream_status !== 429) throw error;
      if (attempt === 3) {
        if (error instanceof PolicyError) throw error;
        throw new PolicyError('MODEL_PRICING', `GET ${PRICING_URL} failed after ${attempt} attempts: ${error.message}. Check network access and retry fetching prices.`, 502);
      }
      console.warn('Model pricing fetch failed; retrying', { url: PRICING_URL, attempt, error: error.message });
      await setTimeout(200 * 2 ** (attempt - 1));
    }
  }
}

/** Public base token rates are suggestions; saving a manual contract price is a separate action. */
export async function modelPriceQuote(model: string): Promise<ModelPriceQuote> {
  const settings = await reloadSettings();
  const entry = settings.catalogue.find(item => item.model === model);
  if (!entry) throw invalid(`${model} is not in the tenant catalogue`);
  const connection = entry.upstream ?? await runtimeModelConnection();
  const hostname = new URL(connection.base_url).hostname;
  const provider = hostname === 'api.anthropic.com' ? 'anthropic' : hostname === 'api.openai.com' ? 'openai' : null;
  if (!provider) return { available: false, reason: 'No published per-token rate is available for this connection. Enter your local hosting or subscription rate manually.' };
  const response = await pricingCatalogue();
  let data: Json;
  try { data = response.json<Json>(); }
  catch (error) {
    if (error instanceof SyntaxError) throw new PolicyError('MODEL_PRICING_SCHEMA', `GET ${PRICING_URL} returned malformed JSON`, 502);
    throw error;
  }
  const catalog = object(data, 'Public model pricing catalogue');
  const models = object(object(catalog[provider]!, `Pricing provider ${provider}`).models!, `Pricing models for ${provider}`);
  const record = models[entry.model] ?? models[entry.upstream_model];
  if (record === undefined) return { available: false, reason: `No exact published price was found for ${provider}/${entry.model}. Enter your contracted rate manually.` };
  const cost = object(object(record, `Pricing model ${entry.model}`).cost!, `Pricing cost for ${entry.model}`);
  if (typeof cost.input !== 'number' || typeof cost.output !== 'number') throw new PolicyError('MODEL_PRICING_SCHEMA', `Published pricing for ${provider}/${entry.model} requires numeric input and output USD rates per million tokens`, 502);
  return parseModelPriceQuote({ available: true, input_per_million: cost.input, output_per_million: cost.output, source_url: 'https://models.dev', fetched_at: new Date().toISOString() });
}

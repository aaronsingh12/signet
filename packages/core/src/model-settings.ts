export const MODEL_PROVIDERS = ['ollama_local', 'ollama_api', 'openai', 'claude'] as const;
export type ModelProvider = typeof MODEL_PROVIDERS[number];
export interface ModelConnection { provider: ModelProvider; base_url: string; model: string; secret_id: string | null }
export interface ModelSettingsDraft { provider: ModelProvider; base_url: string; model: string; api_key: string }
export type ModelProviderDraft = Omit<ModelSettingsDraft, 'model'>;
export interface ModelSettingsView { provider: ModelProvider; base_url: string; model: string; has_api_key: boolean; source: 'saved' | 'installation' }

/** Validates configuration at the API boundary; unrelated fields are ignored. */
export function parseModelProviderDraft(input: ModelProviderDraft): ModelProviderDraft {
  if (!input || !MODEL_PROVIDERS.includes(input.provider)) throw new TypeError('Choose Ollama Local, Ollama API, OpenAI API or Claude API');
  if (typeof input.api_key !== 'string' || input.api_key.length > 4096 || /[\r\n]/.test(input.api_key)) throw new TypeError('API key must be text, at most 4096 characters, without line breaks');
  if (typeof input.base_url !== 'string') throw new TypeError('Provider API URL is required');
  let url: URL;
  try { url = new URL(input.base_url.trim()); } catch { throw new TypeError('Provider API URL must be an absolute address ending in /v1'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname.replace(/\/+$/, '') !== '/v1') throw new TypeError('Provider API URL must end in /v1, without credentials, query parameters or fragments');
  if (input.provider !== 'ollama_local' && url.protocol !== 'https:') throw new TypeError('Remote model APIs require HTTPS');
  const base = url.toString().replace(/\/+$/, '');
  if (input.provider === 'openai' && base !== 'https://api.openai.com/v1') throw new TypeError('OpenAI API uses https://api.openai.com/v1');
  if (input.provider === 'claude' && base !== 'https://api.anthropic.com/v1') throw new TypeError('Claude API uses https://api.anthropic.com/v1');
  return { provider: input.provider, base_url: base, api_key: input.api_key.trim() };
}

export function parseModelSettingsDraft(input: ModelSettingsDraft): ModelSettingsDraft {
  const provider = parseModelProviderDraft(input);
  if (typeof input.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(input.model.trim())) throw new TypeError('Model must be its exact provider ID, using 1-128 letters, numbers, dots, colons, slashes, underscores or hyphens');
  return { ...provider, model: input.model.trim() };
}

export function parseModelSettingsView(input: ModelSettingsView): ModelSettingsView {
  if (!input || typeof input.has_api_key !== 'boolean' || !['saved', 'installation'].includes(input.source)) throw new TypeError('Model settings require a credential status and configuration source');
  const draft = parseModelSettingsDraft({ ...input, api_key: '' });
  return { provider: draft.provider, base_url: draft.base_url, model: draft.model, has_api_key: input.has_api_key, source: input.source };
}

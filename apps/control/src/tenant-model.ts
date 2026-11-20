import { modelRequest, modelRequestBody } from '@signet/core';
import { runtimeModelConnection, runtimeModelKey } from './model-settings';

// The saved tenant model is shared by offline judges and Guardian. Provider failures remain explicit.
export async function askTenantModel(messages: { role: 'system' | 'user'; content: string }[], maxTokens: number): Promise<{ text: string; model: string } | null> {
  const connection = await runtimeModelConnection();
  const key = await runtimeModelKey(connection);
  const response = await modelRequest(connection, key, '/chat/completions', modelRequestBody(connection, {
    model: connection.model, temperature: 0, max_tokens: maxTokens, messages,
  }), AbortSignal.timeout(60_000), 60_000);
  const data = response.json<{ choices: { message: { content: string | null } }[] }>();
  if (!data || !Array.isArray(data.choices) || typeof data.choices[0]?.message?.content !== 'string') throw new TypeError(`Model ${connection.model} returned no assistant text for the offline judge`);
  return { text: data.choices[0].message.content, model: connection.model };
}

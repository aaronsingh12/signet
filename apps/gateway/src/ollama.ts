import type { ChatResponse } from './provider';

// Ollama's native API (POST /api/chat, GET /api/tags) over the same governed chat path: requests are
// translated to a chat request, so every gateway check applies unchanged. An agent built on Ollama
// changes only its base URL and API key.

export class UnsupportedOllamaRequest extends Error {}

type NativeCall = { id?: string; function?: { name?: string; arguments?: unknown } };
type NativeMessage = { role?: string; content?: unknown; images?: unknown; thinking?: unknown; tool_calls?: NativeCall[]; tool_name?: string; [k: string]: unknown };

export function ollamaToChat(body: Record<string, unknown>): Record<string, unknown> {
  if (!Array.isArray(body.messages)) throw new UnsupportedOllamaRequest('messages must be an array');
  const messages = (body.messages as NativeMessage[]).map(({ images, thinking: _thinking, tool_calls, tool_name, ...m }) => {
    if (Array.isArray(images) && images.length) throw new UnsupportedOllamaRequest('images are not supported; send text');
    return {
      ...m,
      ...(tool_name ? { name: tool_name } : {}),
      ...(tool_calls?.length ? { tool_calls: tool_calls.map((tc, i) => ({ id: tc.id ?? `call_${i}`, type: 'function', function: { name: tc.function?.name, arguments: typeof tc.function?.arguments === 'string' ? tc.function.arguments : JSON.stringify(tc.function?.arguments ?? {}) } })) } : {}),
    };
  });
  if (body.format !== undefined && body.format !== 'json') throw new UnsupportedOllamaRequest('only format "json" is supported');
  const options = (body.options ?? {}) as Record<string, unknown>;
  return {
    model: body.model,
    messages,
    ...(body.tools ? { tools: body.tools } : {}),
    ...(body.format === 'json' ? { response_format: { type: 'json_object' } } : {}),
    ...(options.temperature !== undefined ? { temperature: options.temperature } : {}),
    ...(options.top_p !== undefined ? { top_p: options.top_p } : {}),
    ...(options.num_predict !== undefined ? { max_tokens: options.num_predict } : {}),
    ...(options.stop !== undefined ? { stop: options.stop } : {}),
  };
}

function parseArguments(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return {}; // a model can emit broken JSON; the tool proxy still checks whatever the agent sends
  }
}

export function chatToOllama(r: ChatResponse): Record<string, unknown> {
  const choice = r.choices?.[0];
  const m = choice?.message;
  const calls = m?.tool_calls?.map((tc) => ({ id: tc.id, function: { name: tc.function.name, arguments: parseArguments(tc.function.arguments) } }));
  return {
    model: r.model,
    created_at: new Date().toISOString(),
    message: { role: 'assistant', content: m?.content ?? '', ...(m?.reasoning ? { thinking: m.reasoning } : {}), ...(calls?.length ? { tool_calls: calls } : {}) },
    done: true,
    done_reason: choice?.finish_reason ?? 'stop',
    prompt_eval_count: r.usage?.prompt_tokens ?? 0,
    eval_count: r.usage?.completion_tokens ?? 0,
  };
}

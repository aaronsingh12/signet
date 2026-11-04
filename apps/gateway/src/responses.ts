import type { ChatResponse } from './provider';

// OpenAI Responses API (POST /v1/responses) over the same governed chat path: requests are translated
// to a chat request, so every gateway check applies unchanged. Signet stores no conversation, so
// previous_response_id and hosted tools (web search, file search) are refused with a clear message.

export class UnsupportedResponsesRequest extends Error {}

type Item = { type?: string; role?: string; content?: unknown; call_id?: string; name?: string; arguments?: string; output?: unknown };
type Tool = { type?: string; name?: string; description?: string; parameters?: unknown };

function textOf(content: unknown): string {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.map((part: { type?: string; text?: string }) => {
    if (part.type === 'input_text' || part.type === 'output_text' || part.type === 'text') return part.text ?? '';
    throw new UnsupportedResponsesRequest(`content type ${part.type} is not supported; send text`);
  }).join('');
}

function messagesOf(input: unknown): Record<string, unknown>[] {
  if (typeof input === 'string') return [{ role: 'user', content: input }];
  if (!Array.isArray(input)) return [];
  const messages: Record<string, unknown>[] = [];
  for (const item of input as Item[]) {
    if (item.type === 'function_call') messages.push({ role: 'assistant', content: null, tool_calls: [{ id: item.call_id, type: 'function', function: { name: item.name, arguments: item.arguments ?? '{}' } }] });
    else if (item.type === 'function_call_output') messages.push({ role: 'tool', tool_call_id: item.call_id, content: typeof item.output === 'string' ? item.output : JSON.stringify(item.output ?? '') });
    else if (item.type === 'reasoning') continue;
    else if (item.role) messages.push({ role: item.role === 'developer' ? 'system' : item.role, content: textOf(item.content) });
    else throw new UnsupportedResponsesRequest(`input item type ${item.type} is not supported`);
  }
  return messages;
}

export function toChatRequest(body: Record<string, unknown>): Record<string, unknown> {
  if (body.previous_response_id) throw new UnsupportedResponsesRequest('previous_response_id is not supported because Signet stores no conversations; send the full input each time');
  const tools = (body.tools as Tool[] | undefined)?.map((t) => {
    if (t.type !== 'function') throw new UnsupportedResponsesRequest(`hosted tool ${t.type} is not supported; use function tools`);
    return { type: 'function', function: { name: t.name, description: t.description, parameters: t.parameters } };
  });
  const choice = body.tool_choice as string | { type?: string; name?: string } | undefined;
  const chat: Record<string, unknown> = {
    model: body.model,
    messages: [...(typeof body.instructions === 'string' && body.instructions ? [{ role: 'system', content: body.instructions }] : []), ...messagesOf(body.input)],
  };
  if (tools?.length) chat.tools = tools;
  if (choice !== undefined) chat.tool_choice = typeof choice === 'object' && choice.type === 'function' ? { type: 'function', function: { name: choice.name } } : choice;
  if (body.temperature !== undefined) chat.temperature = body.temperature;
  if (body.top_p !== undefined) chat.top_p = body.top_p;
  if (body.max_output_tokens !== undefined) chat.max_tokens = body.max_output_tokens;
  return chat;
}

export function toResponse(chat: ChatResponse): Record<string, unknown> {
  const id = String(chat.id ?? Date.now());
  const choice = chat.choices?.[0];
  const text = choice?.message.content ?? '';
  const output: Record<string, unknown>[] = [];
  if (text) output.push({ type: 'message', id: `msg_${id}`, status: 'completed', role: 'assistant', content: [{ type: 'output_text', text, annotations: [] }] });
  for (const call of choice?.message.tool_calls ?? []) {
    output.push({ type: 'function_call', id: `fc_${call.id}`, call_id: call.id, name: call.function.name, arguments: call.function.arguments, status: 'completed' });
  }
  const incomplete = choice?.finish_reason === 'length';
  const input_tokens = chat.usage?.prompt_tokens ?? 0;
  const output_tokens = chat.usage?.completion_tokens ?? 0;
  return {
    id: `resp_${id}`, object: 'response', created_at: Math.floor(Date.now() / 1000), status: incomplete ? 'incomplete' : 'completed',
    incomplete_details: incomplete ? { reason: 'max_output_tokens' } : null, error: null, model: chat.model, output, output_text: text, parallel_tool_calls: true, tools: [],
    usage: { input_tokens, output_tokens, total_tokens: input_tokens + output_tokens, input_tokens_details: { cached_tokens: 0 }, output_tokens_details: { reasoning_tokens: 0 } },
  };
}

/** The checked answer as Responses streaming events; like chat streaming, it is complete before the first byte. */
export function streamEvents(response: Record<string, unknown>): { event: string; data: Record<string, unknown> }[] {
  const events: { event: string; data: Record<string, unknown> }[] = [];
  const add = (type: string, data: Record<string, unknown>) => events.push({ event: type, data: { type, sequence_number: events.length, ...data } });
  const output = response.output as (Record<string, unknown> & { content?: { text: string }[] })[];
  add('response.created', { response: { ...response, status: 'in_progress', output: [] } });
  add('response.in_progress', { response: { ...response, status: 'in_progress', output: [] } });
  output.forEach((item, output_index) => {
    const item_id = item.id;
    if (item.type === 'message') {
      add('response.output_item.added', { output_index, item: { ...item, status: 'in_progress', content: [] } });
      add('response.content_part.added', { output_index, item_id, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } });
      const text = item.content![0]!.text;
      add('response.output_text.delta', { output_index, item_id, content_index: 0, delta: text });
      add('response.output_text.done', { output_index, item_id, content_index: 0, text });
      add('response.content_part.done', { output_index, item_id, content_index: 0, part: item.content![0]! });
    } else {
      add('response.output_item.added', { output_index, item: { ...item, status: 'in_progress', arguments: '' } });
      add('response.function_call_arguments.delta', { output_index, item_id, delta: item.arguments });
      add('response.function_call_arguments.done', { output_index, item_id, arguments: item.arguments });
    }
    add('response.output_item.done', { output_index, item });
  });
  add('response.completed', { response });
  return events;
}

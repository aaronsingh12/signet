import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { streamEvents, toChatRequest, toResponse, UnsupportedResponsesRequest } from '../src/responses';

test('a Responses request becomes the equivalent chat request', () => {
  const chat = toChatRequest({
    model: 'm', instructions: 'Be brief', max_output_tokens: 50,
    input: [
      { role: 'user', content: [{ type: 'input_text', text: 'refund?' }] },
      { type: 'function_call', call_id: 'c1', name: 'lookup', arguments: '{"id":1}' },
      { type: 'function_call_output', call_id: 'c1', output: 'found' },
    ],
    tools: [{ type: 'function', name: 'lookup', description: 'd', parameters: { type: 'object' } }],
    tool_choice: { type: 'function', name: 'lookup' },
  });
  assert.equal(chat.max_tokens, 50);
  assert.deepEqual((chat.messages as { role: string }[]).map((m) => m.role), ['system', 'user', 'assistant', 'tool']);
  assert.deepEqual(chat.tool_choice, { type: 'function', function: { name: 'lookup' } });
  assert.equal((chat.tools as { function: { name: string } }[])[0]!.function.name, 'lookup');
  assert.deepEqual(toChatRequest({ model: 'm', input: 'hi' }).messages, [{ role: 'user', content: 'hi' }]);
});

test('what Signet cannot honour is refused, not silently ignored', () => {
  assert.throws(() => toChatRequest({ model: 'm', input: 'hi', previous_response_id: 'r' }), UnsupportedResponsesRequest);
  assert.throws(() => toChatRequest({ model: 'm', input: 'hi', tools: [{ type: 'web_search' }] }), UnsupportedResponsesRequest);
  assert.throws(() => toChatRequest({ model: 'm', input: [{ role: 'user', content: [{ type: 'input_image' }] }] }), UnsupportedResponsesRequest);
});

test('chat answers map back to Responses output and stream events', () => {
  const r = toResponse({ id: 'x', model: 'm', choices: [{ index: 0, finish_reason: 'tool_calls', message: { role: 'assistant', content: 'ok', tool_calls: [{ id: 'c1', type: 'function', function: { name: 'f', arguments: '{}' } }] } }], usage: { prompt_tokens: 3, completion_tokens: 2 } });
  assert.equal(r.output_text, 'ok');
  assert.deepEqual((r.output as { type: string }[]).map((o) => o.type), ['message', 'function_call']);
  assert.equal((r.usage as { total_tokens: number }).total_tokens, 5);
  const events = streamEvents(r);
  assert.equal(events.at(-1)!.event, 'response.completed');
  assert.ok(events.some((e) => e.event === 'response.output_text.delta' && e.data.delta === 'ok'));
  assert.ok(events.some((e) => e.event === 'response.function_call_arguments.done'));
  assert.equal(toResponse({ choices: [{ index: 0, finish_reason: 'length', message: { role: 'assistant', content: 'par' } }] }).status, 'incomplete');
});

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { chatToOllama, ollamaToChat, UnsupportedOllamaRequest } from '../src/ollama';

test('a native Ollama request becomes the equivalent chat request', () => {
  const chat = ollamaToChat({
    model: 'beam:cloud', stream: true, options: { temperature: 0.2, num_predict: 50 }, tools: [{ type: 'function', function: { name: 'lookup' } }],
    messages: [
      { role: 'user', content: 'refund?' },
      { role: 'assistant', content: '', thinking: 'hm', tool_calls: [{ function: { name: 'lookup', arguments: { id: 1 } } }] },
      { role: 'tool', content: 'found', tool_name: 'lookup' },
    ],
  });
  assert.equal(chat.temperature, 0.2);
  assert.equal(chat.max_tokens, 50);
  assert.equal(chat.stream, undefined);
  const [, assistant, tool] = chat.messages as { thinking?: string; name?: string; tool_calls?: { type: string; function: { arguments: string } }[] }[];
  assert.equal(assistant!.thinking, undefined);
  assert.equal(assistant!.tool_calls![0]!.type, 'function');
  assert.equal(assistant!.tool_calls![0]!.function.arguments, '{"id":1}');
  assert.equal(tool!.name, 'lookup');
});

test('what Signet cannot honour is refused, not silently ignored', () => {
  assert.throws(() => ollamaToChat({ model: 'm' }), UnsupportedOllamaRequest);
  assert.throws(() => ollamaToChat({ model: 'm', messages: [{ role: 'user', content: 'x', images: ['a'] }] }), UnsupportedOllamaRequest);
  assert.throws(() => ollamaToChat({ model: 'm', messages: [], format: { type: 'object' } }), UnsupportedOllamaRequest);
});

test('chat answers map back to the native shape', () => {
  const r = chatToOllama({ model: 'beam:cloud', usage: { prompt_tokens: 2, completion_tokens: 3 }, choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'ok', tool_calls: [{ id: 'c1', type: 'function', function: { name: 'lookup', arguments: '{"id":1}' } }, { id: 'c2', type: 'function', function: { name: 'bad', arguments: '{' } }] } }] });
  const m = r.message as { content: string; tool_calls: { function: { arguments: unknown } }[] };
  assert.equal(r.done, true);
  assert.equal(r.prompt_eval_count, 2);
  assert.equal(m.content, 'ok');
  assert.deepEqual(m.tool_calls[0]!.function.arguments, { id: 1 });
  assert.deepEqual(m.tool_calls[1]!.function.arguments, {});
});

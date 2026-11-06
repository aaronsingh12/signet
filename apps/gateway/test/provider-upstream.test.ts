import { strict as assert } from 'node:assert';
import { createServer, type IncomingHttpHeaders } from 'node:http';
import { test } from 'node:test';

// An agent's own LLM receives the call, and never the default LLM's credential.
test('a call with an upstream goes to that LLM with only its own credential', async () => {
  process.env.SIGNET_TOOL_PRIVATE_DESTINATIONS = 'allow';
  process.env.SIGNET_LLM_API_KEY = 'default-llm-key-must-not-leak';
  const seen: { url?: string; headers?: IncomingHttpHeaders } = {};
  const server = createServer((req, res) => {
    seen.url = req.url;
    seen.headers = req.headers;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ model: 'beam', choices: [] }));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  try {
    const { chatCompletion } = await import('../src/provider');
    const port = (server.address() as { port: number }).port;
    const r = await chatCompletion({ model: 'beam:cloud', messages: [] }, AbortSignal.timeout(5000), { base_url: `http://127.0.0.1:${port}/v1`, secret_id: null });
    assert.equal(r.model, 'beam');
    assert.equal(seen.url, '/v1/chat/completions');
    assert.equal(seen.headers!.authorization, undefined);
  } finally {
    server.close();
    delete process.env.SIGNET_LLM_API_KEY;
  }
});

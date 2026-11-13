import express, { type Request, type Response } from 'express';
import { destinationPolicyFromEnv, httpToolRequest, request, verifyJws, type ToolAlias } from '@signet/core';
import { handleChat } from './chat';
import { type Done, Halt, hitlDecided, newCtx, preflight } from './ctx';
import { isolation, modelInfo, startRuntime } from './detectors';
import { runningHashes } from './pins';
import { engineName, initEngine } from './engine';
import { llmStatus, probe, type ChatResponse } from './provider';
import * as state from './state';
import { handleTool } from './toolcall';
import { forwardEdge } from './edge';
import { ApiKeyRefused, resolveApiKey } from './apikey';
import { chatToOllama, ollamaToChat, UnsupportedOllamaRequest } from './ollama';
import { streamEvents, toChatRequest, toResponse, UnsupportedResponsesRequest } from './responses';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

// A deployment credential can obtain only its own agent's token; no control-plane login is exposed.
app.post('/v1/identity/token', async (req, res, next) => {
  try {
    const upstream = await request(`${state.CONTROL_URL}/api/v1/identity/deployment-token`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ deployment_credential: req.body?.deployment_credential }), timeoutMs: 5000,
    });
    res.status(upstream.status).set('cache-control', 'no-store').type('application/json').send(upstream.text());
  } catch (error) {
    next(error);
  }
});

// A deployment credential used as an API key (OPENAI_API_KEY=sdc_…) becomes the agent's workload token.
app.use(['/v1', '/api/chat', '/api/tags'], (req, res, next) => {
  resolveApiKey(req.headers).then(() => next(), (error: unknown) => {
    if (error instanceof ApiKeyRefused) {
      let detail = 'deployment credential refused';
      try { detail = (JSON.parse(error.body) as { detail?: string }).detail ?? detail; } catch { /* not JSON */ }
      return res.status(error.status === 403 ? 403 : 401).json({ error: { type: 'signet_policy', code: 'invalid_api_key', message: detail, decision: 'deny', rule_ids: ['BP-4.2'] } });
    }
    console.error('[gateway] API key exchange failed', error);
    res.status(503).json({ error: { type: 'signet_internal', code: 'identity_unavailable', message: 'the control plane could not check the API key; retry' } });
  });
});

// The models a caller's seal grants; null when the key is not valid.
function grantedModels(req: Request): string[] | null {
  let claims: { exp: number; jti: string; cert_id: string };
  try {
    claims = verifyJws<{ exp: number; jti: string; cert_id: string }>(String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, ''), state.tokenKeys, 'JWT').payload;
    if (claims.exp * 1000 < Date.now() || state.isRevoked(claims.jti)) return null;
  } catch {
    return null;
  }
  const grants = state.certs.get(claims.cert_id)?.models ?? [];
  const granted = (name: string) => grants.some((g) => new RegExp(`^${g.model.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`).test(name));
  return (state.bundle?.catalogue ?? []).map((c) => c.model).filter(granted);
}

const unauthenticated = (res: Response) => res.status(401).json({ error: { type: 'signet_policy', code: 'unauthenticated', message: 'a valid API key is required', decision: 'deny', rule_ids: ['BP-5.2-1'] } });

// The model list clients check before chatting: only what the seal grants, and only for a caller
// holding a valid key.
app.get('/v1/models', (req, res) => {
  const models = grantedModels(req);
  if (!models) return unauthenticated(res);
  const created = Math.floor(Date.parse(state.bundle?.issued_at ?? new Date().toISOString()) / 1000);
  res.json({ object: 'list', data: models.map((id) => ({ id, object: 'model', created, owned_by: 'signet' })) });
});

const send = (res: Response, d: Done) => res.status(d.status).set(d.headers).json(d.body);

// Streaming clients get the checked answer as chat.completion.chunk events. The answer is complete
// before the first byte so outbound DLP sees all of it; rolling-window scanning (BP 5.2) comes later.
function sendStream(res: Response, d: Done) {
  const r = d.body as ChatResponse;
  res.writeHead(200, { ...d.headers, 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
  for (const c of r.choices ?? []) {
    const delta = { role: 'assistant', content: c.message.content, tool_calls: c.message.tool_calls?.map((tc, i) => ({ index: i, ...tc })) };
    res.write(`data: ${JSON.stringify({ id: r.id, object: 'chat.completion.chunk', created: r.created, model: r.model, choices: [{ index: c.index, delta, finish_reason: c.finish_reason ?? 'stop' }] })}\n\n`);
  }
  if (r.usage) res.write(`data: ${JSON.stringify({ id: r.id, object: 'chat.completion.chunk', model: r.model, choices: [], usage: r.usage })}\n\n`);
  res.end('data: [DONE]\n\n');
}

const guard = (fn: (req: Request, res: Response) => Promise<unknown>) => (req: Request, res: Response) =>
  fn(req, res).catch((e) => {
    console.error('[gateway] unexpected error', e);
    if (!res.headersSent) res.status(500).json({ error: { type: 'signet_internal', code: 'internal_error', message: 'gateway error' } });
  });

// --- the cloud LLM, OpenAI-compatible (base-URL switch, BP 11.2) ---
app.post(['/v1/chat/completions', '/v1/llm/chat/completions'], guard(async (req, res) => {
  const d = await handleChat(req.headers, req.body);
  if (d.status === 200 && req.body?.stream === true) return sendStream(res, d);
  send(res, d);
}));

// Ollama's native API, translated onto the same governed chat path. A streaming client gets the checked
// answer as one final line, so outbound DLP has seen all of it.
app.get('/api/tags', (req, res) => {
  const models = grantedModels(req);
  if (!models) return unauthenticated(res);
  res.json({ models: models.map((name) => ({ name, model: name })) });
});

app.post('/api/chat', guard(async (req, res) => {
  let chat: Record<string, unknown>;
  try {
    chat = ollamaToChat((req.body ?? {}) as Record<string, unknown>);
  } catch (e) {
    if (e instanceof UnsupportedOllamaRequest) return res.status(400).json({ error: { type: 'invalid_request_error', code: 'unsupported_ollama_feature', message: e.message } });
    throw e;
  }
  const d = await handleChat(req.headers, chat);
  if (d.status !== 200) return send(res, d);
  const answer = chatToOllama(d.body as ChatResponse);
  if (req.body?.stream === false) return send(res, { ...d, body: answer });
  res.writeHead(200, { ...d.headers, 'content-type': 'application/x-ndjson' });
  res.end(`${JSON.stringify(answer)}\n`);
}));

// OpenAI Responses API, translated onto the same governed chat path.
app.post('/v1/responses', guard(async (req, res) => {
  let chat: Record<string, unknown>;
  try {
    chat = toChatRequest((req.body ?? {}) as Record<string, unknown>);
  } catch (e) {
    if (e instanceof UnsupportedResponsesRequest) return res.status(400).json({ error: { type: 'invalid_request_error', code: 'unsupported_responses_feature', message: e.message } });
    throw e;
  }
  const d = await handleChat(req.headers, chat);
  if (d.status !== 200) return send(res, d);
  const response = toResponse(d.body as ChatResponse);
  if (req.body?.stream !== true) return send(res, { ...d, body: response });
  res.writeHead(200, { ...d.headers, 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
  for (const { event, data } of streamEvents(response)) res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  res.end();
}));

// Any other provider's API shape is refused and counted (RB-INV-19, RB-KILL-04).
app.post('/v1/messages', guard(async (req, res) => send(res, await handleChat(req.headers, req.body, 'anthropic'))));
app.post('/v1/llm/:provider/*', guard(async (req, res) => send(res, await handleChat(req.headers, req.body, req.params.provider))));

// --- MCP proxy (Streamable HTTP, JSON responses) ---
// Tool destinations are checked on every connection (SSRF); responses are capped at 5 MB.
const DESTINATIONS = destinationPolicyFromEnv();
const TOOL_MAX_BYTES = 5 * 1024 * 1024;

async function mcpForward(tool: ToolAlias, credential: string | null, msg: unknown, sessionId: string | undefined, signal: AbortSignal) {
  const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  if (sessionId) headers['mcp-session-id'] = sessionId;
  if (credential) headers[tool.auth_header] = tool.auth_header.toLowerCase() === 'authorization' ? `Bearer ${credential}` : credential;
  const r = await request(tool.url, { method: 'POST', headers, body: JSON.stringify(msg), signal, destination: DESTINATIONS, maxBytes: TOOL_MAX_BYTES });
  const outSession = r.headers['mcp-session-id'];
  if (r.status === 202) return { json: null, sessionId: outSession };
  const text = r.text();
  if (!r.ok) throw new Error(`MCP server returned ${r.status}`);
  let json: { result?: unknown; error?: { message: string } } | null = null;
  if ((r.headers['content-type'] ?? '').includes('text/event-stream')) {
    for (const line of text.split('\n')) if (line.startsWith('data:')) json = JSON.parse(line.slice(5).trim());
  } else json = JSON.parse(text);
  return { json, sessionId: outSession };
}

const rpcError = (id: unknown, code: number, message: string, data?: unknown) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data ? { data } : {}) } });

app.post('/v1/mcp/:alias', guard(async (req, res) => {
  const msg = req.body as { jsonrpc?: string; id?: unknown; method?: string; params?: { name?: string; arguments?: Record<string, unknown> } };
  const alias = req.params.alias!;
  if (!msg || Array.isArray(msg) || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return res.status(400).json(rpcError(null, -32600, 'expected one JSON-RPC 2.0 request'));
  const session = typeof req.headers['mcp-session-id'] === 'string' ? req.headers['mcp-session-id'] : undefined;

  if (msg.method === 'tools/call') {
    const d = await handleTool(req.headers, {
      kind: 'mcp',
      alias,
      action: String(msg.params?.name ?? ''),
      args: msg.params?.arguments ?? {},
      forward: async (tool, cred, signal) => {
        const out = await mcpForward(tool, cred, msg, session, signal);
        if (out.json?.error) throw new Error(out.json.error.message);
        return out.json?.result;
      },
    });
    res.set(d.headers);
    if (d.status === 200) return res.json({ jsonrpc: '2.0', id: msg.id, result: d.body });
    const e = (d.body as { error: { message: string } }).error;
    return res.status(d.status === 401 ? 401 : 200).json(rpcError(msg.id, -32003, e.message, e));
  }

  // Session set-up and discovery: authenticated, the tool list filtered to the seal (least privilege).
  const ctx = newCtx('tool_call', `mcp://${alias}`, req.headers);
  let policyActions: string[];
  try {
    const { policy } = await preflight(ctx, req.headers);
    policyActions = Object.keys(policy.actions).filter((k) => k.startsWith(`mcp://${alias}.`)).map((k) => k.slice(`mcp://${alias}.`.length));
  } catch (e) {
    if (e instanceof Halt) return res.status(e.status).json(rpcError(msg.id, -32003, e.message, { code: e.code }));
    throw e;
  }
  const tool = state.tools.get(alias);
  if (!tool || tool.kind !== 'mcp') return res.json(rpcError(msg.id, -32003, `MCP alias ${alias} is not registered`));
  if (!['initialize', 'notifications/initialized', 'ping', 'tools/list'].includes(msg.method)) {
    return res.json(rpcError(msg.id, -32601, `${msg.method} is not governed by this gateway yet`));
  }
  const cred = tool.secret_id ? await state.secret(tool.secret_id) : null;
  const out = await mcpForward(tool, cred, msg, session, AbortSignal.timeout(15_000));
  if (out.sessionId) res.setHeader('mcp-session-id', out.sessionId);
  if (!out.json) return res.status(202).end();
  if (msg.method === 'tools/list' && out.json.result) {
    const r = out.json.result as { tools?: { name: string }[] };
    r.tools = (r.tools ?? []).filter((t) => policyActions.includes(t.name));
  }
  res.json(out.json);
}));

// --- HTTP tool proxy: /v1/tools/http/<alias>/<action> ---
app.all('/v1/tools/http/:alias/:action', guard(async (req, res) => {
  const args = (req.method === 'GET' ? { ...req.query } : (req.body ?? {})) as Record<string, unknown>;
  const d = await handleTool(req.headers, {
    kind: 'http',
    alias: req.params.alias!,
    action: req.params.action!,
    args,
    forward: async (tool, cred, signal) => {
      if (tool.runner_id) return forwardEdge(tool.alias, req.params.action!, args, String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, ''), signal);
      const target = httpToolRequest(tool, req.params.action!, args, cred);
      const r = await request(target.url, { method: target.method, headers: target.headers, body: target.body, signal, destination: DESTINATIONS, maxBytes: TOOL_MAX_BYTES });
      const text = r.text();
      if (!r.ok) throw new Error(`tool returned ${r.status}`);
      try {
        return JSON.parse(text);
      } catch {
        return { text };
      }
    },
  });
  send(res, d);
}));

app.get('/healthz', (_req, res) =>
  res.json({
    ok: !state.bundleExpired(),
    node: state.NODE_ID,
    bundle_version: state.bundle?.version ?? null,
    bundle_expires_at: state.bundle?.expires_at ?? null,
    seals_loaded: state.certs.size,
    tools: [...state.tools.keys()],
    cloud_llm: state.bundle?.catalogue.map((c) => c.model) ?? [],
    cloud_llm_status: llmStatus(),
    policy_engine: engineName,
    detectors: { runtime: modelInfo, modes: Object.fromEntries([...state.detectors].map(([k, v]) => [k, v.mode])) },
  }),
);

state.setHitlListener(hitlDecided);
state.setHeartbeatExtra(llmStatus);
state.setDetectorReport(() => ({ hashes: runningHashes(), runtime: modelInfo, isolation: isolation() }));
await initEngine();
startRuntime();
state
  .init()
  .then(() => {
    void probe().then((st) => console.log(`[gateway] ${state.NODE_ID} cloud LLM check: ${st.state} (${st.detail}; credential from ${st.credential})`));
    setInterval(() => void probe(), 60_000).unref();
  })
  .then(() => app.listen(state.PORT, () => console.log(`[gateway] ${state.NODE_ID} enforcing on http://localhost:${state.PORT}  (${state.certs.size} seals; policy engine: ${engineName})`)))
  .catch((e) => {
    console.error(`[gateway] cannot load the policy bundle from ${state.CONTROL_URL}: ${(e as Error).message}`);
    process.exit(1);
  });

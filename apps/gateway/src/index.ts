import express, { type Request, type Response } from 'express';
import { request, type ToolAlias } from '@signet/core';
import { handleChat } from './chat';
import { type Done, Halt, newCtx, preflight } from './ctx';
import { modelInfo, startRuntime } from './detectors';
import { engineName, initEngine } from './engine';
import type { ChatResponse } from './provider';
import * as state from './state';
import { handleTool } from './toolcall';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

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

// Any other provider's API shape is refused and counted (RB-INV-19, RB-KILL-04).
app.post('/v1/messages', guard(async (req, res) => send(res, await handleChat(req.headers, req.body, 'anthropic'))));
app.post('/v1/llm/:provider/*', guard(async (req, res) => send(res, await handleChat(req.headers, req.body, req.params.provider))));

// --- MCP proxy (Streamable HTTP, JSON responses) ---
async function mcpForward(tool: ToolAlias, credential: string | null, msg: unknown, sessionId: string | undefined, signal: AbortSignal) {
  const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
  if (sessionId) headers['mcp-session-id'] = sessionId;
  if (credential) headers[tool.auth_header] = tool.auth_header.toLowerCase() === 'authorization' ? `Bearer ${credential}` : credential;
  const r = await request(tool.url, { method: 'POST', headers, body: JSON.stringify(msg), signal });
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
    const { policy } = preflight(ctx, req.headers);
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
      const spec = tool.actions[req.params.action!];
      if (!spec) throw new Error('action not mapped on the tool alias');
      const rest = { ...args };
      const path = spec.path.replace(/\{(\w+)\}/g, (_m, k: string) => {
        const v = rest[k];
        delete rest[k];
        return encodeURIComponent(String(v ?? ''));
      });
      const url = new URL(tool.url + path);
      const headers: Record<string, string> = { accept: 'application/json' };
      if (cred) headers[tool.auth_header] = tool.auth_header.toLowerCase() === 'authorization' ? `Bearer ${cred}` : cred;
      let body: string | undefined;
      if (spec.method === 'GET' || spec.method === 'DELETE') for (const [k, v] of Object.entries(rest)) url.searchParams.set(k, String(v));
      else {
        headers['content-type'] = 'application/json';
        body = JSON.stringify(rest);
      }
      const r = await request(url, { method: spec.method, headers, body, signal });
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
    policy_engine: engineName,
    detectors: { runtime: modelInfo, modes: Object.fromEntries([...state.detectors].map(([k, v]) => [k, v.mode])) },
  }),
);

await initEngine();
startRuntime();
state
  .init()
  .then(() => app.listen(state.PORT, () => console.log(`[gateway] ${state.NODE_ID} enforcing on http://localhost:${state.PORT}  (${state.certs.size} seals; policy engine: ${engineName})`)))
  .catch((e) => {
    console.error(`[gateway] cannot load the policy bundle from ${state.CONTROL_URL}: ${(e as Error).message}`);
    process.exit(1);
  });

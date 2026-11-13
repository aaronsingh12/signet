import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import https from 'node:https';
import { identityFromEnv, TokenManager } from './tokens';
import { parseArgs } from 'node:util';
import { connectionFromFile } from './config';

// Signet sidecar: a local endpoint that holds the agent's workload identity and forwards to the Signet
// gateway. For agents that cannot run the SDK (n8n, Flowise, Dify, other languages): point the
// framework's OpenAI base URL at http://<sidecar>:8300/v1 and its MCP servers at
// http://<sidecar>:8300/v1/mcp/<alias>. Any API key the framework insists on is discarded.
//
// Whoever can reach the sidecar acts as this agent, so it listens on 127.0.0.1 unless
// SIGNET_SIDECAR_BIND says otherwise (only a private container network, never a public interface).

const { values } = parseArgs({ options: { config: { type: 'string' } } });
const fileConfig = values.config ? connectionFromFile(values.config) : null;
const GATEWAY = (fileConfig ? fileConfig.gatewayUrl : process.env.SIGNET_GATEWAY_URL ?? '').replace(/\/$/, '');
if (!GATEWAY) throw new Error('SIGNET_GATEWAY_URL is required');
const PORT = Number(process.env.SIGNET_SIDECAR_PORT ?? '8300');
const BIND = process.env.SIGNET_SIDECAR_BIND ?? '127.0.0.1';
const SESSION = process.env.SIGNET_SESSION_ID;
const VERSION = '0.1.0';
const tokens = new TokenManager(fileConfig ? fileConfig.identity : identityFromEnv());
const gw = new URL(GATEWAY);
const mod = gw.protocol === 'https:' ? https : http;
const agent = new mod.Agent({ keepAlive: true });
let lastForwardAt: string | null = null;
let lastForwardStatus: number | null = null;

// Hop-by-hop headers and anything that would carry the framework's own credential are dropped.
const DROP = new Set(['host', 'connection', 'keep-alive', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'authorization', 'api-key', 'x-api-key', 'content-length']);

function forward(req: IncomingMessage, res: ServerResponse, body: Buffer, token: string, retried: boolean) {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) if (!DROP.has(k) && v !== undefined) headers[k] = Array.isArray(v) ? v.join(', ') : v;
  headers.authorization = `Bearer ${token}`;
  if (SESSION && !headers['x-signet-session']) headers['x-signet-session'] = SESSION;
  if (body.length) headers['content-length'] = String(body.length);
  const up = mod.request({ protocol: gw.protocol, hostname: gw.hostname, port: gw.port, path: req.url, method: req.method, headers, agent }, (ur) => {
    // A token refused as expired or revoked: re-authenticate once and replay.
    if (ur.statusCode === 401 && !retried) {
      const chunks: Buffer[] = [];
      ur.on('data', (c: Buffer) => chunks.push(c));
      ur.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (/token_expired|token_revoked|invalid_token/.test(text)) {
          tokens.invalidate();
          tokens.get().then((t) => forward(req, res, body, t, true), (e: Error) => fail(res, 401, e.message));
        } else {
          res.writeHead(401, { 'content-type': ur.headers['content-type'] ?? 'application/json' }).end(text);
        }
      });
      return;
    }
    lastForwardAt = new Date().toISOString();
    lastForwardStatus = ur.statusCode ?? null;
    const out: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(ur.headers)) if (v !== undefined && k !== 'connection' && k !== 'keep-alive') out[k] = v;
    res.writeHead(ur.statusCode ?? 502, out);
    ur.pipe(res); // streams pass through unchanged
  });
  up.on('error', (e) => fail(res, 502, `cannot reach the Signet gateway at ${GATEWAY}: ${e.message}`));
  up.end(body);
}

function fail(res: ServerResponse, status: number, message: string) {
  if (res.headersSent) return res.destroy();
  res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify({ error: { type: 'signet_sidecar', code: status === 401 ? 'identity_unavailable' : 'gateway_unreachable', message } }));
}

const server = http.createServer((req, res) => {
  if (req.url === '/signet/status') {
    const c = tokens.claims;
    res.writeHead(200, { 'content-type': 'application/json' }).end(
      JSON.stringify({ sidecar: VERSION, gateway: GATEWAY, identity: c ? { agent_id: c.agent_id, version: c.ver, instance: c.ins, expires_at: new Date(c.exp * 1000).toISOString() } : null, last_error: tokens.lastError, last_forward_at: lastForwardAt, last_forward_status: lastForwardStatus }),
    );
    return;
  }
  if (!req.url?.startsWith('/v1/')) return fail(res, 404, 'the sidecar forwards /v1/* to the Signet gateway');
  const chunks: Buffer[] = [];
  let size = 0;
  req.on('data', (c: Buffer) => {
    size += c.length;
    if (size > 10 * 1024 * 1024) req.destroy();
    else chunks.push(c);
  });
  req.on('end', () => tokens.get().then((t) => forward(req, res, Buffer.concat(chunks), t, false), (e: Error) => fail(res, 401, e.message)));
});

server.listen(PORT, BIND, async () => {
  console.log(`[signet-sidecar] ${VERSION} on http://${BIND}:${PORT} → ${GATEWAY}`);
  try {
    const t = await tokens.get();
    void t;
    const c = tokens.claims!;
    console.log(`[signet-sidecar] identity: agent ${c.agent_id} version ${c.ver} instance ${c.ins}`);
  } catch (e) {
    console.error(`[signet-sidecar] identity not established yet: ${(e as Error).message}`);
  }
});

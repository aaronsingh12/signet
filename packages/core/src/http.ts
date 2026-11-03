import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { DestinationBlocked, addressAllowed, guardedLookup, type DestinationPolicy } from './netguard';

// Keep-alive HTTP client for hot paths (gateway -> control plane, model, tools). Measured on Windows,
// Node's fetch costs ~10 ms per request against ~1 ms for node:http with keep-alive and Nagle off,
// which matters when every agent call makes a ledger write (RB-INV-15).

const agents = {
  'http:': new http.Agent({ keepAlive: true, maxSockets: 512 }),
  'https:': new https.Agent({ keepAlive: true, maxSockets: 512 }),
};

export interface HttpResponse {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  body: Buffer;
  text(): string;
  json<T = unknown>(): T;
}

export interface HttpOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  signal?: AbortSignal;
  timeoutMs?: number;
  // Outbound tool calls: every dialled address is checked against this policy (SSRF).
  destination?: DestinationPolicy;
  // Largest response body accepted; larger responses are cut and fail.
  maxBytes?: number;
}

export { DestinationBlocked };

export function request(url: string | URL, opts: HttpOptions = {}): Promise<HttpResponse> {
  const u = typeof url === 'string' ? new URL(url) : url;
  const mod = u.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) return reject(opts.signal.reason ?? new Error('aborted'));
    if (opts.destination) {
      const host = u.hostname.replace(/^\[|\]$/g, '');
      if (isIP(host) && !addressAllowed(host, opts.destination).ok) return reject(new DestinationBlocked(`${host} is not a reachable tool address`));
    }
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (opts.body !== undefined) headers['content-length'] = String(Buffer.byteLength(opts.body));
    // Guarded calls get their own connection so the lookup check runs for each one.
    const agent = opts.destination ? false : agents[u.protocol as 'http:' | 'https:'];
    const lookup = opts.destination ? guardedLookup(opts.destination) : undefined;
    const req = mod.request(u, { method: opts.method ?? 'GET', headers, agent, ...(lookup ? { lookup: lookup as never } : {}) }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let tooBig = false;
      res.on('data', (c: Buffer) => {
        size += c.length;
        if (opts.maxBytes && size > opts.maxBytes) {
          tooBig = true;
          res.destroy();
          return reject(new Error(`response larger than ${opts.maxBytes} bytes`));
        }
        chunks.push(c);
      });
      res.on('end', () => {
        if (tooBig) return;
        const body = Buffer.concat(chunks);
        const h: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) h[k] = Array.isArray(v) ? v.join(', ') : v;
        const status = res.statusCode ?? 0;
        resolve({ status, ok: status >= 200 && status < 300, headers: h, body, text: () => body.toString('utf8'), json: <T>() => JSON.parse(body.toString('utf8')) as T });
      });
      res.on('error', reject);
    });
    req.on('socket', (s) => s.setNoDelay(true));
    req.on('error', reject);
    const onAbort = () => req.destroy(opts.signal?.reason instanceof Error ? opts.signal.reason : new Error('aborted'));
    opts.signal?.addEventListener('abort', onAbort, { once: true });
    if (opts.timeoutMs) req.setTimeout(opts.timeoutMs, () => req.destroy(new Error(`timeout after ${opts.timeoutMs} ms`)));
    req.on('close', () => opts.signal?.removeEventListener('abort', onAbort));
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

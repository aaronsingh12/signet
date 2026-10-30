import http from 'node:http';
import https from 'node:https';

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
}

export function request(url: string | URL, opts: HttpOptions = {}): Promise<HttpResponse> {
  const u = typeof url === 'string' ? new URL(url) : url;
  const mod = u.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) return reject(opts.signal.reason ?? new Error('aborted'));
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (opts.body !== undefined) headers['content-length'] = String(Buffer.byteLength(opts.body));
    const req = mod.request(u, { method: opts.method ?? 'GET', headers, agent: agents[u.protocol as 'http:' | 'https:'] }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
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

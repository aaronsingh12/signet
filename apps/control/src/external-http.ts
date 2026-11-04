import { request, type RequestOptions } from 'node:https';
import { randomUUID } from 'node:crypto';
import { validateHeaderName, validateHeaderValue } from 'node:http';
import { setTimeout } from 'node:timers/promises';
import { checkDestination, guardedLookup, DestinationBlocked } from '@signet/core';
import { PolicyError } from './errors';
import type { Json } from './external-contract';

export interface ExternalRequest {
  url: URL; method: string; headers: Record<string, string>; body: string | null; timeout: number;
  expectedStatus?: number[]; tlsMinVersion?: 'TLSv1.2' | 'TLSv1.3'; correlationId?: string;
}
function responseJson(text: string): Json {
  let data: Json;
  try { data = JSON.parse(text) as Json; } catch { throw new PolicyError('EXTERNAL_SCHEMA', 'External endpoint returned malformed JSON', 502); }
  const pending: { value: Json; depth: number }[] = [{ value: data, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const entry = pending.pop()!;
    if (++nodes > 50000 || entry.depth > 32) throw new PolicyError('EXTERNAL_SIZE', 'External JSON exceeds nesting or node limits', 502);
    if (typeof entry.value === 'number' && !Number.isFinite(entry.value)) throw new PolicyError('EXTERNAL_SCHEMA', 'External JSON contains a non-finite number', 502);
    if (entry.value !== null && typeof entry.value === 'object') for (const child of Object.values(entry.value)) pending.push({ value: child, depth: entry.depth + 1 });
  }
  return data;
}
let active = 0;
const MAX_CONCURRENT = 8;
function networkError(error: Error): PolicyError {
  if (error instanceof PolicyError) return error;
  if (error instanceof DestinationBlocked) return new PolicyError('EXTERNAL_DESTINATION', 'DNS destination changed to a disallowed address; connection blocked', 400);
  const code = (error as NodeJS.ErrnoException).code ?? '';
  const category = ['ENOTFOUND', 'EAI_AGAIN'].includes(code) ? 'EXTERNAL_DNS' : /CERT|TLS|SSL/.test(code) ? 'EXTERNAL_TLS' : error.name === 'AbortError' || ['ETIMEDOUT', 'ABORT_ERR'].includes(code) ? 'EXTERNAL_TIMEOUT' : 'EXTERNAL_NETWORK';
  return new PolicyError(category, `External request failed (${category}); check DNS, TLS certificates, timeout and network access. Provider response and credential values withheld`, 502);
}
/** HTTPS only, certificate verification always on, all DNS results checked again at actual socket lookup. */
export async function requestJson(input: ExternalRequest): Promise<Json> {
  if (input.url.protocol !== 'https:' || input.url.username || input.url.password || input.url.hash || (input.url.port && input.url.port !== '443')) throw new PolicyError('EXTERNAL_DESTINATION', 'External requests require HTTPS on port 443 without URL credentials or fragments', 400);
  if (input.url.toString().length > 20000) throw new PolicyError('EXTERNAL_CONFIG', 'External URL exceeds 20000 characters; values withheld', 400);
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(input.method) || input.timeout < 1000 || input.timeout > 30000) throw new PolicyError('EXTERNAL_CONFIG', 'Request method or timeout is outside configured limits', 400);
  const allowed = process.env.SIGNET_CONNECTOR_HOST_ALLOWLIST?.split(',').map((host) => host.trim().toLowerCase()).filter(Boolean);
  if (allowed?.length && !allowed.includes(input.url.hostname.toLowerCase())) throw new PolicyError('EXTERNAL_DESTINATION', 'External hostname is not on the operator configured outbound allowlist', 400);
  for (const [key, value] of Object.entries(input.headers)) {
    try { validateHeaderName(key); validateHeaderValue(key, value); }
    catch { throw new PolicyError('EXTERNAL_CONFIG', 'External header contains invalid characters; values withheld', 400); }
    if (/^(host|cookie|connection|content-length|transfer-encoding|proxy-.*|x-signet-.*|x-forwarded-.*)$/i.test(key)) throw new PolicyError('EXTERNAL_CONFIG', 'External header name is reserved', 400);
  }
  if (input.body !== null && Buffer.byteLength(input.body) > 16000) throw new PolicyError('EXTERNAL_SIZE', 'Request body exceeds 16 KiB', 400);
  try { await checkDestination(input.url, { allowPrivate: false }); }
  catch (error) {
    if (error instanceof DestinationBlocked) throw new PolicyError(error.message.startsWith('cannot resolve') ? 'EXTERNAL_DNS' : 'EXTERNAL_DESTINATION', 'External address cannot be resolved or is a disallowed network address', 400);
    if (error instanceof Error) throw networkError(error);
    throw error;
  }
  if (active >= MAX_CONCURRENT) throw new PolicyError('EXTERNAL_RATE_LIMIT', 'Connector concurrency limit reached; retry after current requests complete', 429);
  active++;
  const correlationId = input.correlationId ?? randomUUID();
  try {
    return await new Promise<Json>((resolve, reject) => {
      const options: RequestOptions = { method: input.method, headers: { ...input.headers, 'x-request-id': correlationId }, lookup: guardedLookup({ allowPrivate: false }), agent: false, rejectUnauthorized: true, minVersion: input.tlsMinVersion ?? 'TLSv1.2', signal: AbortSignal.timeout(input.timeout) };
      const req = request(input.url, options, (res) => {
        const status = res.statusCode ?? 502;
        if (status < 200 || status >= 300 || (input.expectedStatus && !input.expectedStatus.includes(status))) {
          res.destroy();
          const rule = status === 401 || status === 403 ? 'EXTERNAL_AUTH' : status === 404 ? 'EXTERNAL_NOT_FOUND' : status === 429 ? 'EXTERNAL_RATE_LIMIT' : status >= 300 && status < 400 ? 'EXTERNAL_REDIRECT' : 'EXTERNAL_HTTP';
          const after = res.headers['retry-after'];
          const retryAfter = typeof after === 'string' ? Math.min(5000, Math.max(0, /^\d+$/.test(after) ? Number(after) * 1000 : Date.parse(after) - Date.now())) : 0;
          reject(new PolicyError(rule, `External ${input.method} request returned unexpected HTTP ${status}; response body withheld because it may contain credentials`, 502, { upstream_status: status, correlation_id: correlationId, retry_after_ms: Number.isFinite(retryAfter) ? retryAfter : 0 }));
          return;
        }
        if (status === 204) { res.resume(); resolve(null); return; }
        if (!/^application\/(?:[a-z0-9.-]+\+)?json(?:;|$)/i.test(res.headers['content-type'] ?? '')) { res.destroy(); reject(new PolicyError('EXTERNAL_CONTENT', 'Expected an application/json response; provider returned a different content type', 502)); return; }
        let size = 0;
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > 1024 * 1024) { res.destroy(new PolicyError('EXTERNAL_SIZE', 'External response exceeded 1 MiB', 502)); return; }
          chunks.push(chunk);
        });
        res.on('error', (error: Error) => reject(networkError(error)));
        res.on('aborted', () => reject(new PolicyError('EXTERNAL_NETWORK', 'External response was interrupted before completion', 502)));
        res.on('end', () => {
          try { resolve(responseJson(Buffer.concat(chunks).toString('utf8'))); }
          catch (error) { reject(error); }
        });
      });
      req.on('error', (error: Error) => reject(networkError(error)));
      req.end(input.body ?? undefined);
    });
  } finally { active--; }
}
/** Safe GETs only. Honor bounded Retry-After, exponential backoff and jitter; never replay writes. */
export async function readJson(input: ExternalRequest): Promise<Json> {
  if (input.method !== 'GET') throw new TypeError('readJson requires GET');
  for (let attempt = 1; ; attempt++) {
    try { return await requestJson(input); }
    catch (error) {
      if (!(error instanceof PolicyError) || !['EXTERNAL_DNS', 'EXTERNAL_TIMEOUT', 'EXTERNAL_NETWORK', 'EXTERNAL_HTTP', 'EXTERNAL_RATE_LIMIT'].includes(error.rule) || (error.extra.upstream_status !== undefined && ![429, 502, 503, 504].includes(Number(error.extra.upstream_status))) || attempt === 3) throw error;
      console.warn('External read failed; retrying', { attempt, rule: error.rule });
      await setTimeout(Math.max(Number(error.extra.retry_after_ms ?? 0), 200 * 2 ** (attempt - 1) + Math.floor(Math.random() * 100)));
    }
  }
}

import { request } from 'node:https';
import { setTimeout } from 'node:timers/promises';
import { checkDestination, guardedLookup, DestinationBlocked } from '@signet/core';
import { PolicyError } from './errors';
import type { Json } from './external-contract';

export interface ExternalRequest { url: URL; method: string; headers: Record<string, string>; body: string | null; timeout: number }
/** Check DNS on every dial; reject redirects so credentials can never move to another origin. */
export async function requestJson(input: ExternalRequest): Promise<Json> {
  try { await checkDestination(input.url, { allowPrivate: false }); }
  catch (error) {
    if (!(error instanceof DestinationBlocked)) throw error;
    throw new PolicyError('EXTERNAL_DESTINATION', error.message, 400);
  }
  return new Promise<Json>((resolve, reject) => {
    const req = request(input.url, { method: input.method, headers: input.headers, lookup: guardedLookup({ allowPrivate: false }), agent: false, signal: AbortSignal.timeout(input.timeout) }, (res) => {
      const status = res.statusCode ?? 502;
      if (status < 200 || status >= 300) {
        res.destroy();
        reject(new PolicyError(status === 401 || status === 403 ? 'EXTERNAL_AUTH' : 'EXTERNAL_HTTP', `External ${input.method} request returned HTTP ${status}${status === 401 ? ': credential invalid or expired' : status === 403 ? ': insufficient scope or permission' : status >= 300 && status < 400 ? ': redirects are forbidden' : ''}; response body withheld because it may contain credentials`, 502, { upstream_status: status }));
        return;
      }
      let size = 0;
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 1024 * 1024) { res.destroy(new PolicyError('EXTERNAL_SIZE', 'External response exceeded 1 MiB', 502)); return; }
        chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Json); }
        catch { reject(new PolicyError('EXTERNAL_SCHEMA', 'External endpoint returned malformed JSON', 502)); }
      });
    });
    req.on('error', (error) => reject(error instanceof PolicyError ? error : new PolicyError('EXTERNAL_NETWORK', 'External request failed DNS, TLS, destination validation, timeout or network connectivity; check the configured endpoint', 502)));
    req.end(input.body ?? undefined);
  });
}

/** Only harmless reads are retried. Token acquisition and remote writes are never replayed. */
export async function readJson(input: ExternalRequest): Promise<Json> {
  if (input.method !== 'GET') throw new TypeError('readJson requires GET');
  for (let attempt = 1; ; attempt++) {
    try { return await requestJson(input); }
    catch (error) {
      if (!(error instanceof PolicyError) || !['EXTERNAL_NETWORK', 'EXTERNAL_HTTP'].includes(error.rule) || (error.extra.upstream_status !== undefined && ![429, 502, 503, 504].includes(Number(error.extra.upstream_status))) || attempt === 3) throw error;
      console.warn('External read failed; retrying', { attempt, rule: error.rule });
      await setTimeout(attempt * 200);
    }
  }
}

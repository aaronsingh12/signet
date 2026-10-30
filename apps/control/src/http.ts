import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { db, nowIso } from './db';
import { PolicyError } from './errors';
import type { Principal } from './rbac';

// API conventions (BP 13): RFC 9457 problem details, Idempotency-Key on POST, cursor pagination.

// Route wrapper: handlers return a value (sent as JSON) or a [status, value] pair; sync or async.
export const route =
  (fn: (req: Request, res: Response) => unknown | Promise<unknown>): RequestHandler =>
  async (req, res, next) => {
    try {
      const out = await fn(req, res);
      if (res.headersSent || out === undefined) return;
      if (Array.isArray(out) && out.length === 2 && typeof out[0] === 'number') res.status(out[0]).json(out[1]);
      else res.json(out);
    } catch (e) {
      next(e);
    }
  };

export function problemHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
  const isPolicy = err instanceof PolicyError;
  const status = isPolicy ? err.status : (err as { status?: number }).status === 400 ? 400 : 500;
  if (!isPolicy && status === 500) console.error('[control]', err);
  const rule = isPolicy ? err.rule : status === 400 ? 'VALIDATION' : 'INTERNAL';
  res
    .status(status)
    .type('application/problem+json')
    .json({
      type: `urn:signet:problem:${rule.toLowerCase()}`,
      title: rule,
      status,
      detail: isPolicy ? err.message : status === 400 ? 'malformed request body' : 'internal error',
      rule,
      instance: req.originalUrl,
      ...(isPolicy ? err.extra : {}),
    });
}

// Replays the stored response when a POST is retried with the same Idempotency-Key by the same caller.
export function idempotency(req: Request, res: Response, next: NextFunction) {
  const key = req.headers['idempotency-key'];
  const principal = (res.locals.principal as Principal | undefined)?.id;
  if (req.method !== 'POST' || typeof key !== 'string' || !principal) return next();
  if (key.length > 200) return next(new PolicyError('VALIDATION', 'Idempotency-Key too long', 400));
  const prior = db.prepare('SELECT method, path, status, body FROM idempotency_key WHERE key = ? AND principal = ?').get(key, principal) as
    | { method: string; path: string; status: number; body: string }
    | undefined;
  if (prior) {
    if (prior.path !== req.originalUrl) return next(new PolicyError('IDEMPOTENCY', 'this Idempotency-Key was used for a different request', 422));
    res.setHeader('idempotency-replayed', 'true');
    return res.status(prior.status).type('application/json').send(prior.body);
  }
  const json = res.json.bind(res);
  res.json = (body: unknown) => {
    if (res.statusCode < 500) {
      db.prepare('INSERT OR IGNORE INTO idempotency_key (key, principal, method, path, status, body, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        key, principal, req.method, req.originalUrl, res.statusCode, JSON.stringify(body), nowIso(),
      );
    }
    return json(body);
  };
  next();
}

export const cursor = {
  encode: (v: string | number) => Buffer.from(String(v)).toString('base64url'),
  decode: (c: unknown) => (typeof c === 'string' && c ? Buffer.from(c, 'base64url').toString() : null),
};

export const limitOf = (q: unknown, max = 500, dflt = 50) => Math.min(Math.max(Number(q) || dflt, 1), max);

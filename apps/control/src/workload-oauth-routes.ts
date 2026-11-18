import { Router, urlencoded, type Request, type Response, type NextFunction } from 'express';
import { authenticate } from './oidc';
import { principalOf } from './rbac';
import { PolicyError } from './errors';
import { route } from './http';
import { connectionAddresses } from './connection-settings';
import { exchangeBootstrap, exchangeClientCredentials } from './identity';
import * as oauth from './workload-oauth';

/** Rejects arrays, objects and oversized OAuth parameters rather than coercing external input. */
function parameter(source: object, name: string): string {
  const value: string | object | undefined = Reflect.get(source, name);
  if (value === undefined) return '';
  if (typeof value !== 'string' || value.length > 4096) throw new PolicyError('OAUTH', `OAuth parameter ${name} must be a string of at most 4096 characters`, 400, { oauth_error: 'invalid_request' });
  return value;
}

function authorizationInput(req: Request): oauth.AuthorizationInput {
  return {
    response_type: parameter(req.query, 'response_type'), client_id: parameter(req.query, 'client_id'),
    redirect_uri: parameter(req.query, 'redirect_uri'), state: parameter(req.query, 'state'),
    code_challenge: parameter(req.query, 'code_challenge'), code_challenge_method: parameter(req.query, 'code_challenge_method'), scope: parameter(req.query, 'scope'),
  };
}

/** Supports the two confidential-client authentication methods used by ServiceNow. */
function clientCredentials(req: Request): { clientId: string; secret: string } {
  const body: object = req.body ?? {};
  const clientId = parameter(body, 'client_id');
  const secret = parameter(body, 'client_secret');
  const header = req.headers.authorization;
  if (!header) return { clientId, secret };
  if (clientId || secret || !/^Basic [A-Za-z0-9+/]+={0,2}$/i.test(header)) throw new PolicyError('OAUTH', 'Use either HTTP Basic authentication or body client credentials, not both', 400, { oauth_error: 'invalid_request' });
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  if (colon < 1) throw new PolicyError('OAUTH', 'HTTP Basic credentials must contain a client ID and secret separated by a colon', 401, { oauth_error: 'invalid_client' });
  try { return { clientId: decodeURIComponent(decoded.slice(0, colon).replace(/\+/g, ' ')), secret: decodeURIComponent(decoded.slice(colon + 1).replace(/\+/g, ' ')) }; }
  catch { throw new PolicyError('OAUTH', 'HTTP Basic client credentials contain invalid URL encoding', 401, { oauth_error: 'invalid_client' }); }
}

function requireSession(req: Request, res: Response, next: NextFunction): void {
  if (!res.locals.principal) return next(new PolicyError('AUTH', 'Sign in to Signet before managing OAuth authorization', 401));
  if (req.method !== 'GET' && !req.is('application/json')) return next(new PolicyError('AUTH', 'OAuth consent and callback changes require application/json', 415));
  next();
}

/** Public protocol endpoints plus authenticated callback registration and consent APIs. */
export function workloadOAuthRouter(): Router {
  const router = Router();
  router.use('/identity', (_req, res, next) => { res.setHeader('cache-control', 'no-store'); res.setHeader('pragma', 'no-cache'); next(); });
  router.post('/identity/token', urlencoded({ extended: false, limit: '8kb' }), async (req, res, next) => {
    try {
      const grant = parameter(req.body ?? {}, 'grant_type');
      if (!grant) {
        const bootstrap = parameter(req.body ?? {}, 'bootstrap_credential');
        if (!bootstrap) throw new PolicyError('OAUTH', 'grant_type is required for OAuth token requests', 400, { oauth_error: 'invalid_request' });
        const result = await exchangeBootstrap(bootstrap);
        res.json(result); return;
      }
      if (!['client_credentials', 'authorization_code', 'refresh_token'].includes(grant)) throw new PolicyError('OAUTH', 'Supported grants are client_credentials, authorization_code and refresh_token', 400, { oauth_error: 'unsupported_grant_type' });
      const { clientId, secret } = clientCredentials(req);
      if (grant === 'client_credentials') {
        const result = await exchangeClientCredentials(clientId, secret);
        res.json({ ...result, access_token: result.token }); return;
      }
      if (grant === 'authorization_code') {
        res.json(await oauth.exchangeAuthorizationCode(clientId, secret, parameter(req.body ?? {}, 'code'), parameter(req.body ?? {}, 'redirect_uri'), parameter(req.body ?? {}, 'code_verifier'))); return;
      }
      res.json(await oauth.exchangeOAuthRefresh(clientId, secret, parameter(req.body ?? {}, 'refresh_token')));
    } catch (error) {
      if (!(error instanceof PolicyError)) { next(error); return; }
      const name = typeof error.extra?.oauth_error === 'string' ? error.extra.oauth_error : error.status === 401 ? 'invalid_client' : 'invalid_grant';
      if (error.status === 401) res.setHeader('www-authenticate', 'Basic realm="Signet workload OAuth"');
      res.status(error.status).json({ error: name, error_description: error.message });
    }
  });
  router.get('/identity/oauth-metadata', route(async () => {
    const { control_url: origin } = await connectionAddresses();
    return { issuer: origin, authorization_endpoint: `${origin}/api/v1/identity/authorize`, token_endpoint: `${origin}/api/v1/identity/token`, response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'], token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'], code_challenge_methods_supported: ['S256'], scopes_supported: ['mcp'] };
  }));
  router.get('/identity/authorize', authenticate, route(async (req, res) => {
    const input = authorizationInput(req);
    await oauth.validateAuthorization(input);
    if (!res.locals.principal) { res.redirect(`/login?${new URLSearchParams({ return_to: req.originalUrl })}`); return; }
    const request = await oauth.beginAuthorization(input, principalOf(res));
    res.redirect(`/oauth/authorize?${new URLSearchParams({ request })}`);
  }));
  router.get('/identity/authorization/:request', authenticate, requireSession, route(async (req, res) => oauth.authorizationPreview(req.params.request!, principalOf(res))));
  router.post('/identity/authorization/:request/approve', authenticate, requireSession, route(async (req, res) => oauth.approveAuthorization(req.params.request!, principalOf(res))));
  router.post('/identity/authorization/:request/deny', authenticate, requireSession, route(async (req, res) => oauth.denyAuthorization(req.params.request!, principalOf(res))));
  router.get('/identity/clients/:id/oauth', authenticate, requireSession, route(async (req, res) => oauth.oauthClientSettings(req.params.id!, principalOf(res))));
  router.put('/identity/clients/:id/oauth', authenticate, requireSession, route(async (req, res) => oauth.configureOAuthClient(req.params.id!, parameter(req.body ?? {}, 'redirect_uri'), principalOf(res))));
  return router;
}

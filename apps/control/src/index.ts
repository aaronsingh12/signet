import { timingSafeEqual } from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { devSecret, env, newId, toJwk, verifyJws, type CertificateBody } from '@signet/core';
import { db, nowIso } from './db';
import * as detectors from './detectors';
import * as discovery from './discovery';
import * as enforcement from './enforcement';
import { PolicyError, invalid } from './errors';
import * as evidence from './evidence';
import { cursor, idempotency, limitOf, problemHandler, route } from './http';
import * as hub from './hub';
import * as identity from './identity';
import * as deploymentIdentity from './deployment-identity';
import { jwks, keys } from './keys';
import * as ledger from './ledger';
import * as live from './live';
import * as oidc from './oidc';
import * as plugins from './plugins';
import { openapi } from './openapi';
import { principalOf, requires, singleOperatorMode } from './rbac';
import * as registry from './registry';
import * as secrets from './secrets';
import { commandCenter } from './stats';
import { agentAnalytics } from './agent-analytics';
import { agentRemovalPreview, removeAgent } from './agent-removal';
import { reloadSettings, setAgentModel, setModelPrice, tenant } from './tenant';
import * as approvals from './approvals';
import * as controls from './controls';
import * as hitl from './hitl';
import * as notify from './notify';
import * as servicenow from './servicenow';
import * as platforms from './platforms';
import { costs } from './costs';
import { TEMPLATES } from './templates';
import * as workflow from './workflow';
import * as tools from './tools';
import * as connectivity from './connectivity';
import * as edge from './edge';
import * as externalConnections from './external-connections';
import { suggestOpenApi } from './external-openapi';
import * as counters from './counters';
import * as quickConnect from './quick-connect';

const INTERNAL_TOKEN = devSecret('SIGNET_INTERNAL_TOKEN');
const PORT = Number(process.env.PORT ?? env('SIGNET_CONTROL_PORT', '4100'));

const app = express();
const initialized = controls.seed();
app.disable('x-powered-by');
// Behind Vercel's edge the client address arrives in X-Forwarded-For; trust only that one hop.
if (process.env.VERCEL) app.set('trust proxy', 1);
app.use((_req, _res, next) => { void initialized.then(() => next(), next); });
// Provider webhooks use exact raw bytes before JSON parsing and session middleware.
app.post('/api/v1/connection-webhooks/:id', express.raw({ type: 'application/json', limit: '64kb' }), route(async (req) => {
  tokenRateLimit(req);
  if (!Buffer.isBuffer(req.body)) throw invalid('Webhook requires application/json');
  return externalConnections.receiveWebhook(req.params.id!, req.body, String(req.headers['x-signet-timestamp'] ?? ''), String(req.headers['x-signet-event-id'] ?? ''), String(req.headers['x-signet-signature'] ?? ''));
}));
// Log uploads for discovery have their own, larger limit on their route.
const jsonBody = express.json({ limit: '1mb' });
const edgeResultBody = express.json({ limit: '6mb' });
app.use((req, res, next) => req.path.startsWith('/api/v1/edge/runners/') && req.path.endsWith('/result') ? edgeResultBody(req, res, next) : req.path === '/api/v1/discovery/logs' ? next() : jsonBody(req, res, next));
app.use((_req, res, next) => {
  // BP 18.5 security headers
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('content-security-policy', "default-src 'none'; frame-ancestors 'none'");
  next();
});

const same = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
function internal(req: Request, _res: Response, next: NextFunction) {
  if (!same(String(req.headers['x-signet-internal'] ?? ''), INTERNAL_TOKEN)) return next(new PolicyError('AUTH', 'internal token required', 401));
  next();
}

const api = express.Router();
const signedIn = (_req: Request, res: Response, next: NextFunction) => (res.locals.principal ? next() : next(new PolicyError('AUTH', 'sign-in required', 401)));

app.get('/healthz', route(async () => {
  await db.prepare('SELECT 1').get();
  return { ok: true, tenant: tenant.id, database: 'postgresql' };
}));

// --- public: sign-in, identity exchange, API description ---
api.get('/auth/login', route(async (req, res) => (await oidc.login(req, res))));
api.get('/auth/config', route(() => ({ auth_mode: oidc.OIDC.authMode, tenant_name: tenant.name })));
const clientIp = (req: Request) => req.ip ?? req.socket.remoteAddress ?? 'unknown';
// Failed sign-ins are throttled per address and per administrator ID (shared across instances).
async function throttledLogin<T>(req: Request, username: unknown, attempt: () => Promise<T> | T): Promise<T> {
  const id = typeof username === 'string' ? username : '';
  await counters.assertLoginAllowed(clientIp(req), id);
  try {
    return await attempt();
  } catch (e) {
    if (e instanceof PolicyError && e.status === 401) await counters.recordLoginFailure(clientIp(req), id);
    throw e;
  }
}
api.post('/auth/local-login', route(async (req, res) => (await throttledLogin(req, req.body?.username, () => oidc.localLogin(req, res)))));
api.get('/auth/callback', route(async (req, res) => (await oidc.callback(req, res))));
api.post('/auth/logout', route(async (req, res) => (await oidc.logout(req, res))));
api.post('/auth/dev-token', route(async (req) => (await throttledLogin(req, req.body?.username ?? req.body?.client_id, () => oidc.localToken(req.body ?? {})))));
api.get('/identity/jwks', route(() => jwks()));
// Unauthenticated by nature, so limited per client address: 30 exchanges a minute.
const tokenAttempts = new Map<string, { n: number; reset: number }>();
function tokenRateLimit(req: Request) {
  const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
  const now = Date.now();
  const e = tokenAttempts.get(ip);
  if (!e || e.reset < now) tokenAttempts.set(ip, { n: 1, reset: now + 60_000 });
  else if (++e.n > 30) throw new PolicyError('RATE_LIMIT', 'too many token requests from this address; retry in a minute', 429, { retry_after: Math.ceil((e.reset - now) / 1000) });
  if (tokenAttempts.size > 10_000) for (const [k, v] of tokenAttempts) if (v.reset < now) tokenAttempts.delete(k);
}
// Self-hosted agents send their one-time bootstrap credential. Third-party (vendor) platforms use OAuth
// client credentials, as JSON, as a form (RFC 6749 section 4.4) or with HTTP Basic client auth.
api.post('/identity/token', express.urlencoded({ extended: false, limit: '8kb' }), route(async (req, res) => {
  res.setHeader('cache-control', 'no-store');
  res.setHeader('pragma', 'no-cache');
  tokenRateLimit(req);
  const b = (req.body ?? {}) as Record<string, string>;
  if (b.grant_type === 'client_credentials') {
    let id = b.client_id;
    let secret = b.client_secret;
    const basic = String(req.headers.authorization ?? '').match(/^Basic\s+(.+)$/i);
    if (basic) [id, secret] = Buffer.from(basic[1]!, 'base64').toString('utf8').split(':') as [string, string];
    const t = (await identity.exchangeClientCredentials(decodeURIComponent(String(id ?? '')), decodeURIComponent(String(secret ?? ''))));
    return { ...t, access_token: t.token }; // access_token for OAuth clients, token for the Signet SDK
  }
  return (await identity.exchangeBootstrap(String(b.bootstrap_credential ?? '')));
}));
// The SDK and sidecar report what they see in the agent's runtime (variable names, never values).
api.post('/identity/diagnostics', route(async (req) => (await connectivity.report(String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, ''), req.body))));
api.post('/identity/token/refresh', route(async (req) => (await identity.refreshToken((req.headers.authorization ?? '').replace(/^Bearer /, '')))));
api.post('/identity/deployment-token', route(async (req, res) => {
  res.setHeader('cache-control', 'no-store');
  return (await deploymentIdentity.exchangeDeploymentCredential(String(req.body?.deployment_credential ?? '')));
}));
api.get('/openapi.json', (_req, res) => res.json(openapi));

const runners = express.Router();
runners.use('/:runnerId', async (req, _res, next) => {
  try {
    (await edge.authenticateRunner(req.params.runnerId!, String(req.headers.authorization ?? '')));
    next();
  } catch (error) { next(error); }
});
runners.post('/:runnerId/poll', route(async (req) => (await edge.poll(req.params.runnerId!))));
runners.get('/:runnerId/jobs/:jobId/lease', route(async (req) => (await edge.lease(req.params.runnerId!, req.params.jobId!))));
runners.post('/:runnerId/jobs/:jobId/result', route(async (req) => (await edge.complete(req.params.runnerId!, req.params.jobId!, req.body))));
api.use('/edge/runners', runners);

// --- everything below needs a signed-in person or an approved machine client ---
api.use(oidc.authenticate, signedIn, idempotency);

api.get('/me', route((_req, res) => ({ principal: principalOf(res), tenant: { id: tenant.id, name: tenant.name }, single_operator: singleOperatorMode() })));
// Secrets in these requests must never enter idempotency response storage or browser caches.
api.use('/connections', (_req, res, next) => { res.setHeader('cache-control', 'no-store'); next(); });
api.get('/connections', requires('agents.read'), route(async () => ({ items: await externalConnections.list() })));
api.post('/agents/:id/gateway-test', requires('agents.read'), route(async (req) => connectivity.testGateway(req.params.id!)));
api.post('/connections/openapi', requires('connectors.manage'), route((req) => suggestOpenApi(req.body)));
api.post('/connections', requires('connectors.manage'), route(async (req, res) => [201, await externalConnections.create(req.body?.agent_id, req.body, principalOf(res))]));
api.get('/connections/:id', requires('agents.read'), route(async (req) => externalConnections.view(req.params.id!)));
api.put('/connections/:id', requires('connectors.manage'), route(async (req, res) => externalConnections.update(req.params.id!, req.body, principalOf(res))));
api.post('/connections/:id/webhook', requires('connectors.manage'), route(async (req, res) => externalConnections.configureWebhook(req.params.id!, req.body, principalOf(res))));
api.delete('/connections/:id', requires('connectors.manage'), route(async (req, res) => externalConnections.deleteConnection(req.params.id!, principalOf(res))));
api.get('/connections/:id/history', requires('ledger.read'), route(async (req, res) => externalConnections.history(req.params.id!, principalOf(res))));
api.post('/connections/:id/monitoring', requires('connectors.manage'), route(async (req, res) => externalConnections.setMonitoring(req.params.id!, req.body?.enabled, principalOf(res))));
api.post('/connections/:id/agents/:agentId/read/:operation', requires('connectors.manage'), route(async (req, res) => externalConnections.readAgentOperation(req.params.id!, req.params.agentId!, req.params.operation!, typeof req.body?.execution_id === 'string' ? req.body.execution_id : null, principalOf(res))));
api.post('/connections/:id/test', requires('connectors.manage'), route(async (req, res) => externalConnections.testConnection(req.params.id!, principalOf(res))));
api.post('/connections/rest/connect', requires('connectors.manage'), route(async (req, res) => externalConnections.connectRest(req.body?.agent_id, req.body, principalOf(res))));
api.post('/connections/:id/preview-agents', requires('connectors.manage'), route(async (req, res) => externalConnections.previewRestAgents(req.params.id!, principalOf(res))));
api.post('/connections/:id/onboard', requires('connectors.manage'), route(async (req, res) => {
  if (typeof req.body?.external_id !== 'string' || !req.body.external_id) throw invalid('Select an external agent to onboard');
  return externalConnections.onboardRestAgent(req.params.id!, req.body.external_id, principalOf(res));
}));
api.post('/connections/:id/agent-fields', requires('connectors.manage'), route(async (req, res) => externalConnections.inspectAgentList(req.params.id!, principalOf(res))));
api.post('/connections/:id/discover', requires('connectors.manage'), route(async (req, res) => externalConnections.discover(req.params.id!, principalOf(res))));
api.post('/connections/:id/sync', requires('connectors.manage'), route(async (req, res) => externalConnections.sync(req.params.id!, principalOf(res))));
api.post('/connections/:id/disconnect', requires('connectors.manage'), route(async (req, res) => externalConnections.transition(req.params.id!, 'disconnected', principalOf(res))));
api.post('/connections/:id/reconnect', requires('connectors.manage'), route(async (req, res) => externalConnections.transition(req.params.id!, 'enabled', principalOf(res))));
api.post('/connections/:id/revoke', requires('connectors.manage'), route(async (req, res) => externalConnections.transition(req.params.id!, 'revoked', principalOf(res))));
api.get('/connections/:id/observations', requires('ledger.read'), route(async (req) => {
  await externalConnections.view(req.params.id!);
  return { items: await db.prepare('SELECT external_agent_id, external_id, kind, metadata, observed_at FROM external_observation WHERE connection_id = ? ORDER BY observed_at DESC LIMIT 200').all(req.params.id!) };
}));
api.get('/connections/:id/agents', requires('agents.read'), route(async (req) => {
  await externalConnections.view(req.params.id!);
  return externalConnections.inventory(req.params.id!);
}));
api.post('/connections/:id/agents/:agentId/actions/:action', requires('connectors.manage'), route(async (req, res) => externalConnections.remoteAction(req.params.id!, req.params.agentId!, req.params.action!, req.body, principalOf(res))));
api.get('/edge-runners', requires('agents.read'), route(async () => ({ items: (await edge.listRunners()) })));
api.post('/edge-runners', requires('connectors.manage'), route(async (req, res) => {
  res.setHeader('cache-control', 'no-store');
  return [201, (await edge.createRunner(req.body?.name, principalOf(res)))];
}));
api.post('/edge-runners/:id/revoke', requires('connectors.manage'), route(async (req, res) => (await edge.revokeRunner(req.params.id!, principalOf(res)))));
api.get('/plugins/vercel', requires('tenant.admin'), route(async (_req, res) => (await plugins.vercelConnection(principalOf(res)))));
api.get('/plugins/vercel/connect', requires('tenant.admin'), route((_req, res) => plugins.startVercelConnection(res, principalOf(res))));
api.get('/plugins/vercel/callback', requires('tenant.admin'), route(async (req, res) => (await plugins.completeVercelConnection(req, res, principalOf(res)))));
api.post('/plugins/vercel/disconnect', requires('tenant.admin'), route(async (_req, res) => (await plugins.disconnectVercel(principalOf(res)))));
api.get('/catalogue', requires('agents.read'), route(async () => ({ catalogue: (await reloadSettings()).catalogue })));
// An agent's own LLM: agents keep their model and Signet checks each call on its way there. The key goes
// to the Secrets Broker, as kind tool so it can never be taken for the default LLM's credential.
api.post('/catalogue', requires('tenant.admin'), route(async (req, res) => {
  const p = principalOf(res);
  const model = typeof req.body?.model === 'string' ? req.body.model.trim() : '';
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(model)) throw invalid('model must be the name the agent sends, such as beam:cloud');
  let url: URL;
  try { url = new URL(String(req.body?.base_url ?? '').trim()); } catch { throw invalid('base_url must be a full address, such as https://llm.example.com/v1'); }
  const local = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) || url.username || url.password || url.search || url.hash) throw invalid('base_url must use HTTPS, with no credentials or query in it');
  const key = typeof req.body?.api_key === 'string' ? req.body.api_key : '';
  const existing = (await reloadSettings()).catalogue.find((c) => c.model === model);
  if (existing && !existing.upstream) throw invalid(`${model} is the default LLM and cannot be re-pointed here`);
  let secretId = existing?.upstream?.secret_id ?? null;
  if (key && secretId) await secrets.rotateSecret(secretId, key, p);
  else if (key) secretId = (await secrets.putSecret({ name: `llm-${model.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 40)}-${newId('sec').slice(-6).toLowerCase()}`, kind: 'tool', value: key }, p)).id;
  const entry = await setAgentModel(model, { base_url: url.toString().replace(/\/+$/, ''), secret_id: secretId });
  await ledger.append({ kind: 'admin', data: { event: 'catalogue.agent_llm_set', model, base_url: entry.upstream!.base_url, key_stored: !!secretId, actor: p.id } });
  hub.publish('bundle', { reason: 'catalogue.agent_llm_set', model });
  return [existing ? 200 : 201, { model: { model: entry.model, base_url: entry.upstream!.base_url, key_stored: !!secretId } }];
}));
// Model prices drive recorded cost, daily cost budgets and the per-request cost ceiling.
api.put('/catalogue/:model/price', requires('tenant.admin'), route(async (req, res) => {
  const model = String(req.params.model);
  const price = { in: Number(req.body?.in), out: Number(req.body?.out) };
  if (![price.in, price.out].every((v) => Number.isFinite(v) && v >= 0 && v <= 1000)) throw invalid('in and out are USD per 1,000 tokens, between 0 and 1000');
  if (!(await reloadSettings()).catalogue.some((c) => c.model === model)) throw invalid(`${model} is not in the tenant catalogue`);
  const entry = await setModelPrice(model, price);
  await ledger.append({ kind: 'admin', data: { event: 'catalogue.price_set', model, price_per_1k_usd: entry.price_per_1k_usd, actor: principalOf(res).id } });
  hub.publish('bundle', { reason: 'catalogue.price_set', model });
  return { model: entry };
}));
api.get('/stats/command-center', requires('agents.read'), route(async () => (await commandCenter())));
api.get('/stats/costs', requires('agents.read'), route(async (req) => costs(Number(req.query.days ?? 30))));
api.post('/platforms/:id/usage/sync', requires('connectors.manage'), route(async (req) => platforms.syncUsage(req.params.id!, Number(req.body?.days ?? 30))));
api.get('/stats/agents', requires('agents.read'), route(async () => (await agentAnalytics())));
api.get('/gateways', requires('gateways.read'), route(async () => ({ items: (await db.prepare('SELECT * FROM gateway_node ORDER BY id').all()) })));
api.get('/live', requires('ledger.read'), (_req, res) => live.attach(res));

// Registry and seals
api.get('/agents', requires('agents.read'), route(async (req) => {
  const out = (await registry.listAgents({ tier: req.query.tier as string, status: req.query.status as string, q: req.query.q as string, cursor: cursor.decode(req.query.cursor), limit: limitOf(req.query.limit) }));
  return { items: (await Promise.all(out.items.map(async (a) => ({ ...a, enforcement: (await enforcement.agentLevel(a.id)), connection: (await connectivity.status(a.id)).state })))), next_cursor: out.next_cursor ? cursor.encode(out.next_cursor) : null };
}));
// Stage 1 Propose: the agent gets its permanent ID and a lifecycle (BP 6).
api.post('/agents', requires('agents.write'), route(async (req, res) => {
  const p = principalOf(res);
  // A person's agent gets its tier from classification, never from the request.
  const { tier, ...requested } = (req.body ?? {}) as Record<string, unknown>;
  const agent = (await registry.registerAgent((p.kind === 'human' ? requested : req.body) as never, p));
  const lc = (await workflow.start(agent, req.body?.intake ?? { template: req.body?.template }, p));
  return [201, { ...agent, lifecycle_id: lc.id }];
}));
// One form to a working key, for agents that only call the model; see quick-connect.ts for what it refuses to shortcut.
api.post('/agents/quick-connect', requires('agents.write'), route(async (req, res) => {
  res.setHeader('cache-control', 'no-store');
  return [201, await quickConnect.start((req.body ?? {}) as Record<string, unknown>, principalOf(res))];
}));
api.post('/agents/:id/quick-connect', requires('agents.write'), route(async (req, res) => {
  res.setHeader('cache-control', 'no-store');
  return quickConnect.advance(req.params.id!, String(req.body?.lifecycle_id), principalOf(res), req.body?.answers as Record<string, string> | undefined);
}));
api.post('/connect/test', requires('identity.bootstrap'), route(async (req) => quickConnect.testCall(req.body?.credential)));
api.get('/agents/:id/removal-preview', requires('agents.delete'), route(async (req, res) => (await agentRemovalPreview(req.params.id!, principalOf(res)))));
api.delete('/agents/:id', requires('agents.delete'), route(async (req, res) => {
  if (typeof req.body?.confirm_handle !== 'string') throw invalid('confirm_handle must be the exact agent handle');
  return (await removeAgent(req.params.id!, req.body.confirm_handle, principalOf(res)));
}));
api.get('/agents/:id', requires('agents.read'), route(async (req) => {
  const agent = (await registry.getAgent(req.params.id!));
  const active = (await registry.activeCertificate(agent.id));
  const lcs = (await workflow.forAgent(agent.id));
  return {
    agent: { ...agent, vendor_details: JSON.parse(agent.vendor_details || '{}') },
    connection: (await connectivity.status(agent.id)),
    clients: (await identity.clientsOf(agent.id)),
    team: (await registry.teamOf(agent.id)),
    enforcement: { level: (await enforcement.agentLevel(agent.id)), states: (await enforcement.statesFor(agent.id)) },
    certificate: active?.certificate ?? null,
    certificates: (await registry.certificates(agent.id)),
    instances: (await identity.instancesOf(agent.id)),
    events: (await enforcement.recentEvents(10, agent.id)),
    lifecycle: lcs[0] ? (await workflow.view(lcs[0].id)) : null,
    lifecycles: lcs.map((l) => ({ id: l.id, kind: l.kind, stage: l.stage, status: l.status, started_at: l.started_at })),
    attestations: (await db.prepare('SELECT id, type, signer, content_hash, signed_at FROM attestation WHERE agent_id = ? ORDER BY signed_at DESC').all(agent.id)),
  };
}));
// Seals come only from the lifecycle (BP 6: no agent reaches production without all 8 stages).
api.post('/agents/:id/certificates', requires('certificates.approve'), route(async (req, res) => {
  const issued = (await registry.issueSeal(req.params.id!, req.body, principalOf(res)));
  hub.publish('bundle', { reason: 'certificate.issued', cert_id: issued.certificate.cert_id });
  return [201, issued];
}));

// Lifecycle stages (BP 6)
api.get('/lifecycles/:id', requires('agents.read'), route(async (req) => (await workflow.view(req.params.id!))));
api.patch('/lifecycles/:id/intake', requires('agents.write', 'certificates.approve'), route(async (req, res) => (await workflow.updateIntake(req.params.id!, req.body ?? {}, principalOf(res)))));
api.put('/lifecycles/:id/manifest', requires('agents.read'), route(async (req, res) => (await workflow.setManifest(req.params.id!, req.body, principalOf(res)))));
api.post('/lifecycles/:id/stages/propose/submit', requires('agents.read'), route(async (req, res) => (await workflow.submitPropose(req.params.id!, principalOf(res)))));
api.post('/lifecycles/:id/classification', requires('agents.read'), route(async (req, res) => (await workflow.classify(req.params.id!, principalOf(res), req.body ?? {}))));
api.put('/lifecycles/:id/assessments/:type', requires('agents.read'), route(async (req, res) => (await workflow.saveAssessment(req.params.id!, req.params.type!, req.body?.content ?? {}, req.body?.complete === true, principalOf(res)))));
api.post('/lifecycles/:id/gaps', requires('agents.read'), route(async (req, res) => {
  const lc = (await workflow.get(req.params.id!));
  const id = (await workflow.addGap(lc.id, req.body ?? {}, principalOf(res)));
  return [201, { id }];
}));
api.patch('/gaps/:id', requires('agents.read'), route(async (req, res) => (await workflow.updateGap(req.params.id!, req.body ?? {}, principalOf(res)))));
api.post('/gaps/:id/acceptance', requires('agents.read'), route(async (req, res) => [201, (await workflow.requestAcceptance(req.params.id!, principalOf(res), req.body ?? {}))]));
api.post('/lifecycles/:id/stages/assess/submit', requires('agents.read'), route(async (req, res) => (await workflow.submitAssess(req.params.id!, principalOf(res)))));
api.post('/lifecycles/:id/test-runs', requires('agents.read'), route(async (req, res) => [201, (await workflow.runTests(req.params.id!, principalOf(res), req.body ?? {}))]));
api.post('/lifecycles/:id/deploy', requires('agents.read'), route(async (req, res) => (await workflow.advanceDeploy(req.params.id!, principalOf(res), req.body ?? {}))));
api.post('/agents/:id/attest', requires('agents.read'), route(async (req, res) => (await workflow.attest(req.params.id!, principalOf(res), req.body ?? {}))));
api.post('/agents/:id/changes', requires('agents.write', 'certificates.approve'), route(async (req, res) => [201, (await workflow.requestChange(req.params.id!, principalOf(res), req.body ?? {}))]));
api.post('/agents/:id/retire', requires('agents.read'), route(async (req, res) => [201, (await workflow.requestRetire(req.params.id!, principalOf(res), String(req.body?.reason ?? '')))]));
api.get('/templates', requires('agents.read'), route(() => ({ items: TEMPLATES })));

// Approvals engine (BP 7)
api.get('/approvals', requires('agents.read'), route(async (req, res) => {
  const p = principalOf(res);
  if (req.query.mine) return { items: (await approvals.forMe(p)) };
  return { items: (await approvals.list({ status: req.query.status as string, type: req.query.type as string, agent: req.query.agent as string, limit: limitOf(req.query.limit, 500, 100) })) };
}));
api.get('/approvals/:id', requires('agents.read'), route(async (req, res) => {
  const r = (await approvals.get(req.params.id!));
  return { ...r, my_slots: (await approvals.eligibleSlots(r, principalOf(res))).map((s) => s.slot) };
}));
api.post('/approvals/:id/decisions', requires('agents.read'), route(async (req, res) => (await approvals.decide(req.params.id!, principalOf(res), req.body ?? {}))));
api.post('/delegations', requires('agents.read'), route(async (req, res) => [201, (await approvals.delegate(principalOf(res), String(req.body?.to ?? ''), String(req.body?.from_date ?? ''), String(req.body?.to_date ?? '')))]));
api.get('/delegations', requires('agents.read'), route(async (_req, res) => ({ items: (await db.prepare('SELECT * FROM delegation WHERE from_user = ? OR to_user = ? ORDER BY created_at DESC').all(principalOf(res).id, principalOf(res).id)) })));
api.get('/notifications', route(async (_req, res) => ({ items: (await notify.listFor(principalOf(res))), unread: (await notify.unreadCount(principalOf(res))) })));
api.post('/notifications/read', route(async (_req, res) => ((await notify.markRead(principalOf(res))), { ok: true })));

// Control library and compliance (BP 9)
api.get('/library', requires('compliance.read'), route(async () => (await controls.library())));
api.post('/library/evaluate', requires('compliance.read'), route(async () => ({ results: (await controls.evaluate()) })));
api.get('/compliance/scores', requires('compliance.read'), route(async () => ({ items: (await controls.scores()) })));

// Connectors (BP 10)
api.get('/connectors', requires('connectors.manage', 'compliance.read'), route(async () => ({ items: (await servicenow.list()) })));
// Platform connectors: list workloads, flag AI ones, connect a workload to Signet without a code change.
api.get('/platforms', requires('connectors.manage', 'compliance.read'), route(async () => ({ items: await platforms.list(), links: await platforms.links() })));
api.post('/platforms', requires('connectors.manage'), route(async (req, res) => [201, await platforms.create(req.body ?? {}, principalOf(res))]));
api.delete('/platforms/:id', requires('connectors.manage'), route(async (req, res) => platforms.remove(req.params.id!, principalOf(res))));
api.get('/platforms/:id/workloads', requires('connectors.manage'), route(async (req) => ({ items: await platforms.workloads(req.params.id!) })));
api.post('/platforms/:id/scan', requires('connectors.manage'), route(async (req, res) => platforms.scan(req.params.id!, principalOf(res))));
api.post('/platforms/:id/workloads/:workload/stop', requires('ladder.kill'), route(async (req, res) => platforms.stop(req.params.id!, decodeURIComponent(req.params.workload!), String(req.body?.reason ?? ''), principalOf(res).id)));
api.post('/platforms/:id/workloads/:workload/register', requires('connectors.manage'), route(async (req, res) => [201, await platforms.register(req.params.id!, decodeURIComponent(req.params.workload!), principalOf(res))]));
api.post('/platforms/:id/workloads/:workload/link', requires('connectors.manage'), route(async (req, res) => platforms.link(req.params.id!, decodeURIComponent(req.params.workload!), req.body ?? {}, principalOf(res))));
api.get('/platforms/:id/workloads/:workload/link', requires('connectors.manage', 'agents.read'), route(async (req) => platforms.linkStatus(req.params.id!, decodeURIComponent(req.params.workload!))));
api.post('/connectors', requires('connectors.manage'), route(async (req, res) => [201, (await servicenow.create(req.body ?? {}, principalOf(res)))]));
api.post('/connectors/:id/test', requires('connectors.manage'), route(async (req, res) => (await servicenow.selfTest(req.params.id!, principalOf(res)))));
api.post('/connectors/:id/pull', requires('connectors.manage'), route(async (req, res) => (await servicenow.pullLibrary(req.params.id!, principalOf(res)))));
api.get('/connectors/:id/outbox', requires('connectors.manage'), route(async (req) => ({ items: (await servicenow.outbox(req.params.id!, req.query.status as string | undefined)) })));
api.post('/outbox/:id/retry', requires('connectors.manage'), route(async (req, res) => (await servicenow.retry(req.params.id!, principalOf(res)))));
api.get('/agents/:id/certificate', requires('agents.read'), route(async (req) => {
  const agent = (await registry.getAgent(req.params.id!));
  const active = (await registry.activeCertificate(agent.id));
  if (!active) throw new PolicyError('NOT_FOUND', 'no active seal', 404);
  return active;
}));
api.post('/certificates/verify', requires('agents.read'), route(async (req) => {
  const jws = String(req.body?.jws ?? '');
  try {
    const { header, payload } = verifyJws<CertificateBody>(jws, new Map([[keys.ca.kid, keys.ca.publicKey]]), 'signet-seal');
    const row = (await db.prepare('SELECT status FROM certificate WHERE id = ?').get(payload.cert_id)) as { status: string } | undefined;
    return { signature_valid: true, signed_by: header.kid, cert_id: payload.cert_id, status: row?.status ?? 'unknown', valid_to: payload.valid_to };
  } catch (e) {
    return { signature_valid: false, error: (e as Error).message };
  }
}));
// Where agents connect: shown in the console's connection instructions. Set the public URLs in production.
api.get('/connect/info', requires('agents.read'), route(async () => {
  const nodes = (await db.prepare('SELECT id, url, last_seen FROM gateway_node ORDER BY id').all()) as { id: string; url: string; last_seen: string }[];
  const live = nodes.filter((n) => Date.now() - Date.parse(n.last_seen) < 30_000);
  return {
    gateway_url: process.env.SIGNET_GATEWAY_PUBLIC_URL ?? live[0]?.url ?? null,
    gateway_url_source: process.env.SIGNET_GATEWAY_PUBLIC_URL ? 'SIGNET_GATEWAY_PUBLIC_URL' : live[0] ? `gateway node ${live[0].id} (local address; set SIGNET_GATEWAY_PUBLIC_URL for remote agents)` : 'no live gateway node',
    control_url: process.env.SIGNET_CONTROL_PUBLIC_URL ?? `http://localhost:${PORT}`,
    control_url_source: process.env.SIGNET_CONTROL_PUBLIC_URL ? 'SIGNET_CONTROL_PUBLIC_URL' : 'local address; set SIGNET_CONTROL_PUBLIC_URL for remote agents',
    models: tenant.settings.catalogue.map((c) => c.model),
    tools: (await tools.listTools()).map((t) => ({ alias: t.alias, kind: t.kind, actions: Object.keys(t.actions) })),
  };
}));
api.get('/agents/:id/connection', requires('agents.read'), route(async (req) => (await connectivity.status(req.params.id!))));
api.post('/agents/:id/clients', requires('identity.bootstrap'), route(async (req, res) => {
  res.setHeader('cache-control', 'no-store');
  return [201, (await identity.createClient(req.params.id!, principalOf(res), String(req.body?.label ?? ''), String(req.body?.environment ?? 'dev')))];
}));
api.post('/clients/:id/revoke', requires('identity.bootstrap', 'ladder.quarantine'), route(async (req, res) => (await identity.revokeClient(req.params.id!, principalOf(res), String(req.body?.reason ?? '')))));
api.post('/instances/:id/revoke', requires('identity.bootstrap', 'ladder.quarantine'), route(async (req, res) => (await identity.revokeInstance(req.params.id!, principalOf(res), String(req.body?.reason ?? '')))));
api.post('/agents/:id/bootstrap', requires('identity.bootstrap'), route(async (req, res) => {
  res.setHeader('cache-control', 'no-store');
  return [201, (await identity.createBootstrap(req.params.id!, principalOf(res), String(req.body?.environment ?? 'dev')))];
}));
api.post('/agents/:id/deployment-credentials', requires('identity.bootstrap'), route(async (req, res) => {
  res.setHeader('cache-control', 'no-store');
  return [201, (await deploymentIdentity.createDeploymentCredential(req.params.id!, principalOf(res), String(req.body?.environment ?? 'dev')))];
}));
api.delete('/agents/:id/deployment-credentials/:credentialId', requires('identity.bootstrap'), route(async (req, res) =>
  (await deploymentIdentity.revokeDeploymentCredential(req.params.id!, req.params.credentialId!, principalOf(res))),
));

// Response ladder (manual): owners can quarantine or kill their own agents (BP 14.2)
api.post('/agents/:id/ladder', route(async (req, res) => {
  const p = principalOf(res);
  const agent = (await registry.getAgent(req.params.id!));
  const action = req.body?.action as enforcement.LadderAction;
  if (!['step_up', 'throttle', 'quarantine', 'kill', 'release'].includes(action)) throw invalid('action must be step_up, throttle, quarantine, kill or release');
  // Quarantine release goes through the approvals engine (BP 7.2); step-up and throttle windows can
  // be cleared by Security directly (BP 5.4 "window expires or Security clears").
  if (action === 'release' && (await enforcement.agentLevel(agent.id)) === 'quarantined') return [201, (await workflow.requestRelease(agent.id, p, String(req.body?.reason ?? '')))];
  registry.assertCan(p, `ladder.${action}` as never, agent);
  if (action === 'kill' && req.body?.confirm_handle !== agent.handle) throw new PolicyError('BP-14.1', 'type the agent handle to confirm a kill', 400);
  return (await enforcement.applyLadder(
    { agentId: agent.id, scope: req.body?.scope, version: req.body?.version, instanceId: req.body?.instance_id },
    action,
    { actor: p.id, reason: String(req.body?.reason ?? ''), minutes: req.body?.minutes, factor: req.body?.factor },
  ));
}));
api.get('/enforcement-events', requires('ledger.read'), route(async (req) => ({ items: (await enforcement.recentEvents(limitOf(req.query.limit, 200, 50), req.query.agent as string | undefined)) })));
api.get('/enforcement-events/:id', requires('ledger.read'), route(async (req) => (await enforcement.eventStatus(req.params.id!))));
api.get('/circuit-breakers', requires('ledger.read'), route(async () => ({ items: (await enforcement.breakers()) })));
api.post('/circuit-breakers/preview', requires('circuit_breaker.arm'), route(async (req) => ({ matched: (await enforcement.matchSelector(req.body?.selector ?? {})) })));
api.post('/circuit-breakers', requires('circuit_breaker.arm'), route(async (req, res) => [201, (await enforcement.armBreaker(req.body?.selector ?? {}, req.body?.action === 'kill' ? 'kill' : 'quarantine', String(req.body?.reason ?? ''), principalOf(res)))]));

// Tools and the Secrets Broker
api.get('/tools', requires('agents.read'), route(async () => ({ items: (await tools.listTools()) })));
api.post('/tools', requires('tools.manage'), route(async (req, res) => {
  const t = await tools.registerTool(req.body, principalOf(res));
  hub.publish('bundle', { reason: 'tool.registered', alias: t.alias });
  return [201, t];
}));
api.get('/secrets', requires('secrets.manage'), route(async () => ({ items: (await secrets.listSecrets()) })));
api.post('/secrets', requires('secrets.manage'), route(async (req, res) => {
  const s = (await secrets.putSecret(req.body, principalOf(res)));
  (await discovery.reconcileWithBroker());
  return [201, s];
}));
api.post('/secrets/:id/rotate', requires('secrets.manage'), route(async (req, res) => {
  const s = (await secrets.rotateSecret(req.params.id!, String(req.body?.value ?? ''), principalOf(res)));
  hub.publish('secret', { secret_id: s.id, version: s.version });
  return s;
}));

// Discovery (Key Sweep)
api.get('/discovered-assets', requires('discovery.read', 'discovery.write'), route(async (req) => ({ items: (await discovery.list(req.query.status as string | undefined)), kpi: (await discovery.keylessKpi()) })));
api.post('/discovery/findings', requires('discovery.write'), route(async (req, res) => [201, (await discovery.ingest(String(req.body?.source ?? ''), req.body?.items, principalOf(res)))]));
api.get('/discovery/sources', requires('discovery.read', 'discovery.write'), route(async () => ({ items: (await discovery.sources()), providers: discovery.AI_PROVIDERS.map((x) => ({ provider: x.provider, kind: x.kind, domain: x.domain.source })) })));
api.post('/discovery/logs', requires('discovery.write'), express.json({ limit: '25mb' }), route(async (req, res) => {
  const src = req.body?.source === 'saas-audit' ? 'saas-audit' : req.body?.source === 'network-logs' ? 'network-logs' : null;
  if (!src) throw invalid('source must be network-logs or saas-audit');
  return [201, (await discovery.ingestLogs(src, req.body?.records, principalOf(res), Array.isArray(req.body?.gateway_hosts) ? req.body.gateway_hosts.map(String) : []))];
}));
api.post('/discovered-assets/:id/resolve', requires('discovery.write'), route(async (req, res) => (await discovery.resolve(req.params.id!, req.body?.status, String(req.body?.note ?? ''), principalOf(res)))));

// Detectors
api.get('/detectors', requires('agents.read'), route(async () => ({ items: (await detectors.list()) })));
api.post('/detectors/:id/mode', requires('detectors.manage'), route(async (req, res) => (await detectors.setMode(req.params.id!, req.body?.mode, principalOf(res), { reason: String(req.body?.reason ?? ''), dev_override: req.body?.dev_override === true }))));

// Ledger and evidence
api.get('/ledger/records', requires('ledger.read'), route(async (req) => {
  const out = (await ledger.list({ agent: req.query.agent as string, kind: req.query.kind as string, decision: req.query.decision as string, before_seq: Number(cursor.decode(req.query.cursor)) || null, limit: limitOf(req.query.limit, 500, 100) }));
  return { items: out.items, next_cursor: out.next_cursor ? cursor.encode(out.next_cursor) : null };
}));
api.get('/ledger/records/:id', requires('ledger.read'), route(async (req) => {
  const r = (await ledger.get(req.params.id!));
  return { record: r, neighbours: (await ledger.neighbours(r.seq)).map((n) => ({ seq: n.seq, record_id: n.record_id, record_hash: n.record_hash, prev_hash: n.prev_hash })) };
}));
api.get('/ledger/records/:id/proof', requires('ledger.read'), route(async (req) => (await evidence.proofFor(req.params.id!))));
api.post('/ledger/verify', requires('ledger.verify'), route(async (req) => {
  const t0 = performance.now();
  const r = (await ledger.verify(Number(req.body?.from_seq) || 1, Number(req.body?.to_seq) || Number.MAX_SAFE_INTEGER));
  const roots = (await evidence.roots(1000)).map((x) => {
    try {
      const p = evidence.verifyRootJws(x.jws);
      return { day: p.day, signature_valid: true };
    } catch {
      return { day: (x as unknown as { day: string }).day, signature_valid: false };
    }
  });
  return { ...r, roots_checked: roots.length, roots_valid: roots.every((x) => x.signature_valid), ms: Math.round(performance.now() - t0) };
}));
api.get('/ledger/roots', requires('ledger.read'), route(async () => ({ items: (await evidence.roots(60)), ledger_key: toJwk(keys.ledger) })));
api.post('/ledger/roots/seal', requires('ledger.verify'), route(async (req) => (req.body?.day ? { sealed: [(await evidence.sealDay(String(req.body.day)))] } : { sealed: (await evidence.sealFinishedDays()) })));
api.get('/ledger/export', requires('evidence.export'), async (req, res) => {
  const p = principalOf(res);
  res.setHeader('content-type', 'application/gzip');
  res.setHeader('content-disposition', `attachment; filename="signet-${tenant.id}-${new Date().toISOString().slice(0, 10)}.sep"`);
  (await evidence.writePackage(res, { fromDay: req.query.from as string | undefined, toDay: req.query.to as string | undefined, actor: p.id }));
});

app.use('/api/v1', api);

// --- internal: gateway nodes (shared token in dev; mTLS in production, BP 15.3) ---
const int = express.Router();
int.use(internal);
int.post('/edge/jobs', route(async (req) => (await edge.enqueue(req.body))));
int.get('/edge/jobs/:id', route(async (req) => (await edge.result(req.params.id!))));
int.delete('/edge/jobs/:id', route(async (req) => (await edge.discard(req.params.id!))));
int.get('/trust', route(() => ({ ca: toJwk(keys.ca), token: toJwk(keys.token) })));
int.get('/bundle', route(async () => ({ bundle: (await enforcement.buildBundle()) })));
int.get('/events', (req, res) => hub.attach(String(req.query.node ?? 'unknown'), res));
int.post('/acks', route(async (req) => ((await enforcement.recordAck(String(req.body?.event_id), String(req.body?.node_id))), { ok: true })));
int.post('/agent-erasure-acks', route((req) => {
  if (typeof req.body?.request_id !== 'string' || typeof req.body?.node_id !== 'string') throw invalid('request_id and node_id are required strings');
  hub.acknowledgeAgentErasure(req.body.request_id, req.body.node_id);
  return { ok: true };
}));
int.post('/ledger', route(async (req) => (Array.isArray(req.body?.records) ? { records: (await ledger.appendMany(req.body.records)).map((r) => ({ record_id: r.record_id, seq: r.seq })) } : { record: (await ledger.append(req.body)) })));
// Shared limit counters for gateways (rate per minute, daily usage, out-of-manifest attempts).
int.post('/limits/take', route(async (req) => (await counters.takeRequest(String(req.body?.agent_id)))));
int.post('/limits/usage', route(async (req) => ((await counters.addUsage(String(req.body?.agent_id), Number(req.body?.tokens) || 0, Number(req.body?.usd) || 0)), { ok: true })));
int.post('/limits/out-of-manifest', route(async (req) => ({ attempts: await counters.recordOutOfManifest(String(req.body?.agent_id)) })));
int.get('/secrets/:id', route(async (req) => (await secrets.revealForGateway(req.params.id!))));
int.post('/heartbeat', route(async (req) => {
  (await db.prepare('INSERT INTO gateway_node (id, url, last_seen, bundle_version, llm_status) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET url = excluded.url, last_seen = excluded.last_seen, bundle_version = excluded.bundle_version, llm_status = excluded.llm_status').run(
    String(req.body?.node_id), String(req.body?.url ?? ''), nowIso(), Number(req.body?.bundle_version) || null, req.body?.llm_status ? JSON.stringify(req.body.llm_status) : null,
  ));
  return { ok: true };
}));
int.post('/enforce', route(async (req) =>
  (await enforcement.applyLadder(
    { agentId: String(req.body?.agent_id), scope: req.body?.scope, version: req.body?.version, instanceId: req.body?.instance_id },
    req.body?.action,
    { actor: `gateway:${req.body?.node_id ?? 'unknown'}`, reason: String(req.body?.reason ?? ''), rule_id: req.body?.rule_id, automatic: true, evidence: req.body?.evidence },
  )),
));
// Runtime HITL: the gateway opens a hold and waits for the decision (BP 5.2 step 10, 7.4).
int.post('/hitl', route(async (req) => (await hitl.open(req.body ?? {}))));
int.get('/hitl/:id', route(async (req) => (await hitl.status(req.params.id!))));
int.post('/hitl/:id/consume', route(async (req) => (await hitl.consume(req.params.id!, req.body ?? {}))));
int.post('/outage', route(async (req) => {
  const r = (await ledger.append({ kind: 'enforcement', data: { event: `provider.outage.${req.body?.state === 'ended' ? 'ended' : 'declared'}`, rule_id: 'RB-PROV-04', node_id: req.body?.node_id, stats: req.body?.stats ?? {} } }));
  return { record_id: r.record_id };
}));
// These routes remain private to service bindings; the public route table exposes only /api.
int.post('/maintenance/ladder', route(async () => { await enforcement.sweepExpired(); return { ok: true }; }));
int.post('/maintenance/approvals', route(async () => { await approvals.sweep(); return { ok: true }; }));
int.post('/maintenance/lifecycle', route(async () => { await workflow.sweep(); return { ok: true }; }));
int.post('/maintenance/controls', route(async () => { await controls.evaluate(); return { ok: true }; }));
int.post('/maintenance/connectors', route(async () => { await servicenow.work(); return { ok: true }; }));
int.post('/maintenance/connections', route(async () => { await externalConnections.work(); return { ok: true }; }));
int.post('/maintenance/edge', route(async () => { await edge.sweep(); return { ok: true }; }));
int.post('/maintenance/platform-usage', route(async () => { await platforms.sweepUsage(); return { ok: true }; }));
int.post('/maintenance/counters', route(async () => { await counters.sweep(); return { ok: true }; }));
int.post('/maintenance/roots', route(async () => ({ sealed: await evidence.sealFinishedDays() })));
app.use('/internal', int);

app.use(problemHandler);

// Background jobs: ladder windows, approval escalation and timeouts, re-attestation and expiry,
// continuous control tests, connector outbox, daily roots.
// Requests await initialization above; the listening socket can open during cloud cold starts.
enforcement.setRolloutSource(workflow.rollouts);
enforcement.setKillListener(platforms.stopLinkedWorkloads);
// Cloud maintenance runs in the dedicated daemon rather than request-scoped function timers.
if (!process.env.VERCEL) {
const every = (ms: number, name: string, fn: () => unknown) => {
  const run = () => {
    try {
      // Background jobs start only after the control catalogue is in the database (a fresh schema raced it).
      const r = initialized.then(() => fn());
      if (r instanceof Promise) r.catch((e) => console.error(`[control] ${name} failed`, e));
    } catch (e) {
      console.error(`[control] ${name} failed`, e);
    }
  };
  setInterval(run, ms).unref();
  return run;
};
every(15_000, 'ladder sweep', async () => (await enforcement.sweepExpired()));
every(5_000, 'approval sweep', async () => (await approvals.sweep()));
every(10 * 60_000, 'lifecycle sweep', async () => (await workflow.sweep()))();
every(10 * 60_000, 'control evaluation', async () => (await controls.evaluate()))();
every(3_000, 'connector worker', async () => (await servicenow.work()));
every(30_000, 'external connection sync', async () => (await externalConnections.work()));
every(10_000, 'connector job cleanup', async () => (await edge.sweep()));
every(60_000, 'counter and gateway cleanup', async () => (await counters.sweep()));
every(6 * 3_600_000, 'platform usage sync', async () => (await platforms.sweepUsage()));
const sealRoots = async () => {
  try {
    const sealed = (await evidence.sealFinishedDays());
    if (sealed.length) console.log(`[control] daily roots signed for ${sealed.join(', ')}`);
  } catch (e) {
    console.error('[control] daily root sealing failed', e);
  }
};
(await sealRoots());
setInterval(sealRoots, 10 * 60_000).unref();
}

app.listen(PORT, () => {
  console.log(`[control] Signet control plane on http://localhost:${PORT}  tenant=${tenant.id} (${tenant.name})`);
  console.log(`[control] identity provider ${oidc.OIDC.issuer}; cloud LLM ${tenant.settings.catalogue.map((c) => c.model).join(', ')}`);
});


import { timingSafeEqual } from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { devSecret, env, toJwk, verifyJws, type CertificateBody } from '@signet/core';
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
import { principalOf, requires } from './rbac';
import * as registry from './registry';
import * as secrets from './secrets';
import { commandCenter } from './stats';
import { agentAnalytics } from './agent-analytics';
import { agentRemovalPreview, removeAgent } from './agent-removal';
import { tenant } from './tenant';
import * as approvals from './approvals';
import * as controls from './controls';
import * as hitl from './hitl';
import * as notify from './notify';
import * as servicenow from './servicenow';
import { TEMPLATES } from './templates';
import * as workflow from './workflow';
import * as tools from './tools';
import * as connectivity from './connectivity';

const INTERNAL_TOKEN = devSecret('SIGNET_INTERNAL_TOKEN');
const PORT = Number(env('SIGNET_CONTROL_PORT', '4100'));

const app = express();
app.disable('x-powered-by');
// Log uploads for discovery have their own, larger limit on their route.
const jsonBody = express.json({ limit: '1mb' });
app.use((req, res, next) => (req.path === '/api/v1/discovery/logs' ? next() : jsonBody(req, res, next)));
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

app.get('/healthz', (_req, res) => res.json({ ok: true, tenant: tenant.id }));

// --- public: sign-in, identity exchange, API description ---
api.get('/auth/login', route((req, res) => oidc.login(req, res)));
api.get('/auth/config', route(() => ({ auth_mode: oidc.OIDC.authMode, tenant_name: tenant.name })));
api.post('/auth/local-login', route((req, res) => oidc.localLogin(req, res)));
api.get('/auth/callback', route((req, res) => oidc.callback(req, res)));
api.post('/auth/logout', route((req, res) => oidc.logout(req, res)));
api.post('/auth/dev-token', route((req) => oidc.localToken(req.body ?? {})));
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
api.post('/identity/token', express.urlencoded({ extended: false, limit: '8kb' }), route((req) => {
  tokenRateLimit(req);
  const b = (req.body ?? {}) as Record<string, string>;
  if (b.grant_type === 'client_credentials') {
    let id = b.client_id;
    let secret = b.client_secret;
    const basic = String(req.headers.authorization ?? '').match(/^Basic\s+(.+)$/i);
    if (basic) [id, secret] = Buffer.from(basic[1]!, 'base64').toString('utf8').split(':') as [string, string];
    const t = identity.exchangeClientCredentials(decodeURIComponent(String(id ?? '')), decodeURIComponent(String(secret ?? '')));
    return { ...t, access_token: t.token }; // access_token for OAuth clients, token for the Signet SDK
  }
  return identity.exchangeBootstrap(String(b.bootstrap_credential ?? ''));
}));
// The SDK and sidecar report what they see in the agent's runtime (variable names, never values).
api.post('/identity/diagnostics', route((req) => connectivity.report(String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, ''), req.body)));
api.post('/identity/token/refresh', route((req) => identity.refreshToken((req.headers.authorization ?? '').replace(/^Bearer /, ''))));
api.post('/identity/deployment-token', route((req, res) => {
  res.setHeader('cache-control', 'no-store');
  return deploymentIdentity.exchangeDeploymentCredential(String(req.body?.deployment_credential ?? ''));
}));
api.get('/openapi.json', (_req, res) => res.json(openapi));

// --- everything below needs a signed-in person or an approved machine client ---
api.use(oidc.authenticate, signedIn, idempotency);

api.get('/me', route((_req, res) => ({ principal: principalOf(res), tenant: { id: tenant.id, name: tenant.name } })));
api.get('/plugins/vercel', requires('tenant.admin'), route((_req, res) => plugins.vercelConnection(principalOf(res))));
api.get('/plugins/vercel/connect', requires('tenant.admin'), route((_req, res) => plugins.startVercelConnection(res, principalOf(res))));
api.get('/plugins/vercel/callback', requires('tenant.admin'), route((req, res) => plugins.completeVercelConnection(req, res, principalOf(res))));
api.post('/plugins/vercel/disconnect', requires('tenant.admin'), route((_req, res) => plugins.disconnectVercel(principalOf(res))));
api.get('/catalogue', requires('agents.read'), route(() => ({ catalogue: tenant.settings.catalogue })));
api.get('/stats/command-center', requires('agents.read'), route(() => commandCenter()));
api.get('/stats/agents', requires('agents.read'), route(() => agentAnalytics()));
api.get('/gateways', requires('gateways.read'), route(() => ({ items: db.prepare('SELECT * FROM gateway_node ORDER BY id').all() })));
api.get('/live', requires('ledger.read'), (_req, res) => live.attach(res));

// Registry and seals
api.get('/agents', requires('agents.read'), route((req) => {
  const out = registry.listAgents({ tier: req.query.tier as string, status: req.query.status as string, q: req.query.q as string, cursor: cursor.decode(req.query.cursor), limit: limitOf(req.query.limit) });
  return { items: out.items.map((a) => ({ ...a, enforcement: enforcement.agentLevel(a.id), connection: connectivity.status(a.id).state })), next_cursor: out.next_cursor ? cursor.encode(out.next_cursor) : null };
}));
// Stage 1 Propose: the agent gets its permanent ID and a lifecycle (BP 6).
api.post('/agents', requires('agents.write'), route((req, res) => {
  const p = principalOf(res);
  const agent = registry.registerAgent(req.body, p);
  const lc = workflow.start(agent, req.body?.intake ?? { template: req.body?.template }, p);
  return [201, { ...agent, lifecycle_id: lc.id }];
}));
api.get('/agents/:id/removal-preview', requires('agents.delete'), route((req, res) => agentRemovalPreview(req.params.id!, principalOf(res))));
api.delete('/agents/:id', requires('agents.delete'), route((req, res) => {
  if (typeof req.body?.confirm_handle !== 'string') throw invalid('confirm_handle must be the exact agent handle');
  return removeAgent(req.params.id!, req.body.confirm_handle, principalOf(res));
}));
api.get('/agents/:id', requires('agents.read'), route((req) => {
  const agent = registry.getAgent(req.params.id!);
  const active = registry.activeCertificate(agent.id);
  const lcs = workflow.forAgent(agent.id);
  return {
    agent: { ...agent, vendor_details: JSON.parse(agent.vendor_details || '{}') },
    connection: connectivity.status(agent.id),
    clients: agent.kind === 'third_party' ? identity.clientsOf(agent.id) : [],
    team: registry.teamOf(agent.id),
    enforcement: { level: enforcement.agentLevel(agent.id), states: enforcement.statesFor(agent.id) },
    certificate: active?.certificate ?? null,
    certificates: registry.certificates(agent.id),
    instances: identity.instancesOf(agent.id),
    events: enforcement.recentEvents(10, agent.id),
    lifecycle: lcs[0] ? workflow.view(lcs[0].id) : null,
    lifecycles: lcs.map((l) => ({ id: l.id, kind: l.kind, stage: l.stage, status: l.status, started_at: l.started_at })),
    attestations: db.prepare('SELECT id, type, signer, content_hash, signed_at FROM attestation WHERE agent_id = ? ORDER BY signed_at DESC').all(agent.id),
  };
}));
// Seals come only from the lifecycle (BP 6: no agent reaches production without all 8 stages).
api.post('/agents/:id/certificates', requires('certificates.approve'), route((req, res) => {
  const issued = registry.issueSeal(req.params.id!, req.body, principalOf(res));
  hub.publish('bundle', { reason: 'certificate.issued', cert_id: issued.certificate.cert_id });
  return [201, issued];
}));

// Lifecycle stages (BP 6)
api.get('/lifecycles/:id', requires('agents.read'), route((req) => workflow.view(req.params.id!)));
api.patch('/lifecycles/:id/intake', requires('agents.write', 'certificates.approve'), route((req, res) => workflow.updateIntake(req.params.id!, req.body ?? {}, principalOf(res))));
api.put('/lifecycles/:id/manifest', requires('agents.read'), route((req, res) => workflow.setManifest(req.params.id!, req.body, principalOf(res))));
api.post('/lifecycles/:id/stages/propose/submit', requires('agents.read'), route((req, res) => workflow.submitPropose(req.params.id!, principalOf(res))));
api.post('/lifecycles/:id/classification', requires('agents.read'), route((req, res) => workflow.classify(req.params.id!, principalOf(res), req.body ?? {})));
api.put('/lifecycles/:id/assessments/:type', requires('agents.read'), route((req, res) => workflow.saveAssessment(req.params.id!, req.params.type!, req.body?.content ?? {}, req.body?.complete === true, principalOf(res))));
api.post('/lifecycles/:id/gaps', requires('agents.read'), route((req, res) => {
  const lc = workflow.get(req.params.id!);
  const id = workflow.addGap(lc.id, req.body ?? {}, principalOf(res));
  return [201, { id }];
}));
api.patch('/gaps/:id', requires('agents.read'), route((req, res) => workflow.updateGap(req.params.id!, req.body ?? {}, principalOf(res))));
api.post('/gaps/:id/acceptance', requires('agents.read'), route((req, res) => [201, workflow.requestAcceptance(req.params.id!, principalOf(res), req.body ?? {})]));
api.post('/lifecycles/:id/stages/assess/submit', requires('agents.read'), route((req, res) => workflow.submitAssess(req.params.id!, principalOf(res))));
api.post('/lifecycles/:id/test-runs', requires('agents.read'), route((req, res) => [201, workflow.runTests(req.params.id!, principalOf(res), req.body ?? {})]));
api.post('/lifecycles/:id/deploy', requires('agents.read'), route((req, res) => workflow.advanceDeploy(req.params.id!, principalOf(res), req.body ?? {})));
api.post('/agents/:id/attest', requires('agents.read'), route((req, res) => workflow.attest(req.params.id!, principalOf(res), req.body ?? {})));
api.post('/agents/:id/changes', requires('agents.write', 'certificates.approve'), route((req, res) => [201, workflow.requestChange(req.params.id!, principalOf(res), req.body ?? {})]));
api.post('/agents/:id/retire', requires('agents.read'), route((req, res) => [201, workflow.requestRetire(req.params.id!, principalOf(res), String(req.body?.reason ?? ''))]));
api.get('/templates', requires('agents.read'), route(() => ({ items: TEMPLATES })));

// Approvals engine (BP 7)
api.get('/approvals', requires('agents.read'), route((req, res) => {
  const p = principalOf(res);
  if (req.query.mine) return { items: approvals.forMe(p) };
  return { items: approvals.list({ status: req.query.status as string, type: req.query.type as string, agent: req.query.agent as string, limit: limitOf(req.query.limit, 500, 100) }) };
}));
api.get('/approvals/:id', requires('agents.read'), route((req, res) => {
  const r = approvals.get(req.params.id!);
  return { ...r, my_slots: approvals.eligibleSlots(r, principalOf(res)).map((s) => s.slot) };
}));
api.post('/approvals/:id/decisions', requires('agents.read'), route((req, res) => approvals.decide(req.params.id!, principalOf(res), req.body ?? {})));
api.post('/delegations', requires('agents.read'), route((req, res) => [201, approvals.delegate(principalOf(res), String(req.body?.to ?? ''), String(req.body?.from_date ?? ''), String(req.body?.to_date ?? ''))]));
api.get('/delegations', requires('agents.read'), route((_req, res) => ({ items: db.prepare('SELECT * FROM delegation WHERE from_user = ? OR to_user = ? ORDER BY created_at DESC').all(principalOf(res).id, principalOf(res).id) })));
api.get('/notifications', route((_req, res) => ({ items: notify.listFor(principalOf(res)), unread: notify.unreadCount(principalOf(res)) })));
api.post('/notifications/read', route((_req, res) => (notify.markRead(principalOf(res)), { ok: true })));

// Control library and compliance (BP 9)
api.get('/library', requires('compliance.read'), route(() => controls.library()));
api.post('/library/evaluate', requires('compliance.read'), route(() => ({ results: controls.evaluate() })));
api.get('/compliance/scores', requires('compliance.read'), route(() => ({ items: controls.scores() })));

// Connectors (BP 10)
api.get('/connectors', requires('connectors.manage', 'compliance.read'), route(() => ({ items: servicenow.list() })));
api.post('/connectors', requires('connectors.manage'), route((req, res) => [201, servicenow.create(req.body ?? {}, principalOf(res))]));
api.post('/connectors/:id/test', requires('connectors.manage'), route((req, res) => servicenow.selfTest(req.params.id!, principalOf(res))));
api.post('/connectors/:id/pull', requires('connectors.manage'), route((req, res) => servicenow.pullLibrary(req.params.id!, principalOf(res))));
api.get('/connectors/:id/outbox', requires('connectors.manage'), route((req) => ({ items: servicenow.outbox(req.params.id!, req.query.status as string | undefined) })));
api.post('/outbox/:id/retry', requires('connectors.manage'), route((req, res) => servicenow.retry(req.params.id!, principalOf(res))));
api.get('/agents/:id/certificate', requires('agents.read'), route((req) => {
  const agent = registry.getAgent(req.params.id!);
  const active = registry.activeCertificate(agent.id);
  if (!active) throw new PolicyError('NOT_FOUND', 'no active seal', 404);
  return active;
}));
api.post('/certificates/verify', requires('agents.read'), route((req) => {
  const jws = String(req.body?.jws ?? '');
  try {
    const { header, payload } = verifyJws<CertificateBody>(jws, new Map([[keys.ca.kid, keys.ca.publicKey]]), 'signet-seal');
    const row = db.prepare('SELECT status FROM certificate WHERE id = ?').get(payload.cert_id) as { status: string } | undefined;
    return { signature_valid: true, signed_by: header.kid, cert_id: payload.cert_id, status: row?.status ?? 'unknown', valid_to: payload.valid_to };
  } catch (e) {
    return { signature_valid: false, error: (e as Error).message };
  }
}));
// Where agents connect: shown in the console's connection instructions. Set the public URLs in production.
api.get('/connect/info', requires('agents.read'), route(() => {
  const nodes = db.prepare('SELECT id, url, last_seen FROM gateway_node ORDER BY id').all() as { id: string; url: string; last_seen: string }[];
  const live = nodes.filter((n) => Date.now() - Date.parse(n.last_seen) < 30_000);
  return {
    gateway_url: process.env.SIGNET_GATEWAY_PUBLIC_URL ?? live[0]?.url ?? null,
    gateway_url_source: process.env.SIGNET_GATEWAY_PUBLIC_URL ? 'SIGNET_GATEWAY_PUBLIC_URL' : live[0] ? `gateway node ${live[0].id} (local address; set SIGNET_GATEWAY_PUBLIC_URL for remote agents)` : 'no live gateway node',
    control_url: process.env.SIGNET_CONTROL_PUBLIC_URL ?? `http://localhost:${PORT}`,
    control_url_source: process.env.SIGNET_CONTROL_PUBLIC_URL ? 'SIGNET_CONTROL_PUBLIC_URL' : 'local address; set SIGNET_CONTROL_PUBLIC_URL for remote agents',
    models: tenant.settings.catalogue.map((c) => c.model),
    tools: tools.listTools().map((t) => ({ alias: t.alias, kind: t.kind, actions: Object.keys(t.actions) })),
  };
}));
api.get('/agents/:id/connection', requires('agents.read'), route((req) => connectivity.status(req.params.id!)));
api.post('/agents/:id/clients', requires('identity.bootstrap'), route((req, res) => [201, identity.createClient(req.params.id!, principalOf(res), String(req.body?.label ?? ''))]));
api.post('/clients/:id/revoke', requires('identity.bootstrap', 'ladder.quarantine'), route((req, res) => identity.revokeClient(req.params.id!, principalOf(res), String(req.body?.reason ?? ''))));
api.post('/instances/:id/revoke', requires('identity.bootstrap', 'ladder.quarantine'), route((req, res) => identity.revokeInstance(req.params.id!, principalOf(res), String(req.body?.reason ?? ''))));
api.post('/agents/:id/bootstrap', requires('identity.bootstrap'), route((req, res) => [201, identity.createBootstrap(req.params.id!, principalOf(res), String(req.body?.environment ?? 'dev'))]));
api.post('/agents/:id/deployment-credentials', requires('identity.bootstrap'), route((req, res) => {
  res.setHeader('cache-control', 'no-store');
  return [201, deploymentIdentity.createDeploymentCredential(req.params.id!, principalOf(res), String(req.body?.environment ?? 'dev'))];
}));
api.delete('/agents/:id/deployment-credentials/:credentialId', requires('identity.bootstrap'), route((req, res) =>
  deploymentIdentity.revokeDeploymentCredential(req.params.id!, req.params.credentialId!, principalOf(res)),
));

// Response ladder (manual): owners can quarantine or kill their own agents (BP 14.2)
api.post('/agents/:id/ladder', route((req, res) => {
  const p = principalOf(res);
  const agent = registry.getAgent(req.params.id!);
  const action = req.body?.action as enforcement.LadderAction;
  if (!['step_up', 'throttle', 'quarantine', 'kill', 'release'].includes(action)) throw invalid('action must be step_up, throttle, quarantine, kill or release');
  // Quarantine release goes through the approvals engine (BP 7.2); step-up and throttle windows can
  // be cleared by Security directly (BP 5.4 "window expires or Security clears").
  if (action === 'release' && enforcement.agentLevel(agent.id) === 'quarantined') return [201, workflow.requestRelease(agent.id, p, String(req.body?.reason ?? ''))];
  registry.assertCan(p, `ladder.${action}` as never, agent);
  if (action === 'kill' && req.body?.confirm_handle !== agent.handle) throw new PolicyError('BP-14.1', 'type the agent handle to confirm a kill', 400);
  return enforcement.applyLadder(
    { agentId: agent.id, scope: req.body?.scope, version: req.body?.version, instanceId: req.body?.instance_id },
    action,
    { actor: p.id, reason: String(req.body?.reason ?? ''), minutes: req.body?.minutes, factor: req.body?.factor },
  );
}));
api.get('/enforcement-events', requires('ledger.read'), route((req) => ({ items: enforcement.recentEvents(limitOf(req.query.limit, 200, 50), req.query.agent as string | undefined) })));
api.get('/enforcement-events/:id', requires('ledger.read'), route((req) => enforcement.eventStatus(req.params.id!)));
api.get('/circuit-breakers', requires('ledger.read'), route(() => ({ items: enforcement.breakers() })));
api.post('/circuit-breakers/preview', requires('circuit_breaker.arm'), route((req) => ({ matched: enforcement.matchSelector(req.body?.selector ?? {}) })));
api.post('/circuit-breakers', requires('circuit_breaker.arm'), route((req, res) => [201, enforcement.armBreaker(req.body?.selector ?? {}, req.body?.action === 'kill' ? 'kill' : 'quarantine', String(req.body?.reason ?? ''), principalOf(res))]));

// Tools and the Secrets Broker
api.get('/tools', requires('agents.read'), route(() => ({ items: tools.listTools() })));
api.post('/tools', requires('tools.manage'), route(async (req, res) => {
  const t = await tools.registerTool(req.body, principalOf(res));
  hub.publish('bundle', { reason: 'tool.registered', alias: t.alias });
  return [201, t];
}));
api.get('/secrets', requires('secrets.manage'), route(() => ({ items: secrets.listSecrets() })));
api.post('/secrets', requires('secrets.manage'), route((req, res) => {
  const s = secrets.putSecret(req.body, principalOf(res));
  discovery.reconcileWithBroker();
  return [201, s];
}));
api.post('/secrets/:id/rotate', requires('secrets.manage'), route((req, res) => {
  const s = secrets.rotateSecret(req.params.id!, String(req.body?.value ?? ''), principalOf(res));
  hub.publish('secret', { secret_id: s.id, version: s.version });
  return s;
}));

// Discovery (Key Sweep)
api.get('/discovered-assets', requires('discovery.read', 'discovery.write'), route((req) => ({ items: discovery.list(req.query.status as string | undefined), kpi: discovery.keylessKpi() })));
api.post('/discovery/findings', requires('discovery.write'), route((req, res) => [201, discovery.ingest(String(req.body?.source ?? ''), req.body?.items, principalOf(res))]));
api.get('/discovery/sources', requires('discovery.read', 'discovery.write'), route(() => ({ items: discovery.sources(), providers: discovery.AI_PROVIDERS.map((x) => ({ provider: x.provider, kind: x.kind, domain: x.domain.source })) })));
api.post('/discovery/logs', requires('discovery.write'), express.json({ limit: '25mb' }), route((req, res) => {
  const src = req.body?.source === 'saas-audit' ? 'saas-audit' : req.body?.source === 'network-logs' ? 'network-logs' : null;
  if (!src) throw invalid('source must be network-logs or saas-audit');
  return [201, discovery.ingestLogs(src, req.body?.records, principalOf(res), Array.isArray(req.body?.gateway_hosts) ? req.body.gateway_hosts.map(String) : [])];
}));
api.post('/discovered-assets/:id/resolve', requires('discovery.write'), route((req, res) => discovery.resolve(req.params.id!, req.body?.status, String(req.body?.note ?? ''), principalOf(res))));

// Detectors
api.get('/detectors', requires('agents.read'), route(() => ({ items: detectors.list() })));
api.post('/detectors/:id/mode', requires('detectors.manage'), route((req, res) => detectors.setMode(req.params.id!, req.body?.mode, principalOf(res), { reason: String(req.body?.reason ?? ''), dev_override: req.body?.dev_override === true })));

// Ledger and evidence
api.get('/ledger/records', requires('ledger.read'), route((req) => {
  const out = ledger.list({ agent: req.query.agent as string, kind: req.query.kind as string, decision: req.query.decision as string, before_seq: Number(cursor.decode(req.query.cursor)) || null, limit: limitOf(req.query.limit, 500, 100) });
  return { items: out.items, next_cursor: out.next_cursor ? cursor.encode(out.next_cursor) : null };
}));
api.get('/ledger/records/:id', requires('ledger.read'), route((req) => {
  const r = ledger.get(req.params.id!);
  return { record: r, neighbours: ledger.neighbours(r.seq).map((n) => ({ seq: n.seq, record_id: n.record_id, record_hash: n.record_hash, prev_hash: n.prev_hash })) };
}));
api.get('/ledger/records/:id/proof', requires('ledger.read'), route((req) => evidence.proofFor(req.params.id!)));
api.post('/ledger/verify', requires('ledger.verify'), route((req) => {
  const t0 = performance.now();
  const r = ledger.verify(Number(req.body?.from_seq) || 1, Number(req.body?.to_seq) || Number.MAX_SAFE_INTEGER);
  const roots = evidence.roots(1000).map((x) => {
    try {
      const p = evidence.verifyRootJws(x.jws);
      return { day: p.day, signature_valid: true };
    } catch {
      return { day: (x as unknown as { day: string }).day, signature_valid: false };
    }
  });
  return { ...r, roots_checked: roots.length, roots_valid: roots.every((x) => x.signature_valid), ms: Math.round(performance.now() - t0) };
}));
api.get('/ledger/roots', requires('ledger.read'), route(() => ({ items: evidence.roots(60), ledger_key: toJwk(keys.ledger) })));
api.post('/ledger/roots/seal', requires('ledger.verify'), route((req) => (req.body?.day ? { sealed: [evidence.sealDay(String(req.body.day))] } : { sealed: evidence.sealFinishedDays() })));
api.get('/ledger/export', requires('evidence.export'), (req, res) => {
  const p = principalOf(res);
  res.setHeader('content-type', 'application/gzip');
  res.setHeader('content-disposition', `attachment; filename="signet-${tenant.id}-${new Date().toISOString().slice(0, 10)}.sep"`);
  evidence.writePackage(res, { fromDay: req.query.from as string | undefined, toDay: req.query.to as string | undefined, actor: p.id });
});

app.use('/api/v1', api);

// --- internal: gateway nodes (shared token in dev; mTLS in production, BP 15.3) ---
const int = express.Router();
int.use(internal);
int.get('/trust', route(() => ({ ca: toJwk(keys.ca), token: toJwk(keys.token) })));
int.get('/bundle', route(() => ({ bundle: enforcement.buildBundle() })));
int.get('/events', (req, res) => hub.attach(String(req.query.node ?? 'unknown'), res));
int.post('/acks', route((req) => (enforcement.recordAck(String(req.body?.event_id), String(req.body?.node_id)), { ok: true })));
int.post('/agent-erasure-acks', route((req) => {
  if (typeof req.body?.request_id !== 'string' || typeof req.body?.node_id !== 'string') throw invalid('request_id and node_id are required strings');
  hub.acknowledgeAgentErasure(req.body.request_id, req.body.node_id);
  return { ok: true };
}));
int.post('/ledger', route((req) => (Array.isArray(req.body?.records) ? { records: ledger.appendMany(req.body.records).map((r) => ({ record_id: r.record_id, seq: r.seq })) } : { record: ledger.append(req.body) })));
int.get('/secrets/:id', route((req) => secrets.revealForGateway(req.params.id!)));
int.post('/heartbeat', route((req) => {
  db.prepare('INSERT INTO gateway_node (id, url, last_seen, bundle_version, llm_status) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET url = excluded.url, last_seen = excluded.last_seen, bundle_version = excluded.bundle_version, llm_status = excluded.llm_status').run(
    String(req.body?.node_id), String(req.body?.url ?? ''), nowIso(), Number(req.body?.bundle_version) || null, req.body?.llm_status ? JSON.stringify(req.body.llm_status) : null,
  );
  return { ok: true };
}));
int.post('/enforce', route((req) =>
  enforcement.applyLadder(
    { agentId: String(req.body?.agent_id), scope: req.body?.scope, version: req.body?.version, instanceId: req.body?.instance_id },
    req.body?.action,
    { actor: `gateway:${req.body?.node_id ?? 'unknown'}`, reason: String(req.body?.reason ?? ''), rule_id: req.body?.rule_id, automatic: true, evidence: req.body?.evidence },
  ),
));
// Runtime HITL: the gateway opens a hold and waits for the decision (BP 5.2 step 10, 7.4).
int.post('/hitl', route((req) => hitl.open(req.body ?? {})));
int.get('/hitl/:id', route((req) => hitl.status(req.params.id!)));
int.post('/hitl/:id/consume', route((req) => hitl.consume(req.params.id!, req.body ?? {})));
int.post('/outage', route((req) => {
  const r = ledger.append({ kind: 'enforcement', data: { event: `provider.outage.${req.body?.state === 'ended' ? 'ended' : 'declared'}`, rule_id: 'RB-PROV-04', node_id: req.body?.node_id, stats: req.body?.stats ?? {} } });
  return { record_id: r.record_id };
}));
app.use('/internal', int);

app.use(problemHandler);

// Background jobs: ladder windows, approval escalation and timeouts, re-attestation and expiry,
// continuous control tests, connector outbox, daily roots.
controls.seed();
enforcement.setRolloutSource(workflow.rollouts);
const every = (ms: number, name: string, fn: () => unknown) => {
  const run = () => {
    try {
      const r = fn();
      if (r instanceof Promise) r.catch((e) => console.error(`[control] ${name} failed`, e));
    } catch (e) {
      console.error(`[control] ${name} failed`, e);
    }
  };
  setInterval(run, ms).unref();
  return run;
};
every(15_000, 'ladder sweep', () => enforcement.sweepExpired());
every(5_000, 'approval sweep', () => approvals.sweep());
every(10 * 60_000, 'lifecycle sweep', () => workflow.sweep())();
every(10 * 60_000, 'control evaluation', () => controls.evaluate())();
every(3_000, 'connector worker', () => servicenow.work());
const sealRoots = () => {
  try {
    const sealed = evidence.sealFinishedDays();
    if (sealed.length) console.log(`[control] daily roots signed for ${sealed.join(', ')}`);
  } catch (e) {
    console.error('[control] daily root sealing failed', e);
  }
};
sealRoots();
setInterval(sealRoots, 10 * 60_000).unref();

app.listen(PORT, () => {
  console.log(`[control] Signet control plane on http://localhost:${PORT}  tenant=${tenant.id} (${tenant.name})`);
  console.log(`[control] identity provider ${oidc.OIDC.issuer}; cloud LLM ${tenant.settings.catalogue.map((c) => c.model).join(', ')}`);
});


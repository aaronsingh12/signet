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
import { jwks, keys } from './keys';
import * as ledger from './ledger';
import * as live from './live';
import * as oidc from './oidc';
import { openapi } from './openapi';
import { principalOf, requires } from './rbac';
import * as registry from './registry';
import * as secrets from './secrets';
import { commandCenter } from './stats';
import { tenant } from './tenant';
import * as tools from './tools';

const INTERNAL_TOKEN = devSecret('SIGNET_INTERNAL_TOKEN');
const PORT = Number(env('SIGNET_CONTROL_PORT', '4100'));

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
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
api.get('/auth/callback', route((req, res) => oidc.callback(req, res)));
api.post('/auth/logout', route((req, res) => oidc.logout(req, res)));
api.get('/identity/jwks', route(() => jwks()));
api.post('/identity/token', route((req) => identity.exchangeBootstrap(String(req.body?.bootstrap_credential ?? ''))));
api.post('/identity/token/refresh', route((req) => identity.refreshToken((req.headers.authorization ?? '').replace(/^Bearer /, ''))));
api.get('/openapi.json', (_req, res) => res.json(openapi));

// --- everything below needs a signed-in person or an approved machine client ---
api.use(oidc.authenticate, signedIn, idempotency);

api.get('/me', route((_req, res) => ({ principal: principalOf(res), tenant: { id: tenant.id, name: tenant.name } })));
api.get('/catalogue', requires('agents.read'), route(() => ({ catalogue: tenant.settings.catalogue })));
api.get('/stats/command-center', requires('agents.read'), route(() => commandCenter()));
api.get('/gateways', requires('gateways.read'), route(() => ({ items: db.prepare('SELECT * FROM gateway_node ORDER BY id').all() })));
api.get('/live', requires('ledger.read'), (_req, res) => live.attach(res));

// Registry and seals
api.get('/agents', requires('agents.read'), route((req) => {
  const out = registry.listAgents({ tier: req.query.tier as string, status: req.query.status as string, q: req.query.q as string, cursor: cursor.decode(req.query.cursor), limit: limitOf(req.query.limit) });
  return { items: out.items.map((a) => ({ ...a, enforcement: enforcement.agentLevel(a.id) })), next_cursor: out.next_cursor ? cursor.encode(out.next_cursor) : null };
}));
api.post('/agents', requires('agents.write'), route((req, res) => [201, registry.registerAgent(req.body, principalOf(res))]));
api.get('/agents/:id', requires('agents.read'), route((req) => {
  const agent = registry.getAgent(req.params.id!);
  const active = registry.activeCertificate(agent.id);
  return {
    agent,
    team: registry.teamOf(agent.id),
    enforcement: { level: enforcement.agentLevel(agent.id), states: enforcement.statesFor(agent.id) },
    certificate: active?.certificate ?? null,
    certificates: registry.certificates(agent.id),
    instances: identity.instancesOf(agent.id),
    events: enforcement.recentEvents(10, agent.id),
  };
}));
api.post('/agents/:id/certificates', requires('certificates.approve'), route((req, res) => {
  const issued = registry.issueSeal(req.params.id!, req.body, principalOf(res));
  hub.publish('bundle', { reason: 'certificate.issued', cert_id: issued.certificate.cert_id });
  return [201, issued];
}));
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
api.post('/agents/:id/bootstrap', requires('identity.bootstrap'), route((req, res) => [201, identity.createBootstrap(req.params.id!, principalOf(res), String(req.body?.environment ?? 'dev'))]));

// Response ladder (manual): owners can quarantine or kill their own agents (BP 14.2)
api.post('/agents/:id/ladder', route((req, res) => {
  const p = principalOf(res);
  const agent = registry.getAgent(req.params.id!);
  const action = req.body?.action as enforcement.LadderAction;
  if (!['step_up', 'throttle', 'quarantine', 'kill', 'release'].includes(action)) throw invalid('action must be step_up, throttle, quarantine, kill or release');
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
api.post('/tools', requires('tools.manage'), route((req, res) => {
  const t = tools.registerTool(req.body, principalOf(res));
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
int.post('/ledger', route((req) => (Array.isArray(req.body?.records) ? { records: ledger.appendMany(req.body.records).map((r) => ({ record_id: r.record_id, seq: r.seq })) } : { record: ledger.append(req.body) })));
int.get('/secrets/:id', route((req) => secrets.revealForGateway(req.params.id!)));
int.post('/heartbeat', route((req) => {
  db.prepare('INSERT INTO gateway_node (id, url, last_seen, bundle_version) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET url = excluded.url, last_seen = excluded.last_seen, bundle_version = excluded.bundle_version').run(
    String(req.body?.node_id), String(req.body?.url ?? ''), nowIso(), Number(req.body?.bundle_version) || null,
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
int.post('/outage', route((req) => {
  const r = ledger.append({ kind: 'enforcement', data: { event: `provider.outage.${req.body?.state === 'ended' ? 'ended' : 'declared'}`, rule_id: 'RB-PROV-04', node_id: req.body?.node_id, stats: req.body?.stats ?? {} } });
  return { record_id: r.record_id };
}));
app.use('/internal', int);

app.use(problemHandler);

// Background jobs: expired ladder windows, daily roots.
setInterval(() => {
  try {
    enforcement.sweepExpired();
  } catch (e) {
    console.error('[control] ladder sweep failed', e);
  }
}, 15_000).unref();
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


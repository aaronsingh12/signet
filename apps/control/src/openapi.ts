// OpenAPI 3.1 description of the public control API (BP 13). Served at /api/v1/openapi.json.

type Op = { summary: string; permission?: string; public?: boolean; body?: string };

const ops: Record<string, Record<string, Op>> = {
  '/auth/login': { get: { summary: 'Start single sign-on (authorization code + PKCE)', public: true } },
  '/auth/callback': { get: { summary: 'OIDC redirect target', public: true } },
  '/auth/logout': { post: { summary: 'End the Signet session and the IdP session', public: true } },
  '/me': { get: { summary: 'The signed-in principal, roles and permissions' } },
  '/identity/jwks': { get: { summary: 'Public keys: CA (seals, bundles), workload tokens, ledger roots', public: true } },
  '/identity/token': { post: { summary: 'Exchange a one-time bootstrap credential for a workload token', public: true, body: 'BootstrapExchange' } },
  '/identity/token/refresh': { post: { summary: 'Swap a valid workload token for a fresh one', public: true } },
  '/catalogue': { get: { summary: "The tenant's cloud LLM catalogue (Rulebook D-17)", permission: 'agents.read' } },
  '/stats/command-center': { get: { summary: 'Command Center figures', permission: 'agents.read' } },
  '/gateways': { get: { summary: 'Gateway nodes and their last heartbeat', permission: 'gateways.read' } },
  '/live': { get: { summary: 'Server-sent events: decisions as they happen', permission: 'ledger.read' } },
  '/agents': {
    get: { summary: 'List agents (filters tier, status, q; cursor pagination)', permission: 'agents.read' },
    post: { summary: 'Register an agent (Stage 1 Propose, simplified)', permission: 'agents.write', body: 'AgentRegistration' },
  },
  '/agents/{id}': { get: { summary: 'Agent 360: agent, team, ladder state, seal, versions, instances, events', permission: 'agents.read' } },
  '/agents/{id}/certificates': { post: { summary: 'Approve and sign a seal (separation of duties enforced)', permission: 'certificates.approve', body: 'SealInput' } },
  '/agents/{id}/certificate': { get: { summary: 'The active seal (JWS and body)', permission: 'agents.read' } },
  '/certificates/verify': { post: { summary: 'Verify a seal signature and current status', permission: 'agents.read' } },
  '/agents/{id}/bootstrap': { post: { summary: 'Issue a one-time bootstrap credential for a deployment', permission: 'identity.bootstrap' } },
  '/agents/{id}/ladder': { post: { summary: 'Step-up, throttle, quarantine, kill or release (scope agent, version or instance)', permission: 'ladder.*', body: 'LadderAction' } },
  '/enforcement-events': { get: { summary: 'Ladder events with kill acknowledgements per gateway node', permission: 'ledger.read' } },
  '/enforcement-events/{id}': { get: { summary: 'One ladder event and its propagation', permission: 'ledger.read' } },
  '/circuit-breakers': {
    get: { summary: 'Armed circuit breakers', permission: 'ledger.read' },
    post: { summary: 'Arm a circuit breaker on a selector (model, tool, tag, tier)', permission: 'circuit_breaker.arm' },
  },
  '/circuit-breakers/preview': { post: { summary: 'Agents a selector would match', permission: 'circuit_breaker.arm' } },
  '/tools': { get: { summary: 'Tool aliases', permission: 'agents.read' }, post: { summary: 'Register an MCP or HTTP tool alias', permission: 'tools.manage' } },
  '/secrets': { get: { summary: 'Secrets Broker metadata (never values)', permission: 'secrets.manage' }, post: { summary: 'Store a credential in the broker', permission: 'secrets.manage' } },
  '/secrets/{id}/rotate': { post: { summary: 'Rotate a brokered credential', permission: 'secrets.manage' } },
  '/discovered-assets': { get: { summary: 'Discovery Inbox and the keyless KPI', permission: 'discovery.read' } },
  '/discovery/findings': { post: { summary: 'Ingest Key Sweep findings (fingerprints only)', permission: 'discovery.write' } },
  '/discovered-assets/{id}/resolve': { post: { summary: 'Mark a finding migrated, blocked or dismissed', permission: 'discovery.write' } },
  '/detectors': { get: { summary: 'Detector registry and modes', permission: 'agents.read' } },
  '/detectors/{id}/mode': { post: { summary: 'Move a detector between off, shadow and active (RB-MOD-03)', permission: 'detectors.manage' } },
  '/ledger/records': { get: { summary: 'Ledger records (filters agent, kind, decision; cursor pagination)', permission: 'ledger.read' } },
  '/ledger/records/{id}': { get: { summary: 'One record and its chain neighbours', permission: 'ledger.read' } },
  '/ledger/records/{id}/proof': { get: { summary: 'Merkle inclusion proof against the daily root', permission: 'ledger.read' } },
  '/ledger/verify': { post: { summary: 'Verify the hash chain and daily root signatures', permission: 'ledger.verify' } },
  '/ledger/roots': { get: { summary: 'Signed daily Merkle roots and the ledger public key', permission: 'ledger.read' } },
  '/ledger/roots/seal': { post: { summary: 'Sign roots for finished days now', permission: 'ledger.verify' } },
  '/ledger/export': { get: { summary: 'Evidence Package (.sep) for offline verification with signet-verify', permission: 'evidence.export' } },
};

const paths: Record<string, Record<string, unknown>> = {};
for (const [path, methods] of Object.entries(ops)) {
  paths[path] = {};
  for (const [method, op] of Object.entries(methods)) {
    paths[path][method] = {
      summary: op.summary,
      ...(op.permission ? { 'x-signet-permission': op.permission } : {}),
      security: op.public ? [] : [{ oidc: [] }, { session: [] }],
      ...(method === 'post' ? { parameters: [{ name: 'Idempotency-Key', in: 'header', required: false, schema: { type: 'string', maxLength: 200 } }] } : {}),
      ...(op.body ? { requestBody: { content: { 'application/json': { schema: { $ref: `#/components/schemas/${op.body}` } } } } } : {}),
      responses: {
        '200': { description: 'OK' },
        default: { description: 'RFC 9457 problem details', content: { 'application/problem+json': { schema: { $ref: '#/components/schemas/Problem' } } } },
      },
    };
  }
}

export const openapi = {
  openapi: '3.1.0',
  info: { title: 'Signet Control API', version: '1.0.0-phase1', description: 'Everything the console does goes through this API (BP 2 principle 10).' },
  servers: [{ url: '/api/v1' }],
  paths,
  components: {
    securitySchemes: {
      oidc: { type: 'openIdConnect', openIdConnectUrl: '/.well-known/openid-configuration (tenant IdP)' },
      session: { type: 'apiKey', in: 'cookie', name: 'signet_session' },
    },
    schemas: {
      Problem: {
        type: 'object',
        properties: { type: { type: 'string' }, title: { type: 'string' }, status: { type: 'integer' }, detail: { type: 'string' }, rule: { type: 'string', description: 'Blueprint or Rulebook rule behind the refusal' }, instance: { type: 'string' } },
      },
      BootstrapExchange: { type: 'object', required: ['bootstrap_credential'], properties: { bootstrap_credential: { type: 'string' } } },
      AgentRegistration: {
        type: 'object',
        required: ['handle', 'name', 'purpose', 'sponsor', 'tier', 'autonomy_level'],
        properties: {
          handle: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' }, name: { type: 'string' }, purpose: { type: 'string' }, owner: { type: 'string' }, sponsor: { type: 'string' },
          tier: { enum: ['T1', 'T2', 'T3', 'T4'] }, autonomy_level: { enum: ['L0', 'L1', 'L2', 'L3', 'L4'] },
          team: { type: 'array', items: { type: 'object', properties: { user: { type: 'string' }, role: { enum: ['builder', 'operator'] } } } },
        },
      },
      SealInput: {
        type: 'object',
        required: ['models', 'limits', 'environments'],
        properties: {
          models: { type: 'array', items: { type: 'object', properties: { model: { type: 'string' }, region: { type: 'string' }, max_tokens: { type: 'integer' } } } },
          tools: { type: 'array', items: { type: 'object', properties: { server: { type: 'string' }, data_scopes: { type: 'array', items: { type: 'string' } }, actions: { type: 'array' } } } },
          data_classes: { type: 'object', properties: { prompt: { type: 'array', items: { type: 'string' } }, forbidden: { type: 'array', items: { type: 'string' } } } },
          hitl: { type: 'array' },
          limits: { type: 'object', properties: { rpm: { type: 'integer' }, tokens_per_day: { type: 'integer' }, usd_per_day: { type: 'number' }, tool_calls_per_session: { type: 'integer' } } },
          environments: { type: 'array', items: { type: 'string' } },
          tags: { type: 'array', items: { type: 'string' } },
        },
      },
      LadderAction: {
        type: 'object',
        required: ['action', 'reason'],
        properties: { action: { enum: ['step_up', 'throttle', 'quarantine', 'kill', 'release'] }, scope: { enum: ['agent', 'version', 'instance'] }, version: { type: 'string' }, instance_id: { type: 'string' }, reason: { type: 'string' }, confirm_handle: { type: 'string', description: 'required for kill' }, minutes: { type: 'integer' } },
      },
    },
  },
};

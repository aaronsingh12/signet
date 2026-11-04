// OpenAPI 3.1 description of the public control API (BP 13). Served at /api/v1/openapi.json.

type Op = { summary: string; permission?: string; public?: boolean; body?: string; runner?: boolean };

const ops: Record<string, Record<string, Op>> = {
  '/connections': {
    get: { summary: 'List outbound platform connections, separate capabilities and verified coverage', permission: 'agents.read' },
    post: { summary: 'Save encrypted external connection config and credentials in Secrets Broker; requires agent_id, config and credential', permission: 'connectors.manage', body: 'ExternalConnectionInput' },
  },
  '/connections/{id}': {
    get: { summary: 'Connection config without credentials, health, capability and coverage metadata', permission: 'agents.read' },
    delete: { summary: 'Delete connection, monitoring data and brokered credentials; preserve agents and governance ledger', permission: 'connectors.manage' },
    put: { summary: 'Edit config or rotate credential; destination changes require credential resubmission', permission: 'connectors.manage', body: 'ExternalConnectionInput' },
  },
  '/connections/openapi': { post: { summary: 'Review-only suggestions from pasted OpenAPI 3.x JSON; no implicit save or remote authorization', permission: 'connectors.manage' } },
  '/connections/{id}/monitoring': { post: { summary: 'Enable or disable durable metadata polling using explicit enabled boolean', permission: 'connectors.manage' } },
  '/connections/{id}/history': { get: { summary: 'Read sanitized tests, discovery runs, mapping errors and uncertain action outcomes', permission: 'ledger.read' } },
  '/connections/{id}/webhook': { post: { summary: 'Enable, rotate or disable a signed inbound webhook secret', permission: 'connectors.manage' } },
  '/connections/{id}/agents/{agentId}/read/{operation}': { post: { summary: 'Read a configured agent, execution, logs or metrics operation for an onboarded identity', permission: 'connectors.manage' } },
  '/connections/{id}/test': { post: { summary: 'Acquire OAuth token if needed and perform configured harmless GET; redirects and private destinations forbidden', permission: 'connectors.manage' } },
  '/connections/{id}/discover': { post: { summary: 'Validate explicit response mapping and import proposed agents without certification', permission: 'connectors.manage and discovery.write' } },
  '/connections/{id}/sync': { post: { summary: 'Synchronize external metadata separately from Gateway evidence; deduplicate executions', permission: 'connectors.manage' } },
  '/connections/{id}/disconnect': { post: { summary: 'Disable requests and discard cached token; does not revoke upstream credential', permission: 'connectors.manage' } },
  '/connections/{id}/reconnect': { post: { summary: 'Re-enable disconnected connection; requires a new test to verify health', permission: 'connectors.manage' } },
  '/connections/{id}/revoke': { post: { summary: 'Permanently revoke Signet connection and erase brokered credential; revoke upstream credential at its issuer', permission: 'connectors.manage' } },
  '/connections/{id}/observations': { get: { summary: 'Read up to 200 external observations, never Gateway decisions', permission: 'ledger.read' } },
  '/connections/{id}/agents': { get: { summary: 'External-to-Signet agent mappings', permission: 'agents.read' } },
  '/connections/{id}/agents/{agentId}/actions/{action}': { post: { summary: 'Run, pause, stop or activate approved mapped agent; JSON body forwarded once, audited without payload', permission: 'connectors.manage' } },
  '/auth/login': { get: { summary: 'Start single sign-on (authorization code + PKCE)', public: true } },
  '/auth/callback': { get: { summary: 'OIDC redirect target', public: true } },
  '/auth/logout': { post: { summary: 'End the Signet session and the IdP session', public: true } },
  '/me': { get: { summary: 'The signed-in principal, roles and permissions' } },
  '/identity/jwks': { get: { summary: 'Public keys: CA (seals, bundles), workload tokens, ledger roots', public: true } },
  '/identity/token': { post: { summary: 'Exchange a one-time bootstrap credential or OAuth client credentials for an agent workload token; rate limited per address', public: true, body: 'BootstrapExchange' } },
  '/edge-runners': {
    get: { summary: 'List outbound connector runners and heartbeat status', permission: 'agents.read' },
    post: { summary: 'Enroll a private-network HTTP connector runner; returns its secret once', permission: 'connectors.manage' },
  },
  '/edge-runners/{id}/revoke': { post: { summary: 'Revoke a runner and cancel its jobs', permission: 'connectors.manage' } },
  '/edge/runners/{runnerId}/poll': { post: { summary: 'Heartbeat and claim one approved HTTP job', runner: true } },
  '/edge/runners/{runnerId}/jobs/{jobId}/lease': { get: { summary: 'Verify the job identity, seal, expiry and revocation', runner: true } },
  '/edge/runners/{runnerId}/jobs/{jobId}/result': { post: { summary: 'Complete a claimed job with result_json or error', runner: true } },
  '/identity/diagnostics': { post: { summary: 'SDK or sidecar report of the agent runtime (provider variable names, egress check); workload token', public: true } },
  '/identity/token/refresh': { post: { summary: 'Swap a valid workload token for a fresh one', public: true } },
  '/catalogue': { get: { summary: "The tenant's cloud LLM catalogue (Rulebook D-17)", permission: 'agents.read' } },
  '/catalogue/{model}/price': { put: { summary: 'Set a catalogue model price in USD per 1,000 tokens (in, out)', permission: 'tenant.admin' } },
  '/stats/command-center': { get: { summary: 'Command Center figures', permission: 'agents.read' } },
  '/stats/agents': { get: { summary: 'Per-agent status, hourly activity, outcomes, usage and costs over the last 24 hours', permission: 'agents.read' } },
  '/gateways': { get: { summary: 'Gateway nodes and their last heartbeat', permission: 'gateways.read' } },
  '/live': { get: { summary: 'Server-sent events: decisions as they happen', permission: 'ledger.read' } },
  '/agents': {
    get: { summary: 'List agents (filters tier, status, q; cursor pagination)', permission: 'agents.read' },
    post: { summary: 'Register an agent (Stage 1 Propose, simplified)', permission: 'agents.write', body: 'AgentRegistration' },
  },
  '/agents/{id}': { get: { summary: 'Agent 360: agent, team, ladder state, seal, versions, instances, events', permission: 'agents.read' }, delete: { summary: 'Permanently erase an agent and its managed data; requires confirm_handle', permission: 'agents.delete' } },
  '/agents/{id}/removal-preview': { get: { summary: 'Review the data that will be permanently removed with an agent', permission: 'agents.delete' } },
  '/agents/{id}/certificates': { post: { summary: 'Approve and sign a seal (separation of duties enforced)', permission: 'certificates.approve', body: 'SealInput' } },
  '/agents/{id}/certificate': { get: { summary: 'The active seal (JWS and body)', permission: 'agents.read' } },
  '/certificates/verify': { post: { summary: 'Verify a seal signature and current status', permission: 'agents.read' } },
  '/agents/{id}/connection': { get: { summary: 'Connection state from identity records and gateway traffic, with diagnostics', permission: 'agents.read' } },
  '/agents/{id}/gateway-test': { post: { summary: 'Check configured Signet Gateway health and return actual agent evidence; does not simulate agent calls', permission: 'agents.read' } },
  '/agents/{id}/clients': { post: { summary: 'Create environment-bound OAuth client credentials for an approved agent (secret shown once)', permission: 'identity.bootstrap', body: 'ClientEnrollment' } },
  '/clients/{id}/revoke': { post: { summary: 'Revoke an agent OAuth client and its tokens', permission: 'identity.bootstrap or ladder.quarantine' } },
  '/instances/{id}/revoke': { post: { summary: 'Revoke one instance identity and its tokens', permission: 'identity.bootstrap or ladder.quarantine' } },
  '/connect/info': { get: { summary: 'Gateway and control URLs, models and tools for connection instructions', permission: 'agents.read' } },
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
  '/discovery/sources': { get: { summary: 'Discovery sources and when each last delivered data', permission: 'discovery.read' } },
  '/discovery/logs': { post: { summary: 'Analyse a network or SaaS audit log export for traffic to AI providers', permission: 'discovery.write' } },
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
      security: op.runner ? [{ runner: [] }] : op.public ? [] : [{ oidc: [] }, { session: [] }],
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
      runner: { type: 'http', scheme: 'bearer', description: 'Scoped connector runner enrollment secret' },
    },
    schemas: {
      ExternalConnectionInput: {
        type: 'object', required: ['config'],
        properties: { agent_id: { type: ['string', 'null'], description: 'Existing tenant agent ID, or null for a REST platform connected before agent onboarding' }, credential: { type: 'string', writeOnly: true, minLength: 1, maxLength: 16000 }, config: { $ref: '#/components/schemas/ExternalConnectionConfig' } },
      },
      ExternalConnectionConfig: {
        type: 'object', required: ['name', 'method', 'base_url', 'auth', 'header', 'client_id', 'token_url', 'scopes', 'token_auth', 'timeout_ms', 'sync_interval_seconds', 'remote_management', 'endpoints', 'agents_mapping', 'executions_mapping', 'tracking_pointer', 'execution_pagination'],
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 120 }, method: { enum: ['rest', 'oauth', 'hybrid'] }, base_url: { type: 'string', format: 'uri' }, auth: { enum: ['none', 'api_key', 'api_key_query', 'bearer', 'basic', 'custom_headers', 'oauth', 'connector'] }, username: { type: 'string' }, secret_headers: { type: 'array', items: { type: 'string' } }, query_key_acknowledged: { type: 'boolean' }, monitoring_enabled: { type: 'boolean' }, tls_min_version: { enum: ['TLSv1.2', 'TLSv1.3'] }, discovery_pagination: { type: ['object', 'null'] }, header: { type: 'string' }, client_id: { type: 'string' }, token_url: { type: 'string' }, scopes: { type: 'string' }, token_auth: { enum: ['client_secret_basic', 'client_secret_post'] }, timeout_ms: { type: 'integer', minimum: 1000, maximum: 30000 }, sync_interval_seconds: { type: 'integer', minimum: 60, maximum: 86400 }, remote_management: { type: 'boolean' },
          private_connector: { type: ['object', 'null'], required: ['runner_id', 'tool_alias', 'environment'], properties: { runner_id: { type: 'string' }, tool_alias: { type: 'string' }, environment: { type: 'string' } } },
          endpoints: { type: 'object', required: ['test'], additionalProperties: { type: 'object', required: ['path', 'method'], properties: { path: { type: 'string', description: 'Relative path appended to base URL; {id} expands to encoded external agent ID. For private connections must match the registered action with this operation name.' }, method: { enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] } } } },
          agents_mapping: { $ref: '#/components/schemas/ExternalResponseMapping' }, executions_mapping: { $ref: '#/components/schemas/ExternalResponseMapping' },
          tracking_pointer: { type: 'string', description: 'JSON pointer selecting the tracked agent object; empty selects root' },
          execution_pagination: { type: ['object', 'null'], required: ['total', 'offset', 'limit'], description: 'Opt-in offset/limit pagination, up to 1000 execution records per agent per sync', properties: { total: { type: 'string' }, offset: { type: 'string' }, limit: { type: 'string' } } },
        },
      },
      ExternalResponseMapping: { type: ['object', 'null'], required: ['items', 'id', 'name', 'status', 'timestamp'], description: 'Explicit documented or observed JSON pointers. Empty items selects root array; empty optional fields are omitted. Agent and execution IDs must be stable strings.', properties: { items: { type: 'string' }, id: { type: 'string' }, name: { type: 'string' }, status: { type: 'string' }, timestamp: { type: 'string' } } },
      ClientEnrollment: { type: 'object', properties: { label: { type: 'string' }, environment: { type: 'string' } } },
      Problem: {
        type: 'object',
        properties: { type: { type: 'string' }, title: { type: 'string' }, status: { type: 'integer' }, detail: { type: 'string' }, rule: { type: 'string', description: 'Blueprint or Rulebook rule behind the refusal' }, instance: { type: 'string' } },
      },
      BootstrapExchange: { oneOf: [
        { type: 'object', required: ['bootstrap_credential'], properties: { bootstrap_credential: { type: 'string' } } },
        { type: 'object', required: ['grant_type', 'client_id', 'client_secret'], properties: { grant_type: { const: 'client_credentials' }, client_id: { type: 'string' }, client_secret: { type: 'string' } } },
      ] },
      AgentRegistration: {
        type: 'object',
        required: ['handle', 'name', 'purpose', 'sponsor', 'autonomy_level'],
        properties: {
          handle: { type: 'string', pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$' }, name: { type: 'string' }, purpose: { type: 'string' }, owner: { type: 'string' }, sponsor: { type: 'string' },
          tier: { enum: ['T1', 'T2', 'T3', 'T4'] }, autonomy_level: { enum: ['L0', 'L1', 'L2', 'L3', 'L4'] },
          connection_method: { enum: ['oauth', 'rest', 'bootstrap', 'hybrid'] },
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

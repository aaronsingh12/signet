# REST connectors

Signet connects to provider HTTP APIs independently of their implementation language. The provider must expose a documented, reachable API; a base URL and API key cannot reveal an arbitrary undocumented API contract. Mappings are explicit. OpenAPI import offers choices for review and never authorizes remote actions.

## Architecture

The React/Vite console calls the Express control API under `/api/v1/connections`. `external-connections.ts` owns connection leases, the Secrets Broker, discovery, onboarding, observations and governance gates. `external-http.ts` owns HTTPS transport and network policy. `external-contract.ts` and `external-options.ts` validate mappings, templates and responses. `external-normalize.ts` normalizes execution metadata. `external-openapi.ts` reads pasted OpenAPI specifications without fetching references.

PostgreSQL stores connection identity and ownership, encrypted credential references, external identities, observation records and operation history. Configuration and authentication material are encrypted together through the existing AES-GCM Secrets Broker; public connection responses contain configuration but no stored credential values or signing secrets. Tenant lookup precedes connection operations. The current application is one tenant per installation; it does not infer a tenant from webhook payloads.

Connection verification, credential enforcement, discovery, agent approval, monitoring and remote authorization are separate states. A test sends a real configured harmless GET, checks expected HTTP status, JSON content type, JSON parsing and any response schema. A subsequent credential-free GET proves enforcement only if rejected with 401/403. A public health endpoint can be reachable and valid while authentication remains unverified. Choose a protected read endpoint to verify credentials, or explicitly choose no authentication. Private connector requests use the Gateway's scoped workload authentication instead.

## Local setup and deployment

Use Node 22.13 or newer and the repository's existing PostgreSQL setup. Run `npm ci`, `npm run dev`, `npm run typecheck`, `npm test`, and `npm run build`. There is no repository lint script.

`DATABASE_URL` is required. Local development generates development keys under the configured data directory. Production must retain `SIGNET_BROKER_KEY`, `SIGNET_INTERNAL_TOKEN`, `SIGNET_VAULT_KEY` and `SIGNET_SIGNING_KEYS` across instances. The broker/vault keys are base64url key material; signing keys use the existing configured CA, token and ledger key format in `apps/control/src/keys.ts`. Never commit these values. Set public control/Gateway URLs using `SIGNET_CONTROL_PUBLIC_URL` and `SIGNET_GATEWAY_PUBLIC_URL`. Private connector calls additionally need `SIGNET_GATEWAY_URL`. An optional comma-separated `SIGNET_CONNECTOR_HOST_ALLOWLIST` restricts public REST egress to exact hostnames, including an OAuth issuer when used.

The existing idempotent schema initializer in `schema.ts` performs migrations at control-plane startup. Connector additions create `external_operation_run` and `external_webhook_nonce`, add normalized/presence fields to `external_agent_mapping`, and add update time, sync failures and webhook references to `external_connection`. Existing identities and approval records remain intact. Deploy control, Gateway, web and maintenance artifacts from the same revision after backing up PostgreSQL. Production migrations require table ownership/ALTER permission.

`npm run build` bundles Ajv and formats into the control service. Docker images install the patched Express 4 release pinned in the repository. No additional worker framework or external queue is needed. Local control processes invoke maintenance; Vercel must run the existing `maintenance` daemon in `vercel.json`. The daemon calls the authenticated internal connections maintenance route every 30 seconds with a ten-minute request budget. A PostgreSQL lease serializes each connection across replicas; each tick processes one due connection. Failed synchronization backs off exponentially up to one hour. Operation history is retained for 90 days; replay nonces for ten minutes. Signed governance ledger records follow the existing ledger retention policy.

## Connect and onboard

1. Open **New agent → REST API** or an existing REST connection. Enter the provider base URL and credential. A standalone platform does not require a placeholder agent.
2. Open **API settings and endpoint mapping**. Enter a connection name, authentication strategy and a harmless test endpoint. Configure only operations your provider exposes.
3. Optionally paste OpenAPI 3.0/3.1 JSON, click **Read API specification**, and assign documented operations to Signet logical operations. Review path variables, authentication, extraction and fields before saving. Remote references and automatic remote-management authorization are not supported.
4. Configure agent extraction and field pointers. **Save connection / mappings** persists configuration without claiming a live connection. **Test connection & find agents** makes real requests and previews agents without approving them.
5. Click an individual **Onboard** button, or explicitly use **Discover & import agents** to register all valid returned identities. Repeated imports match connection ID and external ID. Complete purpose/intake, classification, assessment, tests and approvals in the existing lifecycle.
6. Configure tracking/execution mappings before enabling monitoring. **Refresh activity** synchronizes real provider metadata. Unsupported or absent measurements remain unavailable, never zero-filled or fabricated.
7. For remote control, register the matching HTTP tool action and include it in the mapped agent's valid seal. Enable remote management, verify the connection and credential enforcement, then explicitly confirm the action. Policy is evaluated on the mapped outgoing body and configured query arguments. A timeout or invalid mutation response can mean the provider acted: inspect provider state and the recorded uncertain outcome before retrying.

## Authentication

- `none`: explicitly unauthenticated; the UI reports authentication not required.
- `api_key`: one secret value sent in the configured header.
- `bearer`: one token; Signet adds the `Bearer` prefix.
- `basic`: configure `username`, put only the password in the secret field. HTTPS is mandatory.
- `api_key_query`: configure the query parameter name and acknowledge `query_key_acknowledged`. The key is injected server-side, never stored in a configured URL. Provider/intermediary URL logs remain a risk.
- `custom_headers`: configure up to ten header names. The secret field contains a JSON object mapping those names to secret string values. The entire object is encrypted; header names and values are validated.
- `oauth`: client credentials only. Configure client ID, HTTPS token URL, scopes and `client_secret_basic` or `client_secret_post`. The secret field is the client secret. Tokens are encrypted and cached until near expiration; rejection invalidates the cache. Other OAuth grants are unsupported.

Editing with an empty credential retains the current secret. Changing its destination or authentication settings requires credential resubmission. Disabling stops requests and clears cached tokens; revocation additionally erases the saved credential. Delete removes the connection, its encrypted credentials, external observations and operation history, while registered agents and the signed governance ledger remain.

## Mapping contract

Logical operations are `test`, `discover`, `agent`, `track`, `executions`, `execution`, `logs`, `metrics`, `run`, `pause`, `stop`, and `activate`. Only successful operations appear as verified capabilities; configuration alone is not operational proof. `test` must be a harmless GET. Other mappings may use configured GET/POST/PUT/PATCH/DELETE methods; mutation operations are never automatically retried, including mutations implemented by a provider using GET.

Paths append to the configured base URL, including its prefix. `{id}` and `{agent_id}` mean the encoded external agent ID. Other names require an explicit `variables` alias to `id` or `execution_id`. Execution-detail reads supply `execution_id`. `query` maps query names to string templates. `request_body` is a JSON template; exact argument substitutions preserve JSON types, while embedded substitutions are strings. Credentials belong in authentication, never in path/body templates.

`expected_status` is an optional list of successful HTTP status codes. `response_schema` is bounded strict Draft 7 JSON Schema, with local references and supported standard formats. Regex keywords, asynchronous validation and external references are rejected. `response_path` optionally extracts a value before field mapping. Response field mappings use **JSON Pointer only**: `/data/items`, `/uuid`, and escaped `~0`/`~1` segments. JSONPath, filters and executable expressions are unsupported.

Agent and execution mappings require `items`, `id`, `name`, `status`, and `timestamp`. Empty `items` selects a root array; optional empty field pointers are omitted. IDs may be strings or non-negative safe integers, normalized to strings. Optional `fields` selects bounded metadata by explicit name/pointer; trusted platform fields and credential fields cannot be overwritten. Description, framework, provider and capabilities can be selected there. Unknown provider values are not automatically retained because they may contain prompts or secrets.

Discovery and execution pagination use explicit `total`, `offset` and `limit` response pointers and send offset/limit query parameters. Each read is capped at 1000 records. Valid rows are retained with per-record mapping errors in history; partial responses never cause missing-state updates. A complete successful discovery marks absent known identities `missing` and never deletes them. Incoming provider metadata does not change approved risk classifications or seals.

### Complete generic example

This is an illustrative contract, not a production preset. The sample API returns `{"ok":true}` from `/status`, `{"data":{"items":[{"uuid":"bot-1","title":"Support","state":"active"}]}}` from `/v2/bots`, and execution metadata under `events`.

```json
{
  "agent_id": null,
  "credential": "<provider-issued-token>",
  "config": {
    "name": "My provider",
    "provider_type": "generic_rest",
    "method": "rest",
    "private_connector": null,
    "base_url": "https://api.your-provider.example",
    "auth": "bearer",
    "header": "",
    "client_id": "",
    "token_url": "",
    "scopes": "",
    "token_auth": "client_secret_basic",
    "timeout_ms": 10000,
    "sync_interval_seconds": 300,
    "monitoring_enabled": false,
    "remote_management": false,
    "tls_min_version": "TLSv1.2",
    "endpoints": {
      "test": {"method":"GET","path":"/status","expected_status":[200],"response_schema":{"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}}}},
      "discover": {"method":"GET","path":"/v2/bots"},
      "executions": {"method":"GET","path":"/v2/bots/{botId}/events","variables":{"botId":"id"}},
      "run": {"method":"POST","path":"/v2/bots/{botId}/execute","variables":{"botId":"id"},"request_body":{"instruction":"{instruction}"},"expected_status":[200],"idempotency_header":"idempotency-key"}
    },
    "agents_mapping": {"items":"/data/items","id":"/uuid","name":"/title","status":"/state","timestamp":""},
    "executions_mapping": {"items":"/events","id":"/event_id","name":"","status":"/state","timestamp":"/recorded_at","fields":{"started_at":"/started","completed_at":"/finished","duration_ms":"/elapsed_ms","metrics":"/metrics"}},
    "tracking_pointer": "",
    "execution_pagination": null,
    "discovery_pagination": null
  }
}
```

Save with `POST /api/v1/connections`, test with `POST /connections/{id}/test`, discover with `POST /connections/{id}/discover`, and inspect `GET /connections/{id}/agents` and `/history`. All API paths except the signed webhook endpoint require the existing console session or authorized principal. The complete public prefix is `/api/v1`.

Remote action requests use `{"payload":{"instruction":"..."},"confirmation":"run:<internal-agent-id>","idempotency_key":"<stable-retry-key>"}`. Reuse a supplied idempotency key only when retrying the same intent and the provider documents idempotency support. Signet sends it only when an idempotency header is configured. It does not claim exactly-once execution or silently replay writes.

## Signed webhooks

Enable in connection controls with a 32-1000 character signing secret, a JSON Pointer selecting the external agent ID and `execution` or `tracking` event kind. Map the payload using the corresponding explicit response mapping. Only already onboarded identities are accepted. Provider-specific webhook protocols require an adapter; arbitrary signatures are not accepted as verified.

POST exact JSON bytes to the returned `/api/v1/connection-webhooks/{id}` endpoint. Supply `x-signet-timestamp` as Unix seconds, `x-signet-event-id` as an 8-100 character URL-safe unique ID, and `x-signet-signature` as `sha256=<hex HMAC-SHA256(secret, timestamp + "." + eventId + "." + rawBody)>`. Timestamp tolerance is five minutes, bodies are capped at 64 KiB, comparison is timing-safe and successful event IDs are persisted for replay rejection. Observation writes and nonce insertion are atomic. Ensure hosting authentication/protection permits this signed route to be reached by the provider; no session bypass is granted to ordinary connection APIs.

## Security and limits

Public outbound connections require HTTPS on port 443 with certificate verification and TLS 1.2 or 1.3. URL userinfo, fragments, unsafe headers, traversal, unsafe redirects, loopback, private, reserved, multicast and link-local addresses are blocked. DNS is validated at registration/request checks and again at socket lookup. An optional exact-host allowlist further restricts egress. Private HTTP agents use the separately enrolled outbound runner and approved tools; public SSRF rules are never weakened.

HTTP responses are capped at 1 MiB, request bodies at 16 KiB, URLs at 20000 characters, per-record selected metadata at 8 KiB and schemas at 16 KiB with bounded nesting. There are eight simultaneous public HTTP requests per process and 60 logical operations per connection per minute, plus serialized connection leases. Safe GETs retry at most three times with exponential backoff, jitter and bounded Retry-After. Each sync handles at most 25 onboarded agents and has a four-minute read budget plus any in-flight bounded HTTP attempt. Discovery is manual; polling never silently onboards new agents.

Provider responses returned by read/action APIs are bounded and redact credential fields and known credential values. They are not raw trace exports. Operation history stores categories, timing, counts, correlation IDs and row-error indexes, not request/response payloads. Metadata mappings require administrator review. TLS CA overrides, mTLS, unbounded pagination, arbitrary proxies, authorization-code OAuth and JSONPath evaluation are not implemented.

## Verification scope

Automated tests use isolated PostgreSQL schemas, mocked provider HTTP servers, a real Express control server and real Gateway/private-runner processes. Provider fixtures cover different paths and JSON shapes, authentication, pagination, partial failures, missing identities, encryption/redaction, action authorization, signature replay protection and socket-time DNS checks. These tests do not establish that a live vendor account works. Validate actual credentials, schema, public/private network reachability, upstream permissions, webhook delivery and remote actions against a non-production provider scope before deployment.

## Implementation file map

- [.env.example](../.env.example)
- [Dockerfile](../Dockerfile)
- [Dockerfile.gateway](../Dockerfile.gateway)
- [Dockerfile.vercel](../Dockerfile.vercel)
- [apps/control/package.json](../apps/control/package.json)
- [apps/control/src/agent-removal.ts](../apps/control/src/agent-removal.ts)
- [apps/control/src/external-connections.ts](../apps/control/src/external-connections.ts)
- [apps/control/src/external-contract.ts](../apps/control/src/external-contract.ts)
- [apps/control/src/external-http.ts](../apps/control/src/external-http.ts)
- [apps/control/src/external-normalize.ts](../apps/control/src/external-normalize.ts)
- [apps/control/src/external-openapi.ts](../apps/control/src/external-openapi.ts)
- [apps/control/src/external-options.ts](../apps/control/src/external-options.ts)
- [apps/control/src/index.ts](../apps/control/src/index.ts)
- [apps/control/src/maintenance.ts](../apps/control/src/maintenance.ts)
- [apps/control/src/openapi.ts](../apps/control/src/openapi.ts)
- [apps/control/src/schema.ts](../apps/control/src/schema.ts)
- [apps/control/test/connection.test.ts](../apps/control/test/connection.test.ts)
- [apps/control/test/external-connections.test.ts](../apps/control/test/external-connections.test.ts)
- [apps/control/test/rest-engine.test.ts](../apps/control/test/rest-engine.test.ts)
- [apps/control/test/support-platform.test.ts](../apps/control/test/support-platform.test.ts)
- [apps/e2e/package.json](../apps/e2e/package.json)
- [apps/gateway/package.json](../apps/gateway/package.json)
- [apps/web/src/components/ConnectorMappingEditor.tsx](../apps/web/src/components/ConnectorMappingEditor.tsx)
- [apps/web/src/components/ConnectorOperations.tsx](../apps/web/src/components/ConnectorOperations.tsx)
- [apps/web/src/components/ExternalConnections.tsx](../apps/web/src/components/ExternalConnections.tsx)
- [apps/web/src/components/RestConnectionWizard.tsx](../apps/web/src/components/RestConnectionWizard.tsx)
- [docs/rest-connectors.md](../docs/rest-connectors.md)
- [package-lock.json](../package-lock.json)
- [package.json](../package.json)
- [packages/core/src/connections.ts](../packages/core/src/connections.ts)
- [packages/core/src/netguard.ts](../packages/core/src/netguard.ts)
- [packages/core/src/types.ts](../packages/core/src/types.ts)
- [packages/core/test/netguard.test.ts](../packages/core/test/netguard.test.ts)

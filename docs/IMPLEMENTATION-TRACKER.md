# Real data and agent connectivity: implementation tracker

Status words: **implemented** (code exists), **tested** (automated test passes), **verified** (ran end to
end against real services), **awaiting external setup** (needs credentials or infrastructure we do not have).

## Audit (start of this work)

Already real before this work:
- Registry, lifecycle, approvals, ledger (hash chain, daily roots), kill and quarantine pushed to every gateway node.
- Bootstrap credential (stored as SHA-256, single use, 15 min) → signed workload token; refresh; revocation list in the policy bundle.
- Secrets Broker (AES-256-GCM, write-only API, gateway-only reads) for tool credentials.
- Gateway: OpenAI-compatible model proxy, MCP proxy, HTTP tool proxy, all forwarding to real upstreams.
- Command Center figures are SQL over the ledger; gateway health is from real heartbeats.
- Control library and detector registry are reference catalogues (not activity data).

Demo leakage and gaps found:

| # | Finding | Fix |
|---|---|---|
| A1 | `npm run dev` always started `apps/mock-tools`; demo scripts wrote fixture agents into the dev database | Mock tools moved to test fixtures; demos become an isolated e2e suite with its own data dir and ports |
| A2 | Demo secrets (`SIGNET_DEMO_*`) in `packages/core` dev secrets | Removed from core; fixtures get their key from the test harness |
| A3 | Live Traffic empty state told users to run the demo | Points to agent connection instead |
| A4 | Cloud LLM key read from an env var, not the Secrets Broker | Gateway takes the `llm_provider` secret from the broker; env only as a labelled dev fallback |
| A5 | No check that the cloud LLM is reachable | Gateway probes the provider; status shown as verified/unreachable/not configured |
| A6 | Workload tokens had no `iss`/`aud`; gateway did not check them | Added and enforced |
| A7 | HTTP tool path parameters could contain `..`; no private/metadata address checks (SSRF) | Destination checks at registration and per call, DNS-resolved |
| A8 | `/identity/token` not rate limited | Per-IP limit |
| A9 | No agent type, runtime, framework, vendor fields; no third-party agents | Added to registry and lifecycle |
| A10 | No connection status (registered ≠ connected) | Derived from identity and gateway records |
| A11 | No SDK or sidecar | Python SDK, Node sidecar (Docker) |
| A12 | No bypass detection | SDK diagnostics report provider keys/URLs in the runtime → Discovery findings (detected, not enforced) |
| A13 | Discovery only from Key Sweep | Network/SaaS log ingestion against a catalogue of AI provider domains; source status |

## Work items (state at 2026-11-02)

| Item | State | Evidence |
| --- | --- | --- |
| A1 Demo out of the runtime | implemented, verified | `npm run dev` starts control, 2 gateways, console only; fixtures live in apps/e2e; dev data reset (old demo data kept in a backup, not in data/) |
| A2 Demo secrets out of core | implemented, tested | DEV_SECRETS has internal, vault and broker keys only |
| A3 Empty states | implemented | Live Traffic, Discovery, Registry show real empty states |
| A4 LLM key from the Secrets Broker | implemented, verified | bundle carries the llm_provider secret; probe reports its source |
| A5 Provider reachability | implemented, verified | gateways log "cloud LLM check: ok"; Command Center shows state and check time |
| A6 Token iss/aud | implemented, tested, verified | e2e scenario 2: wrong audience refused |
| A7 SSRF / path escape / size cap | implemented, tested, verified | core netguard tests; e2e scenario 4 (metadata URL 422, `..` refused) |
| A8 Token endpoint rate limit | implemented | 30 per minute per address; not load-tested |
| A9 Agent types, third-party | implemented, verified | e2e scenario 6 |
| A10 Connection status | implemented, verified | e2e scenarios 1, 2, 5, 6 assert each state transition |
| A11 Python SDK | implemented, tested, verified | 8 offline tests; e2e scenarios 1, 3, 4, 7 run the SDK against a live stack and gpt-oss |
| A11 Sidecar | implemented, verified | e2e: model and MCP call through the sidecar with a fake framework key; Docker target builds as a bundle (image not built here) |
| A12 Bypass detection | implemented, verified | e2e scenario 7: names reported, values never sent, Discovery finding marked detected-not-enforced |
| A13 Log-based discovery | implemented, verified | e2e scenario 7: 5 records, 3 AI matches, gateway egress skipped |
| Console: Propose type, Connection tab, Discovery, Command Center | implemented, type-checked, builds | not yet clicked through in a browser |
| Docs | implemented | docs/connect-agents.md, docs/egress.md, sdk/python/README.md, .env.example, OpenAPI |

## Awaiting external setup

- Signet behind real hostnames (SIGNET_GATEWAY_PUBLIC_URL / SIGNET_CONTROL_PUBLIC_URL, TLS) so agents on RunPod or EC2 can reach it. Until then only local agents can connect.
- A real ServiceNow instance for the connector (verified only against the e2e stand-in).
- Vendor platforms (Copilot Studio, Agentforce, ...): the OAuth client-credentials path is verified with a standard OAuth request; no vendor tenant was available to configure a real connector.
- SaaS admin API connectors and proxy log streaming for Discovery: not built; exports are uploaded.
- Network egress enforcement: by design outside Signet (docs/egress.md); RunPod offers no egress firewall.
- Node SDK as a published package: the token manager exists (apps/sidecar/src/tokens.ts); not packaged.
- Streaming responses: the gateway returns the checked answer whole (DLP needs it); true token streaming is not built.

## Phases A–C (2026-11-03)

| Item | State | Evidence |
| --- | --- | --- |
| Single-administrator mode restored (lost in the PostgreSQL merge) | implemented, tested | workflow test: one admin confirms a T2 tier and one approval fills owner, security and risk; ledger marks `waived_single_operator` |
| Local PostgreSQL without TLS | implemented, tested | only `localhost` with `sslmode=disable`; remote hosts always `verify-full` |
| A1 deployment credential as API key | implemented, tested | connection test: `sdc_…` in `Authorization` or `api-key` reaches a tool through a live gateway; forged key 401 |
| A2 `GET /v1/models` | implemented, tested | returns the tenant's one model |
| A3 Vercel connector (projects, AI detection, set env, remove old key, redeploy) | implemented, tested against a stand-in | platforms test; not yet run against a real Vercel account |
| A5 console: Connections → platform → workload → Connect | implemented, type-checked, builds | not clicked through in a browser |
| B1–B3 AWS (Bedrock agents, Lambda connect), Azure (OpenAI, AI Foundry, App Service connect), Google (Vertex agents, Cloud Run) | implemented, tested against stand-ins | SigV4 signer matches AWS's published example; Google JWT signed with a real RSA key |
| B4 Copilot Studio (Dataverse `bots`) | implemented, tested against a stand-in | |
| B5 OpenAI and Anthropic organisations (projects, keys, owners) | implemented, tested against a stand-in | |
| B6 Discovery: scan → findings; one-click register as agent | implemented, tested | platform AI (Bedrock, Copilot, Vertex) registers as third-party |
| C1 usage outside Signet (OpenAI, Anthropic usage APIs) | implemented, tested against a stand-in | AWS/Azure/Google usage (CloudWatch, Monitor) not built |
| C2 stop on platform (Vercel pause, Lambda concurrency 0, App Service stop, key delete/deactivate); automatic on kill | implemented, tested | |
| C3 cost and activity per agent (30 days) + outside usage | implemented, tested | `/stats/costs`, Command Center card |
| C4 quality: sampled LLM-judge scores | implemented, type-checked | off by default (`SIGNET_EVAL_SAMPLE_RATE`); not run against the live model |
| D: ServiceNow agents into AICT tables | implemented, type-checked | used when the self-test finds AICT; not run against a real instance |

Awaiting setup: `SIGNET_GATEWAY_PUBLIC_URL` on the deployed Signet; real platform credentials (Vercel token, AWS keys, Azure app, Google service account) for live checks; Cloud Run connect; scheduled usage sync (manual button today); e2e suites still target the pre-PostgreSQL stack.

## Remaining items closed (2026-11-03)

| Item | State | Evidence |
| --- | --- | --- |
| Google Cloud Run connect (template read, only Signet's variables changed, new revision followed) | implemented, tested against a stand-in | platforms test |
| Usage outside Signet: AWS CloudWatch (Bedrock per model), Azure Monitor (OpenAI/AI Services per account), Google Cloud Monitoring (Vertex per model) | implemented, tested against stand-ins | platforms test |
| Scheduled usage sync (every 6 h, last 3 days; failures marked on the connection) | implemented, tested | local timer and Vercel maintenance job `platform-usage` |
| C4 quality scoring against the live model | verified | e2e connectivity: gpt-oss judged a real answer (helpful 5, safe 5, on-policy 5) and the scores reached the ledger |
| E2E suites on PostgreSQL (own schema per suite, dropped after) | verified | connectivity, gate-phase1, gate-phase2 all pass |
| Fix: background jobs raced the control catalogue on a fresh database (foreign key error) | fixed | found by the e2e run |

Running the e2e suites needs: `E2E_DATABASE_URL`, the Keycloak dev realm with test users, and `SIGNET_DEMO_OWNER_ID`, `SIGNET_DEMO_SECURITY_ID`, `SIGNET_DEMO_RISK_ID`, `SIGNET_DEMO_PLATFORM_ID`, `SIGNET_DEMO_PASSWORD`, `SIGNET_AUTOMATION_CLIENT_SECRET` (kept out of git on purpose).

Still needing real accounts (code is done, only live confirmation is missing): Vercel token, AWS keys, Azure app registration, Google service account, Copilot Studio environment, OpenAI/Anthropic admin keys, a ServiceNow instance with AI Control Tower.

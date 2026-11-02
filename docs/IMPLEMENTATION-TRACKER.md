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

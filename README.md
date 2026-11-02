# Signet

Independent AI agent governance: nothing acts without Signet's seal, and everything is provable.
Built from the Signet Product & Engineering Blueprint, the Decision Architecture doc (revision 2) and
Signet Rulebook v0.2. All governed agents use **one cloud LLM** (Rulebook D-17): `gpt-oss:120b-cloud`.

This repository holds Phases 0-2 of the Blueprint build plan plus agent connectivity (SDK, sidecar,
third-party agents). Signet runs on real data only: there is no demo mode, no seed activity and no
sample agents. Test fixtures exist only inside the isolated e2e suite. "Status" below lists exactly
what is built, verified, and not built yet; [docs/IMPLEMENTATION-TRACKER.md](docs/IMPLEMENTATION-TRACKER.md)
has the detail.

## Run it

Requirements: Node 22.13+ (uses the built-in `node:sqlite`), Docker (for the identity provider), and
Ollama signed in with access to `gpt-oss:120b-cloud`.

The DET-INJ detector model (about 700 MB, Apache-2.0) is not in git. Download it once; without it the
gateway runs and reports the detector as unavailable:

```bash
mkdir -p models/deberta-injection/onnx && cd models/deberta-injection
B=https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main
for f in config.json tokenizer.json tokenizer_config.json special_tokens_map.json; do curl -sSLO $B/$f; done
curl -sSL -o onnx/model.onnx $B/onnx/model.onnx && cd ../..
```

```bash
npm install
npm run up          # Keycloak identity provider (dev realm) on :8180
npm run dev         # control plane :4100, gateways gw-a1 :8100 and gw-a2 :8101, console :5174
npm run chat -- <agent-handle>   # talk to the cloud LLM as one of your sealed agents, through the gateway
npm run sidecar     # the Signet sidecar for agents that cannot use the SDK (see docs/connect-agents.md)
npm run test:e2e    # e2e suites on an isolated stack (own data dir and ports): connectivity, gate-phase1, gate-phase2
npm run test:sdk    # Python SDK unit tests (needs uv)
npm run verify      # export a .sep evidence package and verify it offline
npm run perf        # gateway latency test (separate node, fast test model)
npm test            # unit, conformance and evidence tests
npm run typecheck
npm run build       # bundled services in dist/ and the console in dist/web
```

Open http://localhost:5174 and sign in through Keycloak. Dev accounts (password `Signet!2026`):

| Account | Role |
| --- | --- |
| jonas.weber | Security Officer (approves seals, kills, circuit breakers, detector promotion) |
| ananya.rao | Risk & Compliance Officer |
| priya.menon | Agent Owner |
| ravi.kapoor | AI Governance Board |
| arjun.mehta | Platform Admin + Builder (tools, Secrets Broker) |
| elena.rossi | Tenant Admin |
| marta.silva | Approver (runtime approvals) |
| lena.vogt | Auditor (read-only) |

To connect a real agent: propose it in the console, take it through approval, then follow its
*Connection* tab (Python SDK, sidecar, or OAuth client credentials for vendor-hosted agents). Guides:
[docs/connect-agents.md](docs/connect-agents.md), [docs/egress.md](docs/egress.md).

Machine clients use OAuth client credentials (`signet-automation`), as CI/CD would. Dev secrets and signing
keys are generated on first start under `data/` (git-ignored); delete `data/` to start again. Optional:
`npm run keysweep -- <dir> --upload` finds credentials in code and files them in the Discovery Inbox.

## Layout

| Path | What it is |
| --- | --- |
| `packages/core` | IDs (ULID), canonical JSON (RFC 8785), Ed25519 JWS, AES-256-GCM, hash-chained ledger, RFC 9162 Merkle trees, pattern DLP, decision combiner, OIDC JWT verification, keep-alive HTTP |
| `apps/control` | Control plane: OIDC sign-in and RBAC, registry, policy compiler and seal signing, workload identity and instances, signed policy bundles with push, response ladder and circuit breaker, Secrets Broker, tool registry, Discovery, detector registry, append-only ledger, daily roots, WORM store, evidence packages, OpenAPI |
| `apps/gateway` | Enforcement point: BP 5.2 pipeline for model calls and tool calls (MCP proxy, HTTP proxy), single cloud-LLM adapter, policy engine, tokenisation vault, detector runtime, session taint, outage handling, group-commit ledger client |
| `apps/web` | Console (React, Vite, Tailwind) following the Console UI & UX design |
| `apps/cli` | `signet-verify` (offline evidence verification), `signet keysweep`, `chat` |
| `apps/sidecar` | Signet sidecar: holds an agent's workload identity and forwards `/v1/*` to the gateway (Docker target `sidecar`) |
| `sdk/python` | Python SDK `signet-sdk`: identity and refresh, OpenAI client, MCP and HTTP tools, diagnostics, `signet-doctor` |
| `apps/e2e` | E2E suites on an isolated stack, test-only fixture tools (MCP, HTTP, ServiceNow stand-in, fast model), latency test |
| `policy/` | `signet.rego` (gateway decision policy), shared conformance cases, OPA tests |
| `infra/keycloak` | Dev realm: users, groups, OIDC clients |
| `docs/` | Evidence Package format, connecting agents, egress, implementation tracker |

## Status

### Phase 0, foundations
| Item | Status |
| --- | --- |
| Monorepo, typed build, bundled services | Done (`npm run build`) |
| CI with security scanning | Workflow written (`.github/workflows/ci.yml`: typecheck, tests, `npm audit`, gitleaks, OPA tests and WASM build, CycloneDX SBOM, cosign-signed images). Not yet run: the repo has no remote |
| IaC for dev/test | Docker Compose (Keycloak; `--profile full` for containerised services) and a multi-target Dockerfile |
| Tenancy skeleton | Every tenant table carries `tenant_id`; one tenant per install until the SaaS cells (Phase 4) |
| OIDC login | Done: authorization code + PKCE + state + nonce against Keycloak; HttpOnly session (30 min idle, 12 h absolute); IdP logout; bearer tokens for machine clients |
| RBAC framework | Done: 11 roles, 22 permissions, IdP group → role mapping, owner-scoped actions |
| API conventions | Done: RFC 9457 problem details citing the rule, Idempotency-Key, cursor pagination, OpenAPI 3.1 at `/api/v1/openapi.json` |
| Design system | Done: console tokens and components from the Console UI & UX design |
| Aegis code review | Not applicable: no Aegis code was provided; the DLP engine was written fresh |

### Phase 1, core enforcement loop
| Item | Status |
| --- | --- |
| Identity, Agent ID, workload tokens, revocation push | Done: single-use bootstrap → EdDSA tokens (10/30 min), instances, token revocation on quarantine/kill |
| Gateway: LLM proxy | Done: OpenAI-compatible, the one cloud LLM only (other providers refused and counted) |
| Gateway: MCP proxy, HTTP tool proxy | Done: manifest default-deny, tools/list filtered to the seal, argument constraints, impact labels |
| Credential injection, keyless agents | Done: Secrets Broker (AES-256-GCM, write-only API), tool credentials injected per call; Key Sweep CLI and Discovery Inbox |
| DLP and tokenisation | Done: secrets, cards (Luhn), IBAN (mod 97), email, phone; data-class matrix for prompts, tool arguments and responses; vault scoped to agent and session |
| Policy compilation and evaluation | Done: seals compile to a policy whose hash the seal carries; gateways verify it. Rules in `policy/signet.rego`; 20 conformance cases. **The gateway currently evaluates with the TypeScript mirror**: compiling Rego to WASM needs the OPA binary, which this machine's permissions blocked; CI compiles it and the gateway then loads it in-process |
| Ledger, WORM, daily roots, verify CLI | Done: hash chain, append-only tables, group commit, signed daily Merkle roots written once, inclusion proofs, `.sep` packages, `signet-verify` |
| Response ladder and kill | Done: step-up, throttle, quarantine, kill at agent, version or instance scope; circuit breaker; kill pushed to every node with acknowledgements; in-flight calls cut; 5 s poll fallback |
| Enforcement Center screen | Done, with registry, Agent 360, Live Traffic, Ledger Explorer, Discovery, tools, policies, tenant |
| Simplified approve-and-certify | Replaced in Phase 2 by the lifecycle and approval matrix |
| Decision combiner (E37) | Done: rules decide, detectors only add caution, fail-safe for T1/T2 |
| Detector runtime and DET-INJ (E38/E39) | Done: isolated process under Node's permission model; DeBERTa-v3 prompt-injection model (Apache-2.0). Off the critical path, because it takes 70-200 ms on CPU against a 15 ms budget; privileged actions wait for pending verdicts |
| Outage handling (E42) | Done: structured `upstream_unavailable`, no strikes, outage declaration recorded |

### Phase 2, lifecycle and approvals
| Item | Status |
| --- | --- |
| 8-stage lifecycle | Done: Propose (intake, templates) → Classify (weighted score, RB-INV-14 floor, EU AI Act category) → Assess (questionnaire, threat model, impact, DPIA, vendor risk by tier; gaps; risk acceptance) → Test (tool misuse, argument constraints, data leakage, HITL, functional, bias, red team) → Approve → Deploy (shadow → canary → enforce) → Monitor (attestation, change requests) → Retire |
| Approvals engine | Done: approval matrix per tier (T3 Owner + Security, T2 + Risk, T1 + Board quorum 2), slots, separation of duties at classification and approval, step-up within 5 min for T1/T2, SLA escalation, delegation, decisions signed over the pack hash |
| Runtime HITL | Done: sync hold (up to 120 s, SSE wake-up) or async 202 + single-use resubmission; approve for session (8 h); reject with quarantine; timeout = reject (RB-INV-11) |
| Shadow and canary | Done: shadow records would_block and lets calls through (kill rules, secret exfiltration and the one-LLM rule always enforced); canary enforces a stable 10% of sessions; would-blocks reviewed before moving on |
| Control library | Done: ~40 Signet Controls mapped to NIST AI RMF, OWASP LLM Top 10, EU AI Act, ISO/IEC 42001; automated controls evaluated every 10 min; framework scores |
| ServiceNow connector | Done against the stand-in: OAuth, self-test, outbox with backoff and dead letters, risks, CIs (IRE), control tests, indicator results, issues, incidents; authority documents pulled into the library. Not yet run against a real instance |
| Console | My Approvals (with step-up re-sign-in), phone approval page, Lifecycle tab on Agent 360, Propose with templates and intake, Control Library & Compliance, Connectors, notifications |

### Agent connectivity and real data
| Item | Status |
| --- | --- |
| No demo data in the runtime | Done: mock tools and demo scripts moved into the isolated e2e suite; demo secrets removed from core; hardcoded "100% keyless" figures replaced by evidence-based counts |
| Agent types | Done: self-hosted, framework, no-code, third-party (vendor, contract, residency); third-party seals list tools only, never a model |
| Workload identity | Done: hashed one-time bootstrap credential; EdDSA tokens with issuer and audience checked at the gateway; refresh; per-instance revocation; OAuth client credentials for vendor platforms; per-address rate limit on token requests |
| Cloud LLM | Done: key from the Secrets Broker (env only as a labelled dev fallback); every gateway checks the provider each minute and the console shows the result |
| Tool calls | Done: SSRF checks at registration and on every connection (no metadata or link-local; private only when allowed), dot-segment and path-escape checks, 5 MB response cap |
| Connection state | Done: pending approval, credentials not provisioned, not connected, connected, connection error, suspended, revoked; from identity records and gateway traffic only |
| Python SDK, sidecar | Done: verified end to end against the real gateway and gpt-oss (`npm run test:e2e -- connectivity`) |
| Bypass detection | Done: SDK reports provider variable names and egress reachability; network/SaaS log upload finds direct AI traffic. Detection only: Signet does not enforce network egress |
| Console | Agent type on Propose; Connection tab (state, credentials shown once, instances and revocation, diagnostics, instructions, model and tool activity); connection column in the registry; Discovery sources and log upload; cloud LLM status |

### Measured
- Gate demo: kill acknowledged by both gateway nodes in 17-33 ms; hijack after a poisoned document quarantines the agent; tampering with one record in an export is caught and located.
- Gateway pipeline latency (excluding upstream), 16 concurrent clients: model calls p50 2.1 / p95 4.1 / p99 8.1 ms; tool calls p50 1.5 / p95 2.6 ms. Budget is p95 50 ms.
- End-to-end throughput on one laptop running every component: about 180-260 req/s. The Blueprint asks 2,000 req/s per 4-vCPU node; that needs the production profile (one process per core, Postgres, sharded ledger writers).

### Not built yet (later phases)
- With DET-JB and DET-PII not deployed, **every T1/T2 model call is held for a person** (RB-INV-06), which is the correct fail-safe; "approve for session" keeps a conversation usable.
- DET-JB and DET-PII models; a faster DET-INJ that fits the 15 ms budget (E39); detector benchmarks and release process (E40).
- Seal Transparency Log, Regulator Portal (Phase 3); SaaS, Hybrid, air-gapped, licensing (Phase 4).
- Postgres profile, RFC 3161 timestamps, live stream scanning (streaming clients get the checked answer as chunks), MFA enforcement in the dev realm (supported by setting `SIGNET_REQUIRE_MFA=true`).

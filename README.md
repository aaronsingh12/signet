# Signet

Independent AI agent governance: nothing acts without Signet's seal, and everything is provable.
Built from the Signet Product & Engineering Blueprint, the Decision Architecture doc (revision 2) and
Signet Rulebook v0.2. All governed agents use **one cloud LLM** (Rulebook D-17): `gpt-oss:120b-cloud`.

This repository holds **Phase 0 (foundations) and Phase 1 (core enforcement loop)** of the Blueprint build
plan. "Status" below lists exactly what is built, measured, and not built yet.

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
npm run dev         # control plane :4100, gateways gw-a1 :8100 and gw-a2 :8101, mock tools :7100, console :5174
npm run demo        # Phase 1 gate demo against the real model, tools and both gateway nodes
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
| lena.vogt | Auditor (read-only) |

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
| `apps/cli` | `signet-verify` (offline evidence verification) and `signet keysweep` |
| `apps/demo-agent` | Phase 1 gate demo and the latency test |
| `apps/mock-tools` | Demo MCP server, HTTP tool and fast test model |
| `policy/` | `signet.rego` (gateway decision policy), shared conformance cases, OPA tests |
| `infra/keycloak` | Dev realm: users, groups, OIDC clients |
| `docs/` | Evidence Package format |

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
| Simplified approve-and-certify | Done: separation of duties (RB-INV-09), validation that cites rules |
| Decision combiner (E37) | Done: rules decide, detectors only add caution, fail-safe for T1/T2 |
| Detector runtime and DET-INJ (E38/E39) | Done: isolated process under Node's permission model; DeBERTa-v3 prompt-injection model (Apache-2.0). Off the critical path, because it takes 70-200 ms on CPU against a 15 ms budget; privileged actions wait for pending verdicts |
| Outage handling (E42) | Done: structured `upstream_unavailable`, no strikes, outage declaration recorded |

### Measured
- Gate demo: kill acknowledged by both gateway nodes in 17-33 ms; hijack after a poisoned document quarantines the agent; tampering with one record in an export is caught and located.
- Gateway pipeline latency (excluding upstream), 16 concurrent clients: model calls p50 2.1 / p95 4.1 / p99 8.1 ms; tool calls p50 1.5 / p95 2.6 ms. Budget is p95 50 ms.
- End-to-end throughput on one laptop running every component: about 180-260 req/s. The Blueprint asks 2,000 req/s per 4-vCPU node; that needs the production profile (one process per core, Postgres, sharded ledger writers).

### Not built yet (later phases)
- Approvals engine and runtime HITL (Phase 2). Until then a hold is rejected, as a timeout would (RB-INV-11). With DET-JB and DET-PII not deployed, **T1/T2 agents are held on every call**, which is the correct fail-safe.
- DET-JB and DET-PII models; a faster DET-INJ that fits the 15 ms budget (E39); detector benchmarks and release process (E40).
- 8-stage lifecycle, classification, control library, ServiceNow connector (Phase 2); Seal Transparency Log, Regulator Portal (Phase 3); SaaS, Hybrid, air-gapped, licensing (Phase 4).
- Postgres profile, RFC 3161 timestamps, live stream scanning (streaming clients get the checked answer as chunks), MFA enforcement in the dev realm (supported by setting `SIGNET_REQUIRE_MFA=true`).

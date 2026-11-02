# Connecting AI agents to Signet

An agent is **connected** only when its own model calls and tool calls go through the Signet gateway
with a valid workload identity. Registering or approving an agent does not connect it; the console's
Connection state changes to *Connected* only after a gateway has accepted a call from it.

| Agent type | How it connects | What Signet governs |
| --- | --- | --- |
| Self-hosted (your code: RunPod, EC2, Docker, Kubernetes) | Python SDK, or the sidecar | Model calls and tool calls |
| Framework-based (LangChain, LangGraph, CrewAI, ...) | Python SDK (an `httpx` auth hook on the framework's OpenAI client) | Model calls and tool calls |
| No-code hosted (n8n, Flowise, Dify) | Sidecar: the framework's OpenAI base URL and MCP URLs point at it | Model calls and tool calls |
| Third-party / vendor-hosted (Copilot Studio, Agentforce, ChatGPT, Amazon) | The vendor platform calls company tools through the gateway with OAuth client credentials | Only the company tools it calls. The vendor's own model is **not** intercepted, and the console says so |

## 1. Register and approve

Console → *Propose agent*. Choose the agent type, runtime and framework (or the vendor), answer the
intake, then take it through the lifecycle on its *Lifecycle* tab: classification, assessments, tests
and the approval matrix. Nothing is approved automatically. Until the seal is signed the agent can get
no credential and every gateway refuses it (`no_active_seal`).

## 2. Identity

**Self-hosted, framework and no-code agents** use a one-time *bootstrap credential*:

1. The deployment pipeline asks for one (console: *Connection → Issue bootstrap credential*, or
   `POST /api/v1/agents/{id}/bootstrap` with the automation client). It is valid for 15 minutes, works
   once, and Signet stores only its SHA-256.
2. The agent exchanges it: `POST /api/v1/identity/token {"bootstrap_credential": "..."}` → a signed
   workload token (EdDSA; 10 minutes for T1/T2, 30 for T3/T4) naming the agent, version and instance,
   issuer `signet-control:<tenant>`, audience `signet-gateway`.
3. Before it expires the agent refreshes it: `POST /api/v1/identity/token/refresh` with the current
   token. Seal, ladder state and instance revocation are checked again on every refresh.

The SDK and sidecar do all three. A bootstrap credential cannot be reused: an agent that was down for
longer than its token's lifetime needs a new one, which is deliberate.

**Third-party agents** cannot hold a bootstrap credential. Create OAuth client credentials on the
agent's *Connection* tab (secret shown once, stored hashed). The vendor platform requests a token with
the standard client-credentials grant (form-encoded, HTTP Basic or JSON) at
`POST /api/v1/identity/token`. Each client is its own instance, so it can be revoked on its own.

Revocation: *Connection → Instances → Revoke identity* (or `POST /api/v1/instances/{id}/revoke`)
puts that instance's tokens on the revocation list every gateway node receives within a second and
refuses its refreshes. Quarantine and kill revoke all of the agent's tokens.

## 3. Credentials stay in Signet

The agent holds no model or tool credentials. The cloud LLM key (if the provider needs one) and every
tool credential live in the Secrets Broker (AES-256-GCM; write-only API; only gateway nodes read them,
over the internal channel). The gateway adds the right credential to each forwarded call. An agent can
only use the tools and actions in its seal, so it can never cause another tool's secret to be used.

## 4. Python SDK

```bash
pip install ./sdk/python[openai]          # package: signet-sdk
export SIGNET_GATEWAY_URL=https://signet-gw.example.com
export SIGNET_CONTROL_URL=https://signet.example.com
export SIGNET_BOOTSTRAP_CREDENTIAL=sbc_...  # or SIGNET_BOOTSTRAP_FILE=/run/secrets/signet-bootstrap
```

```python
from signet_sdk import SignetAgent

agent = SignetAgent.from_env()
client = agent.openai_client()                      # openai.OpenAI → gateway, fresh token per request
client.chat.completions.create(model="gpt-oss:120b-cloud", messages=[...])

agent.mcp_call("orders", "lookup_order", {"order_id": "A-1182"})   # MCP through the gateway
agent.http_tool("crm", "get_customer", id="C-7781")                 # HTTP tool through the gateway
```

Frameworks that take an OpenAI-compatible client:

```python
import httpx
from signet_sdk import SignetAuth
llm = ChatOpenAI(model="gpt-oss:120b-cloud", base_url=agent.openai_base_url, api_key="unused",
                 http_client=httpx.Client(auth=SignetAuth(agent.tokens)))
```

For MCP clients that take a URL and headers, use `agent.mcp_url(alias)` and `agent.auth_headers()`
(tokens expire, so get the headers per connection).

Errors are typed: `SignetAuthError` (identity refused), `SignetPolicyError` (the gateway decided
against the call: `decision`, `code`, `rule_ids`, `record_id`, `approval_id` when a person must
approve), `SignetUpstreamError` (allowed, but the model or tool failed), `SignetUnavailable` (Signet
unreachable), `SignetConfigError`.

`signet-doctor [--model gpt-oss:120b-cloud] [--mcp orders]` checks the whole path step by step.

## 5. Sidecar (n8n, Flowise, Dify, any language)

```bash
docker build --target sidecar -t signet/sidecar .
docker run -d --name signet-sidecar --network agent-net \
  -e SIGNET_GATEWAY_URL=... -e SIGNET_CONTROL_URL=... \
  -e SIGNET_BOOTSTRAP_CREDENTIAL=... -e SIGNET_SIDECAR_BIND=0.0.0.0 signet/sidecar
```

In the framework: OpenAI base URL `http://signet-sidecar:8300/v1`, any API key (it is discarded),
MCP servers `http://signet-sidecar:8300/v1/mcp/<alias>`. `GET /signet/status` shows the identity it
holds. Whoever can reach the sidecar acts as the agent: keep it on the agent's private network.

## 6. Tool endpoints

- MCP: `{gateway}/v1/mcp/<alias>` (JSON-RPC; `tools/list` returns only the actions in the seal)
- HTTP: `{gateway}/v1/tools/http/<alias>/<action>` (method and real address come from the registration)

Tools are registered by a platform admin (*Tools & secrets*). Registration resolves the address and
refuses cloud metadata and link-local addresses, and private or loopback addresses unless
`SIGNET_TOOL_PRIVATE_DESTINATIONS=allow`. The gateway checks again on every connection (DNS
rebinding), refuses `..` path parameters and caps responses at 5 MB.

## 7. Verify

The agent's *Connection* tab shows the state, the last accepted call, refused identities, the runtime
diagnostics the SDK reported, and its real model and tool calls with each decision. The end-to-end
suite does all of the above against a throwaway stack: `npm run test:e2e -- connectivity`.

Keep agents from going around the gateway: see [egress.md](egress.md).

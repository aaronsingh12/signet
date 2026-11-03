# signet-sdk (Python)

Connects an AI agent to the Signet gateway: workload identity (bootstrap or OAuth client credentials),
token refresh, an `openai.OpenAI` client pointed at the gateway, MCP and HTTP tool calls, runtime
diagnostics, and `signet-doctor`.

```bash
pip install ./sdk/python[openai]
```

```python
from signet_sdk import SignetAgent
agent = SignetAgent.from_env()
client = agent.openai_client()
client.chat.completions.create(model="gpt-oss:120b-cloud", messages=[{"role": "user", "content": "Hi"}])
```

Environment: `SIGNET_GATEWAY_URL`, `SIGNET_CONTROL_URL`, and `SIGNET_BOOTSTRAP_CREDENTIAL` (or
`SIGNET_BOOTSTRAP_FILE`), or `SIGNET_CLIENT_ID` + `SIGNET_CLIENT_SECRET`. Optional: `SIGNET_TOKEN_CACHE`
(file kept across restarts, mode 0600), `SIGNET_SESSION_ID`, `SIGNET_FRAMEWORK`, `SIGNET_RUNTIME`,
`SIGNET_REPORT_DIAGNOSTICS=0`, `SIGNET_EGRESS_CHECK=0`.

Diagnostics send variable **names** and provider host names only, never values.

Full guide: [docs/connect-agents.md](../../docs/connect-agents.md). Tests: `npm run test:sdk` (offline)
and `npm run test:e2e -- connectivity` (against a live, isolated Signet stack).

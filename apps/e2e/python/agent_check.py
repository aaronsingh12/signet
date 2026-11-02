"""E2E: a Python agent that connects to Signet with the SDK, exactly as a real deployment would.

Reads SIGNET_* from the environment (set by the e2e suite), then: connects (bootstrap exchange and
diagnostics), sends one model call with the openai package, calls an MCP tool and an HTTP tool, and
tries an action outside its seal. Prints one JSON object with what happened; the suite checks it.
"""

import json
import os
import sys

from signet_sdk import SignetAgent, SignetPolicyError

out = {}
agent = SignetAgent.from_env()
claims = agent.connect()
out["identity"] = {"agent_id": claims["agent_id"], "instance": claims["ins"], "aud": claims.get("aud"), "iss": claims.get("iss")}
out["diagnostics"] = agent.report_diagnostics()  # None: already reported by connect()

model = os.environ["E2E_MODEL"]
client = agent.openai_client()
resp = client.chat.completions.create(model=model, messages=[{"role": "user", "content": "Reply with exactly one word: connected"}], max_tokens=200)
out["model"] = {"content": resp.choices[0].message.content, "model": resp.model}

if os.environ.get("E2E_TOOLS") == "1":
    out["mcp_tools"] = [t["name"] for t in agent.mcp_list_tools("orders")]
    out["mcp_call"] = agent.mcp_call("orders", "lookup_order", {"order_id": "A-1182"})
    out["http_tool"] = agent.http_tool("crm", "get_customer", id="C-7781")
    try:
        agent.mcp_call("orders", "delete_customer", {"customer_id": "C-1"})
        out["out_of_manifest"] = "allowed"
    except SignetPolicyError as e:
        out["out_of_manifest"] = {"decision": e.decision, "code": e.code, "rules": e.rule_ids}

json.dump(out, sys.stdout)

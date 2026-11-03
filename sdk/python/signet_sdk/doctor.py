"""signet-doctor: check, step by step, that this runtime is connected to Signet.

    signet-doctor            # configuration, gateway reachability, identity, diagnostics
    signet-doctor --model    # also send one model call through the gateway
    signet-doctor --mcp ALIAS  # also list the MCP tools this agent may use

Note: a bootstrap credential works once. Running the doctor with one consumes it unless
SIGNET_TOKEN_CACHE is set, in which case the agent process can continue from the cached token.
"""

from __future__ import annotations

import argparse
import sys
import time

import httpx

from .agent import SignetAgent
from .config import SignetConfig
from .errors import SignetError


def _line(ok: bool, label: str, detail: str = "") -> None:
    print(f"  [{'ok' if ok else 'FAIL'}] {label}{(': ' + detail) if detail else ''}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="signet-doctor")
    ap.add_argument("--model", help="send one model call with this model name (e.g. gpt-oss:120b-cloud)")
    ap.add_argument("--mcp", help="list the tools of this MCP alias through the gateway")
    args = ap.parse_args(argv)
    print("Signet connection check")
    try:
        cfg = SignetConfig.from_env()
    except (ValueError, OSError) as exc:
        _line(False, "configuration", str(exc))
        return 2
    _line(True, "configuration", f"gateway {cfg.gateway_url}, control {cfg.control_url}, credential {'client credentials' if cfg.client_id else 'bootstrap' if cfg.bootstrap_credential else 'NONE'}")
    for name, url in (("gateway", f"{cfg.gateway_url}/healthz"), ("control plane", f"{cfg.control_url}/healthz")):
        try:
            r = httpx.get(url, timeout=5.0)
            body = r.json()
            extra = ""
            if name == "gateway":
                st = body.get("cloud_llm_status") or {}
                extra = f"node {body.get('node')}, cloud LLM {st.get('state', 'unknown')} ({st.get('detail', '')})"
            _line(r.status_code < 300, f"{name} reachable", extra)
        except Exception as exc:
            _line(False, f"{name} reachable", str(exc))
            return 3
    agent = SignetAgent(cfg)
    try:
        claims = agent.tokens.claims
        left = int(claims["exp"] - time.time())
        _line(True, "workload identity", f"agent {claims['agent_id']} version {claims['ver']} instance {claims['ins']}, token valid {left} s")
    except SignetError as exc:
        _line(False, "workload identity", str(exc))
        return 4
    diag = agent.report_diagnostics()
    if diag is not None:
        _line(not diag.get("bypass_risk"), "runtime diagnostics", diag.get("note", str(diag)))
    if args.model:
        try:
            out = agent.chat([{"role": "user", "content": "Reply with the word: connected"}], model=args.model, max_tokens=20)
            _line(True, "model call through the gateway", str(out["choices"][0]["message"]["content"]).strip()[:80])
        except SignetError as exc:
            _line(False, "model call through the gateway", f"{type(exc).__name__}: {exc}")
            return 5
    if args.mcp:
        try:
            tools = agent.mcp_list_tools(args.mcp)
            _line(True, f"MCP tools via {args.mcp}", ", ".join(t["name"] for t in tools) or "(none allowed by the seal)")
        except SignetError as exc:
            _line(False, f"MCP tools via {args.mcp}", f"{type(exc).__name__}: {exc}")
            return 6
    return 0


if __name__ == "__main__":
    sys.exit(main())

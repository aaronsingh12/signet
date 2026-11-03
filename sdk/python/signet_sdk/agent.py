"""SignetAgent: one object an agent creates at start-up to reach models and tools through Signet."""

from __future__ import annotations

import itertools
import platform
import threading
from typing import Any, Optional

import httpx

from . import __version__
from .config import SignetConfig
from .diagnostics import egress_check, scan_environment
from .errors import SignetPolicyError, SignetUnavailable, SignetUpstreamError
from .identity import SignetAuth, TokenManager

UPSTREAM_CODES = {"upstream_unavailable", "upstream_rejected", "tool_unavailable", "model_family_drift"}


def raise_for_gateway(r: httpx.Response) -> Any:
    """Turn a gateway answer into data or a typed error."""
    try:
        body = r.json()
    except Exception:
        body = {"text": r.text}
    err = None
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict) and body.get("jsonrpc") == "2.0":
            err = err.get("data") if isinstance(err.get("data"), dict) else {"message": err.get("message"), "code": None}
    if r.status_code < 300 and not err:
        return body
    err = err if isinstance(err, dict) else {"message": r.text[:300]}
    code = err.get("code")
    if code in UPSTREAM_CODES:
        raise SignetUpstreamError(err.get("message") or "upstream failure", r.status_code, code)
    raise SignetPolicyError(
        err.get("message") or f"gateway returned {r.status_code}",
        r.status_code,
        err.get("decision") or r.headers.get("x-signet-decision"),
        code,
        list(err.get("rule_ids") or []),
        err.get("record_id") or r.headers.get("x-signet-record-id"),
        body,
    )


class SignetAgent:
    """Create once per process.

    >>> agent = SignetAgent.from_env()
    >>> client = agent.openai_client()          # openai.OpenAI pointed at the Signet gateway
    >>> client.chat.completions.create(model="gpt-oss:120b-cloud", messages=[...])
    """

    def __init__(self, config: SignetConfig):
        self.config = config
        self.tokens = TokenManager(config)
        self._http = httpx.Client(base_url=config.gateway_url, auth=SignetAuth(self.tokens, config.session_id), timeout=config.timeout_s, headers=config.extra_headers)
        self._rpc_ids = itertools.count(1)
        self._mcp_sessions: dict[str, str] = {}
        self._diag_done = False
        self._diag_lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "SignetAgent":
        return cls(SignetConfig.from_env())

    # --- identity ---
    def connect(self) -> dict:
        """Exchange credentials now (instead of on first call) and report runtime diagnostics."""
        claims = self.tokens.claims
        self.report_diagnostics()
        return claims

    @property
    def agent_id(self) -> str:
        return self.tokens.claims["agent_id"]

    def report_diagnostics(self) -> Optional[dict]:
        if not self.config.report_diagnostics:
            return None
        with self._diag_lock:
            if self._diag_done:
                return None
            self._diag_done = True
        report = {
            "client": f"signet-python/{__version__}",
            "language": f"python {platform.python_version()}",
            "runtime": self.config.runtime,
            "framework": self.config.framework,
            "gateway_url": self.config.gateway_url,
            "env_findings": scan_environment(self.config.gateway_url),
            "egress_check": egress_check() if self.config.egress_check else [],
        }
        try:
            r = httpx.post(f"{self.config.control_url}/api/v1/identity/diagnostics", json=report, headers={"authorization": f"Bearer {self.tokens.token()}"}, timeout=10.0)
            return r.json() if r.status_code < 300 else {"recorded": False, "status": r.status_code}
        except httpx.HTTPError:
            return {"recorded": False, "status": None}

    # --- models ---
    @property
    def openai_base_url(self) -> str:
        return f"{self.config.gateway_url}/v1"

    def openai_client(self, **kwargs: Any):
        """An openai.OpenAI client whose every request goes through the gateway with a fresh token."""
        from openai import OpenAI  # optional dependency: pip install signet-sdk[openai]

        self.report_diagnostics()
        http_client = httpx.Client(auth=SignetAuth(self.tokens, self.config.session_id), timeout=self.config.timeout_s)
        # The api_key is a placeholder: SignetAuth replaces the Authorization header with the workload token.
        return OpenAI(base_url=self.openai_base_url, api_key="signet-workload-token", http_client=http_client, max_retries=kwargs.pop("max_retries", 0), **kwargs)

    def async_openai_client(self, **kwargs: Any):
        from openai import AsyncOpenAI

        self.report_diagnostics()
        http_client = httpx.AsyncClient(auth=_AsyncSignetAuth(self.tokens, self.config.session_id), timeout=self.config.timeout_s)
        return AsyncOpenAI(base_url=self.openai_base_url, api_key="signet-workload-token", http_client=http_client, max_retries=kwargs.pop("max_retries", 0), **kwargs)

    def chat(self, messages: list, model: str, **params: Any) -> dict:
        """Plain chat completion without the openai package."""
        self.report_diagnostics()
        try:
            r = self._http.post("/v1/chat/completions", json={"model": model, "messages": messages, **params})
        except httpx.HTTPError as exc:
            raise SignetUnavailable(f"cannot reach the Signet gateway at {self.config.gateway_url}: {exc}") from exc
        return raise_for_gateway(r)

    # --- tools ---
    def mcp_url(self, alias: str) -> str:
        return f"{self.config.gateway_url}/v1/mcp/{alias}"

    def auth_headers(self) -> dict:
        """Headers for a framework's own MCP or HTTP client. Tokens expire: call this per connection."""
        h = {"authorization": f"Bearer {self.tokens.token()}"}
        if self.config.session_id:
            h["x-signet-session"] = self.config.session_id
        return h

    def _rpc(self, alias: str, method: str, params: Optional[dict] = None, notify: bool = False) -> Any:
        msg: dict = {"jsonrpc": "2.0", "method": method}
        if not notify:
            msg["id"] = next(self._rpc_ids)
        if params is not None:
            msg["params"] = params
        headers = {"accept": "application/json, text/event-stream"}
        if alias in self._mcp_sessions:
            headers["mcp-session-id"] = self._mcp_sessions[alias]
        try:
            r = self._http.post(f"/v1/mcp/{alias}", json=msg, headers=headers)
        except httpx.HTTPError as exc:
            raise SignetUnavailable(f"cannot reach the Signet gateway: {exc}") from exc
        if r.headers.get("mcp-session-id"):
            self._mcp_sessions[alias] = r.headers["mcp-session-id"]
        if notify or r.status_code == 202:
            return None
        body = raise_for_gateway(r)
        return body.get("result")

    def mcp_initialize(self, alias: str) -> dict:
        result = self._rpc(alias, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "signet-python", "version": __version__}})
        self._rpc(alias, "notifications/initialized", notify=True)
        return result

    def mcp_list_tools(self, alias: str) -> list:
        if alias not in self._mcp_sessions:
            self.mcp_initialize(alias)
        return (self._rpc(alias, "tools/list", {}) or {}).get("tools", [])

    def mcp_call(self, alias: str, tool: str, arguments: Optional[dict] = None) -> Any:
        self.report_diagnostics()
        if alias not in self._mcp_sessions:
            self.mcp_initialize(alias)
        return self._rpc(alias, "tools/call", {"name": tool, "arguments": arguments or {}})

    def http_tool(self, alias: str, action: str, **args: Any) -> Any:
        """Call a registered HTTP tool action. The method and real address come from its registration."""
        self.report_diagnostics()
        try:
            r = self._http.post(f"/v1/tools/http/{alias}/{action}", json=args)
        except httpx.HTTPError as exc:
            raise SignetUnavailable(f"cannot reach the Signet gateway: {exc}") from exc
        return raise_for_gateway(r)

    def close(self) -> None:
        self._http.close()


class _AsyncSignetAuth(httpx.Auth):
    requires_response_body = True

    def __init__(self, tokens: TokenManager, session_id: Optional[str]):
        self._sync = SignetAuth(tokens, session_id)

    async def async_auth_flow(self, request: httpx.Request):
        flow = self._sync.auth_flow(request)
        req = next(flow)
        while True:
            response = yield req
            await response.aread()
            try:
                req = flow.send(response)
            except StopIteration:
                return

"""Agent configuration, read from the environment so deployments need no code changes."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


def _env(name: str) -> Optional[str]:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else None


@dataclass
class SignetConfig:
    """Where Signet is and how this agent proves who it is.

    Self-hosted agents use a one-time bootstrap credential (from the deployment pipeline). Vendor
    platforms that can run code use OAuth client credentials. Exactly one of the two is needed.
    """

    gateway_url: str
    control_url: str
    bootstrap_credential: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    # Optional file that keeps the current token across restarts, so a restart inside the token's
    # lifetime refreshes instead of needing a new bootstrap credential. Written with mode 0600.
    token_cache: Optional[str] = None
    framework: Optional[str] = None
    runtime: Optional[str] = None
    session_id: Optional[str] = None
    report_diagnostics: bool = True
    egress_check: bool = True
    timeout_s: float = 130.0
    extra_headers: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "SignetConfig":
        gateway = _env("SIGNET_GATEWAY_URL")
        control = _env("SIGNET_CONTROL_URL")
        if not gateway or not control:
            raise ValueError("SIGNET_GATEWAY_URL and SIGNET_CONTROL_URL must be set")
        bootstrap = _env("SIGNET_BOOTSTRAP_CREDENTIAL")
        bootstrap_file = _env("SIGNET_BOOTSTRAP_FILE")
        if not bootstrap and bootstrap_file:
            with open(bootstrap_file, "r", encoding="utf-8") as fh:
                bootstrap = fh.read().strip() or None
        return cls(
            gateway_url=gateway.rstrip("/"),
            control_url=control.rstrip("/"),
            bootstrap_credential=bootstrap,
            client_id=_env("SIGNET_CLIENT_ID"),
            client_secret=_env("SIGNET_CLIENT_SECRET"),
            token_cache=_env("SIGNET_TOKEN_CACHE"),
            framework=_env("SIGNET_FRAMEWORK"),
            runtime=_env("SIGNET_RUNTIME"),
            session_id=_env("SIGNET_SESSION_ID"),
            report_diagnostics=(_env("SIGNET_REPORT_DIAGNOSTICS") or "1") != "0",
            egress_check=(_env("SIGNET_EGRESS_CHECK") or "1") != "0",
        )

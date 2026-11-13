"""Agent configuration from a UI-issued connection file or existing environment settings."""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from .errors import SignetConfigError


def _env(name: str) -> Optional[str]:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else None


def _file_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SignetConfigError(f"Connection file requires {field_name} as a non-empty string")
    return value.strip()


def _file_url(value: object, field_name: str) -> str:
    text = _file_text(value, field_name)
    url = urlsplit(text)
    local = url.hostname in ("localhost", "127.0.0.1", "::1")
    if not url.hostname or (url.scheme != "https" and not (url.scheme == "http" and local)) or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise SignetConfigError(f"{field_name} must be an HTTPS service origin; HTTP is allowed only on localhost")
    return text.rstrip("/")


@dataclass
class SignetConfig:
    """Where Signet is and how this agent proves who it is.

    Agents use a one-time bootstrap credential, an issued Gateway deployment credential, or OAuth
    client credentials. UI connection files keep these settings out of environment files.
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
    deployment_credential: Optional[str] = None

    @classmethod
    def from_file(cls, path: str) -> "SignetConfig":
        """Read the UI-issued connection file without changing process environment variables."""
        try:
            with open(path, "r", encoding="utf-8") as stream:
                source: object = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise SignetConfigError(f"Cannot read Signet connection file {path}: {exc}") from exc
        if not isinstance(source, dict) or type(source.get("version")) is not int or source.get("version") != 1 or "token_cache" not in source:
            raise SignetConfigError("Connection file requires version 1 and token_cache")
        identity: object = source.get("identity")
        if not isinstance(identity, dict):
            raise SignetConfigError("Connection file requires an identity object")
        kind: object = identity.get("kind")
        bootstrap: Optional[str] = None
        deployment: Optional[str] = None
        client_id: Optional[str] = None
        client_secret: Optional[str] = None
        if kind == "bootstrap":
            bootstrap = _file_text(identity.get("credential"), "identity.credential")
        elif kind == "gateway":
            deployment = _file_text(identity.get("credential"), "identity.credential")
        elif kind == "oauth":
            client_id = _file_text(identity.get("client_id"), "identity.client_id")
            client_secret = _file_text(identity.get("client_secret"), "identity.client_secret")
        else:
            raise SignetConfigError("Connection identity kind must be bootstrap, gateway or oauth")
        cache: object = source["token_cache"]
        return cls(
            control_url=_file_url(source.get("control_url"), "control_url"),
            gateway_url=_file_url(source.get("gateway_url"), "gateway_url"),
            bootstrap_credential=bootstrap,
            deployment_credential=deployment,
            client_id=client_id,
            client_secret=client_secret,
            token_cache=None if cache is None else _file_text(cache, "token_cache"),
        )

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

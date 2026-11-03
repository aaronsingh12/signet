"""Errors that say which layer failed, so an operator knows where to look."""

from __future__ import annotations

from typing import Any, Optional


class SignetError(Exception):
    """Base class."""


class SignetConfigError(SignetError):
    """The SDK is missing configuration (gateway URL, credentials)."""


class SignetAuthError(SignetError):
    """Signet refused this agent's identity: bad, used or expired credential, revoked token, no seal."""

    def __init__(self, message: str, status: Optional[int] = None, rule: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.rule = rule


class SignetUnavailable(SignetError):
    """Signet itself could not be reached (network, DNS, TLS)."""


class SignetPolicyError(SignetError):
    """The gateway evaluated the call and refused or held it (policy, DLP, approval, kill)."""

    def __init__(self, message: str, status: int, decision: Optional[str], code: Optional[str], rule_ids: list, record_id: Optional[str], body: Any):
        super().__init__(message)
        self.status = status
        self.decision = decision
        self.code = code
        self.rule_ids = rule_ids
        self.record_id = record_id
        self.body = body

    @property
    def approval_id(self) -> Optional[str]:
        e = self.body.get("error", {}) if isinstance(self.body, dict) else {}
        return e.get("approval_id")


class SignetUpstreamError(SignetError):
    """Signet allowed the call but the model provider or tool failed."""

    def __init__(self, message: str, status: int, code: Optional[str]):
        super().__init__(message)
        self.status = status
        self.code = code

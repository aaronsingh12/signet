"""Workload identity: exchange the one-time credential for a short-lived token and keep it fresh."""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from typing import Any, Optional

import httpx

from .config import SignetConfig
from .errors import SignetAuthError, SignetConfigError, SignetUnavailable

REFRESH_MARGIN_S = 120  # refresh this long before expiry (tokens live 10 or 30 minutes)


def decode_claims(token: str) -> dict:
    """Read a token's claims without verifying it (the gateway verifies; this is for scheduling)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as exc:  # pragma: no cover - malformed token from the server
        raise SignetAuthError(f"Signet returned a token that cannot be read: {exc}") from exc


def _problem(r: httpx.Response) -> tuple[str, Optional[str]]:
    try:
        b = r.json()
        return str(b.get("detail") or b.get("title") or r.text), b.get("rule") or b.get("title")
    except Exception:
        return r.text[:300], None


class TokenManager:
    """Holds the agent's current workload token; thread-safe; refreshes before expiry.

    A bootstrap credential works once. After it is exchanged the SDK keeps the identity alive by
    refreshing; if the token lapses entirely (agent stopped for longer than its lifetime), a new
    bootstrap credential is needed, which is what Signet intends.
    """

    def __init__(self, config: SignetConfig, http: Optional[httpx.Client] = None):
        self.config = config
        self._http = http or httpx.Client(timeout=15.0)
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._claims: dict = {}
        self._bootstrap_used = False
        self._load_cache()

    # --- public ---
    @property
    def claims(self) -> dict:
        self.token()
        return dict(self._claims)

    def token(self) -> str:
        with self._lock:
            now = time.time()
            if self._token and self._claims.get("exp", 0) - REFRESH_MARGIN_S > now:
                return self._token
            if self._token and self._claims.get("exp", 0) > now + 5:
                try:
                    self._set(self._post("/api/v1/identity/token/refresh", headers={"authorization": f"Bearer {self._token}"}))
                    return self._token  # type: ignore[return-value]
                except SignetAuthError:
                    self._token = None  # fall through to a fresh exchange if we can
            self._set(self._exchange())
            return self._token  # type: ignore[return-value]

    def invalidate(self) -> None:
        """Forget the token (after the gateway refused it) so the next call re-authenticates."""
        with self._lock:
            self._token = None
            self._claims = {}

    # --- internals ---
    def _exchange(self) -> dict:
        c = self.config
        if c.client_id and c.client_secret:
            return self._post("/api/v1/identity/token", json={"grant_type": "client_credentials", "client_id": c.client_id, "client_secret": c.client_secret})
        if c.bootstrap_credential and not self._bootstrap_used:
            self._bootstrap_used = True  # single use, whatever the outcome
            return self._post("/api/v1/identity/token", json={"bootstrap_credential": c.bootstrap_credential})
        if c.bootstrap_credential:
            raise SignetAuthError("the workload token lapsed and the bootstrap credential was already used; redeploy with a new bootstrap credential")
        raise SignetConfigError("no credentials: set SIGNET_BOOTSTRAP_CREDENTIAL (or SIGNET_BOOTSTRAP_FILE), or SIGNET_CLIENT_ID and SIGNET_CLIENT_SECRET")

    def _post(self, path: str, json: Any = None, headers: Optional[dict] = None) -> dict:
        try:
            r = self._http.post(f"{self.config.control_url}{path}", json=json if json is not None else {}, headers=headers or {})
        except httpx.HTTPError as exc:
            raise SignetUnavailable(f"cannot reach the Signet control plane at {self.config.control_url}: {exc}") from exc
        if r.status_code >= 400:
            msg, rule = _problem(r)
            if r.status_code >= 500:
                raise SignetUnavailable(f"Signet control plane error {r.status_code}: {msg}")
            raise SignetAuthError(msg, r.status_code, rule)
        return r.json()

    def _set(self, body: dict) -> None:
        token = body.get("token") or body.get("access_token")
        if not token:
            raise SignetAuthError("Signet did not return a token")
        self._token = token
        self._claims = decode_claims(token)
        self._save_cache()

    def _load_cache(self) -> None:
        path = self.config.token_cache
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
            claims = decode_claims(token)
            if claims.get("exp", 0) > time.time() + 5:
                self._token, self._claims = token, claims
                self._bootstrap_used = True  # the cached identity came from it
        except Exception:
            pass

    def _save_cache(self) -> None:
        path = self.config.token_cache
        if not path or not self._token:
            return
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(self._token)


class SignetAuth(httpx.Auth):
    """httpx auth flow: every request carries the current token; one retry after a refused token."""

    requires_response_body = True

    def __init__(self, tokens: TokenManager, session_id: Optional[str] = None):
        self.tokens = tokens
        self.session_id = session_id

    def auth_flow(self, request: httpx.Request):
        request.headers["authorization"] = f"Bearer {self.tokens.token()}"
        if self.session_id and "x-signet-session" not in request.headers:
            request.headers["x-signet-session"] = self.session_id
        response = yield request
        if response.status_code == 401:
            code = None
            try:
                body = json.loads(response.read())
                err = body.get("error") or {}
                code = err.get("code") or (err.get("data") or {}).get("code")
            except Exception:
                pass
            if code in ("token_expired", "token_revoked", "invalid_token"):
                self.tokens.invalidate()
                request.headers["authorization"] = f"Bearer {self.tokens.token()}"
                yield request

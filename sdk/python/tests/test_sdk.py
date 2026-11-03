"""Offline tests of the SDK's own logic. The live path (real gateway, real model) is covered by the
e2e suite in apps/e2e (npm run test:e2e -- connectivity), which runs this SDK against a Signet stack."""

import base64
import uuid
import json
import time

import httpx
import pytest

from signet_sdk import SignetConfig, SignetPolicyError, SignetUpstreamError, TokenManager, raise_for_gateway
from signet_sdk.diagnostics import scan_environment
from signet_sdk.errors import SignetAuthError, SignetConfigError
from signet_sdk.identity import SignetAuth


def make_token(exp_in: int, **extra) -> str:
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()

    now = int(time.time())
    return f"{b64({'alg': 'EdDSA'})}.{b64({'agent_id': 'agt_1', 'ins': 'ins_1', 'ver': 'v1.0', 'iat': now, 'exp': now + exp_in, 'jti': uuid.uuid4().hex, **extra})}.sig"


class FakeControl:
    def __init__(self, ttl=1800):
        self.calls = []
        self.ttl = ttl

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        self.calls.append((request.url.path, body, request.headers.get("authorization")))
        if request.url.path == "/api/v1/identity/token":
            if body.get("bootstrap_credential") == "sbc_good" or body.get("client_secret") == "scs_good":
                return httpx.Response(200, json={"token": make_token(self.ttl)})
            return httpx.Response(401, json={"rule": "BP-4.2", "detail": "unknown bootstrap credential"})
        if request.url.path == "/api/v1/identity/token/refresh":
            return httpx.Response(200, json={"token": make_token(self.ttl)})
        return httpx.Response(404)


def manager(fake, **cfg):
    config = SignetConfig(gateway_url="http://gw", control_url="http://cp", **cfg)
    return TokenManager(config, http=httpx.Client(transport=httpx.MockTransport(fake)))


def test_bootstrap_is_exchanged_once_and_reused_while_fresh():
    fake = FakeControl()
    tm = manager(fake, bootstrap_credential="sbc_good")
    t1 = tm.token()
    t2 = tm.token()
    assert t1 == t2
    assert [c[0] for c in fake.calls] == ["/api/v1/identity/token"]


def test_refreshes_before_expiry_with_the_current_token():
    fake = FakeControl(ttl=60)  # inside the 120 s refresh margin from the start
    tm = manager(fake, bootstrap_credential="sbc_good")
    first = tm.token()
    tm.token()
    assert fake.calls[1][0] == "/api/v1/identity/token/refresh"
    assert fake.calls[1][2] == f"Bearer {first}"


def test_bootstrap_is_never_sent_twice():
    fake = FakeControl()
    tm = manager(fake, bootstrap_credential="sbc_good")
    tm.token()
    tm.invalidate()
    with pytest.raises(SignetAuthError, match="already used"):
        tm.token()
    assert len([c for c in fake.calls if c[0] == "/api/v1/identity/token"]) == 1


def test_refused_credential_and_missing_credentials():
    with pytest.raises(SignetAuthError) as e:
        manager(FakeControl(), bootstrap_credential="sbc_bad").token()
    assert e.value.status == 401
    with pytest.raises(SignetConfigError):
        manager(FakeControl()).token()


def test_client_credentials_can_re_exchange():
    fake = FakeControl()
    tm = manager(fake, client_id="scl_1", client_secret="scs_good")
    tm.token()
    tm.invalidate()
    tm.token()
    assert len([c for c in fake.calls if c[0] == "/api/v1/identity/token"]) == 2


def test_auth_flow_retries_once_after_a_revoked_token():
    fake = FakeControl()
    tm = manager(fake, client_id="scl_1", client_secret="scs_good")
    seen = []

    def gateway(request: httpx.Request):
        seen.append(request.headers["authorization"])
        if len(seen) == 1:
            return httpx.Response(401, json={"error": {"code": "token_revoked"}})
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(gateway), auth=SignetAuth(tm))
    assert client.get("http://gw/v1/x").json() == {"ok": True}
    assert len(seen) == 2 and seen[0] != seen[1]


def test_gateway_answers_map_to_typed_errors():
    deny = httpx.Response(403, json={"error": {"code": "out_of_manifest", "decision": "deny", "rule_ids": ["RB-PREC-01"], "record_id": "rec_1", "message": "not in seal"}})
    with pytest.raises(SignetPolicyError) as e:
        raise_for_gateway(deny)
    assert e.value.decision == "deny" and e.value.rule_ids == ["RB-PREC-01"] and e.value.record_id == "rec_1"
    rpc = httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32003, "message": "x", "data": {"code": "policy_denied", "decision": "deny", "rule_ids": []}}})
    with pytest.raises(SignetPolicyError):
        raise_for_gateway(rpc)
    upstream = httpx.Response(503, json={"error": {"code": "upstream_unavailable", "message": "LLM down"}})
    with pytest.raises(SignetUpstreamError):
        raise_for_gateway(upstream)
    assert raise_for_gateway(httpx.Response(200, json={"choices": []})) == {"choices": []}


def test_environment_scan_reports_names_not_values():
    env = {"OPENAI_API_KEY": "sk-secret-value", "OPENAI_BASE_URL": "https://api.openai.com/v1", "OLLAMA_HOST": "http://gw:8100", "UNRELATED": "x"}
    found = scan_environment("http://gw:8100", env)
    names = sorted(f["name"] for f in found)
    assert names == ["OPENAI_API_KEY", "OPENAI_BASE_URL"]  # OLLAMA_HOST points at the gateway itself
    assert "sk-secret-value" not in json.dumps(found)

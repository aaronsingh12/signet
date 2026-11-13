"""Exercise UI connection files through a real HTTP token endpoint without environment credentials."""

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from signet_sdk import SignetAgent, SignetConfig, SignetConfigError


@pytest.mark.parametrize("kind", ["gateway", "oauth", "bootstrap"])
def test_connection_file_exchanges_its_identity_over_http(tmp_path: Path, kind: str) -> None:
    requests: list[str] = []
    claims = {"agent_id": "file-agent", "ins": "file-instance", "ver": "v1", "exp": int(time.time()) + 1800}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    token = f"eyJhbGciOiJFZERTQSJ9.{payload}.signature"

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            expected = (
                {"deployment_credential": "sdc_file-credential"} if kind == "gateway"
                else {"bootstrap_credential": "sbc_file-credential"} if kind == "bootstrap"
                else {"grant_type": "client_credentials", "client_id": "file-client", "client_secret": "file-client-secret"}
            )
            expected_path = "/api/v1/identity/deployment-token" if kind == "gateway" else "/api/v1/identity/token"
            valid = self.path == expected_path and body == expected
            requests.append(self.path)
            encoded = json.dumps({"token": token} if valid else {"detail": "Unexpected token request"}).encode()
            self.send_response(200 if valid else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}"
        identity = {"kind": kind, "credential": f"{'sdc' if kind == 'gateway' else 'sbc'}_file-credential"} if kind != "oauth" else {"kind": "oauth", "client_id": "file-client", "client_secret": "file-client-secret"}
        config = {"version": 1, "control_url": url, "gateway_url": url, "identity": identity, "token_cache": None}
        path = tmp_path / "signet-agent.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        agent = SignetAgent.from_file(str(path))
        assert agent.tokens.claims["agent_id"] == "file-agent"
        assert len(requests) == 1
        if kind != "bootstrap":
            agent.tokens.invalidate()
            assert agent.tokens.claims["agent_id"] == "file-agent"
            assert len(requests) == 2
        path.write_text(json.dumps({**config, "control_url": "https://user:password@example.com"}), encoding="utf-8")
        with pytest.raises(SignetConfigError, match="service origin"):
            SignetConfig.from_file(str(path))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

# SPDX-License-Identifier: Apache-2.0
"""CORS loopback-alias equivalence tests.

Verifies that the sidecar accepts any loopback alias (localhost,
127.0.0.1, ::1, [::1]) on the same port as the configured dashboard
origin, and continues to reject a completely different origin.
"""
from __future__ import annotations

import http.client
import importlib
import json
import pathlib
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

_POLLUTABLE_MODULES = [
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]


def _capsule_sidecar():
    import capsule_sidecar as cs

    for name in _POLLUTABLE_MODULES:
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    importlib.reload(cs)
    return cs


@pytest.fixture
def cs():
    return _capsule_sidecar()


class _StubUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        payload = json.dumps({"object": "list", "data": []}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.do_GET()

    def log_message(self, *args):
        pass


@pytest.fixture
def stub_upstream():
    server = HTTPServer(("127.0.0.1", 0), _StubUpstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _make_sidecar(cs, stub_upstream, *, pane_dashboard_origin: str):
    d = pathlib.Path(tempfile.mkdtemp())
    manifest_path = d / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "model_id": "m/1",
            "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"},
            "skippy_abi_version": "1",
        })
    )
    checkpoint_config_path = d / "checkpoint.toml"
    checkpoint_config_path.write_text(
        '[checkpoint]\nlog_id = "test-node"\ncadence_entries = 1\n'
    )
    state = cs.default_state(
        ledger_dir=d / "ledger",
        manifest_path=manifest_path,
        keys_dir=d / "keys",
        runtime_label="rt",
        runtime_digest="0" * 64,
        checkpoint_config_path=checkpoint_config_path,
    )
    upstream_base = f"http://127.0.0.1:{stub_upstream.server_address[1]}"
    server = cs.run_sidecar(
        listen_host="127.0.0.1",
        listen_port=0,
        upstream_base=upstream_base,
        state=state,
        pane_dashboard_origin=pane_dashboard_origin,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _request(port: int, path: str, *, origin: str) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path, headers={"Origin": origin})
    resp = conn.getresponse()
    resp.read()
    status = resp.status
    resp_headers = dict(resp.getheaders())
    conn.close()
    return status, resp_headers


# ---------------------------------------------------------------------------
# Parametrized loopback alias equivalence tests
# ---------------------------------------------------------------------------

# Each tuple is (configured_origin, request_origin) — both should be accepted.
LOOPBACK_ALIAS_CASES = [
    # configured as localhost, request from 127.0.0.1
    ("http://localhost:3131", "http://127.0.0.1:3131"),
    # configured as 127.0.0.1, request from localhost
    ("http://127.0.0.1:3131", "http://localhost:3131"),
    # configured as localhost, request from ::1
    ("http://localhost:3131", "http://[::1]:3131"),
    # configured as 127.0.0.1, request from localhost (reversed from above)
    ("http://127.0.0.1:3131", "http://localhost:3131"),
]


@pytest.mark.parametrize("configured_origin,request_origin", LOOPBACK_ALIAS_CASES)
def test_cors_loopback_alias_accepted(
    cs, stub_upstream, configured_origin: str, request_origin: str
) -> None:
    """A loopback alias on the same port as the configured origin must be accepted."""
    server, thread = _make_sidecar(cs, stub_upstream, pane_dashboard_origin=configured_origin)
    try:
        status, headers = _request(
            server.server_address[1], "/accountability/pane-a", origin=request_origin
        )
        assert status == 200
        acao = headers.get("Access-Control-Allow-Origin")
        assert acao == request_origin, (
            f"Expected Access-Control-Allow-Origin: {request_origin!r}, "
            f"got {acao!r} (configured: {configured_origin!r})"
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_cors_different_origin_rejected(cs, stub_upstream) -> None:
    """A completely different origin must still be rejected."""
    configured = "http://localhost:3131"
    server, thread = _make_sidecar(
        cs, stub_upstream, pane_dashboard_origin=configured
    )
    try:
        status, headers = _request(
            server.server_address[1],
            "/accountability/pane-a",
            origin="https://evil.example.com",
        )
        # The response body is still sent (non-browser callers are not punished),
        # but the CORS header must be absent so browsers block the response.
        assert status == 200
        assert "Access-Control-Allow-Origin" not in headers, (
            "A foreign origin must not receive ACAO header"
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_cors_different_port_loopback_rejected(cs, stub_upstream) -> None:
    """Same hostname but different port is NOT a loopback-alias equivalence."""
    configured = "http://localhost:3131"
    server, thread = _make_sidecar(
        cs, stub_upstream, pane_dashboard_origin=configured
    )
    try:
        status, headers = _request(
            server.server_address[1],
            "/accountability/pane-a",
            origin="http://localhost:9999",  # different port
        )
        assert status == 200
        assert "Access-Control-Allow-Origin" not in headers, (
            "A different port must not be accepted by loopback-alias equivalence"
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

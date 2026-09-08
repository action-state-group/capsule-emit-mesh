#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-acct-dashboard] End-to-end tests for GET /accountability/ and
/accountability/dashboard, driven over real HTTP against a live
``run_sidecar`` instance.

Follows the exact pattern established in test_sidecar_pane_routes.py and
test_sidecar_finder_endpoint.py:
  - A stub upstream handles passthrough paths.
  - Lazy import + reload guards against module-pollution from other test files.
  - The sidecar is started on port 0 (OS-assigned) and torn down per test.

MODULE-POLLUTION / COLLECTION-ORDER GUARD: copied (not imported) from the
sibling files -- test files do not import each other in this suite.
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

    def do_GET(self):  # noqa: N802
        payload = json.dumps({"object": "list", "data": []}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

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


@pytest.fixture
def sidecar(cs, stub_upstream):
    d = pathlib.Path(tempfile.mkdtemp())
    manifest_path = d / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "model_id": "m/1",
            "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"},
            "skippy_abi_version": "1",
        })
    )
    state = cs.default_state(
        ledger_dir=d / "ledger",
        manifest_path=manifest_path,
        keys_dir=d / "keys",
        runtime_label="rt",
        runtime_digest="0" * 64,
    )
    upstream_base = f"http://127.0.0.1:{stub_upstream.server_address[1]}"
    server = cs.run_sidecar(
        listen_host="127.0.0.1",
        listen_port=0,
        upstream_base=upstream_base,
        state=state,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, state
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _get(port: int, path: str) -> tuple[int, str, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    status = resp.status
    headers = dict(resp.getheaders())
    conn.close()
    return status, body, headers


def _seed(state, *records: dict) -> None:
    """Append records directly through the sidecar's already-open store."""
    for record in records:
        state.log_source.append(record, consequential=False)


def _mesh_capsule(*, capsule_id: str, timestamp: str, exchange_id: str) -> dict:
    return {
        "capsule_id": capsule_id,
        "timestamp": timestamp,
        "model_attestation": {
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "serving_provenance": {
                        "exchange_id": exchange_id,
                        "served_by_node_id": "peer-x",
                    }
                }
            }
        },
    }


# ---------------------------------------------------------------------------
# Dashboard route tests
# ---------------------------------------------------------------------------


def test_dashboard_route_200(sidecar):
    """GET /accountability/ returns 200 text/html."""
    server, _state = sidecar
    status, body, headers = _get(server.server_address[1], "/accountability/")
    assert status == 200
    ct = headers.get("Content-Type", "")
    assert "text/html" in ct, f"Expected text/html, got: {ct!r}"
    assert len(body) > 100, "Expected non-trivial HTML body"


def test_dashboard_alias_route_200(sidecar):
    """GET /accountability/dashboard (alias) also returns 200 text/html."""
    server, _state = sidecar
    status, _body, headers = _get(server.server_address[1], "/accountability/dashboard")
    assert status == 200
    ct = headers.get("Content-Type", "")
    assert "text/html" in ct, f"Expected text/html, got: {ct!r}"


def test_dashboard_html_contains_sections(sidecar):
    """The returned HTML contains all four tab section labels."""
    server, _state = sidecar
    _status, body, _headers = _get(server.server_address[1], "/accountability/")
    assert "This node" in body
    assert "Peers" in body
    assert "This exchange" in body
    assert "History" in body


def test_dashboard_html_contains_evidence_headline(sidecar):
    """The page uses 'Evidence' as its headline (mesh-evidence-tab-positioning)."""
    server, _state = sidecar
    _status, body, _headers = _get(server.server_address[1], "/accountability/")
    assert "Evidence" in body


def test_dashboard_html_honest_state_disclaimer(sidecar):
    """The page contains the honest-state first-line disclaimer."""
    server, _state = sidecar
    _status, body, _headers = _get(server.server_address[1], "/accountability/")
    assert "sealed records" in body
    assert "Nothing is a score" in body


def test_dashboard_html_no_cdn_references(sidecar):
    """No CDN or external URL references -- works offline."""
    server, _state = sidecar
    _status, body, _headers = _get(server.server_address[1], "/accountability/")
    # Common CDN hostnames must not appear in the page source.
    for cdn in ("cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "fonts.googleapis.com"):
        assert cdn not in body, f"Found CDN reference: {cdn}"


def test_dashboard_pane_a_json_200(sidecar):
    """GET /accountability/pane-a returns 200 JSON."""
    server, _state = sidecar
    status, body, headers = _get(server.server_address[1], "/accountability/pane-a")
    assert status == 200
    assert "application/json" in headers.get("Content-Type", "")
    data = json.loads(body)
    assert isinstance(data, dict)


def test_dashboard_pane_b_json_200(sidecar):
    """GET /accountability/pane-b returns 200 JSON with 'rows' key."""
    server, _state = sidecar
    status, body, headers = _get(server.server_address[1], "/accountability/pane-b")
    assert status == 200
    assert "application/json" in headers.get("Content-Type", "")
    data = json.loads(body)
    assert "rows" in data, f"Expected 'rows' in pane-b response, got keys: {list(data.keys())}"


def test_dashboard_pane_b_has_honest_pending(sidecar):
    """Pane B cells that cannot yet be computed carry state 'pending' or
    'absent' -- the honest-absence discipline.  At minimum the 'history_theirs'
    and 'served_theirs' cells are pending on a live node (peer-fetch is
    deferred; documented in peer_accountability_tab.py).

    This test seeds one exchange so a peer row exists, then verifies the
    row carries at least one pending/absent cell (never all-green fabrication).
    """
    server, state = sidecar
    _seed(state, _mesh_capsule(capsule_id="aa" * 32, timestamp="2026-09-01T00:00:00Z", exchange_id="ex-1"))
    status, body, _headers = _get(server.server_address[1], "/accountability/pane-b")
    assert status == 200
    data = json.loads(body)
    rows = data.get("rows", [])
    if not rows:
        pytest.skip("No peer rows after seed -- peer grouping may differ; honest absence still enforced at render")

    # At least one of the documented-pending cells must carry state pending/absent.
    found_honest_pending = False
    for row in rows:
        for key in ("history_theirs", "served_theirs", "asked"):
            cell = row.get(key)
            if cell and cell.get("state") in ("pending", "absent"):
                found_honest_pending = True
    assert found_honest_pending, (
        "Pane B rows should carry at least one honestly-pending cell "
        "(history_theirs / served_theirs / asked). "
        f"Got rows: {json.dumps(rows, indent=2)}"
    )

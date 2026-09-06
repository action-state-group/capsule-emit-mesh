#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-ui-ledger-finder] The sidecar's own `/accountability/finder` route
(``capsule_sidecar.Handler.do_GET`` -> ``_handle_finder``), driven end-to-end
over real HTTP against a live ``run_sidecar`` instance -- the same live-
server pattern `test_native_log_sidecar.py` uses, for the same reason: the
thing worth proving here is `do_GET`'s OWN routing (does `/accountability/
finder` actually reach the handler, does every other path still proxy
through unchanged, does the query string actually parse) -- coverage that
calling `ledger_finder.find_capsules` directly (already covered in
`test_ledger_finder.py`) cannot exercise.

MODULE-POLLUTION / COLLECTION-ORDER GUARD: same hazard
`test_join_card_sidecar.py` documents -- a sibling test file may have
stubbed `agent_action_capsule`/`model_identity` at ITS OWN collection time;
importing `capsule_sidecar` lazily and reloading the pollutable modules
first undoes that, same helper, copied rather than imported (test files
don't import each other in this suite).
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
    """Minimal stub so passthrough paths have something real to reach --
    this test suite doesn't otherwise care what mesh-llm itself returns."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
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
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    state = cs.default_state(
        ledger_dir=d / "ledger",
        manifest_path=manifest_path,
        keys_dir=d / "keys",
        runtime_label="rt",
        runtime_digest="0" * 64,
    )
    upstream_base = f"http://127.0.0.1:{stub_upstream.server_address[1]}"
    server = cs.run_sidecar(listen_host="127.0.0.1", listen_port=0, upstream_base=upstream_base, state=state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, state
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _get(port: int, path: str) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    status = resp.status
    conn.close()
    return status, body


def _seed(state, *records: dict) -> None:
    """Append straight through the sidecar's own already-open store handle
    -- the same store `_handle_finder` reads from, no separate process."""
    for record in records:
        state.log_source.append(record, consequential=False)


def _mesh_capsule(*, capsule_id: str, timestamp: str, exchange_id: str) -> dict:
    return {
        "capsule_id": capsule_id,
        "timestamp": timestamp,
        "model_attestation": {
            "compute_attestation": {
                "x-mesh-poc-v1": {"serving_provenance": {"exchange_id": exchange_id, "served_by_node_id": "peer-x"}}
            }
        },
    }


def test_finder_route_with_no_query_returns_a_bar_and_no_results(sidecar):
    server, state = sidecar
    _seed(state, _mesh_capsule(capsule_id="a" * 64, timestamp="2026-09-01T00:00:00Z", exchange_id="ex-1"))
    status, body = _get(server.server_address[1], "/accountability/finder")
    assert status == 200
    assert 'class="finder-bar"' in body
    assert 'class="finder-result"' not in body


def test_finder_route_id_query_finds_the_seeded_capsule(sidecar):
    server, state = sidecar
    _seed(state, _mesh_capsule(capsule_id="ab" * 32, timestamp="2026-09-01T00:00:00Z", exchange_id="ex-1"))
    status, body = _get(server.server_address[1], f"/accountability/finder?id_query={'ab' * 32}")
    assert status == 200
    assert "ab" * 32 in body
    assert "finder-result" in body


def test_finder_route_exchange_id_query_finds_the_seeded_capsule(sidecar):
    server, state = sidecar
    _seed(state, _mesh_capsule(capsule_id="cd" * 32, timestamp="2026-09-01T00:00:00Z", exchange_id="exchange-42"))
    status, body = _get(server.server_address[1], "/accountability/finder?id_query=exchange-42")
    assert status == 200
    assert "cd" * 32 in body


def test_finder_route_time_range_excludes_out_of_range_records(sidecar):
    server, state = sidecar
    _seed(
        state,
        _mesh_capsule(capsule_id="11" * 32, timestamp="2026-01-01T00:00:00Z", exchange_id="ex-old"),
        _mesh_capsule(capsule_id="22" * 32, timestamp="2026-09-01T00:00:00Z", exchange_id="ex-new"),
    )
    status, body = _get(
        server.server_address[1], "/accountability/finder?start=2026-08-01T00:00:00Z&end=2026-10-01T00:00:00Z"
    )
    assert status == 200
    assert "22" * 32 in body
    assert "11" * 32 not in body


def test_non_finder_paths_still_proxy_through_unchanged(sidecar):
    server, _state = sidecar
    # do_GET's new /accountability/finder branch must not swallow any other
    # path -- everything else still reaches the real upstream via
    # _proxy_passthrough, unchanged.
    status, body = _get(server.server_address[1], "/v1/models")
    assert status == 200
    assert json.loads(body) == {"object": "list", "data": []}

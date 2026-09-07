#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-live-tab-pane-proxy] L1 -- the sidecar's own GET /accountability/
pane-a|b|c routes (``capsule_sidecar.Handler.do_GET``/``do_OPTIONS`` ->
``_handle_pane_route``), driven end-to-end over real HTTP against a live
``run_sidecar`` instance -- same live-server pattern
``test_sidecar_finder_endpoint.py`` uses, for the same reason: the thing
worth proving here is routing/CORS, not the JSON-building logic itself
(already covered directly in ``tests/test_accountability_pane_routes.py``).

MODULE-POLLUTION / COLLECTION-ORDER GUARD: same hazard
``test_join_card_sidecar.py``/``test_sidecar_finder_endpoint.py`` document --
copied, not imported (test files don't import each other in this suite).
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


def _make_sidecar(cs, stub_upstream, *, pane_dashboard_origin):
    d = pathlib.Path(tempfile.mkdtemp())
    manifest_path = d / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    checkpoint_config_path = d / "checkpoint.toml"
    checkpoint_config_path.write_text('[checkpoint]\nlog_id = "test-node"\ncadence_entries = 1\n')
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
    return server, state, thread


@pytest.fixture
def sidecar(cs, stub_upstream):
    server, state, thread = _make_sidecar(cs, stub_upstream, pane_dashboard_origin=cs.DEFAULT_PANE_DASHBOARD_ORIGIN)
    try:
        yield server, state
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _request(port: int, method: str, path: str, *, origin: str | None = None) -> tuple[int, str, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Origin": origin} if origin else {}
    conn.request(method, path, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    status = resp.status
    resp_headers = dict(resp.getheaders())
    conn.close()
    return status, body, resp_headers


def _seed(state, *records: dict) -> None:
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


def test_pane_a_route_returns_json_over_an_empty_ledger(sidecar):
    server, _state = sidecar
    status, body, headers = _request(server.server_address[1], "GET", "/accountability/pane-a")
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    payload = json.loads(body)
    assert payload["rows"] == []


def test_pane_b_route_returns_json(sidecar):
    server, _state = sidecar
    status, body, _headers = _request(server.server_address[1], "GET", "/accountability/pane-b")
    assert status == 200
    payload = json.loads(body)
    assert "rows" in payload and "peer_count" in payload


def test_pane_c_route_list_mode_reflects_seeded_records(sidecar):
    server, state = sidecar
    _seed(
        state,
        _mesh_capsule(capsule_id="a" * 64, timestamp="2026-09-01T00:00:00Z", exchange_id="ex-1"),
        _mesh_capsule(capsule_id="b" * 64, timestamp="2026-09-02T00:00:00Z", exchange_id="ex-2"),
    )
    status, body, _headers = _request(server.server_address[1], "GET", "/accountability/pane-c")
    assert status == 200
    payload = json.loads(body)
    assert payload["row_count"] == 2
    assert "next_after_seq" in payload
    assert "archived_segments" in payload


def test_pane_c_route_list_mode_respects_limit_query_param(sidecar):
    server, state = sidecar
    _seed(
        state,
        _mesh_capsule(capsule_id="a" * 64, timestamp="2026-09-01T00:00:00Z", exchange_id="ex-1"),
        _mesh_capsule(capsule_id="b" * 64, timestamp="2026-09-02T00:00:00Z", exchange_id="ex-2"),
    )
    status, body, _headers = _request(server.server_address[1], "GET", "/accountability/pane-c?limit=1")
    assert status == 200
    payload = json.loads(body)
    assert payload["row_count"] == 1
    assert payload["next_after_seq"] is not None


def test_pane_c_route_exchange_id_query_finds_the_seeded_capsule(sidecar):
    server, state = sidecar
    _seed(state, _mesh_capsule(capsule_id="cd" * 32, timestamp="2026-09-01T00:00:00Z", exchange_id="exchange-42"))
    status, body, _headers = _request(server.server_address[1], "GET", "/accountability/pane-c?exchange_id=exchange-42")
    assert status == 200
    payload = json.loads(body)
    assert payload["found"] is True
    assert payload["view"]["capsule_id"] == "cd" * 32


def test_pane_c_route_unknown_exchange_id_is_a_200_not_found_never_a_transport_error(sidecar):
    server, _state = sidecar
    status, body, _headers = _request(server.server_address[1], "GET", "/accountability/pane-c?exchange_id=nope")
    assert status == 200
    assert json.loads(body)["found"] is False


def test_non_pane_paths_still_proxy_through_unchanged(sidecar):
    server, _state = sidecar
    status, body, _headers = _request(server.server_address[1], "GET", "/v1/models")
    assert status == 200
    assert json.loads(body) == {"object": "list", "data": []}


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def test_pane_route_echoes_allow_origin_for_the_configured_dashboard_origin(sidecar, cs):
    server, _state = sidecar
    status, _body, headers = _request(
        server.server_address[1], "GET", "/accountability/pane-a", origin=cs.DEFAULT_PANE_DASHBOARD_ORIGIN
    )
    assert status == 200
    assert headers.get("Access-Control-Allow-Origin") == cs.DEFAULT_PANE_DASHBOARD_ORIGIN


def test_pane_route_omits_allow_origin_for_an_unrecognized_origin(sidecar):
    server, _state = sidecar
    status, _body, headers = _request(
        server.server_address[1], "GET", "/accountability/pane-a", origin="https://evil.example"
    )
    # The response body still exists (a same-origin/non-browser caller isn't
    # punished) -- a real cross-origin browser fetch is blocked client-side
    # by the missing header, never by this sidecar returning an error.
    assert status == 200
    assert "Access-Control-Allow-Origin" not in headers


def test_pane_route_never_sends_a_wildcard_allow_origin(sidecar):
    server, _state = sidecar
    _status, _body, headers = _request(
        server.server_address[1], "GET", "/accountability/pane-a", origin=None
    )
    assert headers.get("Access-Control-Allow-Origin") != "*"


def test_options_preflight_on_a_pane_route_returns_204_with_cors_headers(sidecar, cs):
    server, _state = sidecar
    status, body, headers = _request(
        server.server_address[1], "OPTIONS", "/accountability/pane-b", origin=cs.DEFAULT_PANE_DASHBOARD_ORIGIN
    )
    assert status == 204
    assert body == ""
    assert headers.get("Access-Control-Allow-Origin") == cs.DEFAULT_PANE_DASHBOARD_ORIGIN
    assert "GET" in headers.get("Access-Control-Allow-Methods", "")


def test_options_on_a_non_pane_path_still_proxies_through(cs, stub_upstream):
    """Before this task there was no do_OPTIONS at all (every OPTIONS
    request 501'd). Adding one scoped to the pane routes must not change
    behavior for anything else -- this proves a non-pane OPTIONS still
    reaches the same passthrough do_GET/do_POST already use."""
    server, _state, thread = _make_sidecar(cs, stub_upstream, pane_dashboard_origin=cs.DEFAULT_PANE_DASHBOARD_ORIGIN)
    try:
        status, body, _headers = _request(server.server_address[1], "OPTIONS", "/v1/models")
        assert status == 200
        assert json.loads(body) == {"object": "list", "data": []}
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_pane_dashboard_origin_none_disables_cors_header_entirely(cs, stub_upstream):
    server, _state, thread = _make_sidecar(cs, stub_upstream, pane_dashboard_origin=None)
    try:
        status, _body, headers = _request(
            server.server_address[1], "GET", "/accountability/pane-a", origin=cs.DEFAULT_PANE_DASHBOARD_ORIGIN
        )
        assert status == 200  # the route still answers -- CORS off just means no browser cross-origin fetch
        assert "Access-Control-Allow-Origin" not in headers
    finally:
        server.shutdown()
        thread.join(timeout=5)

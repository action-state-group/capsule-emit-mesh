# SPDX-License-Identifier: Apache-2.0
"""Tests for peer_evidence_client.py -- mock-peer loopback tests.

Uses an in-process HTTP server to simulate a peer's evidence door
(POST /evidence-request) without any live network connections.

HONESTY BAR: these tests verify that the client correctly classifies
responses -- verified only when the response is structurally valid,
refused/no_answer/failed when the response says so.  They never assert
that a fabricated count appears as "verified".
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peer_evidence_client import (
    PEER_FETCH_ENABLED,
    PeerFetchResult,
    fetch_all_peer_cells,
    fetch_peer_history,
    fetch_served_summary,
)
from peer_accountability_tab import (
    CELL_PENDING,
    CELL_VERIFIED,
    build_peers_payload,
)


# ---------------------------------------------------------------------------
# Mock HTTP server
# ---------------------------------------------------------------------------

_VALID_SERVED_SUMMARY = {
    "schema": "mesh-served-summary/1",
    "n_served": 42,
    "n_completed": 40,
    "n_failed": 2,
    "witness_bounded": True,
}

_REFUSAL_RESPONSE = {
    "reason": "not authorized",
    "sig": "mock-sig",
}


class _MockPeerHandler(BaseHTTPRequestHandler):
    """Routes POST /evidence-request based on derivation field."""

    def log_message(self, fmt: str, *args: Any) -> None:  # suppress output
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(length)
        try:
            body = json.loads(body_raw)
        except Exception:
            body = {}

        derivation = body.get("derivation", "")

        if derivation == "served_summary/1":
            # Return a valid served_summary response
            resp = {"served_summary": _VALID_SERVED_SUMMARY}
            self._send_json(200, resp)
        elif derivation == "refuse-me":
            # Return a refusal
            self._send_json(200, _REFUSAL_RESPONSE)
        else:
            # No derivation / range request -> return empty bundles (history path)
            resp = {"bundles": []}
            self._send_json(200, resp)

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_mock_server() -> tuple[HTTPServer, str]:
    """Start a mock peer server on a random loopback port."""
    server = HTTPServer(("127.0.0.1", 0), _MockPeerHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    return server, base_url


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_peer_fetch_enabled_default_is_false() -> None:
    assert PEER_FETCH_ENABLED is False


def test_fetch_served_summary_verified() -> None:
    server, base_url = _start_mock_server()
    try:
        result = fetch_served_summary(base_url, timeout_seconds=5, peer_id="test-peer")
        assert result["status"] == "verified", f"expected verified, got: {result}"
        ss = result["served_summary"]
        assert ss["n_served"] == 42
        assert ss["n_completed"] == 40
        assert ss["n_failed"] == 2
        assert ss["witness_bounded"] is True
        assert result["schema"] == "mesh-served-summary/1"
    finally:
        server.shutdown()


def test_fetch_served_summary_no_answer() -> None:
    # Use a port that is not listening
    result = fetch_served_summary(
        "http://127.0.0.1:1",  # port 1 -- not listening
        timeout_seconds=2,
        peer_id="unreachable-peer",
    )
    assert result["status"] == "no_answer"
    assert result["transport"] == "http"
    assert "reason" in result


def test_fetch_served_summary_refused() -> None:
    server, base_url = _start_mock_server()
    try:
        # Use derivation "refuse-me" -- not supported directly via fetch_served_summary,
        # but we can POST directly to test the refusal path by using a patched URL.
        # Instead, we test via fetch_served_summary with a server that always refuses.
        import urllib.request

        class _RefusingHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                pass
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                resp = json.dumps({"reason": "policy: not authorized", "sig": "mock"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        refusing_server = HTTPServer(("127.0.0.1", 0), _RefusingHandler)
        refusing_port = refusing_server.server_address[1]
        refusing_thread = threading.Thread(target=refusing_server.serve_forever, daemon=True)
        refusing_thread.start()
        refusing_url = f"http://127.0.0.1:{refusing_port}"

        result = fetch_served_summary(refusing_url, timeout_seconds=5, peer_id="refusing-peer")
        assert result["status"] == "refused", f"expected refused, got: {result}"
        assert "policy" in result["reason"]
        assert result["signed"] is True
        refusing_server.shutdown()
    finally:
        server.shutdown()


def test_fetch_peer_history_no_bundles() -> None:
    server, base_url = _start_mock_server()
    try:
        result = fetch_peer_history(base_url, timeout_seconds=5, peer_id="test-peer")
        # Mock server returns empty bundles for non-served-summary requests
        assert result["status"] == "no_answer"
        assert result["reason"] == "peer returned no bundles"
    finally:
        server.shutdown()


def test_fetch_all_peer_cells_disabled() -> None:
    result = fetch_all_peer_cells(
        "any-peer",
        "http://127.0.0.1:1",
        enabled=False,
    )
    assert isinstance(result, PeerFetchResult)
    assert result.served["status"] == "no_answer"  # type: ignore[index]
    assert result.served["reason"] == "peer_fetch_disabled"  # type: ignore[index]
    assert result.history["status"] == "no_answer"  # type: ignore[index]
    assert result.history["reason"] == "peer_fetch_disabled"  # type: ignore[index]
    assert result.verdicts["status"] == "no_answer"  # type: ignore[index]
    assert result.verdicts["reason"] == "peer_fetch_disabled"  # type: ignore[index]


def test_build_peers_payload_with_fetch_config() -> None:
    """build_peers_payload with peer_fetch_config enabled + mock peer -> served cell is CELL_VERIFIED."""
    server, base_url = _start_mock_server()
    try:
        # Build a minimal ledger record with a cross_party initiator_ref so
        # group_by_peer produces a deterministic peer id we can put in the URL map.
        # label_counterparty truncates initiator_ref to 12 chars, so
        # "mock-peer-001"[:12] = "mock-peer-00" -> peer_id = "initiator:mock-peer-00"
        initiator_ref = "mock-peer-001"
        peer_id = "initiator:" + initiator_ref[:12]
        record: dict[str, Any] = {
            "capsule_id": "cap-001",
            "operator": "op",
            "timestamp": "2026-09-07T00:00:00Z",
            "model_attestation": {
                "model_id": "m",
                "compute_attestation": {
                    "x-mesh-poc-v1": {
                        "client_nonce_source": "client_supplied",
                        "cross_party": {
                            "initiator_ref": initiator_ref,
                            "counterparty_ref": "this-node",
                        },
                    }
                },
            },
            "effect": {
                "request_digest": "a" * 64,
                "response_digest": "b" * 64,
                "effect_attestation": "gate_executed",
            },
            "disposition": {"decision": "accept", "verdict_class": "executed"},
        }

        peer_fetch_config = {
            "enabled": True,
            "peer_url_map": {peer_id: base_url},
            "timeout_seconds": 5,
        }

        payload = build_peers_payload(
            [record],
            node_id="this-node",
            log_id="this-node",
            checkpoint_lines=[],
            peer_fetch_config=peer_fetch_config,
        )

        assert payload["peer_fetch_enabled"] is True
        assert payload["peer_fetch_count"] == 1

        # Find the peer row
        rows = payload["rows"]
        assert len(rows) >= 1
        peer_row = next((r for r in rows if r.get("peer_id") == peer_id), None)
        assert peer_row is not None, f"peer_id {peer_id!r} not found in rows"

        served = peer_row["served"]
        assert served["state"] == CELL_VERIFIED, f"expected CELL_VERIFIED for served, got: {served}"
        assert "their count" in served["text"]
    finally:
        server.shutdown()


def test_peer_no_url_stays_pending() -> None:
    """A peer with no URL in peer_url_map stays CELL_PENDING for history/served."""
    record: dict[str, Any] = {
        "capsule_id": "cap-002",
        "operator": "op",
        "timestamp": "2026-09-07T00:00:00Z",
        "model_attestation": {
            "model_id": "m",
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "client_nonce_source": "client_supplied",
                    "cross_party": {
                        "initiator_ref": "no-url-peer",
                        "counterparty_ref": "this-node",
                    },
                }
            },
        },
        "effect": {
            "request_digest": "c" * 64,
            "response_digest": "d" * 64,
            "effect_attestation": "gate_executed",
        },
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }

    peer_fetch_config = {
        "enabled": True,
        "peer_url_map": {},  # no URL for this peer
        "timeout_seconds": 5,
    }

    payload = build_peers_payload(
        [record],
        node_id="this-node",
        log_id="this-node",
        checkpoint_lines=[],
        peer_fetch_config=peer_fetch_config,
    )

    rows = payload["rows"]
    assert len(rows) >= 1
    # The peer has no URL so no fetch was done -> history and served stay pending
    peer_row = rows[0]
    history = peer_row["history"]
    served = peer_row["served"]
    assert history["state"] == CELL_PENDING, f"expected pending history for no-url peer, got: {history}"
    assert served["state"] == CELL_PENDING, f"expected pending served for no-url peer, got: {served}"

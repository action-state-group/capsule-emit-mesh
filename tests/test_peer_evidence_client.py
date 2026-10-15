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

import hashlib
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from agent_action_capsule import evidence_request as er
from agent_action_capsule.canonical import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peer_accountability_tab import (
    CELL_PENDING,
    CELL_VERIFIED,
    build_peers_payload,
)
from peer_evidence_client import (
    PEER_FETCH_ENABLED,
    PeerFetchResult,
    fetch_all_peer_cells,
    fetch_peer_history,
    fetch_served_summary,
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

class _MockSigner:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        self.key_id = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def sign(self, body: bytes) -> tuple[str, str]:
        return self._key.sign(body).hex(), self.key_id


_SIGNER = _MockSigner()
_ANCHOR = "ab" * 32
_ISSUED_AT = "2026-10-15T00:00:00Z"


def _envelope(request_bytes: bytes, body: dict[str, Any], *, anchor: str = _ANCHOR) -> dict[str, Any]:
    """A signed -00 envelope answering ``request_bytes`` with ``body``."""
    request = er.parse_request(request_bytes)
    envelope = er.sign_envelope(
        request_bytes, request.subject, anchor, jcs(body), signer=_SIGNER, issued_at=_ISSUED_AT,
        derivation=request.derivation,
    )
    return json.loads(envelope.encode("json"))


def _refusal(request_bytes: bytes, reason: str) -> dict[str, Any]:
    return er.sign_refusal(er.request_digest(request_bytes), reason, signer=_SIGNER, issued_at=_ISSUED_AT).to_dict()


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
            # A signed envelope around a valid served summary
            self._send_json(200, _envelope(body_raw, {"anchor": _ANCHOR, "served_summary": _VALID_SERVED_SUMMARY}))
        else:
            # The history path asks for checkpoints: answer with the
            # committed demo ledger's real checkpoint lines, or none.
            lines = self.server.checkpoint_lines  # type: ignore[attr-defined]
            anchor = self.server.anchor  # type: ignore[attr-defined]
            self._send_json(200, _envelope(body_raw, {"anchor": anchor, "checkpoints": lines}, anchor=anchor))

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_DEMO_CHECKPOINTS = [
    json.loads(line)
    for line in (Path(__file__).resolve().parent.parent / "ledger-checkpoint-demo" / "checkpoints.jsonl")
    .read_text()
    .splitlines()
    if line.strip()
]


_DEMO_ANCHOR = hashlib.sha256(bytes.fromhex(_DEMO_CHECKPOINTS[-1]["checkpoint_cose"])).hexdigest()


def _start_mock_server(
    *, checkpoint_lines: list[dict[str, Any]] | None = None, anchor: str = _DEMO_ANCHOR
) -> tuple[HTTPServer, str]:
    """Start a mock peer server on a random loopback port."""
    server = HTTPServer(("127.0.0.1", 0), _MockPeerHandler)
    server.checkpoint_lines = checkpoint_lines or []
    server.anchor = anchor
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
                resp = json.dumps(_refusal(self.rfile.read(length), "policy_declined")).encode()
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


def test_fetch_peer_history_no_checkpoints_fails() -> None:
    server, base_url = _start_mock_server()
    try:
        result = fetch_peer_history(base_url, timeout_seconds=5, peer_id="test-peer")
        assert result["status"] == "failed"
        assert result["reason"] == "the artifact carries no checkpoint lines"
    finally:
        server.shutdown()


def test_fetch_peer_history_folds_the_peers_checkpoints() -> None:
    server, base_url = _start_mock_server(checkpoint_lines=_DEMO_CHECKPOINTS)
    try:
        result = fetch_peer_history(base_url, timeout_seconds=5, peer_id="test-peer")
        assert result["status"] == "verified", result
        summary = result["history_summary"]
        assert summary["checkpoint_count"] == len(_DEMO_CHECKPOINTS)
        assert summary["latest_checkpoint"] == _DEMO_CHECKPOINTS[-1]
        assert summary["anchor"] == _DEMO_ANCHOR
        assert summary["continuity"] == "unbroken"
    finally:
        server.shutdown()


def test_fetch_peer_history_refuses_a_forged_genesis() -> None:
    """A signed envelope around a first checkpoint whose statement is not its
    own (here, the last line's) is never folded into a verified card."""
    forged = [{**_DEMO_CHECKPOINTS[0], "checkpoint_cose": _DEMO_CHECKPOINTS[-1]["checkpoint_cose"]}]
    forged_anchor = hashlib.sha256(bytes.fromhex(forged[-1]["checkpoint_cose"])).hexdigest()
    server, base_url = _start_mock_server(checkpoint_lines=forged, anchor=forged_anchor)
    try:
        result = fetch_peer_history(base_url, timeout_seconds=5, peer_id="test-peer")
        assert result["status"] == "failed"
        assert "first checkpoint" in result["reason"]
    finally:
        server.shutdown()


def test_fetch_peer_history_refuses_a_chain_whose_later_link_fails() -> None:
    """A verified genesis followed by a line whose statement does not prove
    it (here, the genesis statement again) is not verified history, even
    when the envelope's anchor names that last statement."""
    assert len(_DEMO_CHECKPOINTS) > 1
    broken = [*_DEMO_CHECKPOINTS[:-1], {**_DEMO_CHECKPOINTS[-1], "checkpoint_cose": _DEMO_CHECKPOINTS[0]["checkpoint_cose"]}]
    anchor = hashlib.sha256(bytes.fromhex(broken[-1]["checkpoint_cose"])).hexdigest()
    server, base_url = _start_mock_server(checkpoint_lines=broken, anchor=anchor)
    try:
        result = fetch_peer_history(base_url, timeout_seconds=5, peer_id="test-peer")
        assert result["status"] == "failed"
        assert "does not verify" in result["reason"]
    finally:
        server.shutdown()


def test_fetch_peer_history_refuses_lines_that_do_not_end_at_the_anchor() -> None:
    server, base_url = _start_mock_server(checkpoint_lines=_DEMO_CHECKPOINTS, anchor="cd" * 32)
    try:
        result = fetch_peer_history(base_url, timeout_seconds=5, peer_id="test-peer")
        assert result["status"] == "failed"
        assert "not the envelope's anchor" in result["reason"]
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


def test_fetch_served_summary_unsigned_reply_fails() -> None:
    """A reply that is not a signed envelope or refusal is never verified."""

    class _UnsignedHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            resp = json.dumps({"served_summary": _VALID_SERVED_SUMMARY}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

    server = HTTPServer(("127.0.0.1", 0), _UnsignedHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = fetch_served_summary(f"http://127.0.0.1:{server.server_address[1]}", timeout_seconds=5)
        assert result["status"] == "failed"
        assert "neither an envelope nor a refusal" in result["reason"]
    finally:
        server.shutdown()

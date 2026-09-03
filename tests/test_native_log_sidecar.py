#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-native-log-join] The sidecar's own native_log.jsonl / lifecycle_
events.jsonl instrumentation, driven end-to-end over real HTTP against the
sidecar (run_sidecar) fronting a stub upstream mesh-llm server -- the same
pattern test_replay_spot_check.py uses for its own live-server tests.

The point of testing this live rather than unit-calling handle_chat_completion
directly: the coverage gap this task exists to close is specifically in
do_POST's routing (the bad-JSON-body and uncaught-sidecar-exception branches
that never reach build_capsule/record_capsule at all) -- a live request is
the only way to exercise that routing honestly.
"""
from __future__ import annotations

import http.client
import json
import pathlib
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import capsule_sidecar as cs  # noqa: E402
import native_log_join as nlj  # noqa: E402


class _StubUpstream(BaseHTTPRequestHandler):
    """Minimal /v1/chat/completions stub. ``mode`` selects the scenario."""

    protocol_version = "HTTP/1.1"
    mode = "ok"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if self.__class__.mode == "ok":
            payload = json.dumps(
                {"id": "chatcmpl-1", "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}]}
            ).encode("utf-8")
            status = 200
        elif self.__class__.mode == "upstream_error":
            payload = json.dumps({"error": {"message": "boom"}}).encode("utf-8")
            status = 500
        elif self.__class__.mode == "malformed_response":
            # Not valid JSON -- handle_chat_completion's response_json =
            # json.loads(...) throws, uncaught, all the way out of
            # handle_chat_completion -- the sidecar-internal-exception gap.
            payload = b"not json"
            status = 200
        else:
            raise AssertionError(f"unknown stub mode {self.__class__.mode!r}")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def stub_upstream():
    handler = type("Handler", (_StubUpstream,), {"mode": "ok"})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, handler
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def sidecar(stub_upstream):
    upstream_server, handler = stub_upstream
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "manifest.json").write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    state = cs.default_state(
        ledger_dir=d / "ledger",
        manifest_path=d / "manifest.json",
        keys_dir=d / "keys",
        runtime_label="rt",
        runtime_digest="0" * 64,
    )
    upstream_base = f"http://127.0.0.1:{upstream_server.server_address[1]}"
    server = cs.run_sidecar(listen_host="127.0.0.1", listen_port=0, upstream_base=upstream_base, state=state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, state, handler
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _post(port: int, body: bytes) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", "/v1/chat/completions", body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = resp.read()
    status = resp.status
    conn.close()
    return status, data


def _native_log_entries(state: cs.NodeState) -> list[dict]:
    if not state.native_log_path.exists():
        return []
    return [json.loads(line) for line in state.native_log_path.read_text().splitlines() if line.strip()]


def _wait_for_native_log_entries(state: cs.NodeState, count: int, *, timeout: float = 2.0) -> list[dict]:
    """Poll for *count* native_log rows.

    do_POST writes its native_log row AFTER flushing the HTTP response --
    the client observing the full response body does not imply the server's
    handler thread has returned yet, so asserting immediately after a POST
    is a real race, not a sidecar bug. Poll instead of sleeping a fixed
    guess.
    """
    deadline = time.monotonic() + timeout
    entries: list[dict] = []
    while time.monotonic() < deadline:
        entries = _native_log_entries(state)
        if len(entries) >= count:
            return entries
        time.sleep(0.01)
    return entries


def _capsules(state: cs.NodeState) -> list[dict]:
    if not state.ledger_path.exists():
        return []
    return [json.loads(line) for line in state.ledger_path.read_text().splitlines() if line.strip()]


# ── SUCCESS path: native_log row joins to a sealed capsule ────────────────

def test_success_request_records_native_log_entry_joined_to_sealed_capsule(sidecar):
    server, state, handler = sidecar
    handler.mode = "ok"
    port = server.server_address[1]
    status, _ = _post(port, json.dumps({"model": "m", "temperature": 0.1}).encode())
    assert status == 200

    entries = _wait_for_native_log_entries(state, 1)
    assert len(entries) == 1
    assert entries[0]["status"] == nlj.NATIVE_STATUS_SUCCESS
    assert entries[0]["capsule_id"] is not None  # capsule_id known at write time

    capsules = _capsules(state)
    report = nlj.coverage_report(entries, capsules)
    assert report["unsealed_count"] == 0
    assert report["coverage_summary"] == "coverage: fully sealed"


# ── upstream error, but sealed as "errored" -- native_log still joins ─────

def test_upstream_error_response_is_sealed_and_native_log_joins_to_it(sidecar):
    server, state, handler = sidecar
    handler.mode = "upstream_error"
    port = server.server_address[1]
    status, _ = _post(port, json.dumps({"model": "m"}).encode())
    assert status == 500  # the upstream's real error status, forwarded

    entries = _wait_for_native_log_entries(state, 1)
    assert len(entries) == 1
    assert entries[0]["status"] == nlj.NATIVE_STATUS_FAILED
    assert entries[0]["capsule_id"] is not None

    capsules = _capsules(state)
    assert capsules[0]["disposition"]["verdict_class"] == "errored"
    report = nlj.coverage_report(entries, capsules)
    assert report["unsealed_count"] == 0
    assert report["failed_unsealed"] == []


# ── MUTANT-relevant gap 1: malformed client body never reaches sealing ────

def test_bad_client_json_never_sealed_and_native_log_shows_unsealed(sidecar):
    server, state, handler = sidecar
    port = server.server_address[1]
    status, _ = _post(port, b"{not valid json")
    assert status == 400

    entries = _wait_for_native_log_entries(state, 1)
    assert len(entries) == 1
    assert entries[0]["status"] == nlj.NATIVE_STATUS_FAILED
    assert entries[0]["capsule_id"] is None
    assert entries[0]["request_digest"] is None  # never reached digest_json

    capsules = _capsules(state)
    assert capsules == []  # confirms this really was never sealed

    report = nlj.coverage_report(entries, capsules)
    assert report["unsealed_count"] == 1
    assert len(report["failed_unsealed"]) == 1


# ── MUTANT-relevant gap 2: sidecar-internal exception never seals either ──

def test_sidecar_internal_exception_never_sealed_and_native_log_shows_unsealed(sidecar):
    server, state, handler = sidecar
    handler.mode = "malformed_response"  # upstream returns non-JSON -- json.loads throws inside handle_chat_completion
    port = server.server_address[1]
    status, body = _post(port, json.dumps({"model": "m"}).encode())
    assert status == 500
    assert b"sidecar_error" in body

    entries = _wait_for_native_log_entries(state, 1)
    assert len(entries) == 1
    assert entries[0]["status"] == nlj.NATIVE_STATUS_FAILED
    assert entries[0]["capsule_id"] is None
    assert entries[0]["request_digest"] is not None  # request WAS parsed/digested before the throw

    capsules = _capsules(state)
    assert capsules == []  # the exact gap this task closes: a real request, zero capsules

    report = nlj.coverage_report(entries, capsules)
    assert report["unsealed_count"] == 1
    assert report["failed_unsealed"][0]["request_id"] == entries[0]["request_id"]
    assert report["coverage_summary"] == "coverage: 1 request(s) unsealed"


# ── lifecycle markers ───────────────────────────────────────────────────────

def _lifecycle_events(state: cs.NodeState) -> list[dict]:
    return [json.loads(line) for line in state.lifecycle_events_path.read_text().splitlines() if line.strip()]


def test_node_state_boot_writes_runtime_shutdown_end():
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "manifest.json").write_text(json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"}))
    state = cs.default_state(ledger_dir=d / "ledger", manifest_path=d / "manifest.json", keys_dir=d / "keys", runtime_label="rt", runtime_digest="0" * 64)
    events = _lifecycle_events(state)
    assert len(events) == 1
    assert events[0]["event"] == nlj.LIFECYCLE_RUNTIME_SHUTDOWN_END


def test_serve_until_shutdown_writes_runtime_shutdown_begin_on_exit():
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "manifest.json").write_text(json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"}))
    state = cs.default_state(ledger_dir=d / "ledger", manifest_path=d / "manifest.json", keys_dir=d / "keys", runtime_label="rt", runtime_digest="0" * 64)

    class _FakeServer:
        def serve_forever(self):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        cs.serve_until_shutdown(_FakeServer(), state)

    events = _lifecycle_events(state)
    # boot (_end) + the shutdown this triggers (_begin).
    assert [e["event"] for e in events] == [nlj.LIFECYCLE_RUNTIME_SHUTDOWN_END, nlj.LIFECYCLE_RUNTIME_SHUTDOWN_BEGIN]

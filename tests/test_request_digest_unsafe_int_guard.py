#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[capsule-emit-mesh-request-digest-unsafe-int-guard] Before this task, NONE of
the sidecar's six ``digest_json()`` call sites (``_seal_chat_completion``,
``forwarded_copy_record``, ``handle_chat_completion`` x2, ``do_POST``,
``_handle_streaming_chat_completion``) caught ``UnsafeIntegerError`` /
``FloatInDigestError``: an integer literal beyond +/-(2**53-1) anywhere in a
request or response body crashed that request's handling -- silently for the
request-digest sites (the exception escaped straight out of ``do_POST``, no
response, no native_log row), or as an opaque 500 with no sealed capsule for
the response-digest sites. The original x-mesh digest-context adversarial
review claimed the response side already caught-and-omitted this; that claim
was checked against ``capsule_sidecar.py`` on origin/main (``cd55a9f``) and
was WRONG -- ``UnsafeIntegerError``/``FloatInDigestError`` were not even
imported into this module.

This suite exercises ``_safe_digest_json`` (the new shared guard) at each of
its six call sites, each given a distinct ``field=`` label specifically so a
test can mock the guard away for exactly one site without disturbing the
other five -- that per-site isolation is what makes the mutant checks below
meaningful rather than accidental.

Every "omits" test is paired with a "mutant" test: monkeypatch that one
site's guard back to a bare, unguarded ``digest_json`` call and confirm the
old crash reproduces. pytest's ``monkeypatch`` fixture reverts automatically
at teardown, satisfying "remove the guard, confirm red, then restore."
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
from agent_action_capsule.canonical import UnsafeIntegerError  # noqa: E402

# One above Number.MAX_SAFE_INTEGER (2**53-1) -- the exact boundary
# agent_action_capsule.canonical._jcs_value's UnsafeIntegerError guard trips
# on (see tests/canonicalization/vectors/base/aac/canonical-integer-above-safe-max).
OVERSIZED_INT = 2**53


# ── _safe_digest_json itself: the shared primitive all six sites call ──────

def test_safe_digest_json_omits_on_oversized_integer():
    result = cs._safe_digest_json({"n": OVERSIZED_INT}, field="test")
    assert result is None


def test_safe_digest_json_matches_digest_json_on_normal_value():
    value = {"model": "m", "temperature": 0.1}
    assert cs._safe_digest_json(value, field="test") == cs.digest_json(value)


# ── Site :1692 -- forwarded_copy_record's own "digest" field (pure fn) ─────

def test_forwarded_copy_record_digest_omitted_on_oversized_integer():
    result = cs.forwarded_copy_record({"id": "x", "usage": {"total_tokens": OVERSIZED_INT}}, [])
    assert result["digest"] is None
    assert result["transforms"] == []


def test_forwarded_copy_record_digest_present_on_normal_value():
    forwarded = {"id": "x", "choices": []}
    result = cs.forwarded_copy_record(forwarded, [])
    assert result["digest"] == cs.digest_json(forwarded)


def test_forwarded_copy_record_mutant_without_guard_crashes(monkeypatch):
    real = cs._safe_digest_json

    def unguarded(value, *, field):
        if field == "forwarded_copy.digest":
            return cs.digest_json(value)  # the guard removed: raises instead of omitting
        return real(value, field=field)

    monkeypatch.setattr(cs, "_safe_digest_json", unguarded)
    with pytest.raises(UnsafeIntegerError):
        cs.forwarded_copy_record({"id": "x", "usage": {"total_tokens": OVERSIZED_INT}}, [])


# ── Site :1509 -- _seal_chat_completion's response_digest (streaming's ────
# ── shared sealer; also exercised by the SSE error branch) ────────────────

def _tmp_state(**kwargs) -> cs.NodeState:
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "manifest.json").write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    return cs.default_state(
        ledger_dir=d / "ledger",
        manifest_path=d / "manifest.json",
        keys_dir=d / "keys",
        runtime_label="rt",
        runtime_digest="0" * 64,
        **kwargs,
    )


def test_seal_chat_completion_response_digest_omitted_and_downgrades_to_failed():
    state = _tmp_state()
    capsule = cs._seal_chat_completion(
        state,
        client_nonce="n",
        client_nonce_source="sidecar_generated_fallback",
        request_json={"model": "m"},
        request_digest="a" * 64,
        response_json={"id": "x", "usage": {"total_tokens": OVERSIZED_INT}},
        status_code=200,  # a REAL success response the sidecar cannot digest
        latency_ms=1.0,
    )
    # process alive: no exception propagated, a capsule came back
    assert capsule["effect"].get("response_digest") is None  # normalize() strips absent fields
    # §5.2's confirmed-effect invariant requires a well-formed response_digest
    # -- undigestable is honestly "failed", never "confirmed" with a null digest.
    assert capsule["effect"]["status"] == "failed"
    assert capsule["disposition"]["verdict_class"] == "errored"
    assert capsule["disposition"]["decision"] == "reject"
    assert capsule["effect"]["request_digest"] == "a" * 64  # unaffected


def test_seal_chat_completion_response_digest_present_and_confirmed_on_normal_response():
    state = _tmp_state()
    response_json = {"id": "x", "choices": []}
    capsule = cs._seal_chat_completion(
        state,
        client_nonce="n",
        client_nonce_source="sidecar_generated_fallback",
        request_json={"model": "m"},
        request_digest="a" * 64,
        response_json=response_json,
        status_code=200,
        latency_ms=1.0,
    )
    assert capsule["effect"]["response_digest"] == cs.digest_json(response_json)
    assert capsule["effect"]["status"] == "confirmed"


def test_seal_chat_completion_response_digest_mutant_without_guard_crashes(monkeypatch):
    real = cs._safe_digest_json

    def unguarded(value, *, field):
        if field == "response_digest[seal_chat_completion]":
            return cs.digest_json(value)
        return real(value, field=field)

    monkeypatch.setattr(cs, "_safe_digest_json", unguarded)
    state = _tmp_state()
    with pytest.raises(UnsafeIntegerError):
        cs._seal_chat_completion(
            state,
            client_nonce="n",
            client_nonce_source="sidecar_generated_fallback",
            request_json={"model": "m"},
            request_digest="a" * 64,
            response_json={"id": "x", "usage": {"total_tokens": OVERSIZED_INT}},
            status_code=200,
            latency_ms=1.0,
        )


# ── Sites :1743 / :1772 -- handle_chat_completion's own request_digest and ─
# ── response_digest (non-streaming, real upstream call) ────────────────────

class _StubUpstream(BaseHTTPRequestHandler):
    """/v1/chat/completions stub. ``mode`` selects the response body."""

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
        elif self.__class__.mode == "oversized_int_response":
            # A real 200 the sidecar cannot digest: valid JSON, but a
            # digest-bearing field carries an integer beyond +/-(2**53-1).
            payload = (
                b'{"id": "chatcmpl-2", "choices": [{"index": 0, "message": '
                b'{"role": "assistant", "content": "hi"}, "finish_reason": "stop"}], '
                b'"usage": {"total_tokens": 9007199254740993}}'
            )
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


def test_handle_chat_completion_request_digest_omitted_when_request_unsafe(stub_upstream):
    upstream_server, handler = stub_upstream
    handler.mode = "ok"
    state = _tmp_state()
    upstream_base = f"http://127.0.0.1:{upstream_server.server_address[1]}"
    raw_body = json.dumps({"model": "m", "trace_id": OVERSIZED_INT}).encode()

    status_code, body, out_headers = cs.handle_chat_completion(state, upstream_base, {}, raw_body)

    assert status_code == 200  # response path unaffected by the request-side guard
    assert json.loads(body)["id"] == "chatcmpl-1"

    from ledger_store_backend import read_all_capsules

    capsules, _archived = read_all_capsules(state.ledger_dir)
    assert len(capsules) == 1
    assert capsules[0]["effect"].get("request_digest") is None  # normalize() strips absent fields
    assert capsules[0]["effect"]["status"] == "confirmed"  # response WAS digestible
    assert capsules[0]["effect"]["response_digest"] is not None


def test_handle_chat_completion_request_digest_mutant_without_guard_crashes(stub_upstream, monkeypatch):
    upstream_server, handler = stub_upstream
    handler.mode = "ok"
    real = cs._safe_digest_json

    def unguarded(value, *, field):
        if field == "request_digest[handle_chat_completion]":
            return cs.digest_json(value)
        return real(value, field=field)

    monkeypatch.setattr(cs, "_safe_digest_json", unguarded)
    state = _tmp_state()
    upstream_base = f"http://127.0.0.1:{upstream_server.server_address[1]}"
    raw_body = json.dumps({"model": "m", "trace_id": OVERSIZED_INT}).encode()

    with pytest.raises(UnsafeIntegerError):
        cs.handle_chat_completion(state, upstream_base, {}, raw_body)


def test_handle_chat_completion_response_digest_omitted_and_downgrades_when_response_unsafe(stub_upstream):
    upstream_server, handler = stub_upstream
    handler.mode = "oversized_int_response"
    state = _tmp_state()
    upstream_base = f"http://127.0.0.1:{upstream_server.server_address[1]}"
    raw_body = json.dumps({"model": "m"}).encode()

    status_code, body, out_headers = cs.handle_chat_completion(state, upstream_base, {}, raw_body)

    assert status_code == 200  # the real upstream status is still forwarded honestly
    assert json.loads(body)["id"] == "chatcmpl-2"  # client still gets the real body

    from ledger_store_backend import read_all_capsules

    capsules, _archived = read_all_capsules(state.ledger_dir)
    assert len(capsules) == 1
    assert capsules[0]["effect"].get("response_digest") is None  # normalize() strips absent fields
    assert capsules[0]["effect"]["status"] == "failed"  # undigestable != confirmed
    assert capsules[0]["disposition"]["verdict_class"] == "errored"
    assert capsules[0]["effect"]["request_digest"] is not None  # request WAS digestible


def test_handle_chat_completion_response_digest_mutant_without_guard_crashes(stub_upstream, monkeypatch):
    upstream_server, handler = stub_upstream
    handler.mode = "oversized_int_response"
    real = cs._safe_digest_json

    def unguarded(value, *, field):
        if field == "response_digest[handle_chat_completion]":
            return cs.digest_json(value)
        return real(value, field=field)

    monkeypatch.setattr(cs, "_safe_digest_json", unguarded)
    state = _tmp_state()
    upstream_base = f"http://127.0.0.1:{upstream_server.server_address[1]}"
    raw_body = json.dumps({"model": "m"}).encode()

    with pytest.raises(UnsafeIntegerError):
        cs.handle_chat_completion(state, upstream_base, {}, raw_body)


# ── Sites :1898 (do_POST) / :1965 (streaming) -- live end-to-end HTTP ──────

@pytest.fixture
def sidecar(stub_upstream):
    upstream_server, handler = stub_upstream
    state = _tmp_state()
    upstream_base = f"http://127.0.0.1:{upstream_server.server_address[1]}"
    server = cs.run_sidecar(listen_host="127.0.0.1", listen_port=0, upstream_base=upstream_base, state=state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, state, handler
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _post(port: int, body: bytes, *, timeout: float = 10) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
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
    deadline = time.monotonic() + timeout
    entries: list[dict] = []
    while time.monotonic() < deadline:
        entries = _native_log_entries(state)
        if len(entries) >= count:
            return entries
        time.sleep(0.01)
    return entries


def test_do_post_oversized_request_int_response_path_unaffected_and_process_alive(sidecar):
    server, state, handler = sidecar
    handler.mode = "ok"
    port = server.server_address[1]

    status, body = _post(port, json.dumps({"model": "m", "trace_id": OVERSIZED_INT}).encode())
    assert status == 200  # response path unaffected

    entries = _wait_for_native_log_entries(state, 1)
    assert len(entries) == 1
    assert entries[0]["request_digest"] is None
    assert entries[0]["capsule_id"] is not None  # the exchange still sealed

    from ledger_store_backend import read_all_capsules

    capsules, _archived = read_all_capsules(state.ledger_dir)
    assert len(capsules) == 1
    assert capsules[0]["effect"].get("request_digest") is None  # normalize() strips absent fields
    assert capsules[0]["effect"]["status"] == "confirmed"

    # process alive: the SAME server instance still serves a normal request.
    status2, _ = _post(port, json.dumps({"model": "m"}).encode())
    assert status2 == 200


def test_do_post_request_digest_mutant_without_guard_crashes_the_connection(sidecar, monkeypatch):
    server, state, handler = sidecar
    handler.mode = "ok"
    port = server.server_address[1]
    real = cs._safe_digest_json

    def unguarded(value, *, field):
        if field == "request_digest[do_POST]":
            return cs.digest_json(value)
        return real(value, field=field)

    monkeypatch.setattr(cs, "_safe_digest_json", unguarded)

    # Before this task: an oversized-int request body raised out of do_POST
    # entirely -- no response, no native_log row, the exact silent crash the
    # x-mesh review flagged. http.client surfaces this as the server closing
    # the connection without sending a response.
    with pytest.raises((http.client.RemoteDisconnected, ConnectionResetError, http.client.BadStatusLine)):
        _post(port, json.dumps({"model": "m", "trace_id": OVERSIZED_INT}).encode(), timeout=5)

    entries = _native_log_entries(state)
    assert entries == []  # unguarded: the crash happens before record_native_request


def _sse_ok_payload() -> bytes:
    chunks = [
        {"id": "chatcmpl-s1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]},
        {"id": "chatcmpl-s1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "hi"}, "finish_reason": None}]},
        {"id": "chatcmpl-s1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    ]
    body = b"".join(f"data: {json.dumps(c)}\n\n".encode() for c in chunks) + b"data: [DONE]\n\n"
    return body


class _StubUpstreamSSE(_StubUpstream):
    def do_POST(self):  # noqa: N802
        if self.__class__.mode != "sse_ok":
            super().do_POST()
            return
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        payload = _sse_ok_payload()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def sse_sidecar():
    handler = type("Handler", (_StubUpstreamSSE,), {"mode": "sse_ok"})
    upstream_server = HTTPServer(("127.0.0.1", 0), handler)
    upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    upstream_thread.start()

    state = _tmp_state()
    upstream_base = f"http://127.0.0.1:{upstream_server.server_address[1]}"
    server = cs.run_sidecar(listen_host="127.0.0.1", listen_port=0, upstream_base=upstream_base, state=state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, state, handler
    finally:
        server.shutdown()
        thread.join(timeout=5)
        upstream_server.shutdown()
        upstream_thread.join(timeout=5)


def test_streaming_request_oversized_int_response_path_unaffected_and_process_alive(sse_sidecar):
    server, state, handler = sse_sidecar
    port = server.server_address[1]

    status, body = _post(port, json.dumps({"model": "m", "stream": True, "trace_id": OVERSIZED_INT}).encode())
    assert status == 200  # SSE response still delivered
    assert b"data: [DONE]" in body

    entries = _wait_for_native_log_entries(state, 1)
    assert len(entries) == 1
    assert entries[0]["request_digest"] is None
    assert entries[0]["capsule_id"] is not None  # the exchange still sealed

    from ledger_store_backend import read_all_capsules

    capsules, _archived = read_all_capsules(state.ledger_dir)
    assert len(capsules) == 1
    assert capsules[0]["effect"].get("request_digest") is None  # normalize() strips absent fields
    assert capsules[0]["effect"]["status"] == "confirmed"

    # process alive: a second streaming request on the same server succeeds.
    status2, body2 = _post(port, json.dumps({"model": "m", "stream": True}).encode())
    assert status2 == 200
    assert b"data: [DONE]" in body2


def test_streaming_request_digest_mutant_without_guard_crashes(sse_sidecar, monkeypatch):
    server, state, handler = sse_sidecar
    port = server.server_address[1]
    real = cs._safe_digest_json

    def unguarded(value, *, field):
        if field == "request_digest[streaming]":
            return cs.digest_json(value)
        return real(value, field=field)

    monkeypatch.setattr(cs, "_safe_digest_json", unguarded)

    # do_POST's own guard (request_digest[do_POST]) still fires first and
    # stays intact here, so the request reaches _handle_streaming_chat_
    # completion; ITS OWN separate digest_json(request_json) call (now
    # unguarded) is what raises, BEFORE any bytes of the SSE response are
    # written. do_POST's `except Exception` around the streaming dispatch
    # catches it and records a FAILED native_log row (the process itself
    # never crashes) but -- unlike the fixed behavior above -- returns from
    # do_POST having sent NO HTTP response at all (sending one after a
    # possible partial SSE write would corrupt the stream) and seals no
    # capsule. do_POST returning "successfully" (no uncaught exception)
    # means the framework treats the request as handled and keeps the
    # keep-alive connection open, so the client just hangs until its own
    # read timeout -- a silent hang, not a clean disconnect.
    with pytest.raises((TimeoutError, http.client.RemoteDisconnected, ConnectionResetError, http.client.BadStatusLine)):
        _post(port, json.dumps({"model": "m", "stream": True, "trace_id": OVERSIZED_INT}).encode(), timeout=2)

    entries = _wait_for_native_log_entries(state, 1)
    assert len(entries) == 1
    assert entries[0]["status"] == cs.NATIVE_STATUS_FAILED
    assert entries[0]["capsule_id"] is None  # unguarded: no capsule, unlike the fixed behavior

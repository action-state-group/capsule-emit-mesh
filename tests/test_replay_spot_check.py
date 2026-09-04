#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the C2a replay spot-check harness (`tools/replay_spot_check.py`).

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its
mutant. The suite below shows BOTH directions of the comparison — a
matched pair reported as `match: true` and a deliberately mismatched pair
(one sampled token flipped) reported as `match: false` — not just the
positive case, per the task's standing constraint 2.

Also asserts the standing scope constraint directly: `SpotCheckResult`
never grows a score/trust-rating field. That is checked here, not just
claimed in the docstring, so a future edit that adds one fails a test
instead of silently drifting past review.
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

# Stub heavy deps so these tests run without installing agent-action-capsule
# and scitt_cose (same pattern as test_forwarded_copy_and_keys.py).
# Apply the attribute stubs ONLY to names we actually created here (the
# not-installed path). Clobbering the real installed module's `.verify`/`.emit`
# leaked a `verify -> None` stub into every later test in the same process and
# broke the coordinator-receipt suite. `_stubbed` gates the clobber.
_stubbed: set[str] = set()
for _name in [
    "scitt_cose",
    "agent_action_capsule",
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]:
    if _name not in sys.modules:
        sys.modules[_name] = types.ModuleType(_name)
        _stubbed.add(_name)
if "agent_action_capsule.canonical" in _stubbed:
    sys.modules["agent_action_capsule.canonical"].json_digest = lambda v: hashlib.sha256(
        json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
if "agent_action_capsule.contracts" in _stubbed:
    for _n in ["Disposition", "EffectRecord"]:
        setattr(sys.modules["agent_action_capsule.contracts"], _n, object)
if "agent_action_capsule.emit" in _stubbed:
    sys.modules["agent_action_capsule.emit"].emit = lambda **k: {}
if "agent_action_capsule.verify" in _stubbed:
    sys.modules["agent_action_capsule.verify"].verify = lambda *a, **k: None
if "model_identity" in _stubbed:
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from replay_spot_check import (  # noqa: E402  (after sys.path/stub setup)
    ADVISORY,
    REPLAY_VOLATILE_FIELDS,
    SpotCheckResult,
    build_pinned_request,
    compare,
    run_replay,
)

VECTORS = Path(__file__).resolve().parent / "replay" / "vectors"


def _load(case: str, name: str) -> dict:
    return json.loads((VECTORS / case / name).read_text())


# ---------------------------------------------------------------------------
# Offline compare() — both directions, per QUEUE_PROTOCOL §7
# ---------------------------------------------------------------------------

def test_matched_pair_reports_match():
    response_a = _load("matched", "response_a.json")
    response_b = _load("matched", "response_b.json")
    result = compare(response_a, response_b)
    assert result.match is True
    assert result.digest_a == result.digest_b


def test_mismatched_pair_flipped_token_reports_mismatch():
    """The mandated mutant demonstration: flip one sampled token, mismatch fires."""
    response_a = _load("mismatched", "response_a.json")
    response_b = _load("mismatched", "response_b.json")
    result = compare(response_a, response_b)
    assert result.match is False
    assert result.digest_a != result.digest_b


def test_mismatch_mutant_of_the_matched_case():
    """Same fixture, mutated in-test: proves match=True isn't a tautology
    of the comparison always returning True. Flip one word, watch it flip.
    """
    response_a = _load("matched", "response_a.json")
    response_b = json.loads(json.dumps(_load("matched", "response_b.json")))
    baseline = compare(response_a, response_b)
    assert baseline.match is True

    response_b["choices"][0]["message"]["content"] = response_b["choices"][0]["message"]["content"].replace(
        "4 GPU-hours", "9 GPU-hours"
    )
    mutated = compare(response_a, response_b)
    assert mutated.match is False
    assert mutated.digest_b != baseline.digest_b


# ---------------------------------------------------------------------------
# REPLAY_VOLATILE_FIELDS — two-sided: excluded fields don't cause a false
# mismatch, non-excluded (content) fields still cause a real one.
# ---------------------------------------------------------------------------

def test_volatile_field_change_alone_still_reports_match():
    """The reviewer's exact repro: byte-identical content, fresh id/created."""
    response_a = _load("volatile-fields", "response_a.json")
    response_b = _load("volatile-fields", "response_b.json")
    assert response_a["id"] != response_b["id"]
    assert response_a["created"] != response_b["created"]
    assert response_a["choices"] == response_b["choices"]

    result = compare(response_a, response_b)

    assert result.match is True
    assert result.digest_a == result.digest_b


def test_content_field_change_still_reports_mismatch_alongside_volatile_change():
    """The two-sided complement: id/created differing does not mask a real
    content change -- exclusion narrows scope to REPLAY_VOLATILE_FIELDS and
    nothing else."""
    response_a = _load("volatile-fields", "response_a.json")
    response_b = json.loads(json.dumps(_load("volatile-fields", "response_b.json")))
    response_b["choices"][0]["message"]["content"] = "different content entirely"

    result = compare(response_a, response_b)

    assert result.match is False
    assert result.digest_a != result.digest_b


def test_replay_volatile_fields_is_exactly_id_and_created():
    assert REPLAY_VOLATILE_FIELDS == frozenset({"id", "created"})


# ---------------------------------------------------------------------------
# Scope guardrail: no scoring/trust-rating field, ever
# ---------------------------------------------------------------------------

def test_result_carries_no_scoring_or_trust_rating_field():
    result = compare(_load("matched", "response_a.json"), _load("matched", "response_b.json"))
    payload = result.to_dict()
    assert set(payload) == {"domain", "digest_a", "digest_b", "match", "advisory"}
    for forbidden in ("score", "confidence", "trust_score", "verdict"):
        assert forbidden not in payload


def test_advisory_is_a_fixed_constant_not_derived_from_outcome():
    matched = compare(_load("matched", "response_a.json"), _load("matched", "response_b.json"))
    mismatched = compare(_load("mismatched", "response_a.json"), _load("mismatched", "response_b.json"))
    assert matched.advisory == mismatched.advisory == ADVISORY
    assert "investigate" in ADVISORY and "verdict" in ADVISORY


# ---------------------------------------------------------------------------
# build_pinned_request — guardrail on the reproducible domain's precondition
# ---------------------------------------------------------------------------

def test_build_pinned_request_sets_temperature_zero_and_seed():
    pinned = build_pinned_request({"model": "m", "messages": []}, seed=7)
    assert pinned["temperature"] == 0
    assert pinned["seed"] == 7


def test_build_pinned_request_rejects_explicit_nonzero_temperature():
    with pytest.raises(ValueError):
        build_pinned_request({"model": "m", "messages": [], "temperature": 0.7})


# ---------------------------------------------------------------------------
# run_replay() end-to-end against a local stub upstream — both directions
# ---------------------------------------------------------------------------

class _StubUpstream(BaseHTTPRequestHandler):
    """Minimal /v1/chat/completions stub. Returns the next queued body.

    Must fully drain the request body and declare Content-Length on its own
    response: leaving unread bytes on a kept-alive HTTP/1.1 socket corrupts
    the framing of the connection's *next* response (observed directly while
    building this test — the second of two POSTs on the same connection came
    back as garbage/reset once request bodies were left unconsumed).
    """

    protocol_version = "HTTP/1.1"
    responses: list[dict] = []
    call_count = 0

    def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = self.__class__.responses[min(self.__class__.call_count, len(self.__class__.responses) - 1)]
        self.__class__.call_count += 1
        payload = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence test output
        pass


@pytest.fixture
def stub_upstream():
    handler = type("Handler", (_StubUpstream,), {"responses": [], "call_count": 0})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, handler
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_run_replay_live_match_direction(stub_upstream):
    server, handler = stub_upstream
    response = _load("matched", "response_a.json")
    handler.responses = [response, response]
    request_body = _load("matched", "request.json")

    result = run_replay(f"http://127.0.0.1:{server.server_port}", request_body)

    assert result.match is True
    assert handler.call_count == 2


def test_run_replay_live_mismatch_direction(stub_upstream):
    """The same end-to-end path, fed a divergent second response: mismatch fires."""
    server, handler = stub_upstream
    handler.responses = [
        _load("mismatched", "response_a.json"),
        _load("mismatched", "response_b.json"),
    ]
    request_body = _load("mismatched", "request.json")

    result = run_replay(f"http://127.0.0.1:{server.server_port}", request_body)

    assert result.match is False
    assert handler.call_count == 2


def test_run_replay_live_reports_match_with_fresh_id_and_created(stub_upstream):
    """End-to-end reviewer repro: a stub upstream that mints a fresh id/created
    on each call (as a real backend does) but returns byte-identical content
    must report match: true via the live path, not a false mismatch."""
    server, handler = stub_upstream
    handler.responses = [
        _load("volatile-fields", "response_a.json"),
        _load("volatile-fields", "response_b.json"),
    ]
    request_body = _load("volatile-fields", "request.json")

    result = run_replay(f"http://127.0.0.1:{server.server_port}", request_body)

    assert result.match is True
    assert handler.call_count == 2

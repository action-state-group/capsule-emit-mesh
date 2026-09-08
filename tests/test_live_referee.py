# SPDX-License-Identifier: Apache-2.0
"""Tests for the live E17c third-node referee call (`live_referee.py`).

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its
mutant.

  - the outbound request carries `x-mesh-target: <target_peer_id>`, the
    nonce on `X-Capsule-Client-Nonce`, and a prefix built from the twins'
    agreed-upon tokens
  - referee token matches twin A only -> contradicted(<twin B's owner>)
  - referee token matches twin B only -> contradicted(<twin A's owner>)
  - referee token matches neither -> inconclusive
  - a non-2xx / network failure raises `RefereeCallError`, never silently
    resolves to a verdict
  - `peer_info_from_status` never reads `weights_digest` off the live
    status JSON's `models`/`hosted_models` fields (E5 gap)

[mesh-referee-capsule-citation] `RefereeResult.capsule_id` is no longer
read from an (unverifiable, and in practice absent) `X-Capsule-Id`
response header -- it is resolved via `resolve_referee_record`:
`correlation{by: "nonce", value: <the nonce this call sent>}` against the
referee node's own evidence door, verified offline, and refused unless the
resolved record's own declared response digest matches what THIS module
actually received. Covered here:
  - no evidence-door transport configured -> `REFEREE_RECORD_UNRESOLVED`,
    cited by nonce alone, never a raise and never silently dropped
  - the door unreachable / refuses -> `REFEREE_RECORD_UNRESOLVED`
  - a genuinely matching, offline-verified bundle -> `REFEREE_RECORD_RESOLVED`,
    `capsule_id` set
  - mutant: the door hands back a DIFFERENT capsule for the same nonce
    (digest mismatch) -> `REFEREE_RECORD_CITATION_UNVERIFIED`, never cited
  - a bundle that fails offline verification -> `REFEREE_RECORD_CITATION_UNVERIFIED`
  - `live_referee()` wired end to end against a real fake evidence door
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit

import live_referee as lr
from capsule_sidecar import digest_json
from live_referee import (
    RefereeCallError,
    build_live_referee,
    live_referee,
    peer_info_from_status,
    resolve_referee_record,
)
from twin_adjudicator import (
    REFEREE_RECORD_CITATION_UNVERIFIED,
    REFEREE_RECORD_RESOLVED,
    REFEREE_RECORD_UNRESOLVED,
    VERDICT_INCONCLUSIVE,
    AdjudicationHalf,
    adjudicate,
    compare_transcripts,
)

REQUEST_DIGEST = "a" * 64


def _half(text: str, *, owner_id: str | None, request_messages: list[dict] | None = None) -> AdjudicationHalf:
    """A lightweight, NOT-necessarily-verifiable half -- fine for
    `live_referee()` tests, which never call `agent_action_capsule.verify()`
    themselves. Tests that route through `adjudicate()` need
    `_verifiable_half` instead."""
    capsule = {"capsule_id": f"capsule-{owner_id}", "model_attestation": {"compute_attestation": {}}}
    disclosed: dict = {"response_text": text, "response_body": {}}
    if request_messages is not None:
        disclosed["request_body"] = {"messages": request_messages}
    return AdjudicationHalf(capsule=capsule, disclosed=disclosed, owner_id=owner_id)


def _verifiable_half(text: str, *, owner_id: str) -> AdjudicationHalf:
    """A self-consistent, VERIFIABLE capsule (mirrors
    `test_twin_adjudicator.py`'s `_make_half`) -- needed for tests that
    route through `adjudicate()`, which verifies each half first."""
    body = {"choices": [{"message": {"role": "assistant", "content": text}}]}
    digest = digest_json(body)
    effect = EffectRecord(
        status="confirmed", type="inference_completion", request_digest=REQUEST_DIGEST, response_digest=digest
    )
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed")
    capsule = emit(
        action_type="decide",
        operator="test-org",
        developer="mesh-node@v1",
        compute_attestation={"owner": {"owner_id": owner_id}},
        effect=effect,
        disposition=disposition,
        tool_name="serve_exchange",
    )
    disclosed = {"capsule_id": capsule["capsule_id"], "response_body": body, "response_text": text}
    return AdjudicationHalf.from_capsule_and_disclosure(capsule, disclosed)


class _FakeRefereeNode:
    """A local HTTP server standing in for a mesh node's
    `/v1/chat/completions` endpoint -- captures the request it received
    (headers/body) and returns a canned response, same `ThreadingHTTPServer`
    convention `tests/test_adjudication_delivery.py` uses for its fake
    evidence door.
    """

    def __init__(self, *, response_text: str, status: int = 200, logprobs: dict | None = None):
        self.last_headers: dict = {}
        self.last_body: dict = {}
        response_text_ = response_text
        status_ = status
        logprobs_ = logprobs
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence test output
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                outer.last_headers = dict(self.headers.items())
                outer.last_body = json.loads(raw) if raw else {}

                message: dict = {"role": "assistant", "content": response_text_}
                choice: dict = {"message": message}
                if logprobs_ is not None:
                    choice["logprobs"] = logprobs_
                body = json.dumps({"choices": [choice]}).encode("utf-8")

                self.send_response(status_)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self._thread.join(timeout=5)


class _FakeEvidenceDoor:
    """A local HTTP server standing in for the referee node's E15
    `/evidence-request` door -- captures the request map it received and
    answers with a canned `{"bundles": [...]}` or `{"reason": ...}`
    payload."""

    def __init__(self, *, payload: dict):
        self.last_request_map: dict = {}
        payload_ = payload
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                outer.last_request_map = json.loads(raw) if raw else {}
                body = json.dumps(payload_).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self._thread.join(timeout=5)


class _FakeBundle:
    """Stand-in for `capsule_emit.bundle.Bundle` -- carries only the
    `.receipt` attribute `resolve_referee_record` actually reads. Used
    with monkeypatched `live_referee.Bundle`/`live_referee.verify_bundle`
    so these tests never need to fabricate a genuinely MMR/checkpoint/
    witness-verifiable bundle (a real one needs a live Transparency
    Service stub -- see `tests/test_ask_the_references.py` -- disproportionate
    for what this module's own resolution logic needs to prove)."""

    def __init__(self, receipt: dict):
        self.receipt = receipt

    @classmethod
    def from_dict(cls, d: dict) -> _FakeBundle:
        return cls(d["receipt"])


def _patch_bundle_verification(monkeypatch: pytest.MonkeyPatch, *, verify_ok: bool = True) -> None:
    monkeypatch.setattr(lr, "Bundle", _FakeBundle)
    monkeypatch.setattr(lr, "verify_bundle", lambda b: (verify_ok, [] if verify_ok else ["mutated"]))


def test_live_referee_sends_mesh_target_header_and_agreed_prefix():
    half_a = _half("the quick brown fox jumps", owner_id="owner-a", request_messages=[{"role": "user", "content": "describe the fox"}])
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)
    assert comparison.divergence_index == 3  # "the quick brown" agree, token 3 (fox/wolf) diverges

    node = _FakeRefereeNode(response_text="fox")
    try:
        result = live_referee(
            half_a, half_b, comparison,
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=42,
            nonce="nonce-agreed-prefix",
        )
    finally:
        node.close()

    assert node.last_headers.get("X-Mesh-Target") == "deadbeef" * 8
    assert node.last_headers.get("X-Capsule-Client-Nonce") == "nonce-agreed-prefix"
    sent_messages = node.last_body["messages"]
    assert sent_messages[0] == {"role": "user", "content": "describe the fox"}
    assert sent_messages[-1] == {"role": "assistant", "content": "the quick brown"}
    assert node.last_body["temperature"] == 0
    assert node.last_body["max_tokens"] == 1
    assert node.last_body["seed"] == 42
    # LIVE-CONFIRMED 2026-09-08: the current runtime 400s the whole request
    # if asked for logprobs -- must never be sent.
    assert "logprobs" not in node.last_body
    assert "top_logprobs" not in node.last_body
    assert result.verdict == "contradicted:owner-b"
    # No evidence-door transport configured -- unresolved, not a raise, not
    # a silently-dropped citation: the nonce still names the referee call.
    assert result.capsule_id is None
    assert result.referee_record_status == REFEREE_RECORD_UNRESOLVED
    assert result.referee_record_nonce == "nonce-agreed-prefix"


def test_live_referee_matches_twin_b_contradicts_twin_a():
    half_a = _half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)

    node = _FakeRefereeNode(response_text="wolf")
    try:
        result = live_referee(
            half_a, half_b, comparison,
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=1,
            nonce="nonce-b",
        )
    finally:
        node.close()

    assert result.verdict == "contradicted:owner-a"


def test_live_referee_matches_neither_is_inconclusive():
    half_a = _half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)

    node = _FakeRefereeNode(response_text="dog")
    try:
        result = live_referee(
            half_a, half_b, comparison,
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=1,
            nonce="nonce-c",
        )
    finally:
        node.close()

    assert result.verdict == VERDICT_INCONCLUSIVE


def test_live_referee_logprobs_absent_when_runtime_omits_them():
    half_a = _half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)

    node = _FakeRefereeNode(response_text="fox", logprobs=None)
    try:
        result = live_referee(
            half_a, half_b, comparison,
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=1,
            nonce="nonce-d",
        )
    finally:
        node.close()

    assert result.logprobs_absent is True
    assert result.margin == 0.0


def test_live_referee_reads_logprob_margin_when_present():
    """Forward-compatible parsing only -- the outbound request never asks
    for logprobs (see above), but IF a future/other runtime includes them
    unprompted, top2_logprob_margin must still read them correctly."""
    half_a = _half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)
    logprobs = {"content": [{"token": "fox", "top_logprobs": [{"token": "fox", "logprob": -0.1}, {"token": "wolf", "logprob": -3.0}]}]}

    node = _FakeRefereeNode(response_text="fox", logprobs=logprobs)
    try:
        result = live_referee(
            half_a, half_b, comparison,
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=1,
            nonce="nonce-e",
        )
    finally:
        node.close()

    assert result.logprobs_absent is False
    assert result.margin == pytest.approx(2.9)


def test_live_referee_raises_on_http_error_never_a_silent_verdict():
    half_a = _half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)

    node = _FakeRefereeNode(response_text="fox", status=500)
    try:
        with pytest.raises(RefereeCallError):
            live_referee(
                half_a, half_b, comparison,
                local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=1,
                nonce="nonce-f",
            )
    finally:
        node.close()


def test_live_referee_requires_a_real_divergence():
    half_a = _half("same text", owner_id="owner-a")
    half_b = _half("same text", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)
    assert comparison.divergence_index is None

    with pytest.raises(ValueError):
        live_referee(
            half_a, half_b, comparison,
            local_api_base_url="http://127.0.0.1:1", target_peer_id="deadbeef" * 8, model="test-model", seed=1,
            nonce="nonce-g",
        )


def test_build_live_referee_wires_end_to_end_through_adjudicate():
    """The whole live E17c wiring from the caller's side: adjudicate()
    calls the bound `Referee`, which makes the real HTTP call and folds the
    result back into an AdjudicationOutcome -- including the nonce
    citation in `references[]` when the evidence door is unresolved."""
    half_a = _verifiable_half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _verifiable_half("the quick brown wolf jumps", owner_id="owner-b")

    node = _FakeRefereeNode(response_text="fox")
    try:
        referee = build_live_referee(
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=7,
            nonce="nonce-h",
        )
        outcome = adjudicate(half_a, half_b, referee=referee, referee_owner_id="owner-c")
    finally:
        node.close()

    assert outcome.referee_called is True
    assert outcome.verdict == "contradicted:owner-b"
    assert outcome.referee_capsule_id is None
    assert outcome.references == (
        {"kind": "referee_capsule", "nonce": "nonce-h", "status": REFEREE_RECORD_UNRESOLVED, "capsule_id": None},
    )


def test_live_referee_resolves_capsule_id_via_nonce_correlation(monkeypatch):
    """End-to-end against a real fake evidence door: the referee call
    carries the nonce, the door is asked `correlation{by: "nonce", ...}`
    for it, and a matching, offline-verified record resolves
    `RefereeResult.capsule_id`."""
    _patch_bundle_verification(monkeypatch, verify_ok=True)
    half_a = _half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)

    expected_digest = digest_json({"choices": [{"message": {"role": "assistant", "content": "fox"}}]})
    node = _FakeRefereeNode(response_text="fox")
    door = _FakeEvidenceDoor(
        payload={"bundles": [{"receipt": {"capsule_id": "referee-cap-live", "effect": {"response_digest": expected_digest}}}]}
    )
    try:
        result = live_referee(
            half_a, half_b, comparison,
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=1,
            nonce="live-nonce-1", evidence_door_base_url=door.base_url,
        )
    finally:
        node.close()
        door.close()

    assert door.last_request_map["subject"] == {"kind": "correlation", "by": "nonce", "value": "live-nonce-1"}
    assert result.referee_record_status == REFEREE_RECORD_RESOLVED
    assert result.capsule_id == "referee-cap-live"
    assert result.referee_record_nonce == "live-nonce-1"


def test_live_referee_mutant_door_returns_different_capsule_is_citation_unverified(monkeypatch):
    """[mesh-referee-capsule-citation] mutant, at the `live_referee()`
    level: the evidence door answers the SAME nonce with a record for an
    unrelated response -- must never be cited as the referee's own
    capsule."""
    _patch_bundle_verification(monkeypatch, verify_ok=True)
    half_a = _half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)

    node = _FakeRefereeNode(response_text="fox")
    door = _FakeEvidenceDoor(
        payload={
            "bundles": [
                {"receipt": {"capsule_id": "someone-elses-capsule", "effect": {"response_digest": "digest-of-a-different-response"}}}
            ]
        }
    )
    try:
        result = live_referee(
            half_a, half_b, comparison,
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=1,
            nonce="live-nonce-2", evidence_door_base_url=door.base_url,
        )
    finally:
        node.close()
        door.close()

    assert result.referee_record_status == REFEREE_RECORD_CITATION_UNVERIFIED
    assert result.capsule_id is None
    assert result.referee_record_nonce == "live-nonce-2"


def test_resolve_referee_record_no_transport_is_unresolved():
    result = resolve_referee_record("nonce-1", expected_response_digest="digest-a", post=None)
    assert result.status == REFEREE_RECORD_UNRESOLVED
    assert result.nonce == "nonce-1"
    assert result.capsule_id is None


def test_resolve_referee_record_door_unreachable_is_unresolved():
    def _post(_request_map):
        raise urllib.error.URLError("connection refused")

    result = resolve_referee_record("nonce-2", expected_response_digest="digest-a", post=_post)
    assert result.status == REFEREE_RECORD_UNRESOLVED


def test_resolve_referee_record_door_refusal_is_unresolved():
    def _post(request_map):
        assert request_map == {"subject": {"kind": "correlation", "by": "nonce", "value": "nonce-3"}, "coverage": {}}
        return {"reason": "no_such_record", "request_digest": "x" * 64, "issued_at": "t", "key_id": "k", "sig": "s"}

    result = resolve_referee_record("nonce-3", expected_response_digest="digest-a", post=_post)
    assert result.status == REFEREE_RECORD_UNRESOLVED


def test_resolve_referee_record_resolves_and_verifies_matching_bundle(monkeypatch):
    _patch_bundle_verification(monkeypatch, verify_ok=True)

    def _post(request_map):
        assert request_map["subject"]["value"] == "nonce-4"
        return {"bundles": [{"receipt": {"capsule_id": "referee-cap-1", "effect": {"response_digest": "digest-match"}}}]}

    result = resolve_referee_record("nonce-4", expected_response_digest="digest-match", post=_post)
    assert result.status == REFEREE_RECORD_RESOLVED
    assert result.capsule_id == "referee-cap-1"


def test_resolve_referee_record_mutant_different_capsule_is_citation_unverified(monkeypatch):
    """[mesh-referee-capsule-citation] mutant: the door hands back a
    record for the right nonce, but it's someone else's capsule (a
    different declared response digest) -- never cited as verified."""
    _patch_bundle_verification(monkeypatch, verify_ok=True)

    def _post(_request_map):
        return {"bundles": [{"receipt": {"capsule_id": "some-other-capsule", "effect": {"response_digest": "digest-of-a-different-response"}}}]}

    result = resolve_referee_record("nonce-5", expected_response_digest="digest-actually-received", post=_post)
    assert result.status == REFEREE_RECORD_CITATION_UNVERIFIED
    assert result.capsule_id is None


def test_resolve_referee_record_failed_offline_verify_is_citation_unverified(monkeypatch):
    _patch_bundle_verification(monkeypatch, verify_ok=False)

    def _post(_request_map):
        return {"bundles": [{"receipt": {"capsule_id": "referee-cap-2", "effect": {"response_digest": "digest-match"}}}]}

    result = resolve_referee_record("nonce-6", expected_response_digest="digest-match", post=_post)
    assert result.status == REFEREE_RECORD_CITATION_UNVERIFIED
    assert result.capsule_id is None


def test_peer_info_from_status_never_reads_weights_digest_from_status_json():
    """[E5 gap] The per-node `local-gguf/sha256-...` load id is NOT the
    cross-node-stable weights_digest -- this adapter must never read one
    off `models`/`hosted_models`, only accept it as an explicit param."""
    peer_json = {
        "id": "c1b5861578",
        "state": "serving",
        "models": ["local-gguf/sha256-887fbdc66ab91eb5"],
        "hosted_models": ["local-gguf/sha256-887fbdc66ab91eb5"],
        "owner": {"status": "unsigned", "verified": False},
        "hostname": "swim-googles.local",
        "rtt_ms": 8,
        "latency_source": "direct",
        "is_soc": True,
        "gpus": [{"name": "Apple M3"}],
        "first_joined_mesh_ts": 1788874805066,
    }

    peer = peer_info_from_status(peer_json)

    assert peer.peer_id == "c1b5861578"
    assert peer.weights_digest is None
    assert peer.owner_id is None
    assert peer.owner_verified is False
    assert peer.hostname == "swim-googles.local"
    assert peer.gpus == ("Apple M3",)

    peer_with_digest = peer_info_from_status(peer_json, weights_digest="sha256-rehearsal-shared")
    assert peer_with_digest.weights_digest == "sha256-rehearsal-shared"

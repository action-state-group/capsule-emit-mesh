# SPDX-License-Identifier: Apache-2.0
"""Tests for the live E17c third-node referee call (`live_referee.py`).

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its
mutant.

  - the outbound request carries `x-mesh-target: <target_peer_id>` and a
    prefix built from the twins' agreed-upon tokens
  - referee token matches twin A only -> contradicted(<twin B's owner>)
  - referee token matches twin B only -> contradicted(<twin A's owner>)
  - referee token matches neither -> inconclusive
  - the response's `X-Capsule-Id` header is read back as
    `RefereeResult.capsule_id`
  - a non-2xx / network failure raises `RefereeCallError`, never silently
    resolves to a verdict
  - `peer_info_from_status` never reads `weights_digest` off the live
    status JSON's `models`/`hosted_models` fields (E5 gap)
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

from capsule_sidecar import digest_json
from live_referee import RefereeCallError, build_live_referee, live_referee, peer_info_from_status
from twin_adjudicator import AdjudicationHalf, VERDICT_INCONCLUSIVE, adjudicate, compare_transcripts

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

    def __init__(self, *, response_text: str, capsule_id: str | None = "referee-capsule-1", status: int = 200,
                 logprobs: dict | None = None):
        self.last_headers: dict = {}
        self.last_body: dict = {}
        response_text_ = response_text
        capsule_id_ = capsule_id
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
                if capsule_id_ is not None:
                    self.send_header("X-Capsule-Id", capsule_id_)
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
        )
    finally:
        node.close()

    assert node.last_headers.get("X-Mesh-Target") == "deadbeef" * 8
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
    assert result.capsule_id == "referee-capsule-1"


def test_live_referee_matches_twin_b_contradicts_twin_a():
    half_a = _half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _half("the quick brown wolf jumps", owner_id="owner-b")
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)

    node = _FakeRefereeNode(response_text="wolf")
    try:
        result = live_referee(
            half_a, half_b, comparison,
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=1,
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
        )


def test_build_live_referee_wires_end_to_end_through_adjudicate():
    """The whole live E17c wiring from the caller's side: adjudicate()
    calls the bound `Referee`, which makes the real HTTP call and folds the
    result back into an AdjudicationOutcome."""
    half_a = _verifiable_half("the quick brown fox jumps", owner_id="owner-a")
    half_b = _verifiable_half("the quick brown wolf jumps", owner_id="owner-b")

    node = _FakeRefereeNode(response_text="fox")
    try:
        referee = build_live_referee(
            local_api_base_url=node.base_url, target_peer_id="deadbeef" * 8, model="test-model", seed=7,
        )
        outcome = adjudicate(half_a, half_b, referee=referee, referee_owner_id="owner-c")
    finally:
        node.close()

    assert outcome.referee_called is True
    assert outcome.verdict == "contradicted:owner-b"
    assert outcome.referee_capsule_id == "referee-capsule-1"


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

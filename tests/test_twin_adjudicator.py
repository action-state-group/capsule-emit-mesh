# SPDX-License-Identifier: Apache-2.0
"""Tests for the E17a offline referee adjudicator (`twin_adjudicator.py`).

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its
mutant. Each acceptance mutant from the inbox item gets its own test:

  - bytes != digest -> abort            (PreimageDigestMismatchError)
  - forged half -> ✗                    (ForgedHalfError)
  - mismatched weights_digest -> no verdict, labeled weights_mismatch
  - same-owner twin -> twin_owner_distinct: false, no verdict
  - thin margin -> inconclusive
  - identical -> corroborated, zero network calls
"""
from __future__ import annotations

import socket

import pytest
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit

from capsule_sidecar import digest_json
from twin_adjudicator import (
    DEFAULT_MARGIN_TAU,
    NO_VERDICT_SAME_OWNER_TWIN,
    NO_VERDICT_WEIGHTS_MISMATCH,
    RELATION_ADJUDICATES,
    VERDICT_CORROBORATED,
    VERDICT_INCONCLUSIVE,
    AdjudicationHalf,
    ForgedHalfError,
    PreimageDigestMismatchError,
    adjudicate,
    compare_transcripts,
    contradicted,
    seal_adjudication_capsule,
)

REQUEST_DIGEST = "a" * 64  # a fixed, well-formed stand-in request_digest


def _response_body(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _make_half(
    text: str,
    *,
    owner_id: str | None = "owner-a",
    weights_digest: str | None = None,
    response_body: dict | None = None,
    declared_digest: str | None = None,
) -> AdjudicationHalf:
    """Build one fixture half: a self-consistent, VERIFIABLE capsule
    declaring response_digest over `response_body` (default: derived from
    `text`), plus the disclosed preimage PR #79's local store would carry.
    """
    body = response_body if response_body is not None else _response_body(text)
    digest = declared_digest if declared_digest is not None else digest_json(body)
    effect = EffectRecord(
        status="confirmed",
        type="inference_completion",
        request_digest=REQUEST_DIGEST,
        response_digest=digest,
    )
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed")
    compute_attestation = {"owner": {"owner_id": owner_id}} if owner_id is not None else {}
    capsule = emit(
        action_type="decide",
        operator="test-org",
        developer="mesh-node@v1",
        compute_attestation=compute_attestation,
        effect=effect,
        disposition=disposition,
        tool_name="serve_exchange",
    )
    disclosed = {"capsule_id": capsule["capsule_id"], "response_body": body, "response_text": text}
    return AdjudicationHalf.from_capsule_and_disclosure(capsule, disclosed, weights_digest=weights_digest)


# ---------------------------------------------------------------------------
# compare_transcripts -- pure, offline
# ---------------------------------------------------------------------------


def test_compare_transcripts_identical():
    result = compare_transcripts("the quick brown fox", "the quick brown fox")
    assert result.divergence_index is None
    assert result.margin == 1.0


def test_compare_transcripts_diverges_midway():
    result = compare_transcripts("the quick brown fox", "the quick red fox")
    assert result.divergence_index == 2  # "the quick" matches, "brown"/"red" diverge
    assert 0.0 < result.margin < 1.0


def test_compare_transcripts_diverges_immediately():
    result = compare_transcripts("alpha beta", "gamma delta")
    assert result.divergence_index == 0
    assert result.margin == 0.0
    assert result.prefix_digest is None


def test_compare_transcripts_length_mismatch_is_a_divergence():
    """A prefix match with a longer/shorter continuation is NOT 'identical'."""
    result = compare_transcripts("the quick brown fox", "the quick brown fox jumps")
    assert result.divergence_index == 4
    assert result.margin < 1.0


# ---------------------------------------------------------------------------
# Mutant: bytes != digest -> abort
# ---------------------------------------------------------------------------


def test_bytes_not_matching_digest_aborts():
    half_a = _make_half("hello world")
    # half_b's disclosed body is tampered post-seal -- no longer hashes to
    # the declared response_digest.
    half_b = _make_half("hello world")
    tampered = AdjudicationHalf(
        capsule=half_b.capsule,
        disclosed={**half_b.disclosed, "response_body": _response_body("TAMPERED")},
        owner_id=half_b.owner_id,
        weights_digest=half_b.weights_digest,
    )
    with pytest.raises(PreimageDigestMismatchError):
        adjudicate(half_a, tampered)


# ---------------------------------------------------------------------------
# Mutant: forged half -> ✗
# ---------------------------------------------------------------------------


def test_forged_half_fails_verify():
    half_a = _make_half("hello world")
    half_b = _make_half("hello world")
    # Tamper the capsule itself post-seal, WITHOUT recomputing capsule_id --
    # the paradigm forgery: content changed, signature/digest stale.
    forged_capsule = dict(half_b.capsule)
    forged_capsule["operator"] = "attacker-org"
    forged = AdjudicationHalf(
        capsule=forged_capsule,
        disclosed=half_b.disclosed,
        owner_id=half_b.owner_id,
        weights_digest=half_b.weights_digest,
    )
    with pytest.raises(ForgedHalfError):
        adjudicate(half_a, forged)


# ---------------------------------------------------------------------------
# Mutant: mismatched weights_digest -> no verdict, labeled weights_mismatch
# ---------------------------------------------------------------------------


def test_mismatched_weights_digest_no_verdict():
    half_a = _make_half("hello world", owner_id="owner-a", weights_digest="sha256:aaa")
    half_b = _make_half("hello world", owner_id="owner-b", weights_digest="sha256:bbb")

    outcome = adjudicate(half_a, half_b)

    assert outcome.verdict is None
    assert outcome.no_verdict_reason == NO_VERDICT_WEIGHTS_MISMATCH
    assert NO_VERDICT_WEIGHTS_MISMATCH != "coverage_unsatisfiable"


def test_weights_digest_absent_on_one_side_does_not_block():
    """E5 may be stubbed -- an unknown weights_digest on one side must not
    itself refuse adjudication (only a KNOWN, differing pair does)."""
    half_a = _make_half("hello world", owner_id="owner-a", weights_digest=None)
    half_b = _make_half("hello world", owner_id="owner-b", weights_digest="sha256:bbb")

    outcome = adjudicate(half_a, half_b)

    assert outcome.no_verdict_reason is None
    assert outcome.verdict == VERDICT_CORROBORATED


# ---------------------------------------------------------------------------
# Mutant: same-owner twin -> twin_owner_distinct: false, no verdict
# ---------------------------------------------------------------------------


def test_same_owner_twin_no_verdict():
    half_a = _make_half("hello world", owner_id="owner-a")
    half_b = _make_half("hello world", owner_id="owner-a")

    outcome = adjudicate(half_a, half_b)

    assert outcome.twin_owner_distinct is False
    assert outcome.verdict is None
    assert outcome.no_verdict_reason == NO_VERDICT_SAME_OWNER_TWIN


# ---------------------------------------------------------------------------
# Mutant: thin margin -> inconclusive
# ---------------------------------------------------------------------------


def test_thin_margin_is_inconclusive():
    half_a = _make_half("the quick brown fox jumps over the lazy dog", owner_id="owner-a")
    half_b = _make_half("the different sentence entirely here now", owner_id="owner-b")

    outcome = adjudicate(half_a, half_b)

    assert outcome.verdict == VERDICT_INCONCLUSIVE
    assert outcome.margin < DEFAULT_MARGIN_TAU


def test_inconclusive_is_not_an_error():
    """inconclusive is returned, never raised -- first-class, not a failure."""
    half_a = _make_half("alpha", owner_id="owner-a")
    half_b = _make_half("beta", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)  # must not raise
    assert outcome.verdict == VERDICT_INCONCLUSIVE


# ---------------------------------------------------------------------------
# Mutant: identical -> corroborated, zero network calls
# ---------------------------------------------------------------------------


def test_identical_transcripts_corroborated_zero_network_calls(monkeypatch):
    half_a = _make_half("the quick brown fox jumps over the lazy dog", owner_id="owner-a")
    half_b = _make_half("the quick brown fox jumps over the lazy dog", owner_id="owner-b")

    def _no_sockets(*_args, **_kwargs):
        raise AssertionError("adjudicate() must make zero network calls")

    monkeypatch.setattr(socket, "socket", _no_sockets)
    monkeypatch.setattr(socket, "create_connection", _no_sockets)

    outcome = adjudicate(half_a, half_b)

    assert outcome.verdict == VERDICT_CORROBORATED
    assert outcome.margin == 1.0
    assert outcome.divergence_index is None


# ---------------------------------------------------------------------------
# seal_adjudication_capsule
# ---------------------------------------------------------------------------


def test_seal_adjudication_capsule_for_corroborated_verdict():
    half_a = _make_half("same text", owner_id="owner-a")
    half_b = _make_half("same text", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)

    capsule = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")

    assert capsule is not None
    assert capsule["chain"]["relation"] == RELATION_ADJUDICATES
    assert capsule["chain"]["parent_capsule_id"] == half_a.capsule_id
    adj = capsule["model_attestation"]["compute_attestation"]["adjudication"]
    assert adj["verdict"] == VERDICT_CORROBORATED
    assert adj["half_a_capsule_id"] == half_a.capsule_id
    assert adj["half_b_capsule_id"] == half_b.capsule_id
    assert isinstance(adj["margin"], str)  # exact decimal string, never a float


def test_seal_adjudication_capsule_none_when_no_verdict():
    half_a = _make_half("hello world", owner_id="owner-a")
    half_b = _make_half("hello world", owner_id="owner-a")  # same owner
    outcome = adjudicate(half_a, half_b)

    assert seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1") is None


def test_contradicted_shape_reused_by_seal(monkeypatch):
    """adjudicate() never returns contradicted:<owner> (needs the E17b/E17c
    referee tiebreak this module doesn't have), but the shape is sealable
    for a caller (E17b/E17c) that does supply one."""
    half_a = _make_half("hello world", owner_id="owner-a")
    half_b = _make_half("hello world", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)
    forced = outcome.__class__(**{**outcome.__dict__, "verdict": contradicted("owner-b")})

    capsule = seal_adjudication_capsule(forced, operator="test-org", developer="referee@v1")
    assert capsule["model_attestation"]["compute_attestation"]["adjudication"]["verdict"] == "contradicted:owner-b"


def test_adjudicate_never_returns_contradicted():
    """This module's own adjudicate() has no referee tiebreak -- any
    divergence resolves to inconclusive, never contradicted:<owner>."""
    half_a = _make_half("the first version of events", owner_id="owner-a")
    half_b = _make_half("a completely different account", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)
    assert outcome.verdict != "contradicted"
    assert not (outcome.verdict or "").startswith("contradicted:")

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
    RefereeResult,
    adjudicate,
    compare_transcripts,
    contradicted,
    seal_adjudication_capsule,
    top2_logprob_margin,
)

REQUEST_DIGEST = "a" * 64  # a fixed, well-formed stand-in request_digest


def _response_body(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _logprobs_body(text: str, *, index: int, top1: float, top2: float) -> dict:
    """An OpenAI-compatible chat-completion body (`logprobs: true,
    top_logprobs: k` shape) whose whitespace-token `index` carries a
    two-candidate `top_logprobs` list with the given logprob values --
    everything `top2_logprob_margin` needs at that position. Other
    positions carry no `top_logprobs` (not needed by any test here).
    """
    tokens = text.split()
    content = [{"token": t, "logprob": -0.01, "top_logprobs": []} for t in tokens]
    if 0 <= index < len(content):
        content[index]["top_logprobs"] = [
            {"token": "a", "logprob": top1},
            {"token": "b", "logprob": top2},
        ]
    return {
        "choices": [
            {
                "message": {"role": "assistant", "content": text},
                "logprobs": {"content": content},
            }
        ]
    }


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
    """Without the opt-in logprob_tau/referee gate, adjudicate() never
    returns contradicted:<owner> -- but the shape is sealable for a caller
    that constructs (or, per test_wide_logprob_margin_calls_referee below,
    receives from a referee) an outcome carrying one."""
    half_a = _make_half("hello world", owner_id="owner-a")
    half_b = _make_half("hello world", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)
    forced = outcome.__class__(**{**outcome.__dict__, "verdict": contradicted("owner-b")})

    capsule = seal_adjudication_capsule(forced, operator="test-org", developer="referee@v1")
    assert capsule["model_attestation"]["compute_attestation"]["adjudication"]["verdict"] == "contradicted:owner-b"


def test_adjudicate_never_returns_contradicted():
    """Without the opt-in logprob_tau/referee gate, adjudicate() has no
    referee tiebreak -- any divergence resolves to inconclusive, never
    contradicted:<owner>."""
    half_a = _make_half("the first version of events", owner_id="owner-a")
    half_b = _make_half("a completely different account", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)
    assert outcome.verdict != "contradicted"
    assert not (outcome.verdict or "").startswith("contradicted:")


# ---------------------------------------------------------------------------
# top2_logprob_margin -- pure, offline
# ---------------------------------------------------------------------------


def test_top2_logprob_margin_computes_top1_minus_top2():
    body = _logprobs_body("the quick brown fox", index=3, top1=-0.1, top2=-2.3)
    assert top2_logprob_margin(body, 3) == pytest.approx(2.2)


def test_top2_logprob_margin_none_when_choices_missing():
    assert top2_logprob_margin({}, 0) is None


def test_top2_logprob_margin_none_when_logprobs_absent():
    assert top2_logprob_margin(_response_body("hello world"), 0) is None


def test_top2_logprob_margin_none_when_index_out_of_range():
    body = _logprobs_body("the quick brown fox", index=3, top1=-0.1, top2=-2.3)
    assert top2_logprob_margin(body, 99) is None


def test_top2_logprob_margin_none_when_fewer_than_two_candidates():
    body = _logprobs_body("the quick brown fox", index=3, top1=-0.1, top2=-2.3)
    body["choices"][0]["logprobs"]["content"][3]["top_logprobs"] = [{"token": "a", "logprob": -0.1}]
    assert top2_logprob_margin(body, 3) is None


# ---------------------------------------------------------------------------
# Opt-in logprob_tau/referee gate (inbox [mesh-twin-logprobs-passthrough])
# ---------------------------------------------------------------------------


def test_logprob_tau_requires_referee():
    half_a = _make_half("the quick brown fox", owner_id="owner-a")
    half_b = _make_half("the quick brown wolf", owner_id="owner-b")
    with pytest.raises(ValueError):
        adjudicate(half_a, half_b, logprob_tau=0.5)


def test_thin_logprob_margin_both_sides_is_inconclusive_no_referee_call():
    """Acceptance: same model both sides, fp-noise divergence -> inconclusive
    with zero referee calls, margin_a/margin_b recorded."""
    half_a = _make_half(
        "the quick brown fox",
        owner_id="owner-a",
        response_body=_logprobs_body("the quick brown fox", index=3, top1=-0.10, top2=-0.11),
    )
    half_b = _make_half(
        "the quick brown wolf",
        owner_id="owner-b",
        response_body=_logprobs_body("the quick brown wolf", index=3, top1=-0.10, top2=-0.12),
    )

    def _referee_must_not_be_called(*_args, **_kwargs):
        raise AssertionError("referee must not be called when both margins are thin")

    outcome = adjudicate(half_a, half_b, logprob_tau=0.5, referee=_referee_must_not_be_called)

    assert outcome.verdict == VERDICT_INCONCLUSIVE
    assert outcome.referee_called is False
    assert outcome.logprobs_absent is False
    assert outcome.tau == 0.5
    assert outcome.margin_a == pytest.approx(0.01)
    assert outcome.margin_b == pytest.approx(0.02)


def test_wide_logprob_margin_calls_referee_and_returns_contradicted():
    """Acceptance: q4 vs q8 -> wide margins -> referee -> contradicted, with
    the referee's own margin recorded (not the text-comparison margin)."""
    half_a = _make_half(
        "the quick brown fox",
        owner_id="owner-a",
        response_body=_logprobs_body("the quick brown fox", index=3, top1=-0.1, top2=-5.0),
    )
    half_b = _make_half(
        "the quick brown wolf",
        owner_id="owner-b",
        response_body=_logprobs_body("the quick brown wolf", index=3, top1=-0.1, top2=-5.2),
    )
    calls = []

    def _referee(a, b, comparison):
        calls.append((a, b, comparison))
        return RefereeResult(verdict=contradicted("owner-b"), margin=4.9)

    outcome = adjudicate(half_a, half_b, logprob_tau=0.5, referee=_referee)

    assert len(calls) == 1
    assert outcome.referee_called is True
    assert outcome.verdict == "contradicted:owner-b"
    assert outcome.margin == pytest.approx(4.9)  # the referee's margin, not compare_transcripts'
    assert outcome.logprobs_absent is False
    assert outcome.margin_a == pytest.approx(4.9)
    assert outcome.margin_b == pytest.approx(5.1)


def test_logprobs_absent_falls_back_to_referee_never_verdict_from_tokens_alone():
    """Mutant: a provider strips logprobs from its response -> adjudicator
    labels logprobs_absent and falls back to the referee path, never to a
    verdict from tokens alone."""
    half_a = _make_half(
        "the quick brown fox",
        owner_id="owner-a",
        response_body=_logprobs_body("the quick brown fox", index=3, top1=-0.10, top2=-0.11),
    )
    # half_b's provider stripped logprobs entirely -- plain response body.
    half_b = _make_half("the quick brown wolf", owner_id="owner-b")
    calls = []

    def _referee(a, b, comparison):
        calls.append((a, b, comparison))
        return RefereeResult(verdict=VERDICT_INCONCLUSIVE, margin=0.0)

    outcome = adjudicate(half_a, half_b, logprob_tau=0.5, referee=_referee)

    assert len(calls) == 1, "logprobs_absent must still reach the referee, never resolve on its own"
    assert outcome.referee_called is True
    assert outcome.logprobs_absent is True
    assert outcome.margin_a == pytest.approx(0.01)
    assert outcome.margin_b is None
    # The verdict came from the referee, not from compare_transcripts' margin
    # (which would have said "inconclusive" here too, by coincidence -- the
    # point is it must be the referee's answer, never derived independently).
    assert outcome.verdict == VERDICT_INCONCLUSIVE


def test_seal_adjudication_capsule_publishes_tau_and_margins():
    half_a = _make_half(
        "the quick brown fox",
        owner_id="owner-a",
        response_body=_logprobs_body("the quick brown fox", index=3, top1=-0.1, top2=-5.0),
    )
    half_b = _make_half(
        "the quick brown wolf",
        owner_id="owner-b",
        response_body=_logprobs_body("the quick brown wolf", index=3, top1=-0.1, top2=-5.2),
    )
    outcome = adjudicate(
        half_a,
        half_b,
        logprob_tau=0.5,
        referee=lambda a, b, comparison: RefereeResult(verdict=contradicted("owner-b"), margin=4.9),
    )

    capsule = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")

    adj = capsule["model_attestation"]["compute_attestation"]["adjudication"]
    assert adj["verdict"] == "contradicted:owner-b"
    assert adj["tau"] == "0.5"
    assert isinstance(adj["margin_a"], str)
    assert isinstance(adj["margin_b"], str)
    assert adj["logprobs_absent"] is False


def test_seal_adjudication_capsule_omits_tau_fields_when_gate_unused():
    """The E17a default path (no logprob_tau) must not grow new keys."""
    half_a = _make_half("same text", owner_id="owner-a")
    half_b = _make_half("same text", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)

    capsule = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")

    adj = capsule["model_attestation"]["compute_attestation"]["adjudication"]
    assert "tau" not in adj
    assert "margin_a" not in adj
    assert "margin_b" not in adj
    assert "logprobs_absent" not in adj

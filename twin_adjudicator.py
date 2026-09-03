# SPDX-License-Identifier: Apache-2.0
"""E17a — the offline referee adjudicator, from two already-sealed fixture halves.

Implements the offline slice of `docs`'s referee build spec (twin inference +
token-level adjudication), §2.2 items 2 and 4, **without** the live twin-send
or third-node referee step (those are E17b/E17c, upstream-gated on a twin
routing flag mesh-llm doesn't expose yet). Given two ALREADY-SEALED "halves"
of a would-be twin comparison — no network call is made or needed:

    compare_transcripts(text_a, text_b) -> ComparisonResult
        Binary-searches the two token sequences for the first divergent
        token (`None` when they fully agree), and reports a `margin` — the
        fraction of the longer sequence that matched before any divergence.

    adjudicate(half_a, half_b, margin_tau=...) -> AdjudicationOutcome
        The full pipeline: verify each half's own self-consistency (a
        forged half fails `agent_action_capsule.verify()`), verify the
        disclosed preimage actually hashes to the half's declared
        `response_digest` (PR #79's local disclosure store is the source of
        these bytes — see `capsule_sidecar.persist_disclosure_preimage`),
        check the two halves' `weights_digest` agree (E5; may be `None` on
        either side — stubbed until E5 lands) and their owners are
        distinct, then runs `compare_transcripts` on the disclosed response
        text and applies the margin-vs-`margin_tau` verdict rule.

    seal_adjudication_capsule(outcome, ...) -> capsule dict | None
        Mints the one new record this module adds: an ordinary capsule
        (built with `agent_action_capsule.emit()`, the same primitive
        every other capsule in this sidecar uses — no new record type)
        carrying `chain.relation = "adjudicates"` and a
        `compute_attestation.adjudication` block. Returns `None` when
        *outcome* has no verdict — a weights-mismatched or same-owner
        "twin" has nothing to adjudicate, so nothing is sealed.

WHAT THIS IS NOT — read before extending
-----------------------------------------
  - NOT a coordinator. There is no fan-out, no node selection, no live twin
    send here — those are E17b (twin send) and E17c (third-node referee),
    both upstream-gated and HELD.
  - NOT a scorer. `AdjudicationOutcome.margin` is the number the verdict
    rule compared against `margin_tau`, never a confidence/trust/reputation
    field, and no such field is ever added (same discipline as
    `output_cross_check.CrossCheckResult` and `replay_spot_check.SpotCheckResult`,
    which this module reuses the digest domain of).
  - Disagreement is a TRIGGER, not a verdict. Two-halves-only, this module
    can tell you the transcripts diverged; it cannot tell you WHICH twin is
    right — that needs the third-node referee tiebreak (E17c). So any
    divergence here resolves to `inconclusive`, never `contradicted:<owner>`
    — the `contradicted()` verdict SHAPE exists (reused by E17b/E17c, which
    DO have a referee tiebreak) but this module's own `adjudicate()` never
    produces it.
  - `inconclusive` is first-class, not a failure mode: it is the expected,
    common result of a thin or absent margin, and callers must not treat it
    as an error.

Two ways to be told "there's nothing to adjudicate," both first-class and
distinct from an exception:
  - `AdjudicationOutcome.no_verdict_reason == "weights_mismatch"` — the two
    halves didn't hold the same weights; nothing to compare. (NOT
    `coverage_unsatisfiable` — that is the referee-*request* refusal that
    lives in E17b/E17c, a different carrier entirely.)
  - `AdjudicationOutcome.no_verdict_reason == "same_owner_twin"` —
    `twin_owner_distinct` is `False`; comparing a node against itself proves
    nothing about independent agreement.

Two ways to be told the input itself can't be trusted, both raised, never
silently downgraded to a verdict:
  - `ForgedHalfError` — a half's capsule fails its own
    `agent_action_capsule.verify()`.
  - `PreimageDigestMismatchError` — a half's disclosed response body (the
    local preimage PR #79 persists) does not hash to the `response_digest`
    that half's capsule actually committed to.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_action_capsule.contracts import Disposition
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.numbers import float_to_str

from capsule_sidecar import digest_json

__all__ = [
    "CAPTURE_METHOD_DETERMINISTIC_REPLAY",
    "DEFAULT_MARGIN_TAU",
    "NO_VERDICT_SAME_OWNER_TWIN",
    "NO_VERDICT_WEIGHTS_MISMATCH",
    "RELATION_ADJUDICATES",
    "SOURCE_TWIN_COMPARISON",
    "VERDICT_CONTRADICTED_PREFIX",
    "VERDICT_CORROBORATED",
    "VERDICT_INCONCLUSIVE",
    "AdjudicationHalf",
    "AdjudicationOutcome",
    "ComparisonResult",
    "ForgedHalfError",
    "PreimageDigestMismatchError",
    "adjudicate",
    "compare_transcripts",
    "contradicted",
    "seal_adjudication_capsule",
]

#: The new chain.relation value (registry-governed but open -- an
#: unregistered chain.relation is informational, never a rejection; see
#: agent_action_capsule.registries).
RELATION_ADJUDICATES = "adjudicates"

SOURCE_TWIN_COMPARISON = "twin_comparison"
CAPTURE_METHOD_DETERMINISTIC_REPLAY = "deterministic_replay"
ADJUDICATION_SCHEMA = "capsule-emit-mesh/adjudication/v1"

#: Verdict SHAPES -- "contradicted" takes an owner. Never a score.
VERDICT_CORROBORATED = "corroborated"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_CONTRADICTED_PREFIX = "contradicted:"

#: no_verdict_reason values -- distinct from an exception: the inputs are
#: fine, there is simply nothing to adjudicate.
NO_VERDICT_WEIGHTS_MISMATCH = "weights_mismatch"
NO_VERDICT_SAME_OWNER_TWIN = "same_owner_twin"

#: Only a fully-matching comparison (margin == 1.0) clears the default
#: threshold. Two temperature-0, fixed-seed, same-weights runs are expected
#: to be byte-identical; any measured margin below this is, first-class,
#: `inconclusive` -- a trigger for the (separate, upstream-gated) referee
#: tiebreak, never a verdict this module reaches on its own.
DEFAULT_MARGIN_TAU = 1.0


def contradicted(owner_id: str) -> str:
    """Build a `"contradicted:<owner_id>"` verdict string.

    This module's own `adjudicate()` never returns this shape (see the
    module docstring) -- it exists so E17b/E17c, which DO run the
    third-node referee tiebreak, share one verdict vocabulary instead of
    reinventing the string format.
    """
    if not owner_id:
        raise ValueError("contradicted(owner_id) requires a non-empty owner_id")
    return f"{VERDICT_CONTRADICTED_PREFIX}{owner_id}"


class ForgedHalfError(RuntimeError):
    """A fixture half's capsule fails `agent_action_capsule.verify()`."""


class PreimageDigestMismatchError(RuntimeError):
    """A fixture half's disclosed preimage does not hash to its declared `response_digest`."""


@dataclass(frozen=True)
class AdjudicationHalf:
    """One twin-comparison fixture half: an already-sealed capsule plus its
    locally-disclosed request/response preimage (PR #79's disclosure store).

    `weights_digest` is NOT auto-extracted from `capsule` -- E5 (the
    `weights_digest`-at-load record field) doesn't exist in this repo yet,
    so there is no stable field location to read it from. Callers pass it
    explicitly (`None` when unknown, the honest default -- `adjudicate()`
    only refuses on a *known, differing* pair, never on absence).
    """

    capsule: dict[str, Any]
    disclosed: dict[str, Any]
    owner_id: str | None = None
    weights_digest: str | None = None

    @property
    def capsule_id(self) -> str:
        return self.capsule["capsule_id"]

    @property
    def declared_response_digest(self) -> str | None:
        return (self.capsule.get("effect") or {}).get("response_digest")

    @property
    def response_body(self) -> dict[str, Any]:
        return self.disclosed.get("response_body") or {}

    @property
    def response_text(self) -> str:
        return self.disclosed.get("response_text") or ""

    @classmethod
    def from_capsule_and_disclosure(
        cls,
        capsule: dict[str, Any],
        disclosed: dict[str, Any],
        *,
        weights_digest: str | None = None,
    ) -> AdjudicationHalf:
        """Build a half, auto-extracting `owner_id` from the capsule's
        existing `compute_attestation.owner` block (b4-who-did) -- a field
        this repo already carries. `weights_digest` is not on that block
        (E5 doesn't exist yet) and must be supplied by the caller.
        """
        owner = ((capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("owner") or {}
        return cls(
            capsule=capsule,
            disclosed=disclosed,
            owner_id=owner.get("owner_id"),
            weights_digest=weights_digest,
        )


def _tokenize(text: str) -> tuple[str, ...]:
    """Stand-in tokenizer: whitespace-split. A real BPE/SentencePiece
    tokenizer would give a tighter divergence_index (sub-word granularity);
    this is deliberately the same 'wire up the seam, not the real model'
    discipline `output_cross_check.py`'s trivial baseline uses -- swapping
    in a real tokenizer changes no caller.
    """
    return tuple(text.split())


@dataclass(frozen=True)
class ComparisonResult:
    """Pure output of `compare_transcripts` -- no verdict, just the measurement."""

    #: First token index at which the two sequences diverge. `None` when
    #: they are fully identical (same length, same tokens).
    divergence_index: int | None
    #: Fraction of the longer sequence that matched before any divergence
    #: (1.0 for a fully-identical pair).
    margin: float
    len_a: int
    len_b: int
    #: Digest over the agreed-upon prefix tokens, so a stranger can confirm
    #: they're checking the same shared prefix this result names. `None`
    #: when there is no matching prefix at all (immediate divergence).
    prefix_digest: str | None


def compare_transcripts(text_a: str, text_b: str) -> ComparisonResult:
    """Binary-search the first divergent token between two response texts.

    Pure function: does not know whether the two texts came from a live
    twin send or two files on disk. Runs entirely in-process on the given
    strings -- no I/O, no network.

    The search relies on prefix-equality being monotonic (`tokens_a[:k] ==
    tokens_b[:k]` implies the same holds for every `j < k`), so the largest
    matching-prefix length can be found in O(log n) comparisons instead of
    scanning token-by-token.
    """
    tokens_a = _tokenize(text_a)
    tokens_b = _tokenize(text_b)
    n = min(len(tokens_a), len(tokens_b))

    lo, hi = 0, n
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if tokens_a[:mid] == tokens_b[:mid]:
            lo = mid
        else:
            hi = mid - 1
    matched_len = lo

    identical = matched_len == len(tokens_a) == len(tokens_b)
    divergence_index = None if identical else matched_len

    total = max(len(tokens_a), len(tokens_b), 1)
    margin = matched_len / total

    prefix_digest = digest_json({"prefix_tokens": list(tokens_a[:matched_len])}) if matched_len else None

    return ComparisonResult(
        divergence_index=divergence_index,
        margin=margin,
        len_a=len(tokens_a),
        len_b=len(tokens_b),
        prefix_digest=prefix_digest,
    )


@dataclass(frozen=True)
class AdjudicationOutcome:
    """The result of `adjudicate()` -- either a verdict, or a first-class
    "nothing to adjudicate" reason. Never both."""

    verdict: str | None
    no_verdict_reason: str | None
    divergence_index: int | None
    margin: float
    margin_tau: float
    prefix_digest: str | None
    twin_owner_distinct: bool | None
    weights_digest: str | None
    half_a_capsule_id: str
    half_b_capsule_id: str
    source: str = SOURCE_TWIN_COMPARISON
    capture_method: str = CAPTURE_METHOD_DETERMINISTIC_REPLAY

    def has_verdict(self) -> bool:
        return self.verdict is not None


def _verify_half_or_raise(label: str, half: AdjudicationHalf) -> None:
    result = verify_capsule(half.capsule)
    if not result.ok:
        raise ForgedHalfError(
            f"{label} ({half.capsule_id[:16]}…) fails agent_action_capsule.verify(): {result.findings}"
        )


def _verify_preimage_or_raise(label: str, half: AdjudicationHalf) -> None:
    declared = half.declared_response_digest
    recomputed = digest_json(half.response_body)
    if declared is None or recomputed != declared:
        raise PreimageDigestMismatchError(
            f"{label} ({half.capsule_id[:16]}…): disclosed response digest {recomputed!r} "
            f"!= declared response_digest {declared!r} -- refusing to compare unverified bytes"
        )


def adjudicate(
    half_a: AdjudicationHalf,
    half_b: AdjudicationHalf,
    *,
    margin_tau: float = DEFAULT_MARGIN_TAU,
) -> AdjudicationOutcome:
    """Adjudicate two twin-comparison fixture halves, offline, no network.

    Order of checks (each a distinct, independently-tested mutant):

    1. Each half's capsule must pass its own `verify()` -- a forged half
       raises `ForgedHalfError`.
    2. Each half's disclosed response body must hash to that half's
       declared `response_digest` -- a mismatch raises
       `PreimageDigestMismatchError` (abort BEFORE any comparison; never
       reason about bytes that don't match what was actually sealed).
    3. If both halves declare a `weights_digest` and they differ, there is
       nothing to adjudicate -- returns with
       `no_verdict_reason="weights_mismatch"`.
    4. If both halves' owners are known and equal, this isn't an
       independent twin -- returns with `twin_owner_distinct=False`,
       `no_verdict_reason="same_owner_twin"`.
    5. Otherwise, `compare_transcripts` the disclosed response text. A full
       match (`margin >= margin_tau`) is `corroborated`; anything else is
       `inconclusive` -- disagreement is a trigger for the (separate)
       referee tiebreak, never a verdict this function reaches alone.
    """
    _verify_half_or_raise("half_a", half_a)
    _verify_half_or_raise("half_b", half_b)
    _verify_preimage_or_raise("half_a", half_a)
    _verify_preimage_or_raise("half_b", half_b)

    half_a_id = half_a.capsule_id
    half_b_id = half_b.capsule_id

    if (
        half_a.weights_digest is not None
        and half_b.weights_digest is not None
        and half_a.weights_digest != half_b.weights_digest
    ):
        return AdjudicationOutcome(
            verdict=None,
            no_verdict_reason=NO_VERDICT_WEIGHTS_MISMATCH,
            divergence_index=None,
            margin=0.0,
            margin_tau=margin_tau,
            prefix_digest=None,
            twin_owner_distinct=None,
            weights_digest=None,
            half_a_capsule_id=half_a_id,
            half_b_capsule_id=half_b_id,
        )

    shared_weights_digest = half_a.weights_digest or half_b.weights_digest

    twin_owner_distinct: bool | None = None
    if half_a.owner_id is not None and half_b.owner_id is not None:
        twin_owner_distinct = half_a.owner_id != half_b.owner_id

    if twin_owner_distinct is False:
        return AdjudicationOutcome(
            verdict=None,
            no_verdict_reason=NO_VERDICT_SAME_OWNER_TWIN,
            divergence_index=None,
            margin=0.0,
            margin_tau=margin_tau,
            prefix_digest=None,
            twin_owner_distinct=False,
            weights_digest=shared_weights_digest,
            half_a_capsule_id=half_a_id,
            half_b_capsule_id=half_b_id,
        )

    comparison = compare_transcripts(half_a.response_text, half_b.response_text)
    verdict = VERDICT_CORROBORATED if comparison.margin >= margin_tau else VERDICT_INCONCLUSIVE

    return AdjudicationOutcome(
        verdict=verdict,
        no_verdict_reason=None,
        divergence_index=comparison.divergence_index,
        margin=comparison.margin,
        margin_tau=margin_tau,
        prefix_digest=comparison.prefix_digest,
        twin_owner_distinct=twin_owner_distinct,
        weights_digest=shared_weights_digest,
        half_a_capsule_id=half_a_id,
        half_b_capsule_id=half_b_id,
    )


def seal_adjudication_capsule(
    outcome: AdjudicationOutcome,
    *,
    action: str = "adjudicate",
    operator: str = "",
    developer: str = "",
) -> dict[str, Any] | None:
    """Seal the one new record this module adds: an adjudication capsule.

    Built with `agent_action_capsule.emit()` -- the same primitive every
    other capsule in this sidecar uses (see `capsule_sidecar.build_capsule`)
    -- so this is not a new record type, just a new `chain.relation` value
    and a `compute_attestation.adjudication` block.

    Returns `None`, sealing nothing, when *outcome* has no verdict: a
    weights-mismatched or same-owner "twin" has nothing to adjudicate (see
    the module docstring) -- there is no "refused" adjudication capsule.
    """
    if outcome.verdict is None:
        return None

    compute_attestation = {
        "adjudication": {
            "schema": ADJUDICATION_SCHEMA,
            "source": outcome.source,
            "capture_method": outcome.capture_method,
            "verdict": outcome.verdict,
            "divergence_index": outcome.divergence_index,
            # §5.1: a JSON float in a digest-bearing field raises
            # FloatInDigestError -- margin/margin_tau travel as exact
            # decimal strings (RFC 8785 §3.2.2.3).
            "margin": float_to_str(outcome.margin, field="adjudication.margin"),
            "margin_tau": float_to_str(outcome.margin_tau, field="adjudication.margin_tau"),
            "prefix_digest": outcome.prefix_digest,
            "twin_owner_distinct": outcome.twin_owner_distinct,
            "weights_digest": outcome.weights_digest,
            "half_a_capsule_id": outcome.half_a_capsule_id,
            "half_b_capsule_id": outcome.half_b_capsule_id,
        }
    }
    disposition = Disposition(
        decision="accept",
        approver="policy",
        human_disposed=False,
        verdict_class="assessed",
    )

    capsule = emit(
        action_type="decide",
        operator=operator,
        developer=developer,
        compute_attestation=compute_attestation,
        disposition=disposition,
        prior_capsule_id=outcome.half_a_capsule_id,
        chain_relation=RELATION_ADJUDICATES,
        domain="action",
        provenance="referee",
        tool_name=action,
    )

    # [adv-run-2-fix-batch] discipline: verify BEFORE returning -- an
    # adjudication capsule that fails its own verify() must never be handed
    # to a caller that might persist it.
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"adjudicator emitted a capsule that fails its own verify(): {result.findings}")
    return capsule

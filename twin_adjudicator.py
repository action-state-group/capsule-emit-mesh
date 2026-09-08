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

    top2_logprob_margin(response_body, index) -> float | None
        The top1-minus-top2 logprob margin at a token index, read from an
        OpenAI-compatible `choices[0].logprobs.content[index].top_logprobs`
        (the twin-flag design's "return logprobs on any twinned response" —
        `_work/mesh-issue-ladder-2026-09-05/tier3-09-twin-flag-v1.md`).
        `None` — logprobs absent — when that data isn't there.

    adjudicate(half_a, half_b, margin_tau=..., logprob_tau=None, referee=None,
               referee_owner_id=None) -> AdjudicationOutcome
        The full pipeline: verify each half's own self-consistency (a
        forged half fails `agent_action_capsule.verify()`), verify the
        disclosed preimage actually hashes to the half's declared
        `response_digest` (PR #79's local disclosure store is the source of
        these bytes — see `capsule_sidecar.persist_disclosure_preimage`),
        check the two halves' `weights_digest` agree (E5; may be `None` on
        either side — stubbed until E5 lands) and their owners are
        distinct, then runs `compare_transcripts` on the disclosed response
        text and applies the margin-vs-`margin_tau` verdict rule.

        [mesh-referee-live-e17c ruling, 2026-09-08] Escalation to a referee
        is triggered by TEXT DIVERGENCE ALONE — never gated on the
        disputants' own logprobs (`half_a`/`half_b` self-report them; a
        liar can report a thin margin and dodge escalation entirely). Given
        a `referee` callable, ANY divergence calls it — no `logprob_tau`
        required. Before calling, if `referee_owner_id` is given and
        matches either half's `owner_id`, the call is refused entirely
        (`no_verdict_reason="referee_not_independent"`) — a referee that
        shares an owner with a disputant proves nothing, so this module
        never even asks it.

        `logprob_tau`, now opt-in and orthogonal to whether the referee is
        called, applies ONLY to the referee's OWN logprob margin (never the
        disputants'): a thin margin on the referee's own answer overrides
        its verdict to `inconclusive`. Absent referee logprobs (today's
        live reality — no runtime returns them yet) is inert — the
        referee's verdict is adopted unchanged — but is always labeled
        `referee_logprobs_absent` so a verifier can see the gate never
        actually ran. This is the only way `adjudicate()` can return
        `contradicted:<owner_id>`.

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
  - NOT a coordinator. There is no fan-out, no node selection here — that
    is `twin_selection.select_referee` (E17c). `adjudicate(...,
    referee=...)` accepts an injected `Referee` callable so a caller
    supplies the actual live third-node recompute (`live_referee.py`, the
    E17c wiring) — this module still never dials the network itself; it
    only decides WHEN to call the callable it was handed and how to fold
    its result into a verdict.
  - NOT a scorer. `AdjudicationOutcome.margin` is the number the verdict
    rule compared against `margin_tau` (or, on the referee path, the
    referee's own margin) — never a confidence/trust-rating field, and no
    such field is ever added (same discipline as
    `output_cross_check.CrossCheckResult` and `replay_spot_check.SpotCheckResult`,
    which this module reuses the digest domain of).
  - Disagreement is a TRIGGER, not a verdict on its own. Two-halves-only,
    text-margin comparison can tell you the transcripts diverged; it cannot
    tell you WHICH twin is right — that needs the third-node referee
    tiebreak. Without a `referee` callable, any divergence resolves to
    `inconclusive`, never `contradicted:<owner>`. Given a `referee`, any
    divergence calls it (subject to the independence refusal above) and
    adopts ITS verdict — `contradicted:<owner>` is then possible, but it is
    always the referee's call, never something this module derives from
    tokens alone.
  - `inconclusive` is first-class, not a failure mode: it is the expected,
    common result of a thin or absent margin (or a referee whose own
    logprob margin was thin), and callers must not treat it as an error.

Three ways to be told "there's nothing to adjudicate," all first-class and
distinct from an exception:
  - `AdjudicationOutcome.no_verdict_reason == "weights_mismatch"` — the two
    halves didn't hold the same weights; nothing to compare. (NOT
    `coverage_unsatisfiable` — that is a referee-*request* refusal, a
    different carrier entirely.)
  - `AdjudicationOutcome.no_verdict_reason == "same_owner_twin"` —
    `twin_owner_distinct` is `False`; comparing a node against itself proves
    nothing about independent agreement.
  - `AdjudicationOutcome.no_verdict_reason == "referee_not_independent"` —
    the caller-supplied `referee_owner_id` matches either half's
    `owner_id`; a referee that shares an owner with a disputant is refused
    BEFORE it is ever called, never adopted as a tiebreak.

Two ways to be told the input itself can't be trusted, both raised, never
silently downgraded to a verdict:
  - `ForgedHalfError` — a half's capsule fails its own
    `agent_action_capsule.verify()`.
  - `PreimageDigestMismatchError` — a half's disclosed response body (the
    local preimage PR #79 persists) does not hash to the `response_digest`
    that half's capsule actually committed to.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_action_capsule.contracts import Disposition
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.numbers import float_to_str

from capsule_sidecar import ROLE_PROVIDER, digest_json

__all__ = [
    "CAPTURE_METHOD_DETERMINISTIC_REPLAY",
    "DEFAULT_MARGIN_TAU",
    "NO_VERDICT_NO_REQUESTER_TRANSCRIPT",
    "NO_VERDICT_REFEREE_NOT_INDEPENDENT",
    "NO_VERDICT_SAME_OWNER_TWIN",
    "NO_VERDICT_WEIGHTS_MISMATCH",
    "REFEREE_RECORD_CITATION_UNVERIFIED",
    "REFEREE_RECORD_RESOLVED",
    "REFEREE_RECORD_UNRESOLVED",
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
    "Referee",
    "RefereeResult",
    "adjudicate",
    "compare_transcripts",
    "contradicted",
    "seal_adjudication_capsule",
    "token_at",
    "top2_logprob_margin",
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
#: [mesh-provider-no-body-persistence] The referee spec is explicit: the
#: REQUESTER holds both twin responses. A half whose sealed serving_provenance
#: names it as the provider role -- and carries no disclosed response body --
#: has no transcript this module could ever have compared; refuse cleanly
#: (`inconclusive: no_requester_transcript`) instead of letting
#: _verify_preimage_or_raise crash on an always-empty disclosed dict.
NO_VERDICT_NO_REQUESTER_TRANSCRIPT = "no_requester_transcript"
#: [mesh-referee-live-e17c] The caller-supplied `referee_owner_id` matches
#: either half's `owner_id` -- refused BEFORE the referee is ever called;
#: see the module docstring's independence-refusal paragraph.
NO_VERDICT_REFEREE_NOT_INDEPENDENT = "referee_not_independent"

#: [mesh-referee-capsule-citation] `RefereeResult.referee_record_status` /
#: an `AdjudicationOutcome.references[]` entry's own `status` -- three
#: states, never a silent fourth. `RESOLVED`: the referee node's own
#: sealed half was found via `correlation{by: "nonce", ...}` against its
#: evidence door, verified offline, and its OWN declared response digest
#: matched what the referee call actually received -- `capsule_id` is
#: trustworthy. `CITATION_UNVERIFIED`: the door answered with a record for
#: the nonce, but it either failed offline verification or its digest did
#: NOT match -- never cited as the referee's capsule. `UNRESOLVED`: no
#: evidence-door transport was configured, or the door was unreachable /
#: refused / had nothing for the nonce -- cited by nonce alone.
REFEREE_RECORD_RESOLVED = "resolved"
REFEREE_RECORD_CITATION_UNVERIFIED = "citation_unverified"
REFEREE_RECORD_UNRESOLVED = "unresolved"

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

    @property
    def request_body(self) -> dict[str, Any]:
        """The disclosed REQUEST preimage (``capsule_sidecar.
        persist_disclosure_preimage``'s ``request_body`` key) -- the
        original prompt this half answered, needed by a live `Referee`
        (`live_referee.py`) to reconstruct [prompt + agreed response
        prefix] for the third-node recompute. `{}` when absent (older
        disclosure records, or a caller that never persisted one)."""
        return self.disclosed.get("request_body") or {}

    @property
    def request_text(self) -> str:
        return self.disclosed.get("request_text") or ""

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


def top2_logprob_margin(response_body: dict[str, Any], index: int) -> float | None:
    """Top-2 logprob margin (top1 - top2, always >= 0) for the token at
    `index` of an OpenAI-compatible chat-completion response's
    `choices[0].logprobs.content[index].top_logprobs` (the shape returned
    when the request set `logprobs: true, top_logprobs: k`).

    `None` -- "logprobs absent" -- whenever the data needed isn't there:
    no `choices`, no `logprobs` block, `index` past the end of `content`,
    or fewer than two candidates at that position. Never raises; absence is
    the caller's `logprobs_absent` signal, not an error.

    `index` is `divergence_index`, itself computed by the whitespace
    `_tokenize` stand-in -- alignment against the API's own token-level
    `content` array is best-effort, the same seam-not-model discipline
    `_tokenize`'s own docstring names.
    """
    choices = response_body.get("choices") or []
    if not choices:
        return None
    logprobs = (choices[0] or {}).get("logprobs")
    if not logprobs:
        return None
    content = logprobs.get("content") or []
    if index is None or index < 0 or index >= len(content):
        return None
    top_logprobs = (content[index] or {}).get("top_logprobs") or []
    if len(top_logprobs) < 2:
        return None
    ranked = sorted((entry["logprob"] for entry in top_logprobs), reverse=True)
    return ranked[0] - ranked[1]


def _tokenize(text: str) -> tuple[str, ...]:
    """Stand-in tokenizer: whitespace-split. A real BPE/SentencePiece
    tokenizer would give a tighter divergence_index (sub-word granularity);
    this is deliberately the same 'wire up the seam, not the real model'
    discipline `output_cross_check.py`'s trivial baseline uses -- swapping
    in a real tokenizer changes no caller.
    """
    return tuple(text.split())


def token_at(text: str, index: int) -> str | None:
    """The token at `index` of `text`'s `_tokenize` split, `None` when
    `index` is out of range (a sequence that ended before the divergence
    point) or negative. Public so a `Referee` implementation (e.g.
    `live_referee.py`'s live third-node call) can align its own single-token
    response against a half's token at `comparison.divergence_index` using
    the SAME whitespace-split stand-in this module's own comparison uses --
    never a second, silently-different tokenizer.
    """
    if index is None or index < 0:
        return None
    tokens = _tokenize(text)
    if index >= len(tokens):
        return None
    return tokens[index]


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
class RefereeResult:
    """What a referee tiebreak (a third-owner one-token recompute over the
    shared prefix, per the twin-flag design) reports back: its own verdict
    (`corroborated`, `inconclusive`, or `contradicted:<owner_id>` -- the
    same closed vocabulary `contradicted()` builds), its own top2-logprob
    margin (0.0 and `logprobs_absent=True` when the runtime didn't return
    any -- today's live reality), and the capsule id the referee node
    sealed for its OWN served half, so the adjudication record can cite it
    alongside `half_a_capsule_id`/`half_b_capsule_id`. Never constructed by
    this module -- callers supply a `Referee` that returns one (see
    `live_referee.py` for the live third-node implementation).

    [mesh-referee-capsule-citation] `capsule_id` is set ONLY when
    `referee_record_status == REFEREE_RECORD_RESOLVED` -- i.e. resolved via
    `correlation{by: "nonce", ...}` against the referee node's own evidence
    door and verified offline (see `live_referee.resolve_referee_record`),
    never trusted from an unverifiable transport-level hint alone.
    `referee_record_nonce` is set whenever the referee call itself carried
    a nonce, REGARDLESS of resolution outcome -- so a caller can always
    cite by nonce even when `referee_record_status` is
    `REFEREE_RECORD_UNRESOLVED` (never a silent omission).
    """

    verdict: str
    margin: float = 0.0
    logprobs_absent: bool = False
    capsule_id: str | None = None
    referee_record_status: str = REFEREE_RECORD_UNRESOLVED
    referee_record_nonce: str | None = None


#: A referee call: given both halves and the `ComparisonResult` that
#: triggered it, returns the tiebreak. This module does not implement one
#: itself -- see `live_referee.py` for the live third-node recompute --
#: callers of `adjudicate(..., referee=...)` supply their own.
Referee = Callable[[AdjudicationHalf, AdjudicationHalf, ComparisonResult], RefereeResult]


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
    #: Set only when `adjudicate()` was called with `logprob_tau` -- the
    #: referee's-own-logprob-margin gate is opt-in and leaves this `None`
    #: for a caller that never asked for it.
    tau: float | None = None
    #: True when the referee's OWN logprobs couldn't be read (today's live
    #: reality -- no runtime returns them yet). Inert, not a refusal: the
    #: referee's verdict is still adopted, but labeled so a verifier can see
    #: the `logprob_tau` gate never actually ran. Never about the
    #: disputants' own (self-reported, unsound) logprobs -- see the module
    #: docstring's 2026-09-08 ruling.
    referee_logprobs_absent: bool = False
    referee_called: bool = False
    #: The capsule id the referee node sealed for its own served half --
    #: the fourth citation alongside `half_a_capsule_id`/`half_b_capsule_id`
    #: (`adjudication_delivery._cited_capsule_ids` picks up any
    #: `*_capsule_id`-suffixed key automatically). `None` when no referee
    #: was called, OR when one was but its record never resolved/verified
    #: (see `references` below -- the nonce citation still survives even
    #: then).
    referee_capsule_id: str | None = None
    #: [mesh-referee-capsule-citation] One entry per cited external record
    #: this outcome could not fold into a plain `*_capsule_id` field --
    #: today, at most one: the referee's own nonce-correlation resolution,
    #: `{"kind": "referee_capsule", "nonce", "status", "capsule_id"}`.
    #: Populated whenever `referee_called` and the referee call carried a
    #: nonce, REGARDLESS of `status` -- an unresolved/unverified door still
    #: gets an entry (nonce cited, `capsule_id: None`), never a silent
    #: omission. Empty tuple when no referee was called.
    references: tuple[dict[str, Any], ...] = ()

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


def _half_role(half: AdjudicationHalf) -> str | None:
    """The half's sealed `serving_provenance.role` ("provider"/"requester"),
    read from the same `x-mesh-poc-v1` block `capsule_mesh_viewer.
    serving_provenance()` reads. `None` for a capsule sealed before
    b6a-requester-seal, which carries neither -- never fabricated."""
    poc = ((half.capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("x-mesh-poc-v1") or {}
    return (poc.get("serving_provenance") or {}).get("role")


def _no_requester_transcript(half: AdjudicationHalf) -> bool:
    """True when this half is a provider-role capsule with no disclosed
    response body -- i.e. there is, by construction, no requester-held
    transcript for it (mesh-provider-no-body-persistence: the provider role
    has no disclosure write path at all). A provider-role half that somehow
    DOES carry a disclosed response body (e.g. a caller manually attached
    one) is not blocked here -- this only refuses the case that would
    otherwise crash `_verify_preimage_or_raise` on an always-empty dict."""
    return _half_role(half) == ROLE_PROVIDER and not half.disclosed.get("response_body")


def adjudicate(
    half_a: AdjudicationHalf,
    half_b: AdjudicationHalf,
    *,
    margin_tau: float = DEFAULT_MARGIN_TAU,
    logprob_tau: float | None = None,
    referee: Referee | None = None,
    referee_owner_id: str | None = None,
) -> AdjudicationOutcome:
    """Adjudicate two twin-comparison fixture halves, offline, no network
    (unless a `referee` is given and a divergence actually calls it).

    Order of checks (each a distinct, independently-tested mutant):

    1. Each half's capsule must pass its own `verify()` -- a forged half
       raises `ForgedHalfError`.
    2. [mesh-provider-no-body-persistence] The referee spec requires the
       REQUESTER to hold both twin responses. Either half being a
       provider-role capsule with no disclosed response body -- i.e. no
       requester-held transcript could exist for it, by construction --
       returns cleanly with `no_verdict_reason="no_requester_transcript"`,
       never a crash.
    3. Each half's disclosed response body must hash to that half's
       declared `response_digest` -- a mismatch raises
       `PreimageDigestMismatchError` (abort BEFORE any comparison; never
       reason about bytes that don't match what was actually sealed).
    4. If both halves declare a `weights_digest` and they differ, there is
       nothing to adjudicate -- returns with
       `no_verdict_reason="weights_mismatch"`.
    5. If both halves' owners are known and equal, this isn't an
       independent twin -- returns with `twin_owner_distinct=False`,
       `no_verdict_reason="same_owner_twin"`.
    6. Otherwise, `compare_transcripts` the disclosed response text.

       No divergence (`margin >= margin_tau`): `corroborated`, referee
       never called -- honest twins cost zero referee calls.

       Divergence, no `referee` given: `inconclusive` -- disagreement is a
       trigger, never a verdict this function reaches alone.

       Divergence, `referee` given: independence is checked FIRST -- if
       `referee_owner_id` is given and equals either half's `owner_id`,
       refuses without calling the referee at all
       (`no_verdict_reason="referee_not_independent"`). Otherwise
       `referee(half_a, half_b, comparison)` is ALWAYS called (text
       divergence is the only trigger -- see the module docstring's
       2026-09-08 ruling; the disputants' own logprobs are never consulted
       here). If `logprob_tau` is given and the referee's own logprobs
       aren't `logprobs_absent` and its margin is below `logprob_tau`, the
       verdict is overridden to `inconclusive`; otherwise the referee's own
       verdict and margin (not the text-comparison margin) become the
       outcome's -- this is the only path through which `adjudicate()` can
       return `contradicted:<owner_id>`.
    """
    if logprob_tau is not None and referee is None:
        raise ValueError("adjudicate(logprob_tau=...) requires a referee callable")
    _verify_half_or_raise("half_a", half_a)
    _verify_half_or_raise("half_b", half_b)

    half_a_id = half_a.capsule_id
    half_b_id = half_b.capsule_id

    if _no_requester_transcript(half_a) or _no_requester_transcript(half_b):
        return AdjudicationOutcome(
            verdict=None,
            no_verdict_reason=NO_VERDICT_NO_REQUESTER_TRANSCRIPT,
            divergence_index=None,
            margin=0.0,
            margin_tau=margin_tau,
            prefix_digest=None,
            twin_owner_distinct=None,
            weights_digest=None,
            half_a_capsule_id=half_a_id,
            half_b_capsule_id=half_b_id,
        )

    _verify_preimage_or_raise("half_a", half_a)
    _verify_preimage_or_raise("half_b", half_b)

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

    if comparison.divergence_index is not None and referee is not None:
        if referee_owner_id is not None and (
            (half_a.owner_id is not None and referee_owner_id == half_a.owner_id)
            or (half_b.owner_id is not None and referee_owner_id == half_b.owner_id)
        ):
            return AdjudicationOutcome(
                verdict=None,
                no_verdict_reason=NO_VERDICT_REFEREE_NOT_INDEPENDENT,
                divergence_index=comparison.divergence_index,
                margin=comparison.margin,
                margin_tau=margin_tau,
                prefix_digest=comparison.prefix_digest,
                twin_owner_distinct=twin_owner_distinct,
                weights_digest=shared_weights_digest,
                half_a_capsule_id=half_a_id,
                half_b_capsule_id=half_b_id,
            )

        # Text divergence is the only escalation trigger -- the disputants'
        # own logprobs are never read here (see the module docstring's
        # 2026-09-08 ruling). Any divergence calls the referee.
        referee_result = referee(half_a, half_b, comparison)

        verdict = referee_result.verdict
        if (
            logprob_tau is not None
            and not referee_result.logprobs_absent
            and referee_result.margin < logprob_tau
        ):
            verdict = VERDICT_INCONCLUSIVE

        # [mesh-referee-capsule-citation] Cite the referee's nonce
        # regardless of resolution outcome -- an unresolved/unverified
        # door still gets an entry naming the nonce, never a silent drop.
        references: tuple[dict[str, Any], ...] = ()
        if referee_result.referee_record_nonce is not None:
            references = (
                {
                    "kind": "referee_capsule",
                    "nonce": referee_result.referee_record_nonce,
                    "status": referee_result.referee_record_status,
                    "capsule_id": referee_result.capsule_id,
                },
            )

        return AdjudicationOutcome(
            verdict=verdict,
            no_verdict_reason=None,
            divergence_index=comparison.divergence_index,
            margin=referee_result.margin,
            margin_tau=margin_tau,
            prefix_digest=comparison.prefix_digest,
            twin_owner_distinct=twin_owner_distinct,
            weights_digest=shared_weights_digest,
            half_a_capsule_id=half_a_id,
            half_b_capsule_id=half_b_id,
            tau=logprob_tau,
            referee_logprobs_absent=referee_result.logprobs_absent,
            referee_called=True,
            referee_capsule_id=referee_result.capsule_id,
            references=references,
        )

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

    adjudication = {
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
    # Only present when a referee was actually called -- the fourth
    # citation (`adjudication_delivery._cited_capsule_ids` picks up any
    # `*_capsule_id`-suffixed key automatically) plus whether the opt-in
    # `logprob_tau` gate (against the REFEREE's own logprobs -- never the
    # disputants') actually ran.
    if outcome.referee_called:
        adjudication["referee_capsule_id"] = outcome.referee_capsule_id
        # [mesh-referee-capsule-citation] The nonce-correlation citation --
        # present even when `referee_capsule_id` above is `None` (an
        # unresolved/unverified door still names the nonce it was asked
        # with; see `AdjudicationOutcome.references`'s own docstring).
        if outcome.references:
            adjudication["references"] = list(outcome.references)
        if outcome.tau is not None:
            adjudication["tau"] = float_to_str(outcome.tau, field="adjudication.tau")
            adjudication["referee_logprobs_absent"] = outcome.referee_logprobs_absent

    compute_attestation = {"adjudication": adjudication}
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

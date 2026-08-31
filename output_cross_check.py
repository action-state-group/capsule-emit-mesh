# SPDX-License-Identifier: Apache-2.0
"""prototype_cross_check (B2 scaffolding): a typed SEAM for cross-checking a
served output against the node's SEALED CONFIG CLAIM -- plus a deliberately
trivial baseline behind it.

WHAT THIS IS -- AND, LOUDLY, WHAT IT IS NOT
===========================================
A capsule already PINS the node's config claim: model identity, quantization,
and a hardware class (GPU / VRAM / SoC). See ``advertisement.Advertisement``
and ``serving_provenance`` -- that pinning is the "claimed config" this module
consumes; it is NOT re-invented here.

This module adds ONE thing: a small, well-typed seam --

    check_output_against_config(config_claim, request, response) -> CrossCheckResult

-- into which a FUTURE, real statistical reference model (expected output shape
per model/quant/hardware) can be dropped WITHOUT changing any caller. Building
that real model is an open-ended data-collection research effort and is
explicitly OUT OF SCOPE here. What ships now is only the seam and a trivial
baseline so a red-team can attack the APPROACH before anyone invests in the
real model.

THE HONESTY GRADE (non-negotiable, shipped in the type, the code, and the docs)
------------------------------------------------------------------------------
Every result this seam produces is a ``prototype_cross_check``. It is:

  * PROBABILISTIC -- it RAISES or LOWERS confidence; it is a recorded signal,
    never a boolean truth about what ran.
  * a PROTOTYPE -- scaffolding, so the real model has somewhere to plug in.
  * NOT "verified" -- a cross-check is not a verification. Nothing here proves
    a node served what it claimed. The capsule's signatures/digests are the
    evidence; this is a plausibility read on top of them.
  * NEVER "gets caught" -- this does not catch cheaters. A LOWERS-confidence
    result means "this output is less plausible for the claimed config", which
    is a reason to look, NOT a verdict, an accusation, or a pass/fail.

There is therefore NO ``pass``/``fail`` field anywhere in ``CrossCheckResult``
and none is ever added -- the same discipline ``advertisement.py`` keeps by
refusing a "silent green" fourth verdict state. A result carries a
``confidence_direction`` (raises / lowers / neutral / inconclusive) and human
``observations``; a caller that wants a verdict must supply its own policy ON
TOP, and own that decision.

NEUTRALITY: meter, not price. The baseline reads metered facts (token counts,
wall-clock/compute milliseconds) that the record already seals. It carries no
currency, rate, invoice, or Authority. There is no field here that could hold
one, and none is ever added (same rule as ``advertisement.compute_meter``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from advertisement import Advertisement

#: Schema tag for the cross-check artifact (co-carried like ADVERTISEMENT_SCHEMA).
CROSS_CHECK_SCHEMA = "capsule-emit-mesh/prototype-cross-check/v1"

#: The permanent honesty label. Shipped ON every result so a reader can never
#: read a cross-check as a verification, a verdict, or a catch. Mirrors
#: advertisement.ADVERTISEMENT_SELF_SIGNED_NOTE.
PROTOTYPE_CROSS_CHECK = "prototype_cross_check"
PROTOTYPE_CROSS_CHECK_NOTE = (
    "prototype_cross_check: PROBABILISTIC, PROTOTYPE scaffolding. This is a "
    "recorded cross-check that RAISES or LOWERS confidence in the claimed "
    "config -- it is NOT a verification, NOT a pass/fail verdict, and it does "
    "NOT 'catch' anyone. A lowers-confidence result is a reason to look, never "
    "an accusation. The real statistical reference model (expected output per "
    "model/quant/hardware) is future work and OUT OF SCOPE; this baseline is "
    "token-rate / output-shape SANITY only, so a red-team can attack the "
    "approach before the real model is built."
)

#: ``confidence_direction`` -- a closed set. Deliberately NOT {pass, fail}.
#: A cross-check never verdicts; it only nudges confidence, or declines to.
DIRECTION_RAISES = "raises"          # output is plausible for the claimed config
DIRECTION_LOWERS = "lowers"          # output is LESS plausible -- a reason to look
DIRECTION_NEUTRAL = "neutral"        # checks ran, nothing moved confidence
DIRECTION_INCONCLUSIVE = "inconclusive"  # not enough sealed facts to check at all


@dataclass
class ConfigClaim:
    """The node's SEALED config claim -- the "claimed config", exposed cleanly.

    This is a thin, honest view over what the capsule ALREADY pins: the model
    identity, quantization, and hardware class from ``Advertisement`` /
    ``serving_provenance``. It re-pins nothing and asserts nothing new; it just
    names the claimed facts so the checker seam reads one clear type instead of
    reaching into the record shape. ``None`` on a field means the config did
    not claim it -- which reconciles to ``inconclusive`` for any check that
    needs it, never to a fabricated value.
    """

    model_id: str | None = None
    model_canonical_ref: str | None = None
    quantization: str | None = None
    hardware_gpu: str | None = None
    hardware_vram_bytes: int | None = None
    hardware_is_soc: bool | None = None

    @classmethod
    def from_advertisement(cls, ad: Advertisement | dict[str, Any] | None) -> "ConfigClaim":
        """Lift the sealed advertisement (the pinned claim) into a ConfigClaim."""
        if ad is None:
            return cls()
        if not isinstance(ad, Advertisement):
            ad = Advertisement.from_value(ad)
        return cls(
            model_id=ad.model_id,
            model_canonical_ref=ad.model_canonical_ref,
            quantization=ad.quantization,
            hardware_gpu=ad.hardware_gpu,
            hardware_vram_bytes=ad.hardware_vram_bytes,
            hardware_is_soc=ad.hardware_is_soc,
        )

    @classmethod
    def from_serving_provenance(cls, sp: dict[str, Any] | None) -> "ConfigClaim":
        """Lift a served-provenance block (the Rust-producer shape) into a claim.

        Tolerant of the nested ``{model{...}, hardware{...}}`` shape and the
        honest ``"unknown"`` sentinel (which becomes ``None``), matching
        ``advertisement._served_facts`` so the two never disagree on what a
        field's absence means.
        """
        sp = sp or {}
        model = sp.get("model") or {}
        hw = sp.get("hardware") or {}

        def clean(v: Any) -> Any:
            if isinstance(v, str) and v.strip().lower() == "unknown":
                return None
            return v

        return cls(
            model_id=clean(sp.get("model_id") or model.get("model_id")),
            model_canonical_ref=clean(sp.get("model_canonical_ref") or model.get("canonical_ref")),
            quantization=clean(sp.get("quantization")),
            hardware_gpu=clean(hw.get("gpu") or sp.get("gpu")),
            hardware_vram_bytes=clean(
                hw.get("vram_bytes") if hw.get("vram_bytes") is not None else sp.get("vram_bytes")
            ),
            hardware_is_soc=clean(
                hw.get("is_soc") if hw.get("is_soc") is not None else sp.get("is_soc")
            ),
        )


@dataclass
class Observation:
    """One named signal from a check -- evidence, not a verdict.

    ``direction`` is one of the DIRECTION_* values. ``detail`` is a
    human-readable, non-load-bearing note. An observation NEVER says "pass" or
    "caught"; it says which way it nudged confidence and why.
    """

    name: str
    direction: str
    detail: str

    def to_value(self) -> dict[str, Any]:
        return {"name": self.name, "direction": self.direction, "detail": self.detail}


@dataclass
class CrossCheckResult:
    """The recorded output of a prototype cross-check. NOT a verdict.

    Every instance is labelled ``prototype_cross_check`` and carries the
    permanent honesty note, so a downstream reader is never solely dependent on
    the caller having remembered the caveat (same discipline as
    ``advertisement``'s self-signed note attached to every reconciliation).

    There is intentionally NO ``passed``/``ok``/``verified`` field. The only
    summary is ``confidence_direction`` -- raises / lowers / neutral /
    inconclusive -- which is a probabilistic nudge, never a decision.
    """

    #: The checker that produced this (e.g. the trivial baseline's id). Lets a
    #: reader know EXACTLY how weak the signal is.
    checker_id: str
    #: The overall nudge. NOT a pass/fail. See DIRECTION_* .
    confidence_direction: str
    #: Per-signal observations that produced the direction.
    observations: list[Observation] = field(default_factory=list)

    #: Permanent, non-removable labels. Present on EVERY result.
    label: str = PROTOTYPE_CROSS_CHECK
    note: str = PROTOTYPE_CROSS_CHECK_NOTE

    def lowers(self) -> bool:
        """True iff this cross-check LOWERED confidence (a reason to look).

        Convenience only. It is NOT "did it fail" -- a lowered-confidence
        result is still not a verdict, and a caller acting on it owns that
        decision and its policy.
        """
        return self.confidence_direction == DIRECTION_LOWERS

    def to_value(self) -> dict[str, Any]:
        """Canonical dict, co-carryable into the capsule alongside the claim."""
        return {
            "schema": CROSS_CHECK_SCHEMA,
            "label": self.label,
            "note": self.note,
            "checker_id": self.checker_id,
            "confidence_direction": self.confidence_direction,
            "observations": [o.to_value() for o in self.observations],
        }


class OutputCrossChecker(Protocol):
    """The SEAM. A future real statistical model implements exactly this.

    Given the sealed config claim and the served (request, response), return a
    ``CrossCheckResult``. Implementations MUST NOT return a pass/fail verdict --
    only a ``confidence_direction`` and observations. The trivial baseline
    below is the reference implementation of this Protocol; the real model is a
    drop-in replacement that changes NO caller.
    """

    checker_id: str

    def __call__(
        self,
        config_claim: ConfigClaim,
        request: dict[str, Any],
        response: dict[str, Any],
    ) -> CrossCheckResult: ...


def _summarize_direction(observations: list[Observation]) -> str:
    """Fold per-signal directions into one overall nudge -- conservatively.

    A single LOWERS anywhere makes the whole check LOWERS (a reason to look is
    not cancelled by other signals looking fine -- the point is to surface it).
    Otherwise, any RAISES makes it RAISES; if signals ran but none moved,
    NEUTRAL; if nothing could be checked at all, INCONCLUSIVE.
    """
    directions = {o.direction for o in observations}
    if not observations:
        return DIRECTION_INCONCLUSIVE
    if DIRECTION_LOWERS in directions:
        return DIRECTION_LOWERS
    if directions == {DIRECTION_INCONCLUSIVE}:
        return DIRECTION_INCONCLUSIVE
    if DIRECTION_RAISES in directions:
        return DIRECTION_RAISES
    return DIRECTION_NEUTRAL


# ---------------------------------------------------------------------------
# Coarse, hand-set sanity bands for the TRIVIAL baseline. These are NOT a
# statistical reference model and make no claim to be tuned -- they are wide,
# hand-picked plausibility rails whose ONLY job is to prove the seam works and
# give a red-team something to push on. Do not read precision into these.
# ---------------------------------------------------------------------------

#: Very coarse tokens/sec plausibility band per hardware kind. Wide on purpose:
#: outside the band LOWERS confidence a little; inside it RAISES a little.
#: These are illustrative rails, NOT measured references.
_TOKENS_PER_SEC_BAND = {
    "soc": (1.0, 400.0),        # on-device / SoC (e.g. an Apple-silicon laptop)
    "discrete_gpu": (2.0, 2000.0),  # a discrete GPU
    "unknown": (0.1, 5000.0),   # hardware not claimed -> near-useless wide rail
}

#: Coarse completion-length plausibility (tokens). A completion far over the
#: requested cap, or an empty completion where tokens were paid for, LOWERS.
_MIN_PLAUSIBLE_COMPLETION_TOKENS = 0


def _hardware_kind(claim: ConfigClaim) -> str:
    if claim.hardware_is_soc is True:
        return "soc"
    if claim.hardware_is_soc is False or claim.hardware_gpu:
        return "discrete_gpu"
    return "unknown"


def _completion_tokens(response: dict[str, Any]) -> int | None:
    usage = (response or {}).get("usage") or {}
    v = usage.get("completion_tokens")
    return v if isinstance(v, int) else None


def _elapsed_ms(response: dict[str, Any]) -> float | None:
    """Wall-clock (or compute) milliseconds from the metered facts, if sealed.

    Reads the neutral ``compute_meter`` block (advertisement.compute_meter),
    whose times are exact decimal STRINGS -- never a currency or rate.
    """
    meter = (response or {}).get("compute_meter") or {}
    for key in ("compute_ms", "wall_clock_ms"):
        raw = meter.get(key)
        if raw is None:
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None


def _requested_cap(request: dict[str, Any]) -> int | None:
    req = request or {}
    cap = req.get("max_tokens")
    if cap is None:
        cap = req.get("max_completion_tokens")
    return cap if isinstance(cap, int) else None


def baseline_cross_check(
    config_claim: ConfigClaim,
    request: dict[str, Any],
    response: dict[str, Any],
) -> CrossCheckResult:
    """TRIVIAL baseline behind the seam: token-rate / output-shape SANITY only.

    NOTHING statistical or learned. It checks two coarse plausibility rails:

      1. Completion-length shape -- an empty completion where a positive cap was
         requested LOWERS confidence a little; a completion wildly over the
         requested cap LOWERS a little; a plausible length RAISES a little.
      2. Tokens/sec band -- completion_tokens over elapsed ms, compared to a
         WIDE, hand-set band for the claimed hardware kind. Outside the band
         LOWERS; inside RAISES. The band is illustrative, not measured.

    Every path returns a ``prototype_cross_check`` result carrying the honesty
    note. A missing fact yields an INCONCLUSIVE observation, never a fabricated
    check. This exists to be ATTACKED (B5b red-team) so we learn whether the
    approach survives before building the real reference model.
    """
    observations: list[Observation] = []

    completion = _completion_tokens(response)
    cap = _requested_cap(request)
    elapsed_ms = _elapsed_ms(response)
    kind = _hardware_kind(config_claim)

    # --- Signal 1: completion-length shape -------------------------------
    if completion is None:
        observations.append(Observation(
            "completion_length_shape", DIRECTION_INCONCLUSIVE,
            "no completion_tokens sealed in usage; cannot read output shape.",
        ))
    elif cap is not None and completion == 0 and cap > 0:
        observations.append(Observation(
            "completion_length_shape", DIRECTION_LOWERS,
            f"empty completion (0 tokens) though a cap of {cap} was requested "
            "-- less plausible; a reason to look, not a verdict.",
        ))
    elif cap is not None and completion > cap:
        observations.append(Observation(
            "completion_length_shape", DIRECTION_LOWERS,
            f"completion {completion} exceeds requested cap {cap} -- "
            "implausible output shape; a reason to look, not a verdict.",
        ))
    elif completion > _MIN_PLAUSIBLE_COMPLETION_TOKENS:
        detail = f"completion {completion} tokens"
        if cap is not None:
            detail += f" within requested cap {cap}"
        observations.append(Observation(
            "completion_length_shape", DIRECTION_RAISES,
            detail + " -- a plausible shape (weak, coarse signal).",
        ))
    else:
        observations.append(Observation(
            "completion_length_shape", DIRECTION_NEUTRAL,
            "completion length present but nothing to compare it against.",
        ))

    # --- Signal 2: tokens/sec band ---------------------------------------
    if completion is None or elapsed_ms is None or elapsed_ms <= 0:
        observations.append(Observation(
            "tokens_per_sec_band", DIRECTION_INCONCLUSIVE,
            "missing completion_tokens or positive elapsed_ms; cannot compute a rate.",
        ))
    else:
        tps = completion / (elapsed_ms / 1000.0)
        low, high = _TOKENS_PER_SEC_BAND.get(kind, _TOKENS_PER_SEC_BAND["unknown"])
        if low <= tps <= high:
            observations.append(Observation(
                "tokens_per_sec_band", DIRECTION_RAISES,
                f"{tps:.2f} tok/s within the coarse [{low}, {high}] band for "
                f"claimed hardware kind '{kind}' (illustrative band, not measured).",
            ))
        else:
            observations.append(Observation(
                "tokens_per_sec_band", DIRECTION_LOWERS,
                f"{tps:.2f} tok/s OUTSIDE the coarse [{low}, {high}] band for "
                f"claimed hardware kind '{kind}' -- less plausible; a reason to "
                "look, not a verdict (band is illustrative, not measured).",
            ))

    return CrossCheckResult(
        checker_id="trivial-baseline/v1",
        confidence_direction=_summarize_direction(observations),
        observations=observations,
    )


#: The active checker behind the seam. Swap this for the real statistical
#: reference model when it exists -- no caller changes. Typed as the Protocol.
_DEFAULT_CHECKER: OutputCrossChecker = baseline_cross_check  # type: ignore[assignment]


def check_output_against_config(
    config_claim: ConfigClaim | Advertisement | dict[str, Any] | None,
    request: dict[str, Any],
    response: dict[str, Any],
    checker: OutputCrossChecker | Callable[..., CrossCheckResult] | None = None,
) -> CrossCheckResult:
    """The public SEAM: cross-check a served output against the sealed config claim.

    ``config_claim`` may be a ``ConfigClaim``, a raw ``Advertisement`` /
    advertisement dict (lifted via ``ConfigClaim.from_advertisement``), or
    ``None``. ``request`` / ``response`` are the served exchange dicts
    (OpenAI-style request; a response dict carrying ``usage`` and the neutral
    ``compute_meter`` block).

    Pass ``checker`` to override the implementation -- this is the plug point
    for the FUTURE real statistical model. It defaults to the trivial baseline.

    ALWAYS returns a ``prototype_cross_check`` result: probabilistic, a
    prototype, NOT a verification, NEVER a pass/fail and NEVER a "catch".
    """
    claim = config_claim if isinstance(config_claim, ConfigClaim) else ConfigClaim.from_advertisement(config_claim)
    impl = checker or _DEFAULT_CHECKER
    return impl(claim, request or {}, response or {})

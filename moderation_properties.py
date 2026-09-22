# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] Moderation properties -- system rates,
never a per-user anything.

Design doc §4/§6: "counts by decision, automated rate, twin-disagreement
rate, human-override rate, appeal-reversal rate -- properties of the
moderation SYSTEM, `derived_metric`, recomputable from the bundle." Follows
`history_card.py`'s own fold discipline
(`reconciliation_counts_from_ledger_dir`/`with_peer_reconciliation`): a pure
counting function over already-sealed records, tagged
`EPISTEMIC_TYPE_DERIVED_METRIC` (the SAME constant `history_card.py` and
`twin_adjudicator.py` already use, not a new value), and NEVER folded back
into a digest-bearing chain-walk result -- this module produces a plain
dict, not a capsule, exactly like `history_card.HistoryProperties` sits
OUTSIDE `HistoryCard.core_account()`'s own verified scope.

**appeal_reversal_rate is the one rate this spike does not yet derive from
a sealed record type.** The build list (design doc §6) does not include an
"appeal outcome" capsule -- Buzz's redress workflow deciding to reverse a
decision after appeal is a follow-up record type, not this spike's scope.
Rather than silently omitting the rate or fabricating it from unrelated
fields, `moderation_counts` accepts an explicit, separately-sourced
`appeal_outcomes` sequence (mirrors `history_card.
reconciliation_counts_from_ledger_dir` reading an external observation
store rather than the checkpoint chain itself) and labels the rate `None`
when none is supplied -- absence stays absence, never a false zero.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from capsule_emit.numbers import float_to_str
from moderation_decision import MODERATION_SUBJECT_KEY
from moderation_twin import find_adjudication_for_decision

__all__ = [
    "EPISTEMIC_TYPE_DERIVED_METRIC",
    "AppealOutcome",
    "ModerationCounts",
    "ModerationProperties",
    "moderation_counts",
    "moderation_properties_from_counts",
]

#: [mesh-fabric-vocab-alignment] the SAME constant `history_card.py` /
#: `twin_adjudicator.py` already carry -- a rate over sealed records is a
#: derived aggregate, not an observation of one and not a claim about it.
EPISTEMIC_TYPE_DERIVED_METRIC = "derived_metric"


@dataclass(frozen=True)
class AppealOutcome:
    """One appeal's outcome -- `decision_capsule_id` + whether the
    original decision was `reversed`. See module docstring: this is not
    (yet) a sealed capsule type this spike builds; a caller supplies these
    from Buzz's own redress workflow log."""

    decision_capsule_id: str
    reversed: bool


def _moderation_block(capsule: dict[str, Any]) -> dict[str, Any]:
    return (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get(MODERATION_SUBJECT_KEY, {})


def _adjudication_block(capsule: dict[str, Any]) -> dict[str, Any]:
    return (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get("adjudication", {})


def _epistemic_type(capsule: dict[str, Any]) -> str | None:
    return (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get("epistemic_type")


@dataclass(frozen=True)
class ModerationCounts:
    """Raw counts a rate is computed FROM -- published alongside the rates
    themselves so a verifier can recompute the fraction and catch a
    mismatched divisor, same transparency `history_card.HistoryProperties`
    affords its own `cadence`/`history_depth` fields."""

    total_decisions: int
    automated_decisions: int
    twinned_decisions: int
    disagreements: int
    human_refereed_decisions: int
    human_overrides: int
    appeals: int
    reversals: int
    #: `None` when no `appeal_outcomes` were supplied at all -- distinct
    #: from `appeals == 0` (zero appeals happened) vs "we don't know" (no
    #: appeal-outcome log was ever consulted).
    appeal_outcomes_known: bool


def moderation_counts(
    decision_capsules: Sequence[dict[str, Any]],
    *,
    ledger: Sequence[dict[str, Any]],
    appeal_outcomes: Sequence[AppealOutcome] | None = None,
) -> ModerationCounts:
    """Count moderation properties from already-sealed
    `moderation_decision` capsules plus any adjudication capsule in
    *ledger* that cites one of them (`moderation_twin.
    find_adjudication_for_decision` -- a decision's content is
    digest-committed before its own twin outcome can exist, so the lookup
    is a reverse scan, never a forward `adjudication_ref` field read off
    the decision itself). A pure function over records alone, no live
    state.
    """
    total = len(decision_capsules)
    automated = sum(1 for c in decision_capsules if _moderation_block(c)["automated"])

    twinned = 0
    disagreements = 0
    human_refereed = 0
    human_overrides = 0
    for capsule in decision_capsules:
        adjudication_capsule = find_adjudication_for_decision(ledger, capsule["capsule_id"])
        if adjudication_capsule is None:
            continue
        twinned += 1
        adjudication = _adjudication_block(adjudication_capsule)
        verdict = adjudication.get("verdict")
        if verdict != "corroborated":
            disagreements += 1
        referee_id = adjudication.get("referee_id") or ""
        if referee_id.startswith("human:"):
            human_refereed += 1
            if isinstance(verdict, str) and verdict.startswith("contradicted:"):
                human_overrides += 1

    if appeal_outcomes is None:
        appeals = 0
        reversals = 0
        appeal_outcomes_known = False
    else:
        appeals = len(appeal_outcomes)
        reversals = sum(1 for outcome in appeal_outcomes if outcome.reversed)
        appeal_outcomes_known = True

    return ModerationCounts(
        total_decisions=total,
        automated_decisions=automated,
        twinned_decisions=twinned,
        disagreements=disagreements,
        human_refereed_decisions=human_refereed,
        human_overrides=human_overrides,
        appeals=appeals,
        reversals=reversals,
        appeal_outcomes_known=appeal_outcomes_known,
    )


@dataclass(frozen=True)
class ModerationProperties:
    """The rates a moderation history publishes -- structural facts about
    the SYSTEM's decisions, never a per-account score (design doc §5).
    Rate values are exact decimal STRINGS (`float_to_str`), never JSON
    floats, same digest-safety discipline `history_card.HistoryProperties.
    cadence` already documents."""

    counts: ModerationCounts
    automated_rate: str | None
    twin_disagreement_rate: str | None
    human_override_rate: str | None
    appeal_reversal_rate: str | None

    def to_value(self) -> dict[str, Any]:
        return {
            "epistemic_type": EPISTEMIC_TYPE_DERIVED_METRIC,
            "counts": {
                "total_decisions": self.counts.total_decisions,
                "automated_decisions": self.counts.automated_decisions,
                "twinned_decisions": self.counts.twinned_decisions,
                "disagreements": self.counts.disagreements,
                "human_refereed_decisions": self.counts.human_refereed_decisions,
                "human_overrides": self.counts.human_overrides,
                "appeals": self.counts.appeals,
                "reversals": self.counts.reversals,
                "appeal_outcomes_known": self.counts.appeal_outcomes_known,
            },
            "automated_rate": self.automated_rate,
            "twin_disagreement_rate": self.twin_disagreement_rate,
            "human_override_rate": self.human_override_rate,
            "appeal_reversal_rate": self.appeal_reversal_rate,
            "not_a_score": (
                "These are rates over this system's own moderation decisions -- never a "
                "per-account score, never a routing or trust recommendation."
            ),
        }


def _rate(numerator: int, denominator: int) -> str | None:
    if denominator == 0:
        return None
    return float_to_str(numerator / denominator, field="moderation_properties.rate")


def moderation_properties_from_counts(counts: ModerationCounts) -> ModerationProperties:
    return ModerationProperties(
        counts=counts,
        automated_rate=_rate(counts.automated_decisions, counts.total_decisions),
        twin_disagreement_rate=_rate(counts.disagreements, counts.twinned_decisions),
        human_override_rate=_rate(counts.human_overrides, counts.human_refereed_decisions),
        appeal_reversal_rate=_rate(counts.reversals, counts.appeals) if counts.appeal_outcomes_known else None,
    )

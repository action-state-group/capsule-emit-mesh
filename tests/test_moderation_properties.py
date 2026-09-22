# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] `moderation_properties.py` unit tests."""
from __future__ import annotations

import hashlib

from moderation_decision import DECISION_ALLOW, DECISION_REMOVE, ModerationDecision, PolicyRef, SubjectRef, seal_moderation_decision
from moderation_properties import AppealOutcome, moderation_counts, moderation_properties_from_counts
from moderation_twin import (
    HumanReportKey,
    adjudicate_moderation_twin,
    make_human_report,
    referee_from_human_report,
    seal_human_report_capsule,
    seal_moderation_twin_capsule,
)
from twin_adjudicator import VERDICT_CORROBORATED, contradicted


def _seal(decision_value: str, *, owner: str, digest: str) -> dict:
    sr = SubjectRef(message_digest=digest, room_ref="room:general", principal_ref="nostr-pubkey:" + "a" * 64)
    pr = PolicyRef(policy_id="hate-speech-v1", version="2026.1")
    ma = {"model_id": f"buzz-mod-classifier-{owner}", "provider": "buzz", "weights_digest": "b" * 64}
    d = ModerationDecision(
        subject_ref=sr,
        policy_ref=pr,
        model_attestation=ma,
        decision=decision_value,
        basis="clause 4.2",
        confidence=0.9,
        automated=True,
        redress_ref="https://buzz.example/appeal",
    )
    return seal_moderation_decision(d, operator=f"buzz-node-{owner}", developer="buzz-mesh-mod/0.1", signing_node_id=f"node-{owner}")


def _digest(n: int) -> str:
    return hashlib.sha256(f"message {n}".encode()).hexdigest()


def test_automated_rate_over_a_mix() -> None:
    decisions = [_seal(DECISION_ALLOW, owner="a", digest=_digest(i)) for i in range(4)]
    counts = moderation_counts(decisions, ledger=[])
    props = moderation_properties_from_counts(counts)
    assert counts.total_decisions == 4
    assert counts.automated_decisions == 4
    assert props.automated_rate == "1"


def test_rates_are_none_not_zero_when_denominator_is_absent() -> None:
    decisions = [_seal(DECISION_ALLOW, owner="a", digest=_digest(0))]
    counts = moderation_counts(decisions, ledger=[])
    props = moderation_properties_from_counts(counts)
    assert counts.twinned_decisions == 0
    assert props.twin_disagreement_rate is None
    assert props.human_override_rate is None
    assert props.appeal_reversal_rate is None  # no appeal_outcomes supplied at all


def test_twin_disagreement_and_human_override_rates() -> None:
    digest = _digest(0)
    a = _seal(DECISION_REMOVE, owner="a", digest=digest)
    b = _seal(DECISION_ALLOW, owner="b", digest=digest)
    key = HumanReportKey.generate()
    report = make_human_report(
        key, reviewer_id="reviewer-1", subject_message_digest=digest, verdict=contradicted("owner-a"), rationale="x"
    )
    report_cap = seal_human_report_capsule(report, operator="buzz-review", developer="buzz-mesh-mod/0.1")

    def referee(x, y):
        return referee_from_human_report(report, report_capsule_id=report_cap["capsule_id"])

    outcome = adjudicate_moderation_twin(
        a, b, owner_a_id="owner-a", owner_b_id="owner-b", referee=referee, referee_owner_id="reviewer-1"
    )
    adjudication_cap = seal_moderation_twin_capsule(outcome, operator="buzz-node-a", developer="buzz-mesh-mod/0.1")

    # `find_adjudication_for_decision` finds `a`'s adjudication by reverse
    # citation (the adjudication capsule cites `a`'s own capsule_id) -- no
    # mutation of the already-sealed decision capsule needed.
    ledger = [a, b, adjudication_cap]
    counts = moderation_counts([a], ledger=ledger)
    props = moderation_properties_from_counts(counts)

    assert counts.twinned_decisions == 1
    assert counts.disagreements == 1
    assert counts.human_refereed_decisions == 1
    assert counts.human_overrides == 1
    assert props.twin_disagreement_rate == "1"
    assert props.human_override_rate == "1"


def test_appeal_reversal_rate_known_vs_unknown() -> None:
    decisions = [_seal(DECISION_ALLOW, owner="a", digest=_digest(0))]
    counts_unknown = moderation_counts(decisions, ledger=[])
    assert moderation_properties_from_counts(counts_unknown).appeal_reversal_rate is None

    outcomes = [AppealOutcome(decision_capsule_id=decisions[0]["capsule_id"], reversed=True)]
    counts_known = moderation_counts(decisions, ledger=[], appeal_outcomes=outcomes)
    props_known = moderation_properties_from_counts(counts_known)
    assert counts_known.appeal_outcomes_known is True
    assert props_known.appeal_reversal_rate == "1"


def test_moderation_properties_never_carry_a_per_account_key() -> None:
    decisions = [_seal(DECISION_ALLOW, owner="a", digest=_digest(0))]
    counts = moderation_counts(decisions, ledger=[])
    props = moderation_properties_from_counts(counts)
    value = props.to_value()
    assert "not_a_score" in value
    assert not any("user" in k or "account" in k or "principal" in k for k in value["counts"])

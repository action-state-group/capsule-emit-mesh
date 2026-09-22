# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] `moderation_twin.py` unit tests."""
from __future__ import annotations

import hashlib

import pytest

from moderation_decision import DECISION_ALLOW, DECISION_REMOVE, ModerationDecision, PolicyRef, SubjectRef, seal_moderation_decision
from moderation_twin import (
    EPISTEMIC_TYPE_HUMAN_REPORT,
    ForgedDecisionError,
    HumanReportKey,
    adjudicate_moderation_twin,
    compare_moderation_decisions,
    make_human_report,
    referee_from_human_report,
    seal_human_report_capsule,
    seal_moderation_twin_capsule,
    verify_human_report,
)
from twin_adjudicator import (
    NO_VERDICT_REFEREE_NOT_INDEPENDENT,
    NO_VERDICT_REFEREE_UNREACHABLE,
    NO_VERDICT_SAME_OWNER_TWIN,
    NO_VERDICT_WEIGHTS_MISMATCH,
    RefereeIdentity,
    RefereeResult,
    UnattributableRefereeError,
    VERDICT_CORROBORATED,
    VERDICT_INCONCLUSIVE,
    contradicted,
)

MSG_DIGEST = hashlib.sha256(b"another message").hexdigest()


def _seal(decision_value: str, *, owner: str, weights: str = "b" * 64) -> dict:
    sr = SubjectRef(message_digest=MSG_DIGEST, room_ref="room:general")
    pr = PolicyRef(policy_id="hate-speech-v1", version="2026.1")
    ma = {"model_id": f"buzz-mod-classifier-{owner}", "provider": "buzz", "weights_digest": weights}
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


class TestHumanReport:
    def test_sign_and_verify_round_trips(self) -> None:
        key = HumanReportKey.generate()
        report = make_human_report(
            key,
            reviewer_id="reviewer-1",
            subject_message_digest=MSG_DIGEST,
            verdict=VERDICT_INCONCLUSIVE,
            rationale="ambiguous context, deferring to policy default",
        )
        assert verify_human_report(report).valid

    def test_tampered_verdict_fails_verification(self) -> None:
        key = HumanReportKey.generate()
        report = make_human_report(
            key,
            reviewer_id="reviewer-1",
            subject_message_digest=MSG_DIGEST,
            verdict=VERDICT_CORROBORATED,
            rationale="agrees with the classifier",
        )
        tampered = {**report, "verdict": contradicted("owner-b")}
        verdict = verify_human_report(tampered)
        assert not verdict.valid

    def test_missing_signature_field_is_invalid_not_a_crash(self) -> None:
        verdict = verify_human_report({"reviewer_public_key": "aa"})
        assert not verdict.valid

    def test_seal_human_report_capsule_refuses_an_unverifiable_report(self) -> None:
        key = HumanReportKey.generate()
        report = make_human_report(
            key, reviewer_id="reviewer-1", subject_message_digest=MSG_DIGEST, verdict=VERDICT_CORROBORATED, rationale="x"
        )
        tampered = {**report, "rationale": "a different rationale entirely"}
        with pytest.raises(ForgedDecisionError):
            seal_human_report_capsule(tampered, operator="buzz-review", developer="buzz-mesh-mod/0.1")

    def test_seal_human_report_capsule_tags_epistemic_type(self) -> None:
        key = HumanReportKey.generate()
        report = make_human_report(
            key, reviewer_id="reviewer-1", subject_message_digest=MSG_DIGEST, verdict=VERDICT_CORROBORATED, rationale="x"
        )
        capsule = seal_human_report_capsule(report, operator="buzz-review", developer="buzz-mesh-mod/0.1")
        assert capsule["model_attestation"]["compute_attestation"]["epistemic_type"] == EPISTEMIC_TYPE_HUMAN_REPORT

    def test_referee_from_human_report_carries_signature_in_identity(self) -> None:
        key = HumanReportKey.generate()
        report = make_human_report(
            key, reviewer_id="reviewer-1", subject_message_digest=MSG_DIGEST, verdict=VERDICT_INCONCLUSIVE, rationale="x"
        )
        result = referee_from_human_report(report, report_capsule_id="c" * 64)
        assert result.identity.referee_id == "human:reviewer-1"
        assert result.identity.signature == report["signature"]
        assert result.verdict == VERDICT_INCONCLUSIVE


class TestCompareModerationDecisions:
    def test_agreeing_twins(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_REMOVE, owner="b")
        assert compare_moderation_decisions(a, b).agree is True

    def test_disagreeing_twins(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")
        assert compare_moderation_decisions(a, b).agree is False


class TestAdjudicateModerationTwin:
    def test_forged_capsule_refuses_to_compare(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        forged = {**a, "capsule_id": "0" * 64}
        with pytest.raises(ForgedDecisionError):
            adjudicate_moderation_twin(forged, _seal(DECISION_ALLOW, owner="b"), owner_a_id="a", owner_b_id="b")

    def test_weights_mismatch_refuses_to_adjudicate(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a", weights="b" * 64)
        b = _seal(DECISION_ALLOW, owner="b", weights="c" * 64)
        outcome = adjudicate_moderation_twin(a, b, owner_a_id="a", owner_b_id="b")
        assert outcome.verdict is None
        assert outcome.no_verdict_reason == NO_VERDICT_WEIGHTS_MISMATCH

    def test_same_owner_twin_refuses_to_adjudicate(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")
        outcome = adjudicate_moderation_twin(a, b, owner_a_id="same-owner", owner_b_id="same-owner")
        assert outcome.no_verdict_reason == NO_VERDICT_SAME_OWNER_TWIN

    def test_agreement_corroborates_without_calling_referee(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_REMOVE, owner="b")
        calls = []

        def referee(x, y):
            calls.append((x, y))
            raise AssertionError("referee must never be called on agreement")

        outcome = adjudicate_moderation_twin(a, b, owner_a_id="a", owner_b_id="b", referee=referee)
        assert outcome.verdict == VERDICT_CORROBORATED
        assert outcome.referee_called is False
        assert calls == []

    def test_disagreement_with_no_referee_is_inconclusive(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")
        outcome = adjudicate_moderation_twin(a, b, owner_a_id="a", owner_b_id="b")
        assert outcome.verdict == VERDICT_INCONCLUSIVE
        assert outcome.referee_called is False

    def test_disagreement_with_non_independent_referee_refuses_before_calling(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")
        calls = []

        def referee(x, y):
            calls.append((x, y))
            return RefereeResult(verdict=VERDICT_CORROBORATED, identity=RefereeIdentity(referee_id="x"))

        outcome = adjudicate_moderation_twin(a, b, owner_a_id="a", owner_b_id="b", referee=referee, referee_owner_id="a")
        assert outcome.no_verdict_reason == NO_VERDICT_REFEREE_NOT_INDEPENDENT
        assert calls == []

    def test_referee_exception_is_referee_unreachable_never_a_crash(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")

        def referee(x, y):
            raise RuntimeError("network down")

        outcome = adjudicate_moderation_twin(a, b, owner_a_id="a", owner_b_id="b", referee=referee)
        assert outcome.no_verdict_reason == NO_VERDICT_REFEREE_UNREACHABLE
        assert outcome.referee_called is True

    def test_unattributed_referee_result_raises(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")

        def referee(x, y):
            return RefereeResult(verdict=VERDICT_CORROBORATED, identity=None)

        with pytest.raises(UnattributableRefereeError):
            adjudicate_moderation_twin(a, b, owner_a_id="a", owner_b_id="b", referee=referee)

    def test_human_referee_can_contradict_the_decider(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")
        key = HumanReportKey.generate()
        report = make_human_report(
            key,
            reviewer_id="reviewer-1",
            subject_message_digest=MSG_DIGEST,
            verdict=contradicted("owner-a"),
            rationale="the removal was too aggressive; allow stands",
        )
        report_cap = seal_human_report_capsule(report, operator="buzz-review", developer="buzz-mesh-mod/0.1")

        def referee(x, y):
            return referee_from_human_report(report, report_capsule_id=report_cap["capsule_id"])

        outcome = adjudicate_moderation_twin(
            a, b, owner_a_id="owner-a", owner_b_id="owner-b", referee=referee, referee_owner_id="reviewer-1"
        )
        assert outcome.verdict == contradicted("owner-a")
        assert outcome.referee_identity_id == "human:reviewer-1"

    def test_human_referee_can_decline_and_stay_inconclusive(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")
        key = HumanReportKey.generate()
        report = make_human_report(
            key,
            reviewer_id="reviewer-1",
            subject_message_digest=MSG_DIGEST,
            verdict=VERDICT_INCONCLUSIVE,
            rationale="genuinely ambiguous, declining to rule",
        )
        report_cap = seal_human_report_capsule(report, operator="buzz-review", developer="buzz-mesh-mod/0.1")

        def referee(x, y):
            return referee_from_human_report(report, report_capsule_id=report_cap["capsule_id"])

        outcome = adjudicate_moderation_twin(
            a, b, owner_a_id="owner-a", owner_b_id="owner-b", referee=referee, referee_owner_id="reviewer-1"
        )
        assert outcome.verdict == VERDICT_INCONCLUSIVE


class TestSealModerationTwinCapsule:
    def test_no_verdict_outcome_seals_nothing(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_ALLOW, owner="b")
        outcome = adjudicate_moderation_twin(a, b, owner_a_id="same", owner_b_id="same")
        assert seal_moderation_twin_capsule(outcome, operator="x", developer="y") is None

    def test_corroborated_outcome_seals_and_verifies(self) -> None:
        a = _seal(DECISION_REMOVE, owner="a")
        b = _seal(DECISION_REMOVE, owner="b")
        outcome = adjudicate_moderation_twin(a, b, owner_a_id="a", owner_b_id="b")
        capsule = seal_moderation_twin_capsule(outcome, operator="buzz-node-a", developer="buzz-mesh-mod/0.1")
        assert capsule is not None
        adjudication = capsule["model_attestation"]["compute_attestation"]["adjudication"]
        assert adjudication["verdict"] == VERDICT_CORROBORATED
        assert adjudication["status"] == "SATISFIED"
        assert "referee_capsule_id" not in adjudication

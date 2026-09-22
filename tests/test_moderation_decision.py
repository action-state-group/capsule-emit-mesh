# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] `moderation_decision.py` unit tests."""
from __future__ import annotations

import hashlib

import pytest
from agent_action_capsule.contracts import InvariantError
from agent_action_capsule.verify import verify as verify_capsule

from moderation_decision import (
    DECISION_ALLOW,
    DECISION_REMOVE,
    EPISTEMIC_TYPE_SEMANTIC_JUDGMENT,
    ModerationDecision,
    PolicyRef,
    SubjectRef,
    check_weights_digest_claim,
    seal_moderation_decision,
)

MSG_DIGEST = hashlib.sha256(b"a message a user sent").hexdigest()
PRINCIPAL_REF = "nostr-pubkey:" + "a" * 64


def _subject_ref(**overrides):
    kwargs = dict(message_digest=MSG_DIGEST, room_ref="room:general", principal_ref=PRINCIPAL_REF)
    kwargs.update(overrides)
    return SubjectRef(**kwargs)


def _policy_ref(**overrides):
    kwargs = dict(policy_id="hate-speech-v1", version="2026.1")
    kwargs.update(overrides)
    return PolicyRef(**kwargs)


def _model_attestation(**overrides):
    kwargs = dict(model_id="buzz-mod-classifier-a", provider="buzz", weights_digest="b" * 64, quantization="fp16")
    kwargs.update(overrides)
    return kwargs


def _decision(**overrides):
    kwargs = dict(
        subject_ref=_subject_ref(),
        policy_ref=_policy_ref(),
        model_attestation=_model_attestation(),
        decision=DECISION_REMOVE,
        basis="policy clause 4.2 (hate speech)",
        confidence=0.91,
        automated=True,
        redress_ref="https://buzz.example/appeal",
    )
    kwargs.update(overrides)
    return ModerationDecision(**kwargs)


def test_subject_ref_rejects_non_digest_message_text() -> None:
    with pytest.raises(InvariantError):
        SubjectRef(message_digest="this is the actual message text", room_ref="room:general")


def test_subject_ref_rejects_empty_room_ref() -> None:
    with pytest.raises(InvariantError):
        SubjectRef(message_digest=MSG_DIGEST, room_ref="")


def test_policy_ref_requires_both_fields() -> None:
    with pytest.raises(InvariantError):
        PolicyRef(policy_id="", version="2026.1")
    with pytest.raises(InvariantError):
        PolicyRef(policy_id="hate-speech-v1", version="")


def test_decision_without_policy_ref_is_rejected_at_construction() -> None:
    """[R4 mutant] "a decision record without a policy version -> rejected
    at seal." `policy_ref` is a required constructor argument typed as
    `PolicyRef`, whose own `__post_init__` already refuses an empty
    version/policy_id -- there is no way to reach `seal_moderation_decision`
    with a policy-version-less decision at all."""
    with pytest.raises(TypeError):
        ModerationDecision(  # type: ignore[call-arg]
            subject_ref=_subject_ref(),
            model_attestation=_model_attestation(),
            decision=DECISION_REMOVE,
            basis="clause 4.2",
            confidence=0.9,
            automated=True,
            redress_ref="https://buzz.example/appeal",
        )


def test_decision_rejects_unknown_decision_value() -> None:
    with pytest.raises(InvariantError):
        _decision(decision="ban_forever")


def test_decision_rejects_empty_basis() -> None:
    with pytest.raises(InvariantError):
        _decision(basis="")


def test_decision_rejects_out_of_range_confidence() -> None:
    with pytest.raises(InvariantError):
        _decision(confidence=1.5)


def test_decision_rejects_empty_redress_ref() -> None:
    with pytest.raises(InvariantError):
        _decision(redress_ref="")


def test_decision_rejects_model_attestation_missing_model_id() -> None:
    with pytest.raises(InvariantError):
        _decision(model_attestation=_model_attestation(model_id=""))


def test_seal_moderation_decision_verifies_offline() -> None:
    capsule = seal_moderation_decision(
        _decision(), operator="buzz-node-1", developer="buzz-mesh-mod/0.1", signing_node_id="node-1"
    )
    result = verify_capsule(capsule)
    assert result.ok, result.findings
    block = capsule["model_attestation"]["compute_attestation"]
    assert block["epistemic_type"] == EPISTEMIC_TYPE_SEMANTIC_JUDGMENT
    assert block["x-mesh-moderation-decision-v1"]["decision"] == DECISION_REMOVE
    assert block["x-mesh-moderation-decision-v1"]["weights_digest_mismatch"] is False


def test_seal_moderation_decision_never_carries_message_text() -> None:
    capsule = seal_moderation_decision(
        _decision(), operator="buzz-node-1", developer="buzz-mesh-mod/0.1", signing_node_id="node-1"
    )
    import json

    raw = json.dumps(capsule)
    assert "a message a user sent" not in raw


class TestWeightsDigestMismatch:
    """[R4 mutant] "classifier lies about its model -> weights_digest
    mismatch labeled." A lying self-report is LABELED, never a reason to
    lose the record."""

    def test_check_weights_digest_claim_flags_a_real_mismatch(self) -> None:
        assert check_weights_digest_claim("b" * 64, "c" * 64) is True

    def test_check_weights_digest_claim_absent_expected_is_not_a_mismatch(self) -> None:
        assert check_weights_digest_claim("b" * 64, None) is False

    def test_check_weights_digest_claim_matching_is_not_a_mismatch(self) -> None:
        assert check_weights_digest_claim("b" * 64, "b" * 64) is False

    def test_sealed_decision_labels_a_lying_weights_digest(self) -> None:
        capsule = seal_moderation_decision(
            _decision(model_attestation=_model_attestation(weights_digest="b" * 64)),
            operator="buzz-node-1",
            developer="buzz-mesh-mod/0.1",
            signing_node_id="node-1",
            expected_weights_digest="c" * 64,
        )
        block = capsule["model_attestation"]["compute_attestation"]["x-mesh-moderation-decision-v1"]
        assert block["weights_digest_mismatch"] is True
        # The record still seals -- a lying self-report is evidence, not a reason to drop it.
        assert verify_capsule(capsule).ok

    def test_sealed_decision_does_not_label_a_true_weights_digest(self) -> None:
        capsule = seal_moderation_decision(
            _decision(model_attestation=_model_attestation(weights_digest="b" * 64)),
            operator="buzz-node-1",
            developer="buzz-mesh-mod/0.1",
            signing_node_id="node-1",
            expected_weights_digest="b" * 64,
        )
        block = capsule["model_attestation"]["compute_attestation"]["x-mesh-moderation-decision-v1"]
        assert block["weights_digest_mismatch"] is False

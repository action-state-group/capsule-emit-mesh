# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] The acceptance test-of-record.

Design doc §6 / task acceptance line: "ten decisions on a Buzz test room,
two twinned, one human-refereed, one appealed via the door; every record
verifies offline; the Art. 17 statement of reasons is generated from the
records alone." Mirrors `[mesh-reconcile-and-close-v0]`'s own "append as a
test-of-record" precedent -- one end-to-end scenario a reviewer can read
top to bottom, plus the two mutants the task's own acceptance line names.
"""
from __future__ import annotations

import hashlib

import pytest
from agent_action_capsule.contracts import InvariantError
from agent_action_capsule.verify import verify as verify_capsule
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from moderation_decision import (
    DECISION_ALLOW,
    DECISION_REMOVE,
    ModerationDecision,
    PolicyRef,
    SubjectRef,
    seal_moderation_decision,
)
from moderation_evidence_door import (
    REASON_POLICY_DECLINE,
    SUBJECT_KIND_MESSAGE_DIGEST,
    RedressRequest,
    answer_redress_request,
    redress_request_signing_body,
)
from moderation_properties import moderation_counts, moderation_properties_from_counts
from moderation_statement import statement_of_reasons_bytes
from moderation_twin import (
    HumanReportKey,
    adjudicate_moderation_twin,
    make_human_report,
    referee_from_human_report,
    seal_human_report_capsule,
    seal_moderation_twin_capsule,
)
from twin_adjudicator import VERDICT_INCONCLUSIVE


class _NodeSigner:
    """A per-node signer -- same duck-typed `.sign(bytes) -> (sig_hex,
    key_id)` contract `capsule_emit.signing`'s real signer offers, standing
    in for it so this test needs no on-disk key material."""

    def __init__(self, key_id: str) -> None:
        self._key = Ed25519PrivateKey.generate()
        self._key_id = key_id

    def sign(self, body: bytes) -> tuple[str, str]:
        return self._key.sign(body).hex(), self._key_id


def _pubkey_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _seal_decision(
    *,
    message_digest: str,
    principal_ref: str | None,
    decision: str,
    owner: str,
    weights_digest: str = "b" * 64,
) -> dict:
    sr = SubjectRef(message_digest=message_digest, room_ref="room:buzz-test-room", principal_ref=principal_ref)
    pr = PolicyRef(policy_id="hate-speech-v1", version="2026.1")
    ma = {"model_id": f"buzz-mod-classifier-{owner}", "provider": "buzz", "weights_digest": weights_digest}
    record = ModerationDecision(
        subject_ref=sr,
        policy_ref=pr,
        model_attestation=ma,
        decision=decision,
        basis="policy clause 4.2 (hate speech)",
        confidence=0.88,
        automated=True,
        redress_ref="https://buzz.example/appeal",
    )
    return seal_moderation_decision(
        record, operator=f"buzz-node-{owner}", developer="buzz-mesh-mod/0.1", signing_node_id=f"node-{owner}"
    )


def test_ten_decisions_two_twinned_one_human_refereed_one_appealed() -> None:
    author_key = Ed25519PrivateKey.generate()
    author_principal_ref = "nostr-pubkey:" + _pubkey_hex(author_key)

    ledger: list[dict] = []

    # -- Eight single-classifier decisions, one per distinct message ------
    # (8 solo + the twin pair below = the acceptance line's "ten decisions,
    # two twinned")
    plain_decisions = []
    for i in range(8):
        digest = _digest(f"buzz-test-room message {i}")
        decision_value = DECISION_REMOVE if i % 2 == 0 else DECISION_ALLOW
        capsule = _seal_decision(
            message_digest=digest, principal_ref=author_principal_ref, decision=decision_value, owner="solo"
        )
        plain_decisions.append(capsule)
        ledger.append(capsule)

    # -- The twin pair: disagreeing twins, human-refereed, appealed --------
    twin2_digest = _digest("buzz-test-room message twin-2 (disagree, appealed)")
    twin2_a = _seal_decision(message_digest=twin2_digest, principal_ref=author_principal_ref, decision=DECISION_REMOVE, owner="c")
    twin2_b = _seal_decision(message_digest=twin2_digest, principal_ref=author_principal_ref, decision=DECISION_ALLOW, owner="d")
    ledger += [twin2_a, twin2_b]

    review_key = HumanReportKey.generate()
    human_report = make_human_report(
        review_key,
        reviewer_id="reviewer-1",
        subject_message_digest=twin2_digest,
        verdict=VERDICT_INCONCLUSIVE,
        rationale="context is genuinely ambiguous; declining to overturn or uphold",
    )
    human_report_capsule = seal_human_report_capsule(human_report, operator="buzz-review", developer="buzz-mesh-mod/0.1")
    ledger.append(human_report_capsule)

    def referee(a, b):
        return referee_from_human_report(human_report, report_capsule_id=human_report_capsule["capsule_id"])

    outcome2 = adjudicate_moderation_twin(
        twin2_a, twin2_b, owner_a_id="owner-c", owner_b_id="owner-d", referee=referee, referee_owner_id="reviewer-1"
    )
    assert outcome2.verdict == VERDICT_INCONCLUSIVE
    assert outcome2.referee_identity_id == "human:reviewer-1"
    adjudication2 = seal_moderation_twin_capsule(outcome2, operator="buzz-node-c", developer="buzz-mesh-mod/0.1")
    ledger.append(adjudication2)

    all_decisions = plain_decisions + [twin2_a, twin2_b]
    assert len(all_decisions) == 10  # the acceptance line's "ten decisions"

    # -- Every record verifies offline -------------------------------------
    for capsule in ledger:
        result = verify_capsule(capsule)
        assert result.ok, (capsule.get("capsule_id"), result.findings)

    # -- The redress door: appeal on twin #2's decision (the SUBJECT) -----
    signer = _NodeSigner(key_id="node-c-key")
    appeal_body = redress_request_signing_body(twin2_digest, author_principal_ref)
    appeal_sig = author_key.sign(appeal_body).hex()
    appeal_req = RedressRequest(
        subject_kind=SUBJECT_KIND_MESSAGE_DIGEST,
        message_digest=twin2_digest,
        requester_principal_ref=author_principal_ref,
        requester_signature=appeal_sig,
    )
    appeal_answer = answer_redress_request(
        ledger, appeal_req, signer=signer, request_digest="appeal-1", issued_at="2026-09-22T00:00:00Z"
    ).to_wire()
    assert appeal_answer["status"] == "SATISFIED"
    bundle = appeal_answer["bundles"][0]
    assert bundle["decision"]["capsule_id"] == twin2_a["capsule_id"]
    assert bundle["adjudication"]["capsule_id"] == adjudication2["capsule_id"]
    assert bundle["human_report"]["capsule_id"] == human_report_capsule["capsule_id"]

    # -- Bundle verifies offline (each cited capsule re-verifies alone) ----
    assert verify_capsule(bundle["decision"]).ok
    assert verify_capsule(bundle["adjudication"]).ok
    assert verify_capsule(bundle["human_report"]).ok

    # -- A non-subject asking for the SAME digest -> WITHHELD --------------
    stranger_key = Ed25519PrivateKey.generate()
    stranger_principal_ref = "nostr-pubkey:" + _pubkey_hex(stranger_key)
    stranger_body = redress_request_signing_body(twin2_digest, stranger_principal_ref)
    stranger_sig = stranger_key.sign(stranger_body).hex()
    stranger_req = RedressRequest(
        subject_kind=SUBJECT_KIND_MESSAGE_DIGEST,
        message_digest=twin2_digest,
        requester_principal_ref=stranger_principal_ref,
        requester_signature=stranger_sig,
    )
    stranger_answer = answer_redress_request(
        ledger, stranger_req, signer=signer, request_digest="appeal-2", issued_at="2026-09-22T00:00:01Z"
    ).to_wire()
    assert stranger_answer["status"] == "WITHHELD"
    assert stranger_answer["reason"] == REASON_POLICY_DECLINE
    assert "bundles" not in stranger_answer

    # -- The statement of reasons regenerates byte-identical from the bundle
    first_regen = statement_of_reasons_bytes(bundle)
    second_regen = statement_of_reasons_bytes(bundle)
    assert first_regen == second_regen
    # A DIFFERENT (but equally SATISFIED) fetch of the same bundle produces
    # the SAME statement bytes too -- "from the records alone" holds across
    # independently-issued requests, not just repeated calls on one object.
    appeal_answer_2 = answer_redress_request(
        ledger, appeal_req, signer=signer, request_digest="appeal-3", issued_at="2026-09-22T00:00:02Z"
    ).to_wire()
    bundle_2 = appeal_answer_2["bundles"][0]
    assert statement_of_reasons_bytes(bundle_2) == first_regen

    # -- Moderation properties: system rates, recomputable from records ----
    counts = moderation_counts(all_decisions, ledger=ledger)
    assert counts.total_decisions == 10
    assert counts.twinned_decisions == 2  # both twin_a and twin_b were twin-compared
    assert counts.disagreements == 2  # both cite the same inconclusive (non-corroborated) verdict
    assert counts.human_refereed_decisions == 2
    props = moderation_properties_from_counts(counts)
    assert props.twin_disagreement_rate == "1"


def test_mutant_weights_digest_mismatch_is_labeled_not_rejected() -> None:
    """[R4] acceptance mutant: "classifier lies about its model ->
    weights_digest mismatch labeled." """
    digest = _digest("a message the lying classifier reviewed")
    capsule = seal_moderation_decision(
        ModerationDecision(
            subject_ref=SubjectRef(message_digest=digest, room_ref="room:buzz-test-room"),
            policy_ref=PolicyRef(policy_id="hate-speech-v1", version="2026.1"),
            model_attestation={"model_id": "buzz-mod-classifier-x", "provider": "buzz", "weights_digest": "b" * 64},
            decision=DECISION_ALLOW,
            basis="clause 4.2",
            confidence=0.7,
            automated=True,
            redress_ref="https://buzz.example/appeal",
        ),
        operator="buzz-node-x",
        developer="buzz-mesh-mod/0.1",
        signing_node_id="node-x",
        expected_weights_digest="c" * 64,  # independently computed -- disagrees with the claim
    )
    assert verify_capsule(capsule).ok  # still seals
    block = capsule["model_attestation"]["compute_attestation"]["x-mesh-moderation-decision-v1"]
    assert block["weights_digest_mismatch"] is True


def test_mutant_decision_without_policy_version_is_rejected_at_seal() -> None:
    """[R4] acceptance mutant: "a decision record without a policy version
    -> rejected at seal." `PolicyRef` itself refuses to construct with an
    empty `version` -- there is no code path that reaches
    `seal_moderation_decision` without one."""
    with pytest.raises(InvariantError):
        PolicyRef(policy_id="hate-speech-v1", version="")


def test_mutant_per_user_history_request_has_no_subject_kind_to_construct() -> None:
    """[R4] acceptance mutant: "a request for a per-user history ->
    refused by construction (no such subject kind)." Demonstrated from BOTH
    sides: (a) the door refuses any subject_kind other than
    `message_digest` (see `test_moderation_evidence_door.
    test_per_user_history_subject_kind_is_refused_by_construction`), and
    (b) `RedressRequest` itself has no field that could name a principal
    and mean "everything this principal was ever moderated for" -- there is
    no `principal_history` constant anywhere in this module to construct
    one with."""
    import moderation_evidence_door as door

    assert not hasattr(door, "SUBJECT_KIND_PRINCIPAL_HISTORY")
    assert door.SUBJECT_KIND_MESSAGE_DIGEST == "message_digest"

# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] `moderation_statement.py` unit tests."""
from __future__ import annotations

import hashlib

from moderation_decision import DECISION_REMOVE, ModerationDecision, PolicyRef, SubjectRef, seal_moderation_decision
from moderation_statement import render_statement_of_reasons, statement_of_reasons_bytes
from moderation_twin import (
    HumanReportKey,
    adjudicate_moderation_twin,
    make_human_report,
    referee_from_human_report,
    seal_human_report_capsule,
    seal_moderation_twin_capsule,
)
from twin_adjudicator import contradicted

MSG_DIGEST = hashlib.sha256(b"the removed message").hexdigest()


def _seal(decision_value: str, *, owner: str) -> dict:
    sr = SubjectRef(message_digest=MSG_DIGEST, room_ref="room:general", principal_ref="nostr-pubkey:" + "a" * 64)
    pr = PolicyRef(policy_id="hate-speech-v1", version="2026.1")
    ma = {"model_id": f"buzz-mod-classifier-{owner}", "provider": "buzz", "weights_digest": "b" * 64}
    d = ModerationDecision(
        subject_ref=sr,
        policy_ref=pr,
        model_attestation=ma,
        decision=decision_value,
        basis="clause 4.2 (hate speech)",
        confidence=0.9,
        automated=True,
        redress_ref="https://buzz.example/appeal",
    )
    return seal_moderation_decision(d, operator=f"buzz-node-{owner}", developer="buzz-mesh-mod/0.1", signing_node_id=f"node-{owner}")


def test_statement_regenerates_byte_identical_from_the_same_bundle() -> None:
    decision_cap = _seal(DECISION_REMOVE, owner="a")
    bundle = {"decision": decision_cap}
    assert statement_of_reasons_bytes(bundle) == statement_of_reasons_bytes(bundle)


def test_statement_never_carries_message_text() -> None:
    decision_cap = _seal(DECISION_REMOVE, owner="a")
    bundle = {"decision": decision_cap}
    raw = statement_of_reasons_bytes(bundle)
    assert b"the removed message" not in raw


def test_statement_carries_the_art17_required_fields() -> None:
    decision_cap = _seal(DECISION_REMOVE, owner="a")
    bundle = {"decision": decision_cap}
    statement = render_statement_of_reasons(bundle)
    assert statement["automated_means"] is True
    assert statement["legal_ground"] == {"policy_id": "hate-speech-v1", "version": "2026.1"}
    assert statement["decision"] == DECISION_REMOVE
    assert statement["redress"] == "https://buzz.example/appeal"


def test_statement_includes_adjudication_when_present() -> None:
    a = _seal(DECISION_REMOVE, owner="a")
    b = _seal("allow", owner="b")
    key = HumanReportKey.generate()
    report = make_human_report(
        key,
        reviewer_id="reviewer-1",
        subject_message_digest=MSG_DIGEST,
        verdict=contradicted("owner-a"),
        rationale="removal was too aggressive",
    )
    report_cap = seal_human_report_capsule(report, operator="buzz-review", developer="buzz-mesh-mod/0.1")

    def referee(x, y):
        return referee_from_human_report(report, report_capsule_id=report_cap["capsule_id"])

    outcome = adjudicate_moderation_twin(
        a, b, owner_a_id="owner-a", owner_b_id="owner-b", referee=referee, referee_owner_id="reviewer-1"
    )
    adjudication_cap = seal_moderation_twin_capsule(outcome, operator="buzz-node-a", developer="buzz-mesh-mod/0.1")

    bundle = {"decision": a, "adjudication": adjudication_cap}
    statement = render_statement_of_reasons(bundle)
    assert statement["adjudication"]["verdict"] == contradicted("owner-a")
    assert statement["adjudication"]["referee_id"] == "human:reviewer-1"

    # Regeneration from the SAME bundle is still byte-identical with an
    # adjudication block present.
    assert statement_of_reasons_bytes(bundle) == statement_of_reasons_bytes(bundle)

# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] The `moderation_decision` record.

Buzz asked for compliance-grade content moderation; the accountable answer is
not a better classifier, it's a SEALED record of every moderation call a
user, auditor, or regulator can check offline -- the same rail as mesh
inference accountability (`join_card.py`, `twin_adjudicator.py`), a
a different capsule profile on top (`buzz.moderation/v1`, spec lane).

Design note: internal moderation-accountability profile note (spec lane).

**epistemic_type: `semantic_judgment`.** Unlike mesh inference accountability
(deterministic -- a referee recomputes a token), a moderation call is a
judgment: reasonable reviewers can disagree, so the epistemic type differs
from `join_card`/`twin_adjudicator`'s `producer_claim`/`adjudication` (see
`[mesh-fabric-vocab-alignment]`, `twin_adjudicator.EPISTEMIC_TYPE_ADJUDICATION`).

**Never the message text.** `subject_ref` carries only a digest + typed room
reference -- the affected user already holds their own message and can
verify the digest themselves (the requester-held-half pattern this repo
already uses for inference accountability, unchanged here). `principal_ref`
binds the record to the message AUTHOR's identity under the `nostr-pubkey`
host-principal profile (`join_card.nostr_pubkey_principal_ref`) so the
redress door (`moderation_evidence_door.py`) can scope a decision bundle to
the one requester who is actually the subject, never a public score.

**No user scores, ever.** `decision`/`basis`/`confidence` are properties of
ONE decision, not a per-account judgment. Anything that aggregates across a
principal's decisions belongs to Buzz's own product surface, never this
record or the neutral properties this repo publishes
(`moderation_properties.py`).

**Rejected at seal, not just discouraged: `policy_ref`.** Art. 17 requires a
statement of reasons to name the policy clause under which a message was
restricted -- a `ModerationDecision` literally cannot be constructed without
one (see `PolicyRef.__post_init__` below), mirroring
`agent_action_capsule.contracts.ReferenceEntry`'s own required-field
discipline (raise, never a silently-absent optional).

**Labeled, not silently rejected: a lying `weights_digest`.** `model_attestation`
is the classifier's own self-report, carried straight from the mesh node's
already-sealed inference half (`join_card.ModelRef`/`capsule_sidecar`'s
`model_attestation` block) -- this module does not re-derive it. When a
caller supplies an independently-computed `expected_weights_digest` (e.g.
from the twin/referee's own model package) and it disagrees with the
classifier's claim, the sealed record carries `weights_digest_mismatch:
true` rather than refusing to seal -- a lying self-report is evidence in
its own right, not a reason to lose the record (see `seal_moderation_decision`).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from agent_action_capsule.contracts import InvariantError
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.numbers import float_to_str

__all__ = [
    "MODERATION_SCHEMA",
    "MODERATION_SUBJECT_KEY",
    "EPISTEMIC_TYPE_SEMANTIC_JUDGMENT",
    "EPISTEMIC_TYPE_PRODUCER_CLAIM",
    "EPISTEMIC_TYPE_OBLIGATION_REFERENCE",
    "DECISION_ALLOW",
    "DECISION_REMOVE",
    "DECISION_RESTRICT",
    "DECISION_ESCALATE",
    "DECISION_VALUES",
    "SubjectRef",
    "PolicyRef",
    "ModerationDecision",
    "check_weights_digest_claim",
    "seal_moderation_decision",
]

#: Capsule marker for the moderation-decision subject block, mirroring
#: `join_card.CARD_SUBJECT_KEY` / `history_card.HISTORY_SUBJECT_KEY`.
MODERATION_SUBJECT_KEY = "x-mesh-moderation-decision-v1"

#: Schema tag on the sealed decision, versioned so a consumer can refuse a
#: shape it does not understand rather than mis-read it.
MODERATION_SCHEMA = "capsule-emit-mesh/moderation-decision/v1"

#: [mesh-fabric-vocab-alignment] the fabric's shared record-header vocabulary
#: convention, extended with the one value the spike's internal design
#: note (sec.1) introduces: a moderation decision is a semantic JUDGMENT, never a
#: deterministic recompute (`twin_adjudicator.EPISTEMIC_TYPE_ADJUDICATION`)
#: and never a bare self-report (`EPISTEMIC_TYPE_PRODUCER_CLAIM` below, used
#: only for the `confidence` sub-field).
EPISTEMIC_TYPE_SEMANTIC_JUDGMENT = "semantic_judgment"
#: The `confidence` field's own epistemic type -- the model's self-report,
#: never an arbiter of anything (see `ModerationDecision.confidence`).
EPISTEMIC_TYPE_PRODUCER_CLAIM = "producer_claim"
#: `policy_ref`'s epistemic type -- a citation to Buzz's own policy registry
#: (external to this record), never a claim this record itself adjudicates.
EPISTEMIC_TYPE_OBLIGATION_REFERENCE = "obligation_reference"

DECISION_ALLOW = "allow"
DECISION_REMOVE = "remove"
DECISION_RESTRICT = "restrict"
DECISION_ESCALATE = "escalate"
DECISION_VALUES = frozenset({DECISION_ALLOW, DECISION_REMOVE, DECISION_RESTRICT, DECISION_ESCALATE})


@dataclass(frozen=True)
class SubjectRef:
    """What decision this record is about -- a digest + typed room
    reference, NEVER the message text (see module docstring).

    `principal_ref` is the message AUTHOR's identity under a host-principal
    profile (`join_card.nostr_pubkey_principal_ref` builds the wire form) --
    `None`, absent rather than fabricated, until the platform actually binds
    one. The redress door refuses to answer without it (see
    `moderation_evidence_door.py`): a decision sealed with no bound
    principal has no requester it could ever recognize as "the subject."
    """

    message_digest: str
    room_ref: str
    principal_ref: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.message_digest, str) or len(self.message_digest) != 64:
            raise InvariantError("subject_ref.message_digest MUST be a 64-hex digest, never the message text")
        if not isinstance(self.room_ref, str) or not self.room_ref:
            raise InvariantError("subject_ref.room_ref MUST be a non-empty string")

    def to_value(self) -> dict[str, Any]:
        return {
            "message_digest": self.message_digest,
            "room_ref": self.room_ref,
            "principal_ref": self.principal_ref,
        }


@dataclass(frozen=True)
class PolicyRef:
    """The obligation reference a decision is made under. REQUIRED on every
    `ModerationDecision` -- Art. 17 requires the legal/contractual ground
    for every restriction, so a policy-version-less decision is not a lesser
    record, it is not a record at all (see module docstring, "Rejected at
    seal")."""

    policy_id: str
    version: str

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id:
            raise InvariantError("policy_ref.policy_id MUST be a non-empty string (Art. 17 legal ground)")
        if not isinstance(self.version, str) or not self.version:
            raise InvariantError("policy_ref.version MUST be a non-empty string (Art. 17 legal ground)")

    def to_value(self) -> dict[str, Any]:
        return {"policy_id": self.policy_id, "version": self.version}


def check_weights_digest_claim(claimed: str | None, expected: str | None) -> bool:
    """True when the classifier's own claimed `weights_digest` disagrees
    with an independently-computed *expected* one. Both `None` (nothing to
    check) or either `None` alone (nothing to compare against) is NOT a
    mismatch -- absence is never fabricated into a lie, only an actual
    disagreement is (see module docstring, "Labeled, not silently rejected").
    """
    if claimed is None or expected is None:
        return False
    return claimed != expected


@dataclass(frozen=True)
class ModerationDecision:
    """One moderation call, ready to seal. Construction itself enforces the
    record's non-negotiable invariants (`policy_ref` presence, `decision`
    closed vocabulary, a non-empty `redress_ref`) -- see the module
    docstring's mutant note. Everything else is exactly the design doc's
    §2 field table."""

    subject_ref: SubjectRef
    policy_ref: PolicyRef
    model_attestation: dict[str, Any]
    decision: str
    basis: str
    confidence: float
    automated: bool
    redress_ref: str
    human_review_ref: str | None = None
    #: Left `None` on the FIRST seal of a decision -- a capsule's content is
    #: digest-committed at seal time, before its own twin/adjudication
    #: outcome can exist, so these can never be forward-filled onto the
    #: original record. `moderation_twin.find_adjudication_for_decision`
    #: (a reverse citation scan -- the adjudication cites the decisions it
    #: compares, never the other way round) is the mechanism
    #: `moderation_evidence_door.py`/`moderation_properties.py` actually use
    #: to find a decision's adjudication. These two fields exist for a
    #: caller that chooses to seal a LATER, superseding decision capsule
    #: (`prior_capsule_id` chained to this one) once the outcome is known --
    #: out of this spike's own build/test scope.
    twin_ref: str | None = None
    adjudication_ref: str | None = None

    def __post_init__(self) -> None:
        if self.decision not in DECISION_VALUES:
            raise InvariantError(f"decision must be one of {sorted(DECISION_VALUES)}, got {self.decision!r}")
        if not isinstance(self.basis, str) or not self.basis:
            raise InvariantError("basis MUST be a non-empty string naming the policy clause")
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 1.0):
            raise InvariantError("confidence MUST be a number in [0.0, 1.0]")
        if not isinstance(self.redress_ref, str) or not self.redress_ref:
            raise InvariantError("redress_ref MUST be a non-empty string -- Art. 17 requires an appeal path always")
        model_id = self.model_attestation.get("model_id")
        provider = self.model_attestation.get("provider")
        if not isinstance(model_id, str) or not model_id or not isinstance(provider, str) or not provider:
            raise InvariantError("model_attestation MUST carry a non-empty model_id and provider")

    def to_value(self, *, weights_digest_mismatch: bool = False) -> dict[str, Any]:
        return {
            "schema": MODERATION_SCHEMA,
            "subject_ref": self.subject_ref.to_value(),
            "policy_ref": {
                "epistemic_type": EPISTEMIC_TYPE_OBLIGATION_REFERENCE,
                **self.policy_ref.to_value(),
            },
            "model_attestation": dict(self.model_attestation),
            "weights_digest_mismatch": weights_digest_mismatch,
            "decision": self.decision,
            "basis": self.basis,
            "confidence": {
                "epistemic_type": EPISTEMIC_TYPE_PRODUCER_CLAIM,
                "value": float_to_str(float(self.confidence), field="moderation_decision.confidence"),
                "not_an_arbiter": (
                    "the classifier's own self-reported confidence -- never treated as the "
                    "verdict on whether the decision was correct"
                ),
            },
            "automated": bool(self.automated),
            "human_review_ref": self.human_review_ref,
            "twin_ref": self.twin_ref,
            "adjudication_ref": self.adjudication_ref,
            "redress_ref": self.redress_ref,
        }


def seal_moderation_decision(
    decision: ModerationDecision,
    *,
    operator: str,
    developer: str,
    signing_node_id: str,
    prior_capsule_id: str | None = None,
    expected_weights_digest: str | None = None,
    provider: str = "mesh-llm",
) -> dict[str, Any]:
    """Seal a `moderation_decision` -- same pattern as `join_card.seal_card`
    / `twin_adjudicator.seal_adjudication_capsule`: a CAPSULE built with
    `agent_action_capsule.emit()`, verified BEFORE it is handed to a caller
    that might persist it (`[adv-run-2-fix-batch]` discipline).

    `expected_weights_digest`, when supplied, is compared against the
    classifier's own claimed `model_attestation.weights_digest` -- a
    mismatch is LABELED on the sealed record (`weights_digest_mismatch:
    true`), never a reason to refuse sealing (see `check_weights_digest_claim`).
    """
    claimed_weights_digest = decision.model_attestation.get("weights_digest")
    mismatch = check_weights_digest_claim(claimed_weights_digest, expected_weights_digest)
    compute_attestation = {
        # [mesh-fabric-vocab-alignment] additive record-header field, a
        # top-level sibling of MODERATION_SUBJECT_KEY.
        "epistemic_type": EPISTEMIC_TYPE_SEMANTIC_JUDGMENT,
        MODERATION_SUBJECT_KEY: decision.to_value(weights_digest_mismatch=mismatch),
    }
    capsule = emit(
        action_id=f"mesh-buzz-moderation/{signing_node_id}/{uuid.uuid4()}",
        action_type="decide",
        operator=operator,
        developer=developer,
        provider=provider,
        compute_attestation=compute_attestation,
        prior_capsule_id=prior_capsule_id,
        chain_relation="follows" if prior_capsule_id else None,
        domain="action",
        provenance="collector",
    )
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"moderation_decision emitted a capsule that fails its own verify(): {result.findings}")
    return capsule

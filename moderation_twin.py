# SPDX-License-Identifier: Apache-2.0
"""[buzz-moderation-profile-spike] Twin + referee for `moderation_decision`.

Reuses `twin_adjudicator.py`'s verdict vocabulary (`VERDICT_CORROBORATED`/
`VERDICT_INCONCLUSIVE`/`contradicted()`), its `status_for_verdict` mapping,
its `RefereeIdentity`/`RefereeResult` wire shapes, and its
`RELATION_ADJUDICATES`/`EPISTEMIC_TYPE_ADJUDICATION` constants directly --
same rail, same vocabulary (`[mesh-fabric-vocab-alignment]`), NOT the same
comparison engine. `twin_adjudicator.adjudicate()` compares two DETERMINISTIC
token sequences (a referee recomputes a token); a moderation decision is a
CATEGORICAL judgment (`allow`/`remove`/`restrict`/`escalate`) where
disagreement is expected, not a divergence to explain away. See design doc
§3: "the shape changes but the rule doesn't: the arbiter must be something
the decider can't forge."

**The referee can be a human.** `twin_adjudicator.RefereeIdentity` already
carries an optional `signature` field for exactly this case
(`[mesh-referee-attribution]`) -- `referee_from_human_report()` below
packages a `human_report` capsule (signed under the reviewer's OWN
persistent key, same discipline as `node_ownership.py`'s owner cert) into
that same shape, so a moderation twin's adjudication capsule cites a human
referee identically to how the inference rail cites a model referee.

**Inconclusive is first-class**, never a default: a human who declines to
rule produces `VERDICT_INCONCLUSIVE` explicitly, same as two models whose
disagreement has no referee at all (design doc §3, "the decision stands or
falls per policy, and the record says so").
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agent_action_capsule.contracts import Disposition
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule
from moderation_decision import MODERATION_SUBJECT_KEY
from twin_adjudicator import (
    EPISTEMIC_TYPE_ADJUDICATION,
    NO_VERDICT_REFEREE_NOT_INDEPENDENT,
    NO_VERDICT_REFEREE_UNREACHABLE,
    NO_VERDICT_SAME_OWNER_TWIN,
    NO_VERDICT_WEIGHTS_MISMATCH,
    RELATION_ADJUDICATES,
    RefereeIdentity,
    RefereeResult,
    UnattributableRefereeError,
    VERDICT_CORROBORATED,
    VERDICT_INCONCLUSIVE,
    contradicted,
    status_for_verdict,
)

__all__ = [
    "HUMAN_REPORT_SCHEMA",
    "HUMAN_REPORT_SUBJECT_KEY",
    "EPISTEMIC_TYPE_HUMAN_REPORT",
    "MODERATION_ADJUDICATION_SCHEMA",
    "ForgedDecisionError",
    "HumanReportKey",
    "HumanReportVerdict",
    "ModerationReferee",
    "ModerationTwinComparison",
    "ModerationAdjudicationOutcome",
    "make_human_report",
    "verify_human_report",
    "seal_human_report_capsule",
    "referee_from_human_report",
    "compare_moderation_decisions",
    "adjudicate_moderation_twin",
    "seal_moderation_twin_capsule",
    "find_adjudication_for_decision",
]

HUMAN_REPORT_SCHEMA = "capsule-emit-mesh/human-report/v1"
HUMAN_REPORT_SUBJECT_KEY = "x-mesh-human-report-v1"
MODERATION_ADJUDICATION_SCHEMA = "capsule-emit-mesh/moderation-adjudication/v1"

#: [buzz-moderation-profile-spike] the record type this module adds to the
#: fabric's epistemic_type vocabulary: a signed human reviewer's OWN report,
#: never a model's self-report (`producer_claim`) and never this node's own
#: recompute (`adjudication`).
EPISTEMIC_TYPE_HUMAN_REPORT = "human_report"


class ForgedDecisionError(ValueError):
    """A `moderation_decision` capsule failed its own `verify()` -- refuse
    to compare, same discipline as `twin_adjudicator.ForgedHalfError`."""


def _jcs(obj: dict[str, Any]) -> bytes:
    """JSON Canonical Serialization -- same convention as
    `requester_identity_binding._jcs()` / `node_ownership.py`'s signing
    body: one signing convention for hex-keyed Ed25519 artifacts across this
    repo."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@dataclass
class HumanReportKey:
    """A reviewer's persistent Ed25519 keypair -- same shape as
    `requester_identity_binding.RequesterIdentityKey`, applied to a human
    moderation reviewer instead of a requester."""

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "HumanReportKey":
        return cls(private_key=Ed25519PrivateKey.generate())

    @property
    def public_key_hex(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def make_human_report(
    key: HumanReportKey,
    *,
    reviewer_id: str,
    subject_message_digest: str,
    verdict: str,
    rationale: str,
    issued_at_unix_ms: int | None = None,
) -> dict[str, Any]:
    """Sign a human reviewer's report: "I looked at this decision and my
    verdict is *verdict*." `verdict` is the SAME closed vocabulary
    `twin_adjudicator` already defines (`VERDICT_CORROBORATED`,
    `VERDICT_INCONCLUSIVE`, or `contradicted(owner_id)`) -- a human referee
    speaks the same language a model referee does, never a fourth
    vocabulary this module invents."""
    body: dict[str, Any] = {
        "schema": HUMAN_REPORT_SCHEMA,
        "reviewer_id": reviewer_id,
        "reviewer_public_key": key.public_key_hex,
        "subject_message_digest": subject_message_digest,
        "verdict": verdict,
        "rationale": rationale,
        "issued_at_unix_ms": issued_at_unix_ms if issued_at_unix_ms is not None else int(time.time() * 1000),
    }
    signature = key.sign(_jcs(body))
    return {**body, "signature": signature.hex()}


@dataclass(frozen=True)
class HumanReportVerdict:
    """Result of `verify_human_report()` -- never raised, a first-class
    result the caller derives a decision from, same discipline as
    `node_ownership.OwnershipRecheck` / `requester_identity_binding.
    IdentityBindingVerdict`."""

    valid: bool
    reason: str


def verify_human_report(report: dict[str, Any]) -> HumanReportVerdict:
    """Verify a human report's own signature verifies under its own
    embedded key -- structural only, same caveat as every other
    self-asserted identity in this repo (see `node_ownership.
    IDENTITY_LIMITATION_CAVEAT`): this proves the reviewer who holds
    `reviewer_public_key` signed this exact report, not that `reviewer_id`
    corresponds to any real, authorized moderator -- that binding is
    Buzz's own reviewer-roster problem, out of scope here."""
    try:
        sig_hex = report["signature"]
        pub_hex = report["reviewer_public_key"]
    except KeyError as exc:
        return HumanReportVerdict(valid=False, reason=f"malformed human report: missing {exc}")
    body = {k: v for k, v in report.items() if k != "signature"}
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pubkey.verify(bytes.fromhex(sig_hex), _jcs(body))
    except InvalidSignature:
        return HumanReportVerdict(valid=False, reason="human report signature verification failed")
    except (ValueError, TypeError) as exc:
        return HumanReportVerdict(valid=False, reason=f"malformed human report key or signature: {exc}")
    return HumanReportVerdict(valid=True, reason="human report signature verified")


def seal_human_report_capsule(report: dict[str, Any], *, operator: str, developer: str) -> dict[str, Any]:
    """Seal a verified human report as its own citable capsule --
    `epistemic_type: human_report` -- so the moderation adjudication
    capsule can cite it by `capsule_id` exactly as it would a model
    referee's served half."""
    verdict = verify_human_report(report)
    if not verdict.valid:
        raise ForgedDecisionError(f"refusing to seal an unverifiable human report: {verdict.reason}")
    compute_attestation = {
        "epistemic_type": EPISTEMIC_TYPE_HUMAN_REPORT,
        HUMAN_REPORT_SUBJECT_KEY: dict(report),
    }
    capsule = emit(
        action_id=f"mesh-buzz-human-report/{report['reviewer_id']}/{uuid.uuid4()}",
        action_type="fyi",
        operator=operator,
        developer=developer,
        compute_attestation=compute_attestation,
        domain="action",
        provenance="collector",
    )
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"human_report emitted a capsule that fails its own verify(): {result.findings}")
    return capsule


def referee_from_human_report(report: dict[str, Any], *, report_capsule_id: str | None) -> RefereeResult:
    """Adapt a signed human report into the SAME `RefereeResult` shape a
    model referee returns (`twin_adjudicator.live_referee`) -- this is the
    substitution point design doc §3.2 calls for: "Referee = a third
    independent model OR a human reviewer.\""""
    return RefereeResult(
        verdict=report["verdict"],
        margin=0.0,
        logprobs_absent=True,
        capsule_id=report_capsule_id,
        identity=RefereeIdentity(
            referee_id=f"human:{report['reviewer_id']}",
            referee_capsule_id=report_capsule_id,
            signature=report["signature"],
        ),
    )


#: A moderation referee call: given both decision capsules and the owner ids
#: that disagreed, returns the tiebreak. Mirrors `twin_adjudicator.Referee`,
#: over `moderation_decision` capsules instead of inference halves.
ModerationReferee = Callable[[dict[str, Any], dict[str, Any]], RefereeResult]


def _moderation_block(capsule: dict[str, Any]) -> dict[str, Any]:
    return (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get(MODERATION_SUBJECT_KEY, {})


def _verify_decision_or_raise(label: str, capsule: dict[str, Any]) -> None:
    result = verify_capsule(capsule)
    if not result.ok:
        raise ForgedDecisionError(f"{label} fails its own verify(): {result.findings}")


def find_adjudication_for_decision(ledger: list[dict[str, Any]], decision_capsule_id: str) -> dict[str, Any] | None:
    """The adjudication capsule (if any) that cites *decision_capsule_id* as
    one of its twins. A `moderation_decision` capsule's content is
    digest-committed at seal time, BEFORE any twin/referee outcome can
    exist -- so `adjudication_ref`/`twin_ref` can never be forward-filled
    onto the original decision the way `chain.parent_capsule_id` cites
    something EARLIER. The adjudication capsule already cites both decisions
    it compares (`decision_a_capsule_id`/`decision_b_capsule_id`, see
    `seal_moderation_twin_capsule`) -- this is the reverse lookup, same
    discipline `adjudication_delivery._cited_capsule_ids` already applies to
    the inference rail's own `*_capsule_id`-suffixed citations. Returns the
    FIRST match; a decision twinned more than once is out of this spike's
    scope."""
    for capsule in ledger:
        adjudication = (capsule.get("model_attestation") or {}).get("compute_attestation", {}).get("adjudication")
        if adjudication is None:
            continue
        if decision_capsule_id in (
            adjudication.get("decision_a_capsule_id"),
            adjudication.get("decision_b_capsule_id"),
        ):
            return capsule
    return None


@dataclass(frozen=True)
class ModerationTwinComparison:
    """Whether two independent classifiers reached the SAME categorical
    `decision` on the same message -- never a text/logprob margin, this is
    a plain equality over a closed vocabulary."""

    agree: bool
    decision_a: str
    decision_b: str


def compare_moderation_decisions(capsule_a: dict[str, Any], capsule_b: dict[str, Any]) -> ModerationTwinComparison:
    decision_a = _moderation_block(capsule_a)["decision"]
    decision_b = _moderation_block(capsule_b)["decision"]
    return ModerationTwinComparison(agree=decision_a == decision_b, decision_a=decision_a, decision_b=decision_b)


@dataclass(frozen=True)
class ModerationAdjudicationOutcome:
    """The result of `adjudicate_moderation_twin()` -- either a verdict, or
    a first-class "nothing to adjudicate" reason. Never both. Mirrors
    `twin_adjudicator.AdjudicationOutcome`'s shape."""

    verdict: str | None
    no_verdict_reason: str | None
    decision_a_capsule_id: str
    decision_b_capsule_id: str
    twin_owner_distinct: bool | None
    weights_digest: str | None = None
    referee_called: bool = False
    referee_capsule_id: str | None = None
    referee_identity_id: str | None = None


def adjudicate_moderation_twin(
    capsule_a: dict[str, Any],
    capsule_b: dict[str, Any],
    *,
    owner_a_id: str,
    owner_b_id: str,
    referee: ModerationReferee | None = None,
    referee_owner_id: str | None = None,
) -> ModerationAdjudicationOutcome:
    """Adjudicate two twin `moderation_decision` capsules over the SAME
    message. Order of checks, each a distinct mutant (mirrors
    `twin_adjudicator.adjudicate()`'s own ordered-checks discipline):

    1. Each capsule must pass its own `verify()` -- a forged twin raises
       `ForgedDecisionError`.
    2. If both capsules declare a `weights_digest` and they differ, there is
       nothing to adjudicate (`NO_VERDICT_WEIGHTS_MISMATCH`) -- the twins
       aren't running comparable classifiers.
    3. Same-owner twins aren't independent (`NO_VERDICT_SAME_OWNER_TWIN`).
    4. Agreement (`compare_moderation_decisions`): `VERDICT_CORROBORATED`,
       referee never called.
    5. Disagreement, no referee: `VERDICT_INCONCLUSIVE` -- disagreement is a
       trigger, never a verdict this function reaches alone.
    6. Disagreement, referee given: independence checked FIRST
       (`NO_VERDICT_REFEREE_NOT_INDEPENDENT` before the referee is ever
       called); a raised exception from the referee callable becomes
       `NO_VERDICT_REFEREE_UNREACHABLE`, never propagated.
    """
    _verify_decision_or_raise("capsule_a", capsule_a)
    _verify_decision_or_raise("capsule_b", capsule_b)

    decision_a_id = capsule_a["capsule_id"]
    decision_b_id = capsule_b["capsule_id"]

    weights_a = _moderation_block(capsule_a).get("model_attestation", {}).get("weights_digest")
    weights_b = _moderation_block(capsule_b).get("model_attestation", {}).get("weights_digest")
    if weights_a is not None and weights_b is not None and weights_a != weights_b:
        return ModerationAdjudicationOutcome(
            verdict=None,
            no_verdict_reason=NO_VERDICT_WEIGHTS_MISMATCH,
            decision_a_capsule_id=decision_a_id,
            decision_b_capsule_id=decision_b_id,
            twin_owner_distinct=None,
            weights_digest=None,
        )
    shared_weights_digest = weights_a if weights_a is not None and weights_a == weights_b else None

    twin_owner_distinct = owner_a_id != owner_b_id
    if not twin_owner_distinct:
        return ModerationAdjudicationOutcome(
            verdict=None,
            no_verdict_reason=NO_VERDICT_SAME_OWNER_TWIN,
            decision_a_capsule_id=decision_a_id,
            decision_b_capsule_id=decision_b_id,
            twin_owner_distinct=False,
            weights_digest=shared_weights_digest,
        )

    comparison = compare_moderation_decisions(capsule_a, capsule_b)
    if comparison.agree:
        return ModerationAdjudicationOutcome(
            verdict=VERDICT_CORROBORATED,
            no_verdict_reason=None,
            decision_a_capsule_id=decision_a_id,
            decision_b_capsule_id=decision_b_id,
            twin_owner_distinct=True,
            weights_digest=shared_weights_digest,
        )

    if referee is None:
        return ModerationAdjudicationOutcome(
            verdict=VERDICT_INCONCLUSIVE,
            no_verdict_reason=None,
            decision_a_capsule_id=decision_a_id,
            decision_b_capsule_id=decision_b_id,
            twin_owner_distinct=True,
            weights_digest=shared_weights_digest,
        )

    if referee_owner_id is not None and referee_owner_id in (owner_a_id, owner_b_id):
        return ModerationAdjudicationOutcome(
            verdict=None,
            no_verdict_reason=NO_VERDICT_REFEREE_NOT_INDEPENDENT,
            decision_a_capsule_id=decision_a_id,
            decision_b_capsule_id=decision_b_id,
            twin_owner_distinct=True,
            weights_digest=shared_weights_digest,
        )

    try:
        referee_result = referee(capsule_a, capsule_b)
    except Exception:  # noqa: BLE001 -- referee unreachable/refused is first-class, never a crash
        return ModerationAdjudicationOutcome(
            verdict=None,
            no_verdict_reason=NO_VERDICT_REFEREE_UNREACHABLE,
            decision_a_capsule_id=decision_a_id,
            decision_b_capsule_id=decision_b_id,
            twin_owner_distinct=True,
            weights_digest=shared_weights_digest,
            referee_called=True,
        )

    if referee_result.identity is None:
        raise UnattributableRefereeError(
            "referee result has no identity -- an unattributed verdict must not seal; "
            "supply a RefereeIdentity with a non-empty referee_id"
        )

    return ModerationAdjudicationOutcome(
        verdict=referee_result.verdict,
        no_verdict_reason=None,
        decision_a_capsule_id=decision_a_id,
        decision_b_capsule_id=decision_b_id,
        twin_owner_distinct=True,
        weights_digest=shared_weights_digest,
        referee_called=True,
        referee_capsule_id=referee_result.capsule_id,
        referee_identity_id=referee_result.identity.referee_id,
    )


def seal_moderation_twin_capsule(
    outcome: ModerationAdjudicationOutcome,
    *,
    operator: str,
    developer: str,
) -> dict[str, Any] | None:
    """Seal a moderation twin's adjudication verdict -- same pattern as
    `twin_adjudicator.seal_adjudication_capsule`. Returns `None`, sealing
    nothing, when *outcome* has no verdict (a weights-mismatched or
    same-owner "twin" has nothing to adjudicate) -- there is no "refused"
    adjudication capsule, same discipline as the inference rail."""
    if outcome.verdict is None:
        return None

    adjudication: dict[str, Any] = {
        "schema": MODERATION_ADJUDICATION_SCHEMA,
        "verdict": outcome.verdict,
        # [mesh-fabric-vocab-alignment] additive per-verdict fabric status.
        "status": status_for_verdict(outcome.verdict),
        "twin_owner_distinct": outcome.twin_owner_distinct,
        "weights_digest": outcome.weights_digest,
        "decision_a_capsule_id": outcome.decision_a_capsule_id,
        "decision_b_capsule_id": outcome.decision_b_capsule_id,
    }
    if outcome.referee_called:
        adjudication["referee_capsule_id"] = outcome.referee_capsule_id
        adjudication["referee_id"] = outcome.referee_identity_id

    compute_attestation = {
        "epistemic_type": EPISTEMIC_TYPE_ADJUDICATION,
        "adjudication": adjudication,
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
        prior_capsule_id=outcome.decision_a_capsule_id,
        chain_relation=RELATION_ADJUDICATES,
        domain="action",
        provenance="referee",
        tool_name="moderation_twin_adjudicate",
    )
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"moderation twin emitted a capsule that fails its own verify(): {result.findings}")
    return capsule

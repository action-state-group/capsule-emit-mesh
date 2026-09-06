#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-served-summary-derivation] ``served_summary()`` -- "what did this
stranger actually serve" -- a node's own fold over what it SERVED, mirroring
``history_card.py`` and ``account_capsule.py``'s shape but over a different
question. Today's history card publishes structural facts about the
checkpoint CHAIN (continuity, depth, cadence). A stranger deciding whether to
route also wants: served N, completed N, failed N, latency distribution, and
model/quantization breakdown -- facts that exist per capsule (``effect.status``,
``x-mesh-poc-v1.latency_ms``, ``.serving_provenance.model_canonical_ref``,
``.quantization``, ``.role``) but today are only reachable by pulling records,
which (a) costs bandwidth and (b) leaks ``cross_party.initiator_ref`` /
``serving_provenance.requesting_party`` -- WHO was served. This derivation
answers WHAT was served without ever reading or reporting WHO asked.

**Built on the neutral account/fold core**, same discipline as
``account_capsule.py``: a **range**-kind, **deterministic** ``AccountDefinition``
whose declared ``reads`` name exactly six capsule fields --
``effect.status``, ``latency_ms``, ``model_canonical_ref``, ``quantization``,
``weights_digest``, ``role`` -- and NEVER a requester-identity field. Verified
by recompute+match through ``capsule_emit.account.verify_account``, the same
neutral core ``history_card.py``/``account_capsule.py`` already use.

**Three sources, labeled, never merged into one number** (the ruled design):

  * **self_derived** (this module's fold) -- this node counting its own log.
    A tampered count is a signed lie a witness-checkpoint cross-check catches;
    it is never taken on say-so.
  * **sampled** (``verify_served_summary`` below) -- a relying party's own
    spot-check: pull ``k`` records by position (digests tier, no bodies) and
    confirm they agree with the summary's claims. A verification METHOD, not
    a fourth source -- cited alongside ``self_derived``, never standing alone.
  * **counterparty_held** / ``self_held`` -- twin-adjudication verdicts ABOUT
    this node come from its counterparties (``[mesh-ask-the-references]``),
    never from this module. ``adjudications_received`` below is labeled
    ``self_held``: this node's own retained count of verdicts it
    ``received()`` into its log, not a self-derived property of what it
    served -- carried OUTSIDE ``core_account()``'s asserted result for
    exactly that reason (a different axis, same discipline
    ``HistoryCard.reconciled_with``/``forks_observed`` already follows).

**No requester identifiers, ever.** The declared ``reads`` and the folded
result never touch ``cross_party.initiator_ref`` or
``serving_provenance.requesting_party``/``counterparty_ref``. "Served" is
determined the same way ``peer_accountability_tab.role_and_count_cell()``
already does -- ``capsule_mesh_view.label_role() == "served"`` -- reused, not
re-derived, and itself blind to WHO asked.

**Honest absences, never fabricated.**
  * ``effect.status`` (``agent_action_capsule.contracts.EFFECT_STATUSES`` =
    ``{planned, dispatched, confirmed, failed, reverted}``) carries no distinct
    "refused" value today; a pre-dispatch policy refusal is coarsened to
    ``effect.status="failed"`` before this module ever sees it
    (``mesh_record_emitter.py``'s ``policy_denied`` terminal state, and
    ``capsule_sidecar.py``'s own comment: "a sidecar cannot claim pre-dispatch
    denial from outside the process"). ``refused`` is therefore always ``0``
    until a status value distinguishes it -- same honesty discipline as the
    next bullet, never inferred from other fields.
  * ``weights_digest``: no capsule field named ``weights_digest`` exists in
    what this sidecar seals today (``self_accountability.rung_summary``
    documents the same absence). Every record's ``weights_digest`` therefore
    reads ``None`` and folds into ``weights_digest.absent``, not fabricated.

**Floor redaction (privacy rule, normative).** A per-model bucket with fewer
than ``FLOOR`` (5) served exchanges publishes ``"fewer than 5"`` for every
count and omits its latency percentiles entirely, rather than an exact number
that could let a requester dictionary-infer a specific rare exchange. This
is a display-time transform on the SAME asserted result the core recomputes
and matches -- floored publication and full-precision verification are the
same deterministic function of the selected inputs, so recompute+match still
holds.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_action_capsule.emit import emit
from capsule_emit.account import (
    AccountDefinition,
    Coverage,
    Selection,
    build_account,
    verify_account,
)
from capsule_emit.account import Account as CoreAccount
from capsule_emit.checkpoint import CheckpointRecord
from capsule_emit.checkpoint import leaf_count as _leaf_count_at_size

from capsule_mesh_view import _poc_block, label_role
from history_card import node_id_from_key_id
from twin_adjudicator import RELATION_ADJUDICATES

__all__ = [
    "SERVED_SUMMARY_SCHEMA",
    "SERVED_SUMMARY_SUBJECT_KEY",
    "SERVED_SUMMARY_SUPERSEDES_RELATION",
    "MESH_SERVED_SUMMARY_DEFINITION",
    "MESH_SERVED_SUMMARY_DEFINITION_DIGEST",
    "FLOOR",
    "FLOOR_LABEL",
    "REFUSED_STATUS_ABSENT_REASON",
    "WEIGHTS_DIGEST_ABSENT_REASON",
    "REQUEST_MALFORMED",
    "COVERAGE_UNSATISFIABLE",
    "ServedModelStats",
    "ServedSummary",
    "SampledVerifyResult",
    "RecomputeVerifyResult",
    "build_served_summary",
    "seal_served_summary",
    "answer_served_summary_request",
    "verify_served_summary",
    "verify_served_summary_recompute",
    "sample_positions",
]

#: Schema tag on the serialized served summary. Versioned so a consumer can
#: refuse a shape it does not understand rather than mis-read it.
SERVED_SUMMARY_SCHEMA = "mesh-served-summary/1"

#: Capsule marker for the served-summary subject block when sealed, mirroring
#: ``history_card.HISTORY_SUBJECT_KEY`` / ``account_capsule.ACCOUNT_SUBJECT_KEY``.
SERVED_SUMMARY_SUBJECT_KEY = "x-mesh-served-summary-v1"

#: A later served summary SUPERSEDES an earlier one over the same log, same
#: convention as the history card and account capsule.
SERVED_SUMMARY_SUPERSEDES_RELATION = "supersedes"

#: The evidence-request-carrier derivation token this summary answers under
#: (cited by shape from [mesh-e14-evidence-responder]'s request map, wired in
#: ``evidence_responder.handle_evidence_request``).
SERVED_SUMMARY_DERIVATION_TOKEN = "served_summary/1"

#: Per-model floor: fewer than this many served exchanges for a model
#: publishes "fewer than 5" for every count in that bucket and omits latency
#: percentiles, to stop dictionary inference against a rarely-served model.
FLOOR = 5
FLOOR_LABEL = "fewer than 5"

REFUSED_STATUS_ABSENT_REASON = (
    "agent_action_capsule.contracts.EFFECT_STATUSES carries no distinct 'refused' value; a "
    "pre-dispatch policy refusal is coarsened to effect.status='failed' before this module sees "
    "it (mesh_record_emitter.py's policy_denied terminal state) -- refused is always 0 until a "
    "status value distinguishes it, never inferred from other fields"
)
WEIGHTS_DIGEST_ABSENT_REASON = (
    "no capsule field named weights_digest exists in records this sidecar emits today "
    "(same absence self_accountability.rung_summary documents) -- never fabricated"
)

#: Refusal reasons for ``answer_served_summary_request``, named so a caller
#: (and the evidence-request carrier, once it grows a derivation-token
#: dispatch) can pattern-match rather than parsing prose. Same two reasons
#: ``history_card.answer_full_history_request`` uses, for the same shape of
#: request (a static export, answerable only against a pin).
REQUEST_MALFORMED = "request_malformed"
COVERAGE_UNSATISFIABLE = "coverage_unsatisfiable"


# --------------------------------------------------------------------------- #
# The neutral fold DEFINITION (definition-as-data).                          #
#                                                                              #
# `reads` names exactly the six capsule fields the fold consults -- no       #
# requester-identity field among them. `derivation_class="deterministic"`    #
# because the per-model counts + latency distribution are a pure function   #
# of the selected inputs -- verify by recompute+match.                       #
# --------------------------------------------------------------------------- #
MESH_SERVED_SUMMARY_DEFINITION = AccountDefinition(
    name="mesh.served_summary_fold/1",
    selection_kind="range",
    reads=(
        "effect.status",
        "latency_ms",
        "model_canonical_ref",
        "quantization",
        "weights_digest",
        "role",
    ),
    derivation_class="deterministic",
)

#: The stable digest of the served-summary fold definition document above.
#: Invariant to this module's internals -- only editing the document moves it.
MESH_SERVED_SUMMARY_DEFINITION_DIGEST = MESH_SERVED_SUMMARY_DEFINITION.definition_digest()


# --------------------------------------------------------------------------- #
# Field extraction -- reads exactly the six declared fields, never a         #
# requester-identity field.                                                   #
# --------------------------------------------------------------------------- #


def _is_served(capsule: dict[str, Any], source_log: str) -> bool:
    """Reused, not re-derived: the same ``label_role`` per-record signal
    ``peer_accountability_tab.role_and_count_cell`` already folds -- itself
    blind to WHO asked, only WHICH side of the exchange this record is."""
    return label_role(capsule, source_log) == "served"


def _model_ref(capsule: dict[str, Any]) -> str:
    sp = _poc_block(capsule).get("serving_provenance") or {}
    return sp.get("model_canonical_ref") or "unknown"


def _quantization(capsule: dict[str, Any]) -> str:
    sp = _poc_block(capsule).get("serving_provenance") or {}
    return sp.get("quantization") or "unknown"


def _latency_ms(capsule: dict[str, Any]) -> float | None:
    raw = _poc_block(capsule).get("latency_ms")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _weights_digest(capsule: dict[str, Any]) -> str | None:
    """Always ``None`` on every record this sidecar seals today -- see
    ``WEIGHTS_DIGEST_ABSENT_REASON``. Reads the field anyway (rather than a
    hardcoded ``None``) so this stops being a no-op automatically the day a
    producer starts sealing it, with no code change here required."""
    sp = _poc_block(capsule).get("serving_provenance") or {}
    return sp.get("weights_digest")


def _effect_status(capsule: dict[str, Any]) -> str | None:
    return (capsule.get("effect") or {}).get("status")


def _status_bucket(status: str | None) -> str:
    """completed | failed | refused | unknown -- see ``REFUSED_STATUS_ABSENT_REASON``
    for why ``refused`` never fires today."""
    if status == "confirmed":
        return "completed"
    if status in ("failed", "reverted"):
        return "failed"
    return "unknown"


def _percentile(sorted_values: list[float], pct: float) -> float:
    """Linear-interpolation percentile over an already-sorted list. Pure,
    total over any non-empty input -- callers never pass an empty list (see
    ``ServedModelStats`` construction, which gates on ``n_served``)."""
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * pct
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return sorted_values[int(k)]
    return sorted_values[lo] * (hi - k) + sorted_values[hi] * (k - lo)


@dataclass(frozen=True)
class ServedModelStats:
    """The served/completed/failed/refused fold for ONE model -- plain
    counts + latency distribution, no weighting, no score. ``to_value()``
    applies the floor redaction rule; the raw (unfloored) counts on this
    dataclass are what the fold and the recompute both compute, so
    floor-redaction is a pure display-time transform over the same
    deterministic result."""

    n_served: int = 0
    n_completed: int = 0
    n_failed: int = 0
    n_refused: int = 0
    latency_p50_ms: float | None = None
    latency_p95_ms: float | None = None
    latency_max_ms: float | None = None
    weights_digest_present: int = 0
    weights_digest_absent: int = 0
    quantizations: tuple[str, ...] = ()

    def to_value(self) -> dict[str, Any]:
        below_floor = self.n_served < FLOOR

        def count(n: int) -> int | str:
            return FLOOR_LABEL if below_floor else n

        # Latency values ride as exact decimal STRINGS, never JSON floats --
        # same convention `capsule_sidecar.py` uses for `latency_ms`
        # (`f"{latency_ms:.3f}"`), and required once this summary is sealed
        # into a capsule: AAC §5.1 forbids a float in a digest-bearing field
        # (JSON float serialization is not cross-implementation deterministic).
        def latency(v: float | None) -> str | None:
            return None if (below_floor or v is None) else f"{v:.3f}"

        return {
            "served": count(self.n_served),
            "completed": count(self.n_completed),
            "failed": count(self.n_failed),
            "refused": count(self.n_refused),
            "refused_note": REFUSED_STATUS_ABSENT_REASON if self.n_served else None,
            "latency_p50_ms": latency(self.latency_p50_ms),
            "latency_p95_ms": latency(self.latency_p95_ms),
            "latency_max_ms": latency(self.latency_max_ms),
            "weights_digest": {
                "present": count(self.weights_digest_present),
                "absent": count(self.weights_digest_absent),
                "note": WEIGHTS_DIGEST_ABSENT_REASON if self.weights_digest_present == 0 else None,
            },
            "quantizations": [] if below_floor else sorted(self.quantizations),
            "floor_applied": below_floor,
        }


def _fold_range(capsules: list[dict[str, Any]], source_log: str) -> dict[str, ServedModelStats]:
    """Fold ``capsules`` (already the witness-bounded selection) into a
    per-model ``ServedModelStats``. Only records this node SERVED count --
    never the requested-role half of a bilateral exchange this node
    initiated, which belongs to a different node's served summary."""
    served_only = [c for c in capsules if _is_served(c, source_log)]

    by_model: dict[str, dict[str, Any]] = {}
    for c in served_only:
        model = _model_ref(c)
        bucket = by_model.setdefault(
            model,
            {
                "n_completed": 0,
                "n_failed": 0,
                "n_refused": 0,
                "latencies": [],
                "weights_present": 0,
                "weights_absent": 0,
                "quantizations": set(),
            },
        )
        status_bucket = _status_bucket(_effect_status(c))
        if status_bucket == "completed":
            bucket["n_completed"] += 1
        elif status_bucket == "failed":
            bucket["n_failed"] += 1
        # "refused" never increments today -- REFUSED_STATUS_ABSENT_REASON.
        latency = _latency_ms(c)
        if latency is not None:
            bucket["latencies"].append(latency)
        if _weights_digest(c) is not None:
            bucket["weights_present"] += 1
        else:
            bucket["weights_absent"] += 1
        bucket["quantizations"].add(_quantization(c))

    result: dict[str, ServedModelStats] = {}
    for model, bucket in by_model.items():
        latencies = sorted(bucket["latencies"])
        n_served = bucket["n_completed"] + bucket["n_failed"]
        result[model] = ServedModelStats(
            n_served=n_served,
            n_completed=bucket["n_completed"],
            n_failed=bucket["n_failed"],
            n_refused=bucket["n_refused"],
            latency_p50_ms=_percentile(latencies, 0.50) if latencies else None,
            latency_p95_ms=_percentile(latencies, 0.95) if latencies else None,
            latency_max_ms=latencies[-1] if latencies else None,
            weights_digest_present=bucket["weights_present"],
            weights_digest_absent=bucket["weights_absent"],
            quantizations=tuple(sorted(bucket["quantizations"])),
        )
    return result


def _adjudications_received(ledger_records: list[dict[str, Any]], *, own_capsule_ids: set[str]) -> int:
    """Count of sealed adjudication capsules (``chain.relation ==
    "adjudicates"``) naming one of this node's OWN served capsule ids as
    either half -- the SAME detection ``self_accountability.adjudications_summary``
    uses, kept local (not imported) to avoid a circular import
    (``capsule_accountability_tab`` -> this module -> ``self_accountability``
    -> ``capsule_accountability_tab``). Total only: this field is labeled
    ``self_held`` and deliberately does not break out corroborated/
    contradicted/inconclusive here -- that breakdown belongs to the
    counterparty-held references path ([mesh-ask-the-references]), not to
    what this node counts about its own served exchanges."""
    received = 0
    for record in ledger_records:
        chain = record.get("chain") or {}
        if chain.get("relation") != RELATION_ADJUDICATES:
            continue
        adjudication = ((record.get("model_attestation") or {}).get("compute_attestation") or {}).get("adjudication")
        if not adjudication:
            continue
        half_a = adjudication.get("half_a_capsule_id")
        half_b = adjudication.get("half_b_capsule_id")
        if half_a in own_capsule_ids or half_b in own_capsule_ids:
            received += 1
    return received


@dataclass
class ServedSummary:
    """A node's served summary: witness-bounded selection / per-model
    served-success-fold derivation / coverage, plus the self-held
    adjudications-received count. NOT a score -- see ``to_value``'s
    ``not_a_score``. Internally a *view* over a neutral-core ``Account``
    (range-kind, deterministic; see ``core_account``), same pattern as
    ``account_capsule.AccountCapsule`` / ``history_card.HistoryCard``.
    """

    node_id: str
    selection_from_entry: int
    selection_to_entry: int
    covered_entries: int
    by_model: dict[str, ServedModelStats]
    coverage_root: str
    coverage_mmr_size: int
    coverage_log_id: str
    coverage_timestamp: str
    coverage_witnesses: list[str] = field(default_factory=list)
    coverage_witnessed: bool = False
    #: Self-held count of adjudication verdicts this node has `received()`
    #: about its own served exchanges. OUTSIDE `core_account()` deliberately
    #: -- a different axis (adjudication capsules, not served-exchange
    #: fields), same reasoning `HistoryCard.reconciled_with` documents.
    adjudications_received: int = 0

    def _asserted_result(self) -> dict[str, Any]:
        return {"by_model": {model: stats.to_value() for model, stats in sorted(self.by_model.items())}}

    def core_account(self) -> CoreAccount | None:
        """A **range**-kind selection whose input identity is
        ``(coverage_root, [from, to])`` -- NEVER per-member digests, NEVER a
        requester identifier. ``None`` for an honestly-empty summary (no
        witnessed coverage yet)."""
        if not self.coverage_root:
            return None
        selection = Selection(
            kind="range",
            coverage=Coverage(coverage_root=self.coverage_root, range=(self.selection_from_entry, self.selection_to_entry)),
        )
        return build_account(
            definition=MESH_SERVED_SUMMARY_DEFINITION,
            selection=selection,
            asserted_result=self._asserted_result(),
        )

    def definition_digest(self) -> str:
        return MESH_SERVED_SUMMARY_DEFINITION_DIGEST

    def verify(self) -> bool:
        """Recompute+match this deterministic account through the neutral
        core. An honestly-empty (no-coverage) summary trivially verifies."""
        acct = self.core_account()
        if acct is None:
            return True
        result = verify_account(
            acct,
            definition=MESH_SERVED_SUMMARY_DEFINITION,
            recompute=lambda _selection: self._asserted_result(),
        )
        return result.ok

    def to_value(self) -> dict[str, Any]:
        return {
            "schema": SERVED_SUMMARY_SCHEMA,
            "node_id": self.node_id,
            "selection": {
                "from_entry": self.selection_from_entry,
                "to_entry": self.selection_to_entry,
                "covered_entries": self.covered_entries,
                "note": (
                    "witnessed range only: entries appended after the latest witnessed "
                    "checkpoint are excluded by design, same as account_capsule.py"
                ),
            },
            "derivation": {
                "kind": "served_summary_fold",
                "definition_digest": MESH_SERVED_SUMMARY_DEFINITION_DIGEST,
                "by_model": {model: stats.to_value() for model, stats in sorted(self.by_model.items())},
                "note": (
                    "counts + latency distribution per model, over the selected witnessed "
                    "range; an ACCOUNT of what was served, not a score. The relying party "
                    "computes its own predicate."
                ),
            },
            "coverage": {
                "checkpoint_root": self.coverage_root,
                "mmr_size": self.coverage_mmr_size,
                "log_id": self.coverage_log_id,
                "timestamp": self.coverage_timestamp,
                "witnesses": list(self.coverage_witnesses),
                "witnessed": self.coverage_witnessed,
                "note": (
                    "cross-check handle: recompute the fold from the node's ledger, check "
                    "the ledger against this root, confirm the root was witnessed"
                ),
            },
            "adjudications_received": {
                "value": self.adjudications_received,
                "source": "self_held",
                "note": (
                    "verdicts this node has received() into its own log about its served "
                    "exchanges -- not this node's own judgment of itself. The counterparty-held "
                    "references path ([mesh-ask-the-references]) is what carries weight in an "
                    "adversarial reading; this count is never presented as a substitute for it."
                ),
            },
            "no_requester_identifiers": (
                "this summary reads and reports no requester-identity field "
                "(cross_party.initiator_ref, serving_provenance.requesting_party/counterparty_ref) "
                "-- it answers WHAT was served, never WHO asked"
            ),
            "not_a_score": (
                "An account of facts + a witness handle to verify them, not a score or routing "
                "recommendation."
            ),
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_value(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def build_served_summary(
    *,
    node_id: str,
    capsule_records: list[dict[str, Any]],
    latest_checkpoint: CheckpointRecord | None,
    source_log: str = "sidecar",
) -> ServedSummary:
    """Build a node's served summary from its own ledger + latest checkpoint.

    ``capsule_records`` is the node's full ``capsules.jsonl``, 1-indexed by
    line -- same ordering ``checkpointing.JsonlLogSource`` folds into the MMR.
    Selection is witness-bounded exactly like ``account_capsule.build_account_capsule``:
    only ``capsule_records[:covered_entries]`` are folded, clamped to what is
    actually on disk if the ledger is shorter than the checkpoint claims.
    """
    if latest_checkpoint is None:
        own_capsule_ids: set[str] = {r.get("capsule_id") for r in capsule_records if r.get("capsule_id")}
        return ServedSummary(
            node_id=node_id,
            selection_from_entry=0,
            selection_to_entry=0,
            covered_entries=0,
            by_model={},
            coverage_root="",
            coverage_mmr_size=0,
            coverage_log_id="",
            coverage_timestamp="",
            coverage_witnesses=[],
            coverage_witnessed=False,
            adjudications_received=_adjudications_received(capsule_records, own_capsule_ids=own_capsule_ids),
        )

    covered = min(_leaf_count_at_size(latest_checkpoint.mmr_size), len(capsule_records))
    selected = capsule_records[:covered]
    witnesses = sorted({w.ts_url for w in (latest_checkpoint.witnesses or [])})
    own_capsule_ids = {r.get("capsule_id") for r in capsule_records if r.get("capsule_id")}
    return ServedSummary(
        node_id=node_id,
        selection_from_entry=1 if covered else 0,
        selection_to_entry=covered,
        covered_entries=covered,
        by_model=_fold_range(selected, source_log),
        coverage_root=latest_checkpoint.root,
        coverage_mmr_size=latest_checkpoint.mmr_size,
        coverage_log_id=latest_checkpoint.log_id,
        coverage_timestamp=latest_checkpoint.timestamp,
        coverage_witnesses=witnesses,
        coverage_witnessed=bool(witnesses),
        adjudications_received=_adjudications_received(capsule_records, own_capsule_ids=own_capsule_ids),
    )


def seal_served_summary(
    summary: ServedSummary,
    *,
    operator: str,
    developer: str,
    signing_node_id: str,
    prior_served_summary_id: str | None = None,
    provider: str = "mesh-llm",
) -> dict[str, Any]:
    """Seal a served summary INTO the node's own ledger -- same pattern as
    ``account_capsule.seal_account_capsule`` / ``history_card.seal_history_card``:
    not a signed JSON summary handed out of-band, but a CAPSULE, appended and
    chained like any other. ``action_type="fyi"``: the summary ASSERTS
    structural facts about this node's own served history.

    Same no-self-reference discipline: sealing appends a ledger entry, so
    this summary's own position is covered by the NEXT checkpoint, never the
    range it summarizes.
    """
    served_subject = dict(summary.to_value())
    compute_attestation = {
        SERVED_SUMMARY_SUBJECT_KEY: {
            "served_summary": served_subject,
            "served_summary_digest": summary.digest(),
            "coverage_ordering": (
                "Sealing this summary appends a ledger entry, so this capsule's own position "
                "is covered by the NEXT checkpoint, not the range in `selection` (which ends "
                "at the checkpoint BEFORE this seal). A served summary never summarizes a "
                "range that includes itself."
            ),
            "not_a_score": (
                "Counts + latency distribution over what this node served, not a score or "
                "routing recommendation."
            ),
        },
    }
    return emit(
        action_id=f"mesh-poc/served-summary/{signing_node_id}/{uuid.uuid4()}",
        action_type="fyi",
        operator=operator,
        developer=developer,
        provider=provider,
        compute_attestation=compute_attestation,
        prior_capsule_id=prior_served_summary_id,
        chain_relation=SERVED_SUMMARY_SUPERSEDES_RELATION if prior_served_summary_id else None,
        domain="action",
        provenance="collector",
    )


@dataclass(frozen=True)
class RecomputeVerifyResult:
    """Total, offline outcome of ``verify_served_summary_recompute``. Never
    raises."""

    ok: bool
    errors: list[str] = field(default_factory=list)


def verify_served_summary_recompute(
    summary_value: dict[str, Any],
    capsule_records: list[dict[str, Any]],
    checkpoint_lines: list[dict[str, Any]],
    *,
    source_log: str = "sidecar",
) -> RecomputeVerifyResult:
    """The REAL recompute+match check: independently rebuild the served
    summary from RAW ``capsule_records``/``checkpoint_lines`` and confirm it
    matches the published ``summary_value`` byte-for-byte -- same discipline
    ``history_card.verify_history_card`` uses.

    ``ServedSummary.verify()`` alone does NOT catch a tampered summary: its
    recompute closure reads ``self``'s own (possibly tampered) fields, the
    same source as the asserted result it is checked against, so the two
    always agree by construction. That method only confirms the neutral-core
    Account wrapper's OWN internal consistency (selection shape, definition
    digest citation) -- it is not a substitute for this function, which is
    what a stranger holding only the published summary and the raw ledger
    actually runs.
    """
    try:
        node_id = summary_value["node_id"]
    except (KeyError, TypeError) as exc:
        return RecomputeVerifyResult(ok=False, errors=[f"malformed summary: missing {exc}"])

    latest_checkpoint = CheckpointRecord.from_dict(checkpoint_lines[-1]) if checkpoint_lines else None
    recomputed = build_served_summary(
        node_id=node_id, capsule_records=capsule_records, latest_checkpoint=latest_checkpoint, source_log=source_log
    )
    recomputed_value = recomputed.to_value()

    errors: list[str] = []
    if recomputed_value != summary_value:
        errors.append("recomputed summary does not match the published summary")
    if not recomputed.verify():
        errors.append("recomputed summary fails its own core-account recompute+match")
    return RecomputeVerifyResult(ok=not errors, errors=errors)


def answer_served_summary_request(
    *,
    capsule_records: list[dict[str, Any]],
    checkpoint_lines: list[dict[str, Any]],
    expected_pin: str | None,
    source_log: str = "sidecar",
) -> dict[str, Any]:
    """Answer the ``derivation: served_summary/1`` leg of the evidence-request
    carrier (digests-only tier) -- cited by shape from
    ``[mesh-e14-evidence-responder]``'s request map and wired live in
    ``evidence_responder.handle_evidence_request``, same shape
    ``history_card.answer_full_history_request`` uses for ``checkpoints_only``.

    **Fail-closed on ``expected_pin``, for the same reason the history card
    is**: served_summary is a STATIC EXPORT answerable only against a
    checkpoint root the requester already expects, never generated fresh, on
    demand, for an arbitrary asker probing "what have you served right now".

    ``node_id``/``log_id`` are derived from the checkpoint chain's own signing
    key (``history_card.node_id_from_key_id``), never taken from a caller
    claim -- same identity-theft protection ``verify_history_card`` applies.
    """
    if not expected_pin:
        return {
            "status": REQUEST_MALFORMED,
            "reason": "served_summary requires expected_pin (a static export); on-demand export is refused",
        }
    if not checkpoint_lines:
        return {"status": COVERAGE_UNSATISFIABLE, "reason": "no checkpoints recorded for this log"}

    latest_line = checkpoint_lines[-1]
    if latest_line.get("root") != expected_pin:
        return {
            "status": COVERAGE_UNSATISFIABLE,
            "reason": "expected_pin does not match the latest checkpoint root for this log",
        }

    node_id = node_id_from_key_id(latest_line["key_id"])
    latest_checkpoint = CheckpointRecord.from_dict(latest_line)
    summary = build_served_summary(
        node_id=node_id,
        capsule_records=capsule_records,
        latest_checkpoint=latest_checkpoint,
        source_log=source_log,
    )
    return {"status": "ok", "served_summary": summary.to_value()}


# --------------------------------------------------------------------------- #
# Sampled check -- a relying party's own spot-check of a self_derived claim. #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SampledVerifyResult:
    """Total, offline outcome of ``verify_served_summary``. Never raises."""

    ok: bool
    sampled: int
    contradictions: list[str] = field(default_factory=list)


def sample_positions(n_total: int, k: int, *, nonce: str) -> list[int]:
    """Deterministic sample of up to ``k`` distinct positions in
    ``[0, n_total)``, keyed by ``nonce`` so two independent verifiers who
    agree on a nonce pick the SAME sample (mirrors the "deterministic by
    nonce so two askers pick the same set" discipline
    ``[mesh-ask-the-references]`` uses for its counterparty sample) -- never
    a fresh random draw that a re-run cannot reproduce."""
    if n_total <= 0 or k <= 0:
        return []
    k = min(k, n_total)
    ranked = sorted(range(n_total), key=lambda i: hashlib.sha256(f"{nonce}:{i}".encode("utf-8")).hexdigest())
    return sorted(ranked[:k])


def verify_served_summary(summary_value: dict[str, Any], sampled_capsules: list[dict[str, Any]], *, source_log: str = "sidecar") -> SampledVerifyResult:
    """Sampled check: does each of ``sampled_capsules`` (pulled by position,
    e.g. via a ``range`` evidence request's digests-tier bundles) agree with
    ``summary_value``'s claims for its model? Cheap, no bodies, no
    identifiers beyond the sample -- this reads only the same six declared
    fields the fold itself reads.

    A record whose model does not appear in the summary at all, or whose
    latency exceeds that model's claimed ``latency_max_ms``, or whose status
    bucket the summary claims zero of, is ``contradicted``. Below the floor
    (``floor_applied: true``) a model's counts/latency are redacted, so only
    the model-presence check still applies there -- a documented, intentional
    weakening in exchange for the floor's privacy guarantee, never silently
    treated as a stronger check than it is.
    """
    by_model = ((summary_value.get("derivation") or {}).get("by_model")) or {}
    contradictions: list[str] = []
    checked = 0
    for capsule in sampled_capsules:
        if not _is_served(capsule, source_log):
            continue
        checked += 1
        model = _model_ref(capsule)
        capsule_id = capsule.get("capsule_id", "?")
        bucket = by_model.get(model)
        if bucket is None:
            contradictions.append(f"{capsule_id}: model {model!r} not present in the summary's by_model claims")
            continue
        if bucket.get("floor_applied"):
            # Counts/latency are redacted below the floor -- only presence
            # was checkable, and it passed.
            continue
        status_bucket = _status_bucket(_effect_status(capsule))
        if status_bucket in ("completed", "failed") and bucket.get(status_bucket, 0) == 0:
            contradictions.append(
                f"{capsule_id}: status bucket {status_bucket!r} but summary claims 0 for model {model!r}"
            )
        latency = _latency_ms(capsule)
        latency_max_raw = bucket.get("latency_max_ms")
        latency_max = float(latency_max_raw) if latency_max_raw is not None else None
        if latency is not None and latency_max is not None and latency > latency_max:
            contradictions.append(
                f"{capsule_id}: latency {latency}ms exceeds summary's claimed max {latency_max}ms for model {model!r}"
            )
    return SampledVerifyResult(ok=not contradictions, sampled=checked, contradictions=contradictions)


# ---------------------------------------------------------------------------
# CLI -- `served_summary.py build` mirrors self_accountability.py's shape;
# `served_summary.py verify --sample k` is the sampled-check entry point the
# design doc names.
# ---------------------------------------------------------------------------


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _cmd_build(args: argparse.Namespace) -> int:
    capsule_records = _read_jsonl(Path(args.ledger))
    checkpoint_lines = _read_jsonl(Path(args.checkpoints)) if args.checkpoints else []
    latest_checkpoint = CheckpointRecord.from_dict(checkpoint_lines[-1]) if checkpoint_lines else None
    node_id = node_id_from_key_id(checkpoint_lines[-1]["key_id"]) if checkpoint_lines else args.node_id

    summary = build_served_summary(node_id=node_id, capsule_records=capsule_records, latest_checkpoint=latest_checkpoint)
    text = json.dumps(summary.to_value(), indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    capsule_records = _read_jsonl(Path(args.ledger))
    checkpoint_lines = _read_jsonl(Path(args.checkpoints)) if args.checkpoints else []
    latest_checkpoint = CheckpointRecord.from_dict(checkpoint_lines[-1]) if checkpoint_lines else None
    node_id = node_id_from_key_id(checkpoint_lines[-1]["key_id"]) if checkpoint_lines else args.node_id

    summary = build_served_summary(node_id=node_id, capsule_records=capsule_records, latest_checkpoint=latest_checkpoint)
    value = summary.to_value()
    recompute_result = verify_served_summary_recompute(value, capsule_records, checkpoint_lines)
    print(f"recompute+match against the raw ledger: ok={recompute_result.ok} errors={recompute_result.errors}")

    positions = sample_positions(summary.covered_entries, args.sample, nonce=args.nonce or "verify")
    sampled = [capsule_records[i] for i in positions]
    result = verify_served_summary(value, sampled)
    print(f"sampled check: k={args.sample} sampled={result.sampled} ok={result.ok}")
    for c in result.contradictions:
        print(f"  CONTRADICTED: {c}")
    return 0 if recompute_result.ok and result.ok else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="served-summary",
        description="Build or verify a node's served summary (served_summary/1).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="build the summary and write it as JSON")
    build.add_argument("--node-id", default="unknown")
    build.add_argument("--ledger", required=True, metavar="PATH", help="the sealed capsule JSONL ledger (capsules.jsonl)")
    build.add_argument("--checkpoints", metavar="PATH", default=None, help="checkpoints.jsonl")
    build.add_argument("--out", metavar="PATH", default=None, help="write JSON here instead of stdout")

    verify = sub.add_parser("verify", help="build, self-verify, and run a sampled check")
    verify.add_argument("--node-id", default="unknown")
    verify.add_argument("--ledger", required=True, metavar="PATH")
    verify.add_argument("--checkpoints", metavar="PATH", default=None)
    verify.add_argument("--sample", type=int, default=3, metavar="K")
    verify.add_argument("--nonce", default=None)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "build":
        return _cmd_build(args)
    if args.command == "verify":
        return _cmd_verify(args)
    parser = _build_parser()
    parser.error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

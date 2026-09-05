# SPDX-License-Identifier: Apache-2.0
"""The `history_card()` verb -- "checkpoints + receipts + consistency proofs
since size S" -- for a mesh node's own checkpoint chain.

**No new record type.** A history card is NOT a new capsule schema: like
`account_capsule.py`'s account capsule (PR #65, reviewed -- see
`docs/PR65-ACCOUNT-CAPSULE-REVIEW.md` for the reuse boundary),
it is built on the SAME neutral primitives already in the trunk:

  * `capsule_emit.account` -- the fold-definition-as-DATA core (`AccountDefinition`,
    `Selection`/`Coverage`, `build_account`/`verify_account`). A history card is a
    **chain_segment**-kind account: its input identity is `(start_digest,
    end_digest, relation)` -- the two boundary checkpoints' own persisted-entry
    digests plus the traversal relation -- and NEVER a per-checkpoint reference
    list. The core's `chain_segment` kind exists for exactly this shape: "a
    capsule/record A->B walk over an in-record relation, self-verifying from its
    two endpoints" (`capsule_emit/account/definition.py`).
  * `capsule_emit.checkpoint` -- `CheckpointRecord`, `MmrLedger`, and, above
    all, `cose_wire.verify_checkpoint_cose_offline`: each checkpoint's COSE-wire
    statement already carries a REAL `ConsistencyProof` against its immediate
    predecessor (checkpointing.py's `_checkpoint_now`), and
    `verify_checkpoint_cose_offline` already re-verifies that proof
    cryptographically, offline, from the statement bytes alone. This module
    reuses that function directly for every link in the chain rather than
    re-deriving or re-proving consistency itself.

This module does NOT import `account_capsule.py`. That module is PR #65's
mesh-specific wrapper (account capsule + Nostr publish path), still HELD for
review (Nostr overlaps the open NIP-56 question). The reusable part -- the
neutral account/fold core plus the checkpoint/COSE primitives -- is already
merged and carries no such hold, so `history_card()` ships independently of
PR #65's disposition. If/when PR #65's own `AccountCapsule` lands, a future
`node_history()`-style rollup could compose both views over the same node,
but nothing here requires that.

**Publishes properties, never a score.** `continuity`, `history_depth`,
`unforked`, `cadence` -- structural facts about the checkpoint chain, no
capsule content, no per-record (per-capsule) digests. A relying party gets
"this node's history since size S is an unbroken, witnessed chain of N
checkpoints averaging a K-second cadence" (or an honest `broken at <...>`),
never a trust-rating number.

**Answerable only under a pin, never on demand.** `answer_full_history_request`
refuses outright unless the requester supplies `expected_pin` -- the root of a
checkpoint it already expects (a previously-published, static export). This
mirrors the evidence-request carrier's `expected_pin` coverage resolution
(`[mesh-e14-evidence-responder]`, not yet merged as of this module -- the
carrier's request/response *shape* is cited here, not its code) and rules out
a node answering "what is your full history right now" freshly, on demand,
for an arbitrary asker -- the answer is only ever a pin match against a
checkpoint the node already published.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime
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
from capsule_emit.checkpoint.cose_wire import verify_checkpoint_cose_offline

__all__ = [
    "HISTORY_CARD_SCHEMA",
    "HISTORY_SUBJECT_KEY",
    "HISTORY_CHAIN_RELATION",
    "HISTORY_SUPERSEDES_RELATION",
    "MESH_HISTORY_DEFINITION",
    "MESH_HISTORY_DEFINITION_DIGEST",
    "REQUEST_MALFORMED",
    "COVERAGE_UNSATISFIABLE",
    "CheckpointRef",
    "HistoryProperties",
    "HistoryCard",
    "HistoryVerifyResult",
    "build_history_card",
    "verify_history_card",
    "seal_history_card",
    "answer_full_history_request",
    "reconciliation_counts_from_ledger_dir",
    "with_peer_reconciliation",
]

#: Schema tag on the serialized history card. Versioned so a consumer can
#: refuse a shape it does not understand rather than mis-read it.
HISTORY_CARD_SCHEMA = "mesh-history-card/1"

#: Capsule marker for the history card's subject block, mirroring
#: `account_capsule.ACCOUNT_SUBJECT_KEY`.
HISTORY_SUBJECT_KEY = "x-mesh-history-v1"

#: The chain_segment traversal relation a history card's `core_account()`
#: names: consecutive checkpoints link via their own `prev_size`/`prev_root`
#: fields plus a real `ConsistencyProof` carried in the COSE-wire statement
#: (`checkpointing.CheckpointState._checkpoint_now`) -- in-record linkage,
#: same discipline `chain_segment` requires (no per-member/per-checkpoint
#: references), just expressed over checkpoints instead of capsule `chain`
#: relations.
HISTORY_CHAIN_RELATION = "checkpoint_prev"

#: A later history card SUPERSEDES an earlier one over the same log, same
#: convention as `account_capsule.ACCOUNT_SUPERSEDES_RELATION`.
HISTORY_SUPERSEDES_RELATION = "supersedes"

#: Refusal reasons, named so a caller (and the evidence-request carrier, once
#: [mesh-e14-evidence-responder] lands) can pattern-match on them rather than
#: parsing prose.
REQUEST_MALFORMED = "request_malformed"
COVERAGE_UNSATISFIABLE = "coverage_unsatisfiable"


# --------------------------------------------------------------------------- #
# The neutral fold DEFINITION (definition-as-data) for a history card.        #
#                                                                              #
# `reads` names exactly the CheckpointRecord fields the chain walk consults;  #
# `derivation_class="deterministic"` because the properties are a pure        #
# function of the cited checkpoint chain -- verify by recompute+match.        #
# --------------------------------------------------------------------------- #
MESH_HISTORY_DEFINITION = AccountDefinition(
    name="mesh.history_chain_walk/1",
    selection_kind="chain_segment",
    reads=(
        "mmr_size",
        "root",
        "prev_size",
        "prev_root",
        "timestamp",
        "log_id",
        "key_id",
        "witnesses",
        "checkpoint_cose",
    ),
    derivation_class="deterministic",
)

#: The stable digest of the history-chain-walk definition document. Invariant
#: to this module's internals -- only editing the document above moves it.
MESH_HISTORY_DEFINITION_DIGEST = MESH_HISTORY_DEFINITION.definition_digest()


@dataclass(frozen=True)
class CheckpointRef:
    """A boundary checkpoint of the covered chain segment -- just enough to
    name and re-locate it, never the ledger content it covers."""

    mmr_size: int
    root: str
    entry_digest: str
    timestamp: str

    @classmethod
    def from_record(cls, cp: CheckpointRecord) -> "CheckpointRef":
        return cls(mmr_size=cp.mmr_size, root=cp.root, entry_digest=cp.entry_digest(), timestamp=cp.timestamp)

    def to_value(self) -> dict[str, Any]:
        return {
            "mmr_size": self.mmr_size,
            "root": self.root,
            "entry_digest": self.entry_digest,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class HistoryProperties:
    """The structural properties a history card publishes -- facts about the
    checkpoint CHAIN, never a score and never per-checkpoint content."""

    #: "unbroken" once every consecutive link in the covered range verifies
    #: (signature + real consistency proof); otherwise
    #: "broken at mmr_size=<N>: <reason>" -- NEVER silently green.
    continuity: str
    #: How many checkpoints the chain walk actually verified, starting from
    #: `since_size` -- clipped to the break point when `continuity` is broken.
    history_depth: int
    #: True iff `continuity == "unbroken"` over the WHOLE requested range
    #: (not just the verified prefix) -- i.e. no fork/rewrite/gap was found
    #: anywhere in [since_size, latest].
    unforked: bool
    #: Cadence over the verified prefix: checkpoint count, span, and interval
    #: stats (seconds). `{"checkpoints": N}` only when N < 2 (insufficient
    #: data for interval stats -- never a fabricated average from one point).
    cadence: dict[str, Any] = field(default_factory=dict)

    def to_value(self) -> dict[str, Any]:
        return {
            "continuity": self.continuity,
            "history_depth": self.history_depth,
            "unforked": self.unforked,
            "cadence": dict(self.cadence),
        }


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _cadence(checkpoints: list[CheckpointRecord]) -> dict[str, Any]:
    if len(checkpoints) < 2:
        return {"checkpoints": len(checkpoints)}
    times = [_parse_ts(cp.timestamp) for cp in checkpoints]
    intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    span = (times[-1] - times[0]).total_seconds()
    return {
        "checkpoints": len(checkpoints),
        "span_seconds": span,
        "mean_interval_seconds": sum(intervals) / len(intervals),
        "min_interval_seconds": min(intervals),
        "max_interval_seconds": max(intervals),
    }


def _cp_dict(cp: CheckpointRecord) -> dict[str, Any]:
    """`CheckpointRecord.to_dict()` never carries `checkpoint_cose` (a
    sibling field `checkpointing._checkpoint_now` persists alongside it,
    additive, never folded into the signed body) -- callers here always pass
    the persisted-line dict alongside the record, never the record alone,
    for that reason. See `build_history_card`."""
    return cp.to_dict()


def _verify_link(prev_cp: CheckpointRecord, cur_cp: CheckpointRecord, cur_cose_hex: str | None) -> str | None:
    """Verify that `cur_cp` genuinely, cryptographically extends `prev_cp`.

    Returns `None` on success, or a human-readable reason string on failure.
    Never raises -- a total check, same discipline as
    `verify_checkpoint_cose_offline` itself.
    """
    if cur_cp.log_id != prev_cp.log_id:
        return f"log_id changed ({prev_cp.log_id!r} -> {cur_cp.log_id!r})"
    if cur_cp.prev_size != prev_cp.mmr_size or cur_cp.mmr_size <= prev_cp.mmr_size:
        return (
            f"prev_size={cur_cp.prev_size} does not chain from the prior checkpoint's "
            f"mmr_size={prev_cp.mmr_size}"
        )
    if not cur_cose_hex:
        return "no checkpoint_cose on this checkpoint -- continuity is asserted, not proven"
    try:
        cose_bytes = bytes.fromhex(cur_cose_hex)
    except ValueError:
        return "checkpoint_cose is not valid hex"
    result = verify_checkpoint_cose_offline(cose_bytes)
    if not result.ok:
        return f"COSE-wire consistency proof failed: {result.errors}"
    decoded = result.decoded
    if decoded.mmr_size != cur_cp.mmr_size or decoded.root != cur_cp.root:
        return "checkpoint_cose does not bind to this checkpoint's own JSON record"
    if decoded.prev_size != prev_cp.mmr_size or decoded.prev_root != prev_cp.root:
        return "checkpoint_cose's proven predecessor does not match the prior checkpoint in this chain"
    return None


def _walk_chain(
    checkpoints_in_range: list[CheckpointRecord],
    cose_by_size: dict[int, str],
    *,
    boundary: CheckpointRecord | None,
) -> tuple[str, bool, int, list[CheckpointRecord]]:
    """Walk `boundary -> checkpoints_in_range[0] -> ... -> checkpoints_in_range[-1]`,
    verifying every link. Returns `(continuity, unforked, verified_depth,
    verified_prefix)` where `verified_prefix` is the checkpoints actually
    confirmed to chain unbroken from the start (used for the cadence fold).

    `boundary` is the checkpoint at `since_size` (the requester's pin), or
    `None` when `since_size == 0` (walking from the log's own genesis).
    """
    if not checkpoints_in_range:
        return "no checkpoints since the requested size", True, 0, []

    verified: list[CheckpointRecord] = []
    prev = boundary
    for cp in checkpoints_in_range:
        if prev is None:
            # Genesis leg: the first checkpoint of the whole log carries no
            # predecessor to verify against -- prev_size==0 is its own proof.
            if cp.prev_size != 0:
                return (
                    f"broken at mmr_size={cp.mmr_size}: claims prev_size={cp.prev_size} "
                    "but no earlier checkpoint is in range (incomplete history)",
                    False,
                    len(verified),
                    verified,
                )
        else:
            reason = _verify_link(prev, cp, cose_by_size.get(cp.mmr_size))
            if reason is not None:
                return f"broken at mmr_size={cp.mmr_size}: {reason}", False, len(verified), verified
        verified.append(cp)
        prev = cp
    return "unbroken", True, len(verified), verified


@dataclass
class HistoryCard:
    """A node's history card: checkpoints + receipts + consistency proofs
    since size S, folded into properties -- selection/derivation/coverage,
    same three-part shape `account_capsule.AccountCapsule` uses.
    """

    node_id: str
    log_id: str
    since_size: int
    #: selection -- the two boundary checkpoints of the covered chain segment.
    #: `from_checkpoint is None` iff `since_size == 0` and the log has no
    #: checkpoint yet (an honestly-empty card).
    from_checkpoint: CheckpointRef | None
    to_checkpoint: CheckpointRef | None
    #: derivation -- the chain-walk properties.
    properties: HistoryProperties
    #: coverage -- how many checkpoints are covered, and the latest's witness
    #: state (never the un-anchored tail beyond the latest checkpoint).
    checkpoint_count: int
    witnesses: list[str] = field(default_factory=list)
    witnessed: bool = False
    #: peer checkpoint-root reconciliation ([mesh-peer-root-exchange]) --
    #: OUTSIDE `properties`/`core_account()` deliberately: these come from a
    #: separate observation store (the mesh plugin's gossip-fed reconciliation
    #: ledger), not from this log's own checkpoint chain, so they must never
    #: fold into the chain-walk digest `MESH_HISTORY_DEFINITION` binds.
    #: Defaults to 0 -- "no peer observations recorded yet", never fabricated.
    reconciled_with: int = 0
    forks_observed: int = 0

    def core_account(self) -> CoreAccount | None:
        """The neutral-core `Account` this card is a view of: a
        `chain_segment` selection whose input identity is `(start_digest,
        end_digest, relation)` -- never a per-checkpoint reference list.

        `None` for an honestly-empty card (no checkpoints in range): there is
        no chain segment to name.
        """
        if self.from_checkpoint is None or self.to_checkpoint is None:
            return None
        selection = Selection(
            kind="chain_segment",
            coverage=Coverage(
                start_digest=self.from_checkpoint.entry_digest,
                end_digest=self.to_checkpoint.entry_digest,
                relation=HISTORY_CHAIN_RELATION,
            ),
        )
        return build_account(
            definition=MESH_HISTORY_DEFINITION,
            selection=selection,
            asserted_result=self.properties.to_value(),
        )

    def definition_digest(self) -> str:
        return MESH_HISTORY_DEFINITION_DIGEST

    def verify(self) -> bool:
        """Self-consistency: the card's own `core_account()` recompute+matches
        through the neutral core (definition digest binds, selection shape is
        valid). The cryptographic chain-walk itself already ran in
        `build_history_card`/`verify_history_card` against the raw
        checkpoints -- this mirrors `AccountCapsule.verify()`'s scope, not a
        second independent recompute from scratch."""
        acct = self.core_account()
        if acct is None:
            return True
        result = verify_account(
            acct,
            definition=MESH_HISTORY_DEFINITION,
            recompute=lambda _selection: self.properties.to_value(),
        )
        return result.ok

    def to_value(self) -> dict[str, Any]:
        return {
            "schema": HISTORY_CARD_SCHEMA,
            "node_id": self.node_id,
            "log_id": self.log_id,
            "selection": {
                "since_size": self.since_size,
                "from_checkpoint": self.from_checkpoint.to_value() if self.from_checkpoint else None,
                "to_checkpoint": self.to_checkpoint.to_value() if self.to_checkpoint else None,
                "note": (
                    "checkpoints_only -- digests-only tier: checkpoint roots and entry "
                    "digests only, no capsule content, no per-record (per-capsule) digests"
                ),
            },
            "derivation": {
                "kind": "history_chain_walk",
                "definition_digest": MESH_HISTORY_DEFINITION_DIGEST,
                "properties": self.properties.to_value(),
                "note": (
                    "structural properties of the checkpoint chain since size S; an "
                    "ACCOUNT of continuity, not a score. The relying party computes its "
                    "own predicate."
                ),
            },
            "coverage": {
                "checkpoint_count": self.checkpoint_count,
                "witnesses": list(self.witnesses),
                "witnessed": self.witnessed,
            },
            "peer_reconciliation": {
                "reconciled_with": self.reconciled_with,
                "forks_observed": self.forks_observed,
                "note": (
                    "peer count and fork count from this node's own checkpoint-root "
                    "observation store, not from this log's checkpoint chain -- see "
                    "reconciliation_counts_from_ledger_dir()"
                ),
            },
            "not_a_score": (
                "This is an account of structural facts about the checkpoint chain, not "
                "a score or routing recommendation."
            ),
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_value(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def reconciliation_counts_from_ledger_dir(ledger_dir: Path) -> tuple[int, int]:
    """Read `(reconciled_with, forks_observed)` from
    `<ledger_dir>/reconciliation_state.json` -- the peer checkpoint-root
    observation store a mesh plugin (e.g. the Rust `admission-policy`
    plugin's `peer_root_ledger`) persists as it reconciles gossiped
    checkpoint heads. `(0, 0)` when the file is absent or unreadable: "no
    peer observations recorded (yet)" is the honest reading, never an error
    that blocks the rest of the history card.

    Cross-language note: this reads the Rust ledger's own on-disk JSON shape
    directly (`{"observed": {...}, "reconciled_peers": [...], "forks": [...]}`)
    rather than expecting pre-computed counts, so the two languages can never
    silently disagree about what a "count" means.
    """
    state_path = ledger_dir / "reconciliation_state.json"
    try:
        raw = state_path.read_text()
    except OSError:
        return (0, 0)
    try:
        state = json.loads(raw)
    except json.JSONDecodeError:
        return (0, 0)
    reconciled_with = len(state.get("reconciled_peers") or [])
    forks_observed = len(state.get("forks") or [])
    return (reconciled_with, forks_observed)


def with_peer_reconciliation(card: HistoryCard, ledger_dir: Path) -> HistoryCard:
    """Return a copy of `card` with `reconciled_with`/`forks_observed` folded
    in from `ledger_dir`'s reconciliation store. Never mutates `card` --
    `HistoryCard.verify()`/`digest()` on the ORIGINAL card are unaffected,
    since these fields live outside `core_account()`'s asserted result (see
    the field docstring on `HistoryCard`)."""
    reconciled_with, forks_observed = reconciliation_counts_from_ledger_dir(ledger_dir)
    return replace(card, reconciled_with=reconciled_with, forks_observed=forks_observed)


def build_history_card(
    *,
    node_id: str,
    log_id: str,
    checkpoint_lines: list[dict[str, Any]],
    since_size: int = 0,
) -> HistoryCard:
    """Build a history card over the checkpoint chain since `since_size`.

    `checkpoint_lines` is the node's full `checkpoints.jsonl`, parsed (one
    dict per line, in file order == mmr_size-ascending order -- every
    checkpointer here is a single writer, so this is already the chain
    order). Each dict is the PERSISTED line (including the sibling
    `checkpoint_cose` hex field, when present) -- passing bare
    `CheckpointRecord`s loses that field and every link fails closed as
    "no checkpoint_cose", so this function reads the persisted dicts
    directly rather than requiring a second lookup structure.

    `since_size == 0` (default) walks from the log's genesis. A positive
    `since_size` must exactly match some checkpoint's `mmr_size` already in
    `checkpoint_lines` -- that checkpoint becomes the trust anchor (`S`) the
    walk starts from; a `since_size` that names no known checkpoint is
    refused (`ValueError`), never silently rounded to the nearest one.
    """
    records = [CheckpointRecord.from_dict(line) for line in checkpoint_lines]
    cose_by_size = {line["mmr_size"]: line.get("checkpoint_cose") for line in checkpoint_lines if "mmr_size" in line}

    boundary: CheckpointRecord | None = None
    if since_size > 0:
        matches = [r for r in records if r.mmr_size == since_size]
        if not matches:
            raise ValueError(f"since_size={since_size} does not match any known checkpoint for log_id={log_id!r}")
        boundary = matches[0]

    in_range = [r for r in records if r.mmr_size > since_size]

    if boundary is None and not in_range:
        return HistoryCard(
            node_id=node_id,
            log_id=log_id,
            since_size=since_size,
            from_checkpoint=None,
            to_checkpoint=None,
            properties=HistoryProperties(continuity="no checkpoints since the requested size", history_depth=0, unforked=True, cadence={}),
            checkpoint_count=0,
        )

    continuity, unforked, depth, verified_prefix = _walk_chain(in_range, cose_by_size, boundary=boundary)
    cadence = _cadence(verified_prefix)

    span = ([boundary] if boundary is not None else []) + verified_prefix
    from_ref = CheckpointRef.from_record(span[0]) if span else None
    to_ref = CheckpointRef.from_record(verified_prefix[-1]) if verified_prefix else (
        CheckpointRef.from_record(boundary) if boundary is not None else None
    )

    latest = in_range[-1] if in_range else boundary
    witnesses = sorted({w.ts_url for w in (latest.witnesses or [])}) if latest is not None else []

    return HistoryCard(
        node_id=node_id,
        log_id=log_id,
        since_size=since_size,
        from_checkpoint=from_ref,
        to_checkpoint=to_ref,
        properties=HistoryProperties(continuity=continuity, history_depth=depth, unforked=unforked, cadence=cadence),
        checkpoint_count=len(in_range),
        witnesses=witnesses,
        witnessed=bool(witnesses),
    )


@dataclass
class HistoryVerifyResult:
    """Total, offline outcome of `verify_history_card`. Never raises."""

    ok: bool
    errors: list[str] = field(default_factory=list)


def verify_history_card(card_value: dict[str, Any], checkpoint_lines: list[dict[str, Any]]) -> HistoryVerifyResult:
    """The offline verifier: given a published card (`HistoryCard.to_value()`)
    and the RAW checkpoint lines it claims to summarize, independently
    rebuild the card from the checkpoints alone and confirm it matches
    byte-for-byte -- recompute+match, the same discipline
    `verify_real_deployment_checkpoint.py` uses for capsule inclusion.

    A stranger holding only these two things (no live sidecar, no MMR state)
    can run this. Every cryptographic link (signature + consistency proof) is
    re-verified from scratch via `verify_checkpoint_cose_offline` inside
    `build_history_card` -- this function does not additionally trust the
    published card's `derivation.properties`.
    """
    try:
        since_size = card_value["selection"]["since_size"]
        node_id = card_value["node_id"]
        log_id = card_value["log_id"]
    except (KeyError, TypeError) as exc:
        return HistoryVerifyResult(ok=False, errors=[f"malformed card: missing {exc}"])

    try:
        recomputed = build_history_card(
            node_id=node_id, log_id=log_id, checkpoint_lines=checkpoint_lines, since_size=since_size
        )
    except ValueError as exc:
        return HistoryVerifyResult(ok=False, errors=[str(exc)])

    errors: list[str] = []
    if recomputed.to_value() != card_value:
        errors.append("recomputed card does not match the published card")
        recomputed_props = recomputed.properties.to_value()
        published_props = (card_value.get("derivation") or {}).get("properties")
        if recomputed_props != published_props:
            errors.append(f"properties mismatch: recomputed={recomputed_props!r} published={published_props!r}")
    if not recomputed.verify():
        errors.append("recomputed card fails its own core-account recompute+match")

    return HistoryVerifyResult(ok=not errors, errors=errors)


def seal_history_card(
    card: HistoryCard,
    *,
    operator: str,
    developer: str,
    signing_node_id: str,
    prior_history_card_id: str | None = None,
    provider: str = "mesh-llm",
) -> dict[str, Any]:
    """Seal a history card INTO the node's own ledger -- same pattern as
    `account_capsule.seal_account_capsule`: not a signed JSON summary handed
    out of-band, but a CAPSULE, appended and chained like any other, so the
    assertion act itself is on the record and folds into the next checkpoint.

    `action_type="fyi"`: the card ASSERTS structural facts about the node's
    own checkpoint chain, same informational grade as the account capsule.

    **Same no-self-reference discipline as the account capsule.** Sealing
    this card appends a ledger entry, so the card's own position is covered
    by the NEXT checkpoint, never the range it summarizes.
    """
    history_subject = dict(card.to_value())
    compute_attestation = {
        HISTORY_SUBJECT_KEY: {
            "history": history_subject,
            "history_digest": card.digest(),
            "coverage_ordering": (
                "Sealing this card appends a ledger entry, so this capsule's own position "
                "is covered by the NEXT checkpoint, not the range in `selection` (which ends "
                "at the checkpoint BEFORE this seal). A history card never summarizes a range "
                "that includes itself."
            ),
            "not_a_score": (
                "Structural properties of a checkpoint chain, not a score or routing "
                "recommendation."
            ),
        },
    }
    return emit(
        action_id=f"mesh-poc/history/{signing_node_id}/{uuid.uuid4()}",
        action_type="fyi",
        operator=operator,
        developer=developer,
        provider=provider,
        compute_attestation=compute_attestation,
        prior_capsule_id=prior_history_card_id,
        chain_relation=HISTORY_SUPERSEDES_RELATION if prior_history_card_id else None,
        domain="action",
        provenance="collector",
    )


def answer_full_history_request(
    *,
    node_id: str,
    log_id: str,
    checkpoint_lines: list[dict[str, Any]],
    since_size: int,
    expected_pin: str | None,
) -> dict[str, Any]:
    """Answer the `subject: full_history` leg of the evidence-request carrier
    (`derivation: checkpoints_only`, digests-only tier) -- cited by shape from
    `[mesh-e14-evidence-responder]`'s request map, not by import (that
    responder is not merged yet).

    **Fail-closed on `expected_pin` -- this is the whole point.** A caller
    with no pin gets `request_malformed`: full-history is a STATIC EXPORT
    answerable only against a checkpoint root the requester already expects
    (e.g. from a prior card, or the node's own published listing), never
    generated fresh, on demand, for an arbitrary asker probing "what is your
    history right now". A pin that does not match the node's latest
    checkpoint root is `coverage_unsatisfiable` -- the node will not silently
    answer against a DIFFERENT (e.g. newer) checkpoint than the one asked
    about.
    """
    if not expected_pin:
        return {
            "status": REQUEST_MALFORMED,
            "reason": "full_history requires expected_pin (a static export); on-demand history export is refused",
        }
    if not checkpoint_lines:
        return {"status": COVERAGE_UNSATISFIABLE, "reason": "no checkpoints recorded for this log"}

    latest_root = checkpoint_lines[-1].get("root")
    if latest_root != expected_pin:
        return {
            "status": COVERAGE_UNSATISFIABLE,
            "reason": f"expected_pin does not match the latest checkpoint root for log_id={log_id!r}",
        }

    card = build_history_card(node_id=node_id, log_id=log_id, checkpoint_lines=checkpoint_lines, since_size=since_size)
    return {"status": "ok", "history_card": card.to_value()}

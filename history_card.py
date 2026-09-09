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
from capsule_emit.numbers import float_to_str

__all__ = [
    "HISTORY_CARD_SCHEMA",
    "HISTORY_SUBJECT_KEY",
    "HISTORY_CHAIN_RELATION",
    "HISTORY_SUPERSEDES_RELATION",
    "MESH_HISTORY_DEFINITION",
    "MESH_HISTORY_DEFINITION_DIGEST",
    "REQUEST_MALFORMED",
    "COVERAGE_UNSATISFIABLE",
    "FORKS_STATE_ABSENT",
    "FORKS_STATE_UNREADABLE",
    "FORKS_STATE_OK",
    "CheckpointRef",
    "HistoryProperties",
    "HistoryCard",
    "HistoryVerifyResult",
    "node_id_from_key_id",
    "build_history_card",
    "verify_history_card",
    "seal_history_card",
    "answer_full_history_request",
    "reconciliation_counts_from_ledger_dir",
    "with_peer_reconciliation",
    "with_references",
]

#: forks_state values -- distinguish honest absence from unreadable/tampered state.
#: "absent": file not present; plugin never ran; zero is an honest default.
#: "unreadable": file present but corrupt OR 'forks' key missing (tampering signal).
#: "ok": file parsed successfully and all expected fields are present.
FORKS_STATE_ABSENT = "absent"
FORKS_STATE_UNREADABLE = "unreadable"
FORKS_STATE_OK = "ok"

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
    #: The stat values are exact decimal STRINGS (`float_to_str`), never JSON
    #: floats -- this dict lands in a digest-bearing field via `seal_history_card`.
    cadence: dict[str, Any] = field(default_factory=dict)
    #: Whether the temporal properties (`history_depth`, `cadence`) are bounded
    #: by external witness receipt times.  Two values:
    #:
    #: ``"producer_asserted"`` -- all timestamps come from the producer's own
    #: checkpoint records (``cp.timestamp`` is a self-written field).  An actor
    #: can backdate or fast-forward these timestamps with no cryptographic cost;
    #: a "three-year unbroken cadence" is an afternoon's work on a fresh log.
    #: ``history_depth`` and ``cadence`` stats are STRUCTURALLY correct (they
    #: reflect the chain as presented) but carry no independent time guarantee.
    #:
    #: ``"receipt_bounded"`` -- at least one checkpoint in the verified prefix
    #: carries a real (non-stub) witness receipt, meaning a Transparency Service
    #: confirmed the checkpoint's existence.  The TS registration places an
    #: external upper bound on when that checkpoint could have occurred relative
    #: to the TS's own clock, partially bounding the producer's timestamp claims.
    #: Note: current receipts do not carry a TS-signed time field that this
    #: verifier can decode; the bound is structural (presence of a real receipt),
    #: not numeric.
    #:
    #: [mesh-history-card-time-provenance]: no published temporal property may
    #: be derivable purely from producer-written timestamps without this label.
    temporal_provenance: str = "producer_asserted"

    def to_value(self) -> dict[str, Any]:
        return {
            "continuity": self.continuity,
            "history_depth": self.history_depth,
            "unforked": self.unforked,
            "cadence": dict(self.cadence),
            "temporal_provenance": self.temporal_provenance,
        }


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _cadence(checkpoints: list[CheckpointRecord]) -> dict[str, Any]:
    if len(checkpoints) < 2:
        return {"checkpoints": len(checkpoints)}
    times = [_parse_ts(cp.timestamp) for cp in checkpoints]
    intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    span = (times[-1] - times[0]).total_seconds()
    # §5.1: a JSON float in a digest-bearing field raises FloatInDigestError --
    # cadence stats travel as exact decimal strings (RFC 8785 §3.2.2.3), same
    # class as `twin_adjudicator.py`'s margin/margin_tau.
    return {
        "checkpoints": len(checkpoints),
        "span_seconds": float_to_str(span, field="history_card.cadence.span_seconds"),
        "mean_interval_seconds": float_to_str(
            sum(intervals) / len(intervals), field="history_card.cadence.mean_interval_seconds"
        ),
        "min_interval_seconds": float_to_str(min(intervals), field="history_card.cadence.min_interval_seconds"),
        "max_interval_seconds": float_to_str(max(intervals), field="history_card.cadence.max_interval_seconds"),
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
    #: Integrity signal for the forks count -- distinguishes honest absence
    #: (plugin never ran) from unreadable/tampered state.  "State unreadable"
    #: must never grade as "no forks observed" ([mesh-forks-observed-integrity]).
    forks_state: str = FORKS_STATE_ABSENT
    #: [mesh-ask-the-references] discovery-mechanism-1 counts -- ALSO outside
    #: `properties`/`core_account()`: these come from `ask_history.py
    #: references <X>` live-asking a SAMPLE of this card's own counterparties
    #: about a DIFFERENT node's history, never from this log's own checkpoint
    #: chain, and never a score. Defaults are the honest "never asked"
    #: state, not zero-as-if-asked-and-clean.
    references_asked: int = 0
    references_answered: int = 0
    adjudications_about_x: dict[str, int] = field(default_factory=dict)
    ack_refusals_about_x: int = 0

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
                "forks_observed": None if self.forks_state == FORKS_STATE_UNREADABLE else self.forks_observed,
                "forks_state": self.forks_state,
                "note": (
                    "peer count and fork count from this node's own checkpoint-root "
                    "observation store, not from this log's checkpoint chain -- see "
                    "reconciliation_counts_from_ledger_dir(). forks_state signals whether "
                    "the count is trustworthy: 'absent'=plugin never ran (zero is honest), "
                    "'unreadable'=file present but corrupt or tampered (forks_observed=None), "
                    "'ok'=normal read, all fields present."
                ),
            },
            "references": {
                "asked": self.references_asked,
                "answered": self.references_answered,
                "adjudications_about_x": dict(self.adjudications_about_x),
                "ack_refusals_about_x": self.ack_refusals_about_x,
                "note": (
                    "counts from live-asking a SAMPLE of this card's own counterparties "
                    "(discovery mechanism 1, [mesh-ask-the-references]) about a DIFFERENT "
                    "node's history -- never derived from this log's own checkpoint chain, "
                    "never a score; refusals are counted, never inferred from"
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


def reconciliation_counts_from_ledger_dir(ledger_dir: Path) -> tuple[int, int, str]:
    """Read `(reconciled_with, forks_observed, forks_state)` from
    `<ledger_dir>/reconciliation_state.json` -- the peer checkpoint-root
    observation store a mesh plugin (e.g. the Rust `admission-policy`
    plugin's `peer_root_ledger`) persists as it reconciles gossiped
    checkpoint heads.

    The third element `forks_state` signals whether the count is trustworthy:

    - ``FORKS_STATE_ABSENT`` ("absent"): OSError -- file doesn't exist, plugin
      never ran; zero is an honest default.
    - ``FORKS_STATE_UNREADABLE`` ("unreadable"): JSONDecodeError OR the `forks`
      key is missing from the parsed JSON (both indicate corruption or tampering).
      "State unreadable" must NEVER grade as "no forks observed"
      ([mesh-forks-observed-integrity]: an attacker can `jq 'del(.forks)'` to
      remove just that key while keeping the file valid JSON).
    - ``FORKS_STATE_OK`` ("ok"): normal read, all expected fields present.

    Cross-language note: this reads the Rust ledger's own on-disk JSON shape
    directly (`{"observed": {...}, "reconciled_peers": [...], "forks": [...]}`)
    rather than expecting pre-computed counts, so the two languages can never
    silently disagree about what a "count" means.
    """
    state_path = ledger_dir / "reconciliation_state.json"
    try:
        raw = state_path.read_text()
    except OSError:
        return (0, 0, FORKS_STATE_ABSENT)
    try:
        state = json.loads(raw)
    except json.JSONDecodeError:
        return (0, 0, FORKS_STATE_UNREADABLE)
    # The 'forks' key being absent is a tampering signal -- an attacker can
    # delete just that key while leaving the file as valid JSON.  Treat this
    # identically to a corrupt file: unreadable, never zero.
    if "forks" not in state:
        return (0, 0, FORKS_STATE_UNREADABLE)
    reconciled_with = len(state.get("reconciled_peers") or [])
    forks_observed = len(state.get("forks") or [])
    return (reconciled_with, forks_observed, FORKS_STATE_OK)


def with_peer_reconciliation(card: HistoryCard, ledger_dir: Path) -> HistoryCard:
    """Return a copy of `card` with `reconciled_with`/`forks_observed`/`forks_state`
    folded in from `ledger_dir`'s reconciliation store. Never mutates `card` --
    `HistoryCard.verify()`/`digest()` on the ORIGINAL card are unaffected,
    since these fields live outside `core_account()`'s asserted result (see
    the field docstring on `HistoryCard`).

    When `forks_state` is FORKS_STATE_UNREADABLE, `to_value()` emits
    `forks_observed: null` rather than a false zero -- "state unreadable" must
    never grade as "no forks observed" ([mesh-forks-observed-integrity])."""
    reconciled_with, forks_observed, forks_state = reconciliation_counts_from_ledger_dir(ledger_dir)
    return replace(card, reconciled_with=reconciled_with, forks_observed=forks_observed, forks_state=forks_state)


def with_references(
    card: HistoryCard,
    *,
    references_asked: int,
    references_answered: int,
    adjudications_about_x: dict[str, int],
    ack_refusals_about_x: int,
) -> HistoryCard:
    """Return a copy of `card` with the `[mesh-ask-the-references]` fields
    folded in -- never mutates `card`, same discipline as
    `with_peer_reconciliation`. These counts come from `ask_history.py
    references <X>` live-asking a sample of `card`'s own counterparties
    about a DIFFERENT node's (`x`'s) history, so they sit outside
    `core_account()`/`verify()`'s scope exactly like peer reconciliation
    does -- folding them in never perturbs the cryptographically-verified
    chain-walk properties.
    """
    return replace(
        card,
        references_asked=references_asked,
        references_answered=references_answered,
        adjudications_about_x=dict(adjudications_about_x),
        ack_refusals_about_x=ack_refusals_about_x,
    )


def node_id_from_key_id(key_id: str) -> str:
    """The canonical `node_id` label derived from a checkpoint's own signing
    `key_id` -- `f"node:{key_id[:16]}"`. Single definition site: the CLI
    (`verify_history_card.py`) and `verify_history_card()`'s identity check
    both call this rather than each inlining the derivation, so a claimed
    `node_id` is always checked against the checkpoint chain's own key, never
    trusted from the party presenting it.
    """
    return f"node:{key_id[:16]}"


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

    # [mesh-history-card-time-provenance]: determine whether the temporal
    # properties (history_depth, cadence) are bounded by external witness
    # receipts or are purely producer-asserted.  A real (non-stub) witness
    # receipt on ANY checkpoint in the verified prefix places an external
    # constraint on when that checkpoint could have occurred -- the producer
    # cannot backdate past the TS's own registration time.  Without any real
    # receipt, the cadence and depth numbers are derived entirely from the
    # producer's own self-written cp.timestamp fields.
    has_real_witnesses = any(
        not w.is_stub
        for cp in verified_prefix
        for w in (cp.witnesses or [])
    )
    temporal_provenance = "receipt_bounded" if has_real_witnesses else "producer_asserted"

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
        properties=HistoryProperties(
            continuity=continuity,
            history_depth=depth,
            unforked=unforked,
            cadence=cadence,
            temporal_provenance=temporal_provenance,
        ),
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

    **Identity is derived from `checkpoint_lines`, never taken from the
    card.** `node_id`/`log_id` are read from the checkpoint chain's own
    `log_id` and signing `key_id` (`node_id_from_key_id`) and checked
    against what the card claims, not the reverse. Without this, a
    STRUCTURALLY VALID, honestly witnessed chain belonging to node A could
    be republished under a false `node_id` naming node B, and a
    byte-for-byte recompute+match would trivially succeed because both the
    published card and the recompute would carry the same (false) label --
    the chain's own content was never consulted to check who it belongs to.
    """
    try:
        since_size = card_value["selection"]["since_size"]
        claimed_node_id = card_value["node_id"]
        claimed_log_id = card_value["log_id"]
    except (KeyError, TypeError) as exc:
        return HistoryVerifyResult(ok=False, errors=[f"malformed card: missing {exc}"])

    if checkpoint_lines:
        chain_key_id = checkpoint_lines[0].get("key_id")
        chain_log_id = checkpoint_lines[0].get("log_id")
        chain_node_id = node_id_from_key_id(chain_key_id) if chain_key_id else None

        identity_errors: list[str] = []
        if claimed_log_id != chain_log_id:
            identity_errors.append(
                f"log_id mismatch: card claims log_id={claimed_log_id!r} but the "
                f"checkpoint chain's own log_id is {chain_log_id!r}"
            )
        if claimed_node_id != chain_node_id:
            identity_errors.append(
                f"node_id mismatch: card claims node_id={claimed_node_id!r} but the "
                f"checkpoint chain's signing key derives node_id={chain_node_id!r} -- "
                "refusing a history card presented under an identity the checkpoint "
                "chain does not carry"
            )
        if identity_errors:
            return HistoryVerifyResult(ok=False, errors=identity_errors)
        node_id, log_id = chain_node_id, chain_log_id
    else:
        # No checkpoint lines to bind identity against (an honestly-empty
        # chain) -- fall back to the card's own claim, matching
        # `build_history_card`'s empty-chain handling.
        node_id, log_id = claimed_node_id, claimed_log_id

    try:
        recomputed = build_history_card(
            node_id=node_id, log_id=log_id, checkpoint_lines=checkpoint_lines, since_size=since_size
        )
    except ValueError as exc:
        return HistoryVerifyResult(ok=False, errors=[str(exc)])

    # [mesh-history-card-enrichment-verify]: peer_reconciliation and references
    # live OUTSIDE core_account() -- they come from a separate observation store
    # (the mesh plugin's gossip-fed reconciliation ledger and ask_history counts),
    # not from the checkpoint chain.  build_history_card() always returns a card
    # with their default (zero) values.  Before comparing with the published card
    # we must fold in whatever enrichment the published card carries, so that an
    # enriched card (produced by with_peer_reconciliation() / with_references())
    # passes its own offline verification.  This does NOT weaken the
    # cryptographic chain-walk check: those properties live in
    # recomputed.properties (inside core_account()) which is untouched here.
    pr_block = card_value.get("peer_reconciliation") or {}
    refs_block = card_value.get("references") or {}
    recomputed = replace(
        recomputed,
        reconciled_with=pr_block.get("reconciled_with", 0),
        forks_observed=pr_block.get("forks_observed", 0),
        references_asked=refs_block.get("asked", 0),
        references_answered=refs_block.get("answered", 0),
        adjudications_about_x=dict(refs_block.get("adjudications_about_x") or {}),
        ack_refusals_about_x=refs_block.get("ack_refusals_about_x", 0),
    )

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

# SPDX-License-Identifier: Apache-2.0
"""A node's reputation **account capsule** — an ACCOUNT of its own history,
never a score.

The mesh already gives a node two public-facing evidence layers:

  * **the capsule ledger** (`capsules.jsonl`) — one signed capsule per exchange,
    the raw served/requested history (`capsule_sidecar.py`); and
  * **the witness checkpoint** (`checkpointing.py` / `checkpoints.jsonl`) — a
    periodic, signed commitment over that ledger that an independent witness
    co-signs, so a range of the log becomes tamper-evident against equivocation.

This module builds the thin summarizing layer that rides BOTH. An **account
capsule** answers "what has this node done, over the range a witness has
actually seen?" in three fields:

  * **selection** — the checkpoint-covered range. ONLY witnessed entries count.
    We fold over `[1 .. leaf_count(checkpoint.mmr_size)]`, never the un-anchored
    tail. Entries appended after the latest witnessed checkpoint are excluded on
    purpose: an account that summarized un-witnessed activity would let a node
    inflate its own record between anchors, which is exactly the equivocation
    the witness exists to prevent.
  * **derivation** — a served/success **fold** over the selected range. This is
    a plain, documented fold (counts, not a weighted opinion): total exchanges,
    how many the node SERVED (was the provider) vs. requested, and how many of
    the served ones carried a confirmed effect. It reuses the same served-vs-
    requested role vocabulary as `trust_summary.compute_gradient` and the same
    "confirmed effect" signal the sidecar already writes
    (`effect.status == "confirmed"`); it does not invent a new trust metric.
  * **coverage** — the latest witnessed checkpoint's `root` (+ `mmr_size`,
    `log_id`, and the witness URLs that co-signed it). This is the cross-check
    handle: a relying party recomputes the fold from the node's own ledger,
    checks that ledger against THIS root, and confirms the root was witnessed —
    so the summary is verifiable against the witness, not taken on the node's
    word.

**It is an account, not a verdict.** The account capsule carries facts and the
witness handle to check them. It deliberately emits NO score, ranking, or
routing recommendation. *The relying party computes its own predicate* over
these facts — see `example_predicate()` for a documented EXAMPLE of one such
predicate, shipped as an example only and never as a default routing policy.

**Sybil / identity-reset residual (stated in the capsule itself and here).**
Reputation is only as durable as identity, and a mesh node's identity is a
free, self-minted keypair (Ed25519 for the ledger, a Nostr key for discovery).
A node with a poor account can walk away and mint a fresh key with an empty —
therefore un-incriminating — history at zero cost. Nothing in this layer raises
that cost; the witness makes a *single* identity's history tamper-evident, it
does NOT bind that identity to a scarce real-world entity. Any relying party
that treats the account as durable reputation MUST supply its own Sybil
resistance (stake, bilateral counterparty attestation, an allow-list, a
proof-of-work/proof-of-personhood layer, …). This residual is carried as a
first-class field (`sybil_residual`) so it can never be silently dropped when
the account is serialized, forwarded, or published to Nostr.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from capsule_emit.checkpoint import CheckpointRecord
from capsule_emit.checkpoint import leaf_count as _leaf_count_at_size

__all__ = [
    "ACCOUNT_CAPSULE_SCHEMA",
    "SYBIL_RESIDUAL_TEXT",
    "AccountFold",
    "AccountCapsule",
    "build_account_capsule",
    "example_predicate",
]

#: Schema tag on the serialized account capsule. Versioned so a consumer can
#: refuse an account shape it does not understand rather than mis-read it.
ACCOUNT_CAPSULE_SCHEMA = "mesh-account-capsule/1"

#: The Sybil / identity-reset residual, in one place, carried verbatim into
#: every account capsule (`sybil_residual`) AND into the Nostr listing's
#: transparency block, so the caveat travels with the summary wherever it goes.
SYBIL_RESIDUAL_TEXT = (
    "Reputation is only as durable as identity. A mesh node key is free to mint, "
    "so a node with a poor account can reset to a fresh key with an empty history "
    "at zero cost. The witness makes ONE identity's history tamper-evident; it "
    "does not bind that identity to a scarce real-world entity. A relying party "
    "that needs Sybil resistance must add its own (stake, counterparty "
    "attestation, allow-list, proof-of-personhood) — this account does not "
    "provide it."
)


def _role_of(capsule: dict[str, Any]) -> str:
    """served | requested | unknown — the same role vocabulary trust_summary
    uses. A mesh node is the PROVIDER for a served exchange (it produced the
    inference completion) and the REQUESTER otherwise. We read the served
    signal off the effect block the sidecar writes (`type ==
    "inference_completion"` with a `response_digest`), falling back to an
    explicit `served_by_node_id`/`role` when present."""
    effect = capsule.get("effect") or {}
    if effect.get("type") == "inference_completion" and effect.get("response_digest"):
        return "served"
    prov = capsule.get("provenance") or {}
    if prov.get("served_by_node_id") or capsule.get("served_by_node_id"):
        return "served"
    role = (prov.get("role") or capsule.get("role") or "").lower()
    if role in ("served", "provider"):
        return "served"
    if role in ("requested", "requester", "sent"):
        return "requested"
    return "unknown"


def _effect_confirmed(capsule: dict[str, Any]) -> bool:
    """The success leg of the fold: did the served exchange carry a CONFIRMED
    effect? This is the same `effect.status == "confirmed"` signal the sidecar
    already writes (a gate-executed, confirmed inference completion) — not a new
    quality judgement. A served exchange whose effect is anything other than
    `confirmed` (e.g. rejected, pending) counts as served-but-not-confirmed."""
    effect = capsule.get("effect") or {}
    return effect.get("status") == "confirmed"


@dataclass(frozen=True)
class AccountFold:
    """The served/success fold over the selected (witnessed) range — plain
    counts, no weighting, no score."""

    n_total: int = 0
    n_served: int = 0
    n_requested: int = 0
    n_unknown_role: int = 0
    n_served_confirmed: int = 0

    def to_value(self) -> dict[str, Any]:
        return {
            "n_total": self.n_total,
            "n_served": self.n_served,
            "n_requested": self.n_requested,
            "n_unknown_role": self.n_unknown_role,
            "n_served_confirmed": self.n_served_confirmed,
        }


def _fold_range(capsules: list[dict[str, Any]]) -> AccountFold:
    n_served = n_requested = n_unknown = n_confirmed = 0
    for c in capsules:
        role = _role_of(c)
        if role == "served":
            n_served += 1
            if _effect_confirmed(c):
                n_confirmed += 1
        elif role == "requested":
            n_requested += 1
        else:
            n_unknown += 1
    return AccountFold(
        n_total=len(capsules),
        n_served=n_served,
        n_requested=n_requested,
        n_unknown_role=n_unknown,
        n_served_confirmed=n_confirmed,
    )


@dataclass
class AccountCapsule:
    """A node's account of its own witnessed history: selection / derivation /
    coverage, plus the Sybil residual carried verbatim so it is never dropped.

    NOT a score. Carries facts + the witness handle to check them; the relying
    party computes its own predicate.
    """

    node_id: str
    #: selection — the checkpoint-covered range (1-indexed, inclusive), the ONLY
    #: entries the fold saw. `covered_entries == 0` means no witnessed checkpoint
    #: yet, so the account is honestly empty rather than summarizing un-anchored
    #: activity.
    selection_from_entry: int
    selection_to_entry: int
    covered_entries: int
    #: derivation — the served/success fold over that range.
    fold: AccountFold
    #: coverage — the latest witnessed checkpoint this account is pinned to.
    coverage_root: str
    coverage_mmr_size: int
    coverage_log_id: str
    coverage_timestamp: str
    coverage_witnesses: list[str] = field(default_factory=list)
    #: True only when at least one independent witness co-signed the coverage
    #: checkpoint. A self-checkpointed (un-witnessed) coverage root is still
    #: recorded, but `coverage_witnessed=False` says the cross-check has no
    #: independent freshness evidence behind it yet — the same honesty
    #: discipline as `checkpointing.describe_witness_state`.
    coverage_witnessed: bool = False
    sybil_residual: str = SYBIL_RESIDUAL_TEXT

    def to_value(self) -> dict[str, Any]:
        return {
            "schema": ACCOUNT_CAPSULE_SCHEMA,
            "node_id": self.node_id,
            "selection": {
                "from_entry": self.selection_from_entry,
                "to_entry": self.selection_to_entry,
                "covered_entries": self.covered_entries,
                "note": (
                    "witnessed range only: entries appended after the latest "
                    "witnessed checkpoint are excluded by design"
                ),
            },
            "derivation": {
                "kind": "served_success_fold",
                "fold": self.fold.to_value(),
                "note": (
                    "plain counts over the selected range; an ACCOUNT, not a "
                    "score. The relying party computes its own predicate."
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
                    "cross-check handle: recompute the fold from the node's "
                    "ledger, check the ledger against this root, confirm the "
                    "root was witnessed"
                ),
            },
            "sybil_residual": self.sybil_residual,
            "not_a_score": (
                "This is an account of facts + a witness handle to verify them, "
                "not a score or routing recommendation. See example_predicate() "
                "for an EXAMPLE predicate only — never a default routing policy."
            ),
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_value(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        """Stable content address over the account's canonical bytes — the
        digest a Nostr listing pins so a reader can confirm the published
        summary matches the account it claims to be."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def build_account_capsule(
    *,
    node_id: str,
    capsules: list[dict[str, Any]],
    latest_checkpoint: CheckpointRecord | None,
) -> AccountCapsule:
    """Build a node's account capsule from its own ledger + latest checkpoint.

    `capsules` is the node's full `capsules.jsonl`, 1-indexed by line (the same
    ordering `checkpointing.JsonlLogSource` folds into the MMR). `latest_checkpoint`
    is the most recent `CheckpointRecord` from `checkpoints.jsonl` (or `None`).

    **Selection is witness-bounded.** We fold ONLY `capsules[:covered_entries]`
    where `covered_entries = leaf_count(latest_checkpoint.mmr_size)`. If there is
    no checkpoint, the account is honestly empty (covered range `0`). If the
    ledger somehow has fewer lines than the checkpoint claims, we clamp to what
    is actually on disk (never fold phantom entries), and the coverage note lets
    a verifier notice the shortfall against the root.
    """
    if latest_checkpoint is None:
        covered = 0
        selected: list[dict[str, Any]] = []
        return AccountCapsule(
            node_id=node_id,
            selection_from_entry=0,
            selection_to_entry=0,
            covered_entries=0,
            fold=_fold_range(selected),
            coverage_root="",
            coverage_mmr_size=0,
            coverage_log_id="",
            coverage_timestamp="",
            coverage_witnesses=[],
            coverage_witnessed=False,
        )

    covered = _leaf_count_at_size(latest_checkpoint.mmr_size)
    # Clamp to entries actually present: never fold a range the ledger cannot
    # back. A shortfall is visible to a verifier via the root cross-check.
    covered = min(covered, len(capsules))
    selected = capsules[:covered]
    witnesses = sorted({w.ts_url for w in (latest_checkpoint.witnesses or [])})
    return AccountCapsule(
        node_id=node_id,
        selection_from_entry=1 if covered else 0,
        selection_to_entry=covered,
        covered_entries=covered,
        fold=_fold_range(selected),
        coverage_root=latest_checkpoint.root,
        coverage_mmr_size=latest_checkpoint.mmr_size,
        coverage_log_id=latest_checkpoint.log_id,
        coverage_timestamp=latest_checkpoint.timestamp,
        coverage_witnesses=witnesses,
        coverage_witnessed=bool(witnesses),
    )


def example_predicate(account: AccountCapsule, *, min_confirmed: int = 1) -> bool:
    """An **EXAMPLE** relying-party predicate over an account capsule — shipped
    as an example ONLY, and deliberately NOT wired as a default routing policy
    anywhere in this repo.

    It shows the shape of the check a relying party might write for itself:
    "the coverage root is independently WITNESSED, and the node served at least
    `min_confirmed` confirmed exchange(s) in the witnessed range." It is
    intentionally trivial and conservative. A real deployment writes its own
    predicate over these facts, weighs the Sybil residual for its threat model,
    and does NOT treat this function as a recommendation. Importing it does not
    change any node's routing; nothing in the mesh calls it.
    """
    if not account.coverage_witnessed:
        return False
    return account.fold.n_served_confirmed >= min_confirmed

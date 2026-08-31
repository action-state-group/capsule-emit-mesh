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

**Built on the neutral account/fold core.** The served/success fold is NOT a
bespoke reimplementation any more: it is an ``Account`` from the neutral
``capsule_emit.account`` core, built the way the core prescribes for a
*range-kind* account —

  * **selection-kind = range.** The account's input identity is
    ``(coverage_root, range)`` — the witnessed checkpoint root plus the covered
    ``[from, to]`` span — and NEVER the per-member capsule digests. A range
    account cites WHAT it covered (the root the range lives under and the span),
    not each member; the core refuses per-member references on a range.
  * **derivation-class = deterministic.** The served/success counts are a pure
    function of the selected inputs, so the derivation is deterministic and
    carries the core's ``definition_digest`` — the SHA-256 over the fold's
    canonical *definition document* (name, selection-kind, the fields it reads,
    derivation-class), never over this code. Verification is recompute+match.
  * **asserted_result = the fold counts.** The served/success/requested counts
    ARE the account's asserted result over the selected range.

The ``definition_digest`` is the load-bearing property: it is a digest of the
DEFINITION-as-data, so it does not move when this module's internals change —
only when the definition document itself changes. That is what lets the Nostr
event ship the digest now and swap the internals under it.

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
import uuid
from dataclasses import dataclass, field
from typing import Any

from agent_action_capsule.emit import emit

# The neutral account/fold core — the single implementation of
# fold-definition-as-DATA + definition_digest, the account object, and
# replay/verify. This module CONSUMES it rather than re-forking the fold.
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

__all__ = [
    "ACCOUNT_CAPSULE_SCHEMA",
    "ACCOUNT_SUBJECT_KEY",
    "ACCOUNT_SUPERSEDES_RELATION",
    "SYBIL_RESIDUAL_TEXT",
    "MESH_ACCOUNT_DEFINITION",
    "MESH_ACCOUNT_DEFINITION_DIGEST",
    "AccountFold",
    "AccountCapsule",
    "build_account_capsule",
    "seal_account_capsule",
    "example_predicate",
]

#: Schema tag on the serialized account capsule. Versioned so a consumer can
#: refuse an account shape it does not understand rather than mis-read it.
ACCOUNT_CAPSULE_SCHEMA = "mesh-account-capsule/1"

#: Capsule marker for the account capsule's account-of-history subject block,
#: mirroring node_ownership.OWNERSHIP_SUBJECT_KEY. This is the compute-attestation
#: key under which the account fold + coverage rides inside the sealed capsule.
ACCOUNT_SUBJECT_KEY = "x-mesh-account-v1"

#: The registry-governed chain relation a NEWER account capsule uses to point at
#: the account capsule it supersedes. Both stay in the log (append-only); the
#: later one cites the earlier as `supersedes` so a reader folds forward to the
#: authoritative (latest) account while the earlier remains auditable. This is
#: the same "supersedes" relation §5.4.4 / §6 verify store-level checks read.
ACCOUNT_SUPERSEDES_RELATION = "supersedes"

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


# --------------------------------------------------------------------------- #
# The neutral fold DEFINITION (definition-as-data)                             #
#                                                                              #
# The mesh served/success fold is a canonical DEFINITION DOCUMENT in the core: #
# a name, selection-kind (range), the fields it reads, and derivation-class    #
# (deterministic). ``MESH_ACCOUNT_DEFINITION_DIGEST`` is the SHA-256 over that #
# document (JCS bytes), NOT over this module's code — so changing how the fold #
# is implemented below cannot move the digest. Only editing this document      #
# (renaming, adding a read field, changing the class/kind) moves it.           #
#                                                                              #
# ``reads`` names the capsule fields ``_role_of`` / ``_effect_confirmed`` read #
# — the served/requested role signal and the confirmed-effect signal — so the #
# definition honestly declares its inputs.                                     #
# --------------------------------------------------------------------------- #
MESH_ACCOUNT_DEFINITION = AccountDefinition(
    name="mesh.served_success_fold/1",
    selection_kind="range",
    reads=(
        "effect.type",
        "effect.response_digest",
        "effect.status",
        "provenance.role",
        "provenance.served_by_node_id",
        "role",
        "served_by_node_id",
    ),
    derivation_class="deterministic",
)

#: The stable digest of the fold definition document above. This is what the
#: account capsule and its Nostr event carry; it is byte-identical across any
#: implementation that shares the same definition document (the core's
#: definition-as-data property), and is invariant to how the fold is computed.
MESH_ACCOUNT_DEFINITION_DIGEST = MESH_ACCOUNT_DEFINITION.definition_digest()


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
    counts, no weighting, no score.

    This IS the account's ``asserted_result`` in the neutral core: a
    deterministic, recompute+match-able result over the selected range. It is
    kept as a small typed value (rather than a bare dict) so callers, the
    sealed subject, and the Nostr event all read the same field names — but its
    ``to_value()`` is exactly the asserted-result document the core carries.
    """

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

    Internally this is a *view* over a neutral-core ``Account`` (range-kind,
    deterministic; see ``core_account``): the mesh-specific serialization
    (`to_value()`) is unchanged in shape, and it now also carries the core's
    ``definition_digest`` so a reader binds the fold to its definition document.
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

    # ----------------------------------------------------------------------- #
    # Neutral-core view                                                       #
    # ----------------------------------------------------------------------- #
    def core_account(self) -> CoreAccount:
        """Build the neutral-core ``Account`` this capsule is a view of.

        A **range-kind** selection whose input identity is
        ``(coverage_root, [from, to])`` — NOT per-member digests — with a
        **deterministic** derivation carrying ``MESH_ACCOUNT_DEFINITION``'s
        ``definition_digest``, and the served/success fold counts as the
        ``asserted_result``. ``build_account`` is fail-closed: it refuses
        per-member references on a range and (being deterministic) refuses
        provenance.

        When there is no witnessed coverage yet (``coverage_root == ""``) the
        core cannot express a valid range selection, so this returns ``None``:
        an honestly-empty account has no core range to build.
        """
        if not self.coverage_root:
            return None
        selection = Selection(
            kind="range",
            coverage=Coverage(
                coverage_root=self.coverage_root,
                # (from, to) is the covered span; when covered==0 build_account
                # is not reached because coverage_root is empty above.
                range=(self.selection_from_entry, self.selection_to_entry),
            ),
        )
        return build_account(
            definition=MESH_ACCOUNT_DEFINITION,
            selection=selection,
            asserted_result=self.fold.to_value(),
        )

    def definition_digest(self) -> str:
        """The fold's ``definition_digest`` — the SHA-256 over the fold's
        DEFINITION DOCUMENT (definition-as-data), invariant to this module's
        internals. This is the value the event GAINS by the core swap."""
        return MESH_ACCOUNT_DEFINITION_DIGEST

    def verify(self) -> bool:
        """Recompute+match this deterministic account through the core.

        The recompute callable re-derives the served/success counts from the
        selection's input identity — here, from the fold already computed over
        the selected range — and the core confirms it equals the asserted
        result and that the cited ``definition_digest`` matches the definition.
        An honestly-empty (no-coverage) account has no core range and trivially
        verifies.
        """
        acct = self.core_account()
        if acct is None:
            return True
        result = verify_account(
            acct,
            definition=MESH_ACCOUNT_DEFINITION,
            recompute=lambda _selection: self.fold.to_value(),
        )
        return result.ok

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
                # The fold's DEFINITION digest — definition-as-data, invariant to
                # the fold's implementation. Carried so a reader binds these
                # counts to the fold definition document that produced them and
                # can recompute+match through the neutral core. This is the ONLY
                # field the core swap adds to the account/event shape.
                "definition_digest": MESH_ACCOUNT_DEFINITION_DIGEST,
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

    The fold result becomes the neutral-core ``Account``'s asserted_result over
    a *range* selection whose input identity is (coverage_root, [from, to]); see
    ``AccountCapsule.core_account``.
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


def seal_account_capsule(
    account: AccountCapsule,
    *,
    operator: str,
    developer: str,
    signing_node_id: str,
    prior_account_capsule_id: str | None = None,
    provider: str = "mesh-llm",
) -> dict[str, Any]:
    """Seal an account capsule INTO the node's own ledger — mirror of
    node_ownership.seal_identity_capsule (the B4 "who" self-assertion).

    The account is not a signed JSON summary that lives only on a Nostr relay: it
    is a CAPSULE, sealed like any other into the node's `capsules.jsonl` under the
    node's Ed25519 ledger key (the caller signs + appends the returned dict, e.g.
    via `capsule_sidecar.record_capsule`). That puts the assertion act ON THE
    RECORD: it gets a `capsule_id`, chains to the ledger head, and folds into the
    NEXT witnessed checkpoint like every other capsule.

    action_type="fyi": the account capsule ASSERTS a fact (this node accounts for
    its own witnessed history) rather than deciding or running an inference — the
    same informational self-assertion grade as the identity capsule. The subject
    is the account fold + coverage, carried verbatim (via `account.to_value()`) so
    a verifier recomputes the fold from the node's ledger and cross-checks the
    coverage root against the witness, from these bytes alone. Because
    `to_value()` now carries the core's `definition_digest`, the sealed subject
    binds the fold to its definition document too.

    **Supersede model.** A later account capsule SUPERSEDES an earlier one: pass
    the earlier account capsule's `capsule_id` as `prior_account_capsule_id` and
    this capsule chains to it with `relation="supersedes"`. BOTH stay in the
    append-only log — the earlier remains auditable, the later is authoritative
    (§5.4.4: the earliest supersedes over a given parent is authoritative, and a
    reader folds forward to the latest account).

    **Honest coverage ordering — no self-reference paradox.** Sealing the account
    APPENDS an entry to the ledger, so this account capsule's own ledger position
    is NOT covered by the checkpoint it summarizes: its `coverage` root is the
    checkpoint BEFORE it, and the sealing act itself is only covered by the NEXT
    checkpoint. An account capsule never summarizes a range that includes itself;
    the coverage always trails the seal by one checkpoint. This is recorded in the
    subject's `coverage_ordering` note so a reader is not surprised.
    """
    account_subject = dict(account.to_value())
    compute_attestation = {
        ACCOUNT_SUBJECT_KEY: {
            # The account, verbatim — selection / derivation (fold) / coverage /
            # sybil_residual — so a reader recomputes and cross-checks from these
            # bytes, never from our say-so.
            "account": account_subject,
            # The digest a Nostr listing pins, sealed alongside the account so the
            # relay copy and the ledgered capsule are provably the same account.
            "account_digest": account.digest(),
            # Sybil residual at the top of the block too, so it is unmissable and
            # can never be silently dropped from the sealed record.
            "sybil_residual": account.sybil_residual,
            "coverage_ordering": (
                "Sealing this account appends a ledger entry, so this capsule's "
                "own position is covered by the NEXT witnessed checkpoint, not "
                "the one in `coverage` (which is the checkpoint BEFORE this "
                "seal). An account never summarizes a range that includes "
                "itself — no self-reference."
            ),
            "not_a_score": (
                "An account of facts + a witness handle to verify them, not a "
                "score or routing recommendation."
            ),
        },
    }

    return emit(
        action_id=f"mesh-poc/account/{signing_node_id}/{uuid.uuid4()}",
        action_type="fyi",
        operator=operator,
        developer=developer,
        provider=provider,
        compute_attestation=compute_attestation,
        prior_capsule_id=prior_account_capsule_id,
        chain_relation=ACCOUNT_SUPERSEDES_RELATION if prior_account_capsule_id else None,
        domain="action",
        provenance="collector",
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

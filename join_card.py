# SPDX-License-Identifier: Apache-2.0
"""The `card` record -- a node's own self-announcement, sealed once at start
and again on any change to what it serves, and `card_consistency`, the
offline verifier that checks every exchange's claims against the card that
was actually in effect when that exchange was sealed.

**Closes "advertised vs sealed" without a gate or an enrollment service.**
Today a node's `advertisement.Advertisement` (self-attested capability claim)
and its per-exchange `serving_provenance` (what actually ran) reconcile
one-to-one, per exchange (`advertisement.reconcile_advertised_vs_served`).
That catches "advertises one model, serves another" on a SINGLE exchange, but
says nothing about whether the node changed what it serves WITHOUT saying so.
A `card` is the missing middle layer: a standalone, infrequent record of
"here is everything I currently claim about myself" (served models +
weights_digest, hardware, measurement rung, and a digest of my own current
self-announcement), chained by `supersedes` so a later card can be told apart
from an earlier one, and checked against every exchange sealed since.

**Same three primitives, reused, never re-derived:**
  * `hardware_inventory` is exactly `mac_hardware_inventory.HardwareInventory
    .to_capsule_block()` -- the existing OS-measured hardware self-report,
    nested here rather than reinvented.
  * `models[].weights_digest` is exactly the `weights_digest` the Rust
    producer already mirrors from the host at load time
    (`[mesh-weights-digest-at-load]`) -- a hash of the served GGUF's BYTES,
    landing on every exchange at
    `x-mesh-poc-v1.serving_provenance.model.weights_digest`. This module does
    not compute it a second way; it only compares the card's copy against the
    exchange's copy.
  * `announcement_digest` is `advertisement.Advertisement.digest()` -- THIS
    module's honest answer to "PeerAnnouncement bytes as gossiped" (see the
    HONEST GAP note below).

**HONEST GAP, stated not hidden.** The mesh-full-ladder-rehearsal runbook
describes `announcement_digest` as a hash of the node's own current
`PeerAnnouncement` -- the actual mesh-llm gossip struct
(`mesh-llm-protocol/proto/node.proto`, mirrored in
`mesh-llm-host-runtime/src/mesh/peer_state.rs`). As of this module, the
admission-policy plugin has NO read access to that struct's bytes: no gossip/
announcement/topology field reaches `lifecycle_channel.rs` today (that is a
real, separate host-wiring gap -- the same shape of gap
`[mesh-peer-root-exchange]` closes for the checkpoint field, not this task's
scope, whose repo line names `capsule-emit-mesh` only). Rather than fabricate
that hookup, `announcement_digest` is defined here as the digest of this
node's own `Advertisement` -- the one artifact this codebase already treats
as "what a node announces about itself to a relying party", already
co-carried onto every exchange (`x-mesh-poc-v1.advertisement`) for exactly
the same self-attested-claim reason. `check_announcement_consistency` takes
the comparison digest as a caller-supplied argument for this reason: a future
caller with real gossip-bytes access can pass that digest in without this
module changing. If/when the host wiring lands, swap the producer of
`observed_digest`, not this function's contract.

**Never compare to the latest card.** `card_consistency` walks a ledger
(cards and exchanges interleaved, single-writer, file order -- exactly the
shape `history_card.build_history_card` already assumes) and tracks the
CURRENT card as it goes, so an exchange sealed between card #1 and card #2 is
checked against #1, never against whatever the newest card later turns out to
be. This is the same "as of this position, not as of now" discipline
`history_card`'s chain walk and `advertisement`'s three-state reconciliation
already use.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from agent_action_capsule.emit import emit

__all__ = [
    "CARD_SCHEMA",
    "CARD_SUBJECT_KEY",
    "CARD_SUPERSEDES_RELATION",
    "STATUS_OK",
    "STATUS_BROKEN",
    "STATUS_NO_CARD_SEALED",
    "FIELD_MATCH",
    "FIELD_MISMATCH",
    "FIELD_ABSENT",
    "ANNOUNCEMENT_MATCH",
    "ANNOUNCEMENT_MISMATCH",
    "ANNOUNCEMENT_ABSENT",
    "ModelRef",
    "Card",
    "ExchangeCardVerdict",
    "CardConsistencyResult",
    "build_card",
    "seal_card",
    "latest_card",
    "card_consistency",
    "check_announcement_consistency",
]

#: Schema tag on the serialized card -- versioned so a consumer can refuse a
#: shape it does not understand rather than mis-read it.
CARD_SCHEMA = "mesh-join-card/1"

#: Capsule marker for the card's subject block, mirroring
#: `history_card.HISTORY_SUBJECT_KEY` / `account_capsule.ACCOUNT_SUBJECT_KEY`.
CARD_SUBJECT_KEY = "x-mesh-join-card-v1"

#: A later card SUPERSEDES an earlier one over the same node, same convention
#: as `history_card.HISTORY_SUPERSEDES_RELATION`.
CARD_SUPERSEDES_RELATION = "supersedes"

#: `card_consistency` per-exchange status -- a closed set, never a silent pass.
STATUS_OK = "ok"
STATUS_BROKEN = "broken"
#: The exchange was sealed before this node ever sealed a card -- honestly
#: distinct from `STATUS_OK`; there is nothing to check it against.
STATUS_NO_CARD_SEALED = "no_card_sealed"

#: Per-field verdict inside a broken entry's `mismatches` -- same three-state
#: shape `advertisement._reconcile_field` already uses (minus
#: `not_advertised`, which has no analogue here: a card is a direct
#: self-report, not an advertised claim reconciled against a served fact).
FIELD_MATCH = "match"
FIELD_MISMATCH = "mismatch"
FIELD_ABSENT = "absent"

#: `check_announcement_consistency` verdicts.
ANNOUNCEMENT_MATCH = "match"
ANNOUNCEMENT_MISMATCH = "advertised_mismatch"
ANNOUNCEMENT_ABSENT = "absent"


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _compute_attestation(line: dict[str, Any]) -> dict[str, Any]:
    """A ledger line's `compute_attestation` block lives at
    `model_attestation.compute_attestation` (the sealed capsule envelope
    shape `agent_action_capsule.emit.emit` produces -- same path
    `capsule_mesh_view._poc_block` already reads), never at the line's own
    top level."""
    return (line.get("model_attestation") or {}).get("compute_attestation") or {}


def _values_equal(a: Any, b: Any) -> bool:
    """Same tolerance as `advertisement._values_equal`: case/whitespace-
    insensitive string compare, exact compare otherwise."""
    if isinstance(a, str) and isinstance(b, str):
        return a.strip().casefold() == b.strip().casefold()
    return a == b


@dataclass(frozen=True)
class ModelRef:
    """One currently-served model, named + content-addressed. `weights_digest`
    is `None` when the host has not yet emitted one for this model (a host
    predating `[mesh-weights-digest-at-load]`) -- absent, never fabricated."""

    name: str
    weights_digest: str | None = None

    def to_value(self) -> dict[str, Any]:
        return {"name": self.name, "weights_digest": self.weights_digest}

    @classmethod
    def from_value(cls, value: dict[str, Any]) -> "ModelRef":
        return cls(name=value.get("name", ""), weights_digest=value.get("weights_digest"))


@dataclass
class Card:
    """A node's join card: what it currently claims about itself. Sealed
    infrequently (start, and any change to served models / inventory) --
    never per-exchange."""

    node_id: str
    #: `mac_hardware_inventory.HardwareInventory.to_capsule_block()`, or
    #: `None` when hardware could not be captured (non-Mac host, or the
    #: capture failed) -- absent, never a fabricated block.
    hardware_inventory: dict[str, Any] | None
    models: tuple[ModelRef, ...]
    #: The node's current binary-attestation measurement class
    #: (`self_measured` / `os_measured` / `tee_measured`,
    #: `runtime_attest.MeasurementClass`), or `None` when this sealing path
    #: cannot independently measure it.
    measurement_rung: str | None
    #: sha256 of this node's own current `Advertisement` -- see this module's
    #: HONEST GAP note for why this stands in for gossiped PeerAnnouncement
    #: bytes. `None` when the node advertises nothing.
    announcement_digest: str | None
    #: The PRIOR card's own `digest()`, or `None` for this node's first card.
    #: Content-addressed (not a capsule_id) so a holder of just the two card
    #: bodies -- no ledger access -- can already tell they chain.
    supersedes: str | None = None

    def to_value(self) -> dict[str, Any]:
        return {
            "schema": CARD_SCHEMA,
            "node_id": self.node_id,
            "hardware_inventory": self.hardware_inventory,
            "models": [m.to_value() for m in self.models],
            "measurement_rung": self.measurement_rung,
            "announcement_digest": self.announcement_digest,
            "supersedes": self.supersedes,
        }

    @classmethod
    def from_value(cls, value: dict[str, Any]) -> "Card":
        return cls(
            node_id=value.get("node_id", ""),
            hardware_inventory=value.get("hardware_inventory"),
            models=tuple(ModelRef.from_value(m) for m in value.get("models") or []),
            measurement_rung=value.get("measurement_rung"),
            announcement_digest=value.get("announcement_digest"),
            supersedes=value.get("supersedes"),
        )

    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self.to_value())

    def digest(self) -> str:
        return _digest(self.to_value())


def build_card(
    *,
    node_id: str,
    hardware_inventory: dict[str, Any] | None,
    models: list[ModelRef] | tuple[ModelRef, ...],
    measurement_rung: str | None = None,
    announcement_digest: str | None = None,
    supersedes: str | None = None,
) -> Card:
    return Card(
        node_id=node_id,
        hardware_inventory=hardware_inventory,
        models=tuple(models),
        measurement_rung=measurement_rung,
        announcement_digest=announcement_digest,
        supersedes=supersedes,
    )


def seal_card(
    card: Card,
    *,
    operator: str,
    developer: str,
    signing_node_id: str,
    prior_card_capsule_id: str | None = None,
    provider: str = "mesh-llm",
) -> dict[str, Any]:
    """Seal a card INTO the node's own ledger -- same pattern as
    `history_card.seal_history_card` / `account_capsule.seal_account_capsule`:
    a CAPSULE, appended and chained like any other, not a signed JSON summary
    handed out of-band.

    `prior_card_capsule_id` is the LEDGER chain link (this capsule's
    `chain.parent_capsule_id`); `card.supersedes` (the prior card's own
    content digest) is the separate, ledger-independent link a stranger
    holding just the two card bodies can already verify.
    """
    card_subject = dict(card.to_value())
    compute_attestation = {
        CARD_SUBJECT_KEY: {
            "card": card_subject,
            "card_digest": card.digest(),
            "not_a_score": (
                "A self-report of what this node currently claims to serve, not a "
                "trust rating or routing recommendation."
            ),
        },
    }
    return emit(
        action_id=f"mesh-poc/card/{signing_node_id}/{uuid.uuid4()}",
        action_type="fyi",
        operator=operator,
        developer=developer,
        provider=provider,
        compute_attestation=compute_attestation,
        prior_capsule_id=prior_card_capsule_id,
        chain_relation=CARD_SUPERSEDES_RELATION if prior_card_capsule_id else None,
        domain="action",
        provenance="collector",
    )


def _card_from_ledger_line(line: dict[str, Any]) -> tuple[Card, str] | None:
    """Return `(card, capsule_id)` if `line` is a sealed card record, else
    `None`."""
    subject = _compute_attestation(line).get(CARD_SUBJECT_KEY)
    if not subject:
        return None
    card_value = subject.get("card") or {}
    return Card.from_value(card_value), line.get("capsule_id", "")


def latest_card(ledger_lines: list[dict[str, Any]]) -> tuple[Card | None, str | None, str | None]:
    """Walk `ledger_lines` in order and return `(card, card_digest,
    capsule_id)` for the LAST card sealed, or `(None, None, None)` if this
    node has never sealed one. Used to find `supersedes` / the chain link for
    the NEXT card -- never used by `card_consistency` itself, which tracks
    the current card incrementally as it walks (see module docstring, "Never
    compare to the latest card")."""
    found: tuple[Card, str] | None = None
    for line in ledger_lines:
        maybe = _card_from_ledger_line(line)
        if maybe is not None:
            found = maybe
    if found is None:
        return None, None, None
    card, capsule_id = found
    return card, card.digest(), capsule_id


def _exchange_claims(line: dict[str, Any]) -> dict[str, Any] | None:
    """Extract the (model, weights_digest, hardware, rung) claims from an
    exchange ledger line, tolerant of both the Rust-producer nested shape and
    the Python-sidecar flat shape (same tolerance as
    `advertisement._served_facts`). Returns `None` if `line` carries no
    `serving_provenance` at all (i.e. is not an exchange record)."""
    poc = _compute_attestation(line).get("x-mesh-poc-v1") or {}
    sp = poc.get("serving_provenance")
    if sp is None:
        return None
    model = sp.get("model") or {}
    hardware = sp.get("hardware") or {}
    binary_attestation = (poc.get("evidence_refs") or {}).get("binary_attestation") or {}

    def clean(v: Any) -> Any:
        if isinstance(v, str) and v.strip().lower() == "unknown":
            return None
        return v

    return {
        "model_name": clean(model.get("canonical_ref") or sp.get("model_canonical_ref")),
        "weights_digest": clean(model.get("weights_digest")),
        "hardware_gpu": clean(hardware.get("gpu") or sp.get("hardware_gpu")),
        "hardware_vram_bytes": clean(
            hardware.get("vram_bytes") if hardware.get("vram_bytes") is not None else sp.get("hardware_vram_bytes")
        ),
        "hardware_is_soc": clean(
            hardware.get("is_soc") if hardware.get("is_soc") is not None else sp.get("hardware_is_soc")
        ),
        "measurement_rung": clean(binary_attestation.get("measurement_class")),
    }


def _find_model(card: Card, name: Any) -> ModelRef | None:
    if name is None:
        return None
    for m in card.models:
        if _values_equal(m.name, name):
            return m
    return None


def _field(mismatches: list[dict[str, Any]], field_name: str, exchange_val: Any, card_val: Any) -> None:
    """Compare one field; append a mismatch entry (never a silent drop) when
    both sides are present and unequal. Either side absent -> nothing to
    compare, no verdict recorded (same as `advertisement`'s three-state
    discipline: absence is not a pass, but it is not a broken promise either
    -- it is simply not asserted here)."""
    if exchange_val is None or card_val is None:
        return
    if not _values_equal(exchange_val, card_val):
        mismatches.append({"field": field_name, "exchange": exchange_val, "card": card_val})


@dataclass(frozen=True)
class ExchangeCardVerdict:
    """The `card_consistency` outcome for ONE exchange ledger line."""

    exchange_digest: str | None
    card_digest: str | None
    status: str  # STATUS_OK | STATUS_BROKEN | STATUS_NO_CARD_SEALED
    mismatches: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def to_value(self) -> dict[str, Any]:
        return {
            "exchange_digest": self.exchange_digest,
            "card_digest": self.card_digest,
            "status": self.status,
            "mismatches": list(self.mismatches),
        }


@dataclass(frozen=True)
class CardConsistencyResult:
    """Total, offline outcome of `card_consistency` over a ledger. Never
    raises. `ok` is true iff no exchange came back `STATUS_BROKEN` --
    `STATUS_NO_CARD_SEALED` entries do not flip `ok` to `False` (there is no
    broken promise before any card exists) but ARE counted separately so they
    are never silently indistinguishable from a real pass."""

    entries: tuple[ExchangeCardVerdict, ...]

    @property
    def ok(self) -> bool:
        return not any(e.status == STATUS_BROKEN for e in self.entries)

    @property
    def broken_count(self) -> int:
        return sum(1 for e in self.entries if e.status == STATUS_BROKEN)

    @property
    def no_card_sealed_count(self) -> int:
        return sum(1 for e in self.entries if e.status == STATUS_NO_CARD_SEALED)

    def to_value(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "broken_count": self.broken_count,
            "no_card_sealed_count": self.no_card_sealed_count,
            "entries": [e.to_value() for e in self.entries],
        }


def card_consistency(ledger_lines: list[dict[str, Any]]) -> CardConsistencyResult:
    """Walk `ledger_lines` (cards and exchanges interleaved, single-writer,
    file order -- exactly the shape this node's own `capsules.jsonl` is) and,
    for every exchange, check its (model, weights_digest, hardware,
    measurement_rung) claims against the card CURRENT AT THAT POSITION.

    Hardware comparison is deliberately narrow, stated here rather than
    guessed silently: `hardware_inventory`'s schema (chip name, total system
    memory) and an exchange's `serving_provenance.hardware` (GPU device name,
    VRAM bytes) name different axes in general. They coincide only on an
    Apple-Silicon unified-memory host (`hardware_is_soc` true), where the
    GPU IS the chip and VRAM IS system memory -- so `chip` is compared
    against `hardware_gpu` and `memory_bytes` against `hardware_vram_bytes`
    ONLY when the exchange reports `hardware_is_soc: true`. A non-SoC host,
    or either side absent, is not compared (absent, never fabricated) rather
    than compared against a mapping this module cannot justify.
    """
    entries: list[ExchangeCardVerdict] = []
    current_card: Card | None = None
    current_card_digest: str | None = None

    for line in ledger_lines:
        card_hit = _card_from_ledger_line(line)
        if card_hit is not None:
            current_card, _capsule_id = card_hit
            current_card_digest = current_card.digest()
            continue

        claims = _exchange_claims(line)
        if claims is None:
            continue  # neither a card nor an exchange -- e.g. an identity/adjudication capsule
        exchange_digest = line.get("capsule_id")

        if current_card is None:
            entries.append(
                ExchangeCardVerdict(
                    exchange_digest=exchange_digest,
                    card_digest=None,
                    status=STATUS_NO_CARD_SEALED,
                )
            )
            continue

        mismatches: list[dict[str, Any]] = []
        model_ref = _find_model(current_card, claims["model_name"])
        if claims["model_name"] is not None and model_ref is None and current_card.models:
            mismatches.append(
                {"field": "model", "exchange": claims["model_name"], "card": [m.name for m in current_card.models]}
            )
        elif model_ref is not None:
            _field(mismatches, "weights_digest", claims["weights_digest"], model_ref.weights_digest)

        _field(mismatches, "measurement_rung", claims["measurement_rung"], current_card.measurement_rung)

        hw = current_card.hardware_inventory
        if hw is not None and claims["hardware_is_soc"] is True:
            _field(mismatches, "hardware_chip_vs_gpu", claims["hardware_gpu"], hw.get("chip"))
            _field(mismatches, "hardware_memory_vs_vram", claims["hardware_vram_bytes"], hw.get("memory_bytes"))

        entries.append(
            ExchangeCardVerdict(
                exchange_digest=exchange_digest,
                card_digest=current_card_digest,
                status=STATUS_BROKEN if mismatches else STATUS_OK,
                mismatches=tuple(mismatches),
            )
        )

    return CardConsistencyResult(entries=tuple(entries))


def check_announcement_consistency(card: Card, observed_digest: str | None) -> dict[str, Any]:
    """Compare a card's `announcement_digest` against a freshly observed one
    (e.g. a live `Advertisement.digest()` recompute, or -- once the host
    wiring in this module's HONEST GAP note lands -- an actual gossiped
    PeerAnnouncement digest). Three states, never a silent pass:

      match               -- both present and equal.
      advertised_mismatch -- both present and NOT equal: the node's live
                              self-announcement changed without a new card.
      absent               -- either side missing; nothing to reconcile.
    """
    if card.announcement_digest is None or observed_digest is None:
        status = ANNOUNCEMENT_ABSENT
    elif card.announcement_digest == observed_digest:
        status = ANNOUNCEMENT_MATCH
    else:
        status = ANNOUNCEMENT_MISMATCH
    return {
        "status": status,
        "card_digest": card.digest(),
        "card_announcement_digest": card.announcement_digest,
        "observed_digest": observed_digest,
    }

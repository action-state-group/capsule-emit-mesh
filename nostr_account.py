# SPDX-License-Identifier: Apache-2.0
"""The Nostr publish path for a node's **account capsule**, plus the
**transparency-courtesy** sealing declaration that ships in the node's listing.

Background. mesh-llm already publishes a signed **mesh-discovery** listing to
public Nostr relays — a parameterized-replaceable event (Kind **31990**, content
a `MeshListing`, signed by the node's Nostr key) so each node has exactly one
live listing that updates in place. This module rides the same rail for the
account layer:

  1. **Account capsule → Nostr event.** We serialize an
     `account_capsule.AccountCapsule` as a Nostr event of Kind
     **``31991``** — one above mesh-llm's discovery listing, in the
     parameterized-replaceable range (30000–39999), with a ``d`` tag so it is
     replaceable *in place*: publishing a newer account for the same node key +
     ``d`` supersedes the old one on the relay.

     **Replaceable ⇒ NO durability claim on the summary.** A relay MAY drop the
     older event the moment a newer one lands, and MAY drop the listing
     entirely. The Nostr event is a *convenience mirror* of the account, not its
     system of record. The **durable layer is the witness**: the account's
     ``coverage`` root is what a reader cross-checks, and that root's durability
     comes from the witness checkpoint, never from the relay. We say this in the
     event content (``durability`` field) so no reader mistakes a replaceable
     listing for a durable attestation.

  2. **Transparency-courtesy sealing declaration.** Mesh nodes SEAL (digest-only,
     zero payload retention — the account/coverage carry hashes, never request
     or response bodies). In a zero-retention culture an *undeclared* seal reads
     as betrayal, so the node DECLARES it, out loud, in the same public listing.
     `transparency_courtesy_tags()` / `merge_into_listing()` add that
     declaration to the node's mesh listing content and as first-class Nostr
     tags, and the Sybil residual rides along verbatim.

CRITICAL — MOCK RELAY ONLY. Building and testing the publish capability is in
scope; firing it at a real public relay (relay.damus.io, …) is a separate,
explicit, gated act and is NOT done here. `publish_account_capsule` takes a
relay *client* argument and the module ships only `MockRelay` (in-process, keeps
what it received). It has NO default public relay URL and opens NO network
socket. A real-relay client is intentionally not provided in this module.

Signing. Nostr uses BIP-340 Schnorr over secp256k1 with x-only pubkeys (NIP-01).
`SchnorrNostrKey` wraps that (via `coincurve` when available). The node's Nostr
key is its discovery identity — the SAME key mesh-llm signs its 31990 listing
with — kept distinct from the Ed25519 ledger/checkpoint key on purpose (they
live on different curves); the account capsule's `node_id`/`coverage` still pin
the ledger identity, so a reader binds the two.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from account_capsule import SYBIL_RESIDUAL_TEXT, AccountCapsule

__all__ = [
    "KIND_MESH_DISCOVERY",
    "KIND_ACCOUNT_CAPSULE",
    "ACCOUNT_D_TAG",
    "SEAL_DECLARATION_TEXT",
    "SchnorrNostrKey",
    "NostrEvent",
    "build_account_event",
    "transparency_courtesy_tags",
    "transparency_courtesy_block",
    "merge_into_listing",
    "RelayClient",
    "MockRelay",
    "publish_account_capsule",
]

#: mesh-llm's existing mesh-discovery listing kind (for reference / adjacency).
KIND_MESH_DISCOVERY = 31990
#: The account-capsule kind — one above discovery, parameterized-replaceable
#: (30000–39999) so it updates in place per (pubkey, d-tag).
#:
#: PROVISIONAL. 31991 is currently UNASSIGNED in the NIPs registry (verified
#: 2026-08-31), but it sits in the NIP-89 handler neighborhood (31989 = handler
#: recommendation, 31990 = handler information — the latter is the discovery
#: listing convention mesh-llm already uses). Because 31991 is adjacent to that
#: convention, this number is PROVISIONAL pending confirmation / coordination
#: with the mesh-llm maintainers (who own the 31990 convention) and, ideally, a
#: NIPs registry entry. Treat it as a NAMED CONSTANT that may change: reference
#: KIND_ACCOUNT_CAPSULE everywhere and never hardcode the literal 31991 elsewhere,
#: so a reassignment is a one-line change here.
KIND_ACCOUNT_CAPSULE = 31991
#: The ``d`` tag value that makes the account replaceable in place. A node keeps
#: exactly one live account listing (same discipline as mesh-llm's ``d=mesh-llm``
#: discovery listing).
ACCOUNT_D_TAG = "mesh-account"

#: The transparency-courtesy sealing declaration, in one place, carried verbatim
#: into the node's listing content and as a Nostr tag.
SEAL_DECLARATION_TEXT = (
    "This node SEALS: it retains digests only, with zero payload retention. "
    "The capsule ledger, checkpoints, and this account carry hashes of requests "
    "and responses, never their bodies. Sealing is declared here on purpose — in "
    "a zero-retention culture an undeclared seal would be a betrayal of that "
    "expectation."
)


# --------------------------------------------------------------------------- #
# Schnorr key (NIP-01 signing identity)                                        #
# --------------------------------------------------------------------------- #
class SchnorrNostrKey:
    """A node's Nostr signing identity: BIP-340 Schnorr over secp256k1, x-only
    pubkey (NIP-01). Backed by `coincurve` when available.

    Construct from a 32-byte secret (`from_secret`) or generate one
    (`generate`). `pubkey_hex` is the 32-byte x-only public key, hex — the
    Nostr ``pubkey`` field. This is the node's DISCOVERY identity (the same key
    that would sign its mesh-llm 31990 listing), distinct from the Ed25519
    ledger key.
    """

    def __init__(self, secret: bytes):
        if len(secret) != 32:
            raise ValueError("Nostr secret key must be exactly 32 bytes")
        try:
            from coincurve import PrivateKey, PublicKeyXOnly
        except ImportError as exc:  # pragma: no cover - env-dependent
            raise RuntimeError(
                "SchnorrNostrKey needs the 'coincurve' package for BIP-340 "
                "Schnorr signing (Nostr / NIP-01). Install coincurve, or pass a "
                "pre-built key object to publish_account_capsule for a pure "
                "mock path."
            ) from exc
        self._priv = PrivateKey(secret)
        self._PublicKeyXOnly = PublicKeyXOnly
        self._secret = secret

    @classmethod
    def from_secret(cls, secret_hex: str) -> "SchnorrNostrKey":
        return cls(bytes.fromhex(secret_hex))

    @classmethod
    def generate(cls) -> "SchnorrNostrKey":
        import os

        return cls(os.urandom(32))

    @property
    def pubkey_hex(self) -> str:
        xo = self._PublicKeyXOnly.from_secret(self._secret)
        return xo.format().hex()

    def sign(self, message32: bytes) -> str:
        """BIP-340 Schnorr signature over a 32-byte message (the NIP-01 event
        id), returned hex."""
        if len(message32) != 32:
            raise ValueError("Nostr signs the 32-byte event id")
        return self._priv.sign_schnorr(message32).hex()

    def verify(self, sig_hex: str, message32: bytes) -> bool:
        xo = self._PublicKeyXOnly.from_secret(self._secret)
        return xo.verify(bytes.fromhex(sig_hex), message32)


# --------------------------------------------------------------------------- #
# NIP-01 event                                                                 #
# --------------------------------------------------------------------------- #
def _nip01_serialize(pubkey: str, created_at: int, kind: int, tags: list[list[str]], content: str) -> bytes:
    """The NIP-01 canonical serialization the event id hashes over:
    ``[0, pubkey, created_at, kind, tags, content]`` as compact UTF-8 JSON with
    no whitespace, exactly as clients/relays compute it."""
    arr = [0, pubkey, created_at, kind, tags, content]
    return json.dumps(arr, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class NostrEvent:
    """A NIP-01 event: id = sha256 of the canonical serialization; sig = the
    node's Schnorr signature over that id."""

    pubkey: str
    created_at: int
    kind: int
    tags: list[list[str]]
    content: str
    id: str = ""
    sig: str = ""

    def compute_id(self) -> str:
        return hashlib.sha256(
            _nip01_serialize(self.pubkey, self.created_at, self.kind, self.tags, self.content)
        ).hexdigest()

    def finalize(self, key: SchnorrNostrKey) -> "NostrEvent":
        """Compute the id and sign it (NIP-01). Verifies the pubkey matches the
        signing key so an event can't claim an identity it can't sign for."""
        if key.pubkey_hex != self.pubkey:
            raise ValueError("event pubkey does not match the signing key")
        self.id = self.compute_id()
        self.sig = key.sign(bytes.fromhex(self.id))
        return self

    def to_value(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": [list(t) for t in self.tags],
            "content": self.content,
            "sig": self.sig,
        }

    @staticmethod
    def verify_value(value: dict[str, Any]) -> bool:
        """Offline verify a received event dict: recompute the id and check the
        Schnorr signature against the claimed x-only pubkey. Pure verification —
        no coincurve PrivateKey needed."""
        try:
            from coincurve import PublicKeyXOnly
        except ImportError:  # pragma: no cover
            return False
        expect_id = hashlib.sha256(
            _nip01_serialize(
                value["pubkey"], value["created_at"], value["kind"],
                [list(t) for t in value["tags"]], value["content"],
            )
        ).hexdigest()
        if expect_id != value.get("id"):
            return False
        xo = PublicKeyXOnly(bytes.fromhex(value["pubkey"]))
        return xo.verify(bytes.fromhex(value["sig"]), bytes.fromhex(expect_id))


def build_account_event(
    account: AccountCapsule,
    key: SchnorrNostrKey,
    *,
    sealed_capsule_id: str | None = None,
    created_at: int | None = None,
) -> NostrEvent:
    """Serialize an account capsule as a signed, parameterized-replaceable
    Nostr event (Kind 31991).

    The event content is the account's canonical value plus an explicit
    ``durability`` disclaimer: the listing is replaceable, so the WITNESS (the
    ``coverage`` root), not the relay, is the durable layer. The ``d`` tag makes
    it replaceable in place; ``k``/``account_digest``/``coverage_root`` tags let
    a reader filter and cross-check without parsing the content.

    ``sealed_capsule_id`` is the ``capsule_id`` of the account capsule as SEALED
    into the node's own ledger (`account_capsule.seal_account_capsule`). Carrying
    it — in the content (``sealed_capsule_id``) and as a ``sealed_capsule_id``
    tag — lets a reader pull the SEALED capsule from the node's ledger and
    cross-check the Nostr copy against the on-the-record capsule. The Nostr event
    mirrors a sealed capsule; it is not the account's system of record (the ledger
    + witness are).
    """
    content_obj = dict(account.to_value())
    content_obj["durability"] = (
        "This is a REPLACEABLE Nostr listing — a relay may drop or supersede it "
        "at any time. No durability is claimed for this summary here. The "
        "durable layer is the WITNESS: cross-check the coverage.checkpoint_root "
        "against the witness, do not rely on this relay copy."
    )
    if sealed_capsule_id is not None:
        content_obj["sealed_capsule_id"] = sealed_capsule_id
        content_obj["sealed_note"] = (
            "This account is SEALED as a capsule in the node's own ledger under "
            "capsule_id=" + sealed_capsule_id + ". Pull that capsule from the "
            "node's capsules.jsonl and cross-check it against this listing; the "
            "ledgered capsule (not this relay copy) is the on-the-record assertion."
        )
    content = json.dumps(content_obj, sort_keys=True, separators=(",", ":"))
    tags = [
        ["d", ACCOUNT_D_TAG],  # parameterized-replaceable key
        ["k", "mesh-account"],
        ["account_digest", account.digest()],
        ["coverage_root", account.coverage_root],
        ["node_id", account.node_id],
        ["witnessed", "1" if account.coverage_witnessed else "0"],
    ]
    if sealed_capsule_id is not None:
        tags.append(["sealed_capsule_id", sealed_capsule_id])
    evt = NostrEvent(
        pubkey=key.pubkey_hex,
        created_at=int(created_at if created_at is not None else time.time()),
        kind=KIND_ACCOUNT_CAPSULE,
        tags=tags,
        content=content,
    )
    return evt.finalize(key)


# --------------------------------------------------------------------------- #
# Transparency-courtesy sealing declaration (rides the mesh listing)           #
# --------------------------------------------------------------------------- #
def transparency_courtesy_tags() -> list[list[str]]:
    """Nostr tags declaring that the node SEALS (digest-only, zero payload
    retention) and carrying the Sybil residual verbatim. Added to the node's
    mesh listing so the declaration is public and machine-readable."""
    return [
        ["seals", "digest-only", "zero-payload-retention"],
        ["transparency", SEAL_DECLARATION_TEXT],
        ["sybil_residual", SYBIL_RESIDUAL_TEXT],
    ]


def transparency_courtesy_block() -> dict[str, Any]:
    """The same declaration as a content block, for embedding in a listing's
    JSON content (mesh-llm's `MeshListing` is a JSON object)."""
    return {
        "seals": True,
        "retention": "digest-only",
        "payload_retention": "zero",
        "transparency_declaration": SEAL_DECLARATION_TEXT,
        "sybil_residual": SYBIL_RESIDUAL_TEXT,
    }


def merge_into_listing(listing: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a node's mesh listing (mesh-llm `MeshListing` shape,
    Kind 31990 content) extended with the transparency-courtesy declaration.
    Non-destructive: existing fields are preserved; the declaration is added
    under ``transparency``. This is what a node calls before it (separately,
    gated) publishes its discovery listing, so the seal is DECLARED with it."""
    out = dict(listing)
    out["transparency"] = transparency_courtesy_block()
    return out


# --------------------------------------------------------------------------- #
# Relay client (MOCK ONLY — never a public relay)                              #
# --------------------------------------------------------------------------- #
class RelayClient(Protocol):
    """The minimal relay surface the publish path needs. Implemented here ONLY
    by `MockRelay`. A real public-relay client is intentionally not shipped in
    this module — publishing to relay.damus.io etc. is a separate gated act."""

    def send_event(self, event: NostrEvent) -> dict[str, Any]:
        ...


@dataclass
class MockRelay:
    """An in-process mock Nostr relay. Verifies each event's id + Schnorr
    signature (rejecting a bad one the way a real relay would), applies
    parameterized-replaceable semantics (a newer event for the same
    pubkey+kind+``d`` supersedes the older, mirroring how a relay drops the
    stale replaceable event), and keeps what it accepted so a test can assert on
    it. Opens no socket, reaches no network."""

    #: url is cosmetic/labelling only — this relay never dials it.
    url: str = "mock://in-process"
    #: accepted[(pubkey, kind, d_tag)] = latest NostrEvent
    accepted: dict[tuple[str, int, str], NostrEvent] = field(default_factory=dict)
    log: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def _d_tag(event: NostrEvent) -> str:
        for t in event.tags:
            if t and t[0] == "d":
                return t[1] if len(t) > 1 else ""
        return ""

    def send_event(self, event: NostrEvent) -> dict[str, Any]:
        # NIP-01 OK message shape: ["OK", <id>, <accepted?>, <message>]
        if not NostrEvent.verify_value(event.to_value()):
            resp = {"ok": False, "id": event.id, "message": "invalid: bad id or signature"}
            self.log.append(resp)
            return resp
        key = (event.pubkey, event.kind, self._d_tag(event))
        replaced = None
        if key in self.accepted:
            prior = self.accepted[key]
            # Replaceable: keep the newer created_at (ties broken by lower id per
            # NIP-16), the older is dropped.
            if (event.created_at, event.id) <= (prior.created_at, prior.id):
                resp = {"ok": False, "id": event.id, "message": "replaced: older than stored replaceable event"}
                self.log.append(resp)
                return resp
            replaced = prior.id
        self.accepted[key] = event
        resp = {"ok": True, "id": event.id, "message": "", "replaced": replaced}
        self.log.append(resp)
        return resp

    def latest_for(self, pubkey: str, kind: int = KIND_ACCOUNT_CAPSULE, d_tag: str = ACCOUNT_D_TAG) -> NostrEvent | None:
        return self.accepted.get((pubkey, kind, d_tag))


def publish_account_capsule(
    account: AccountCapsule,
    key: SchnorrNostrKey,
    relay: RelayClient,
    *,
    sealed_capsule_id: str | None = None,
    created_at: int | None = None,
) -> tuple[NostrEvent, dict[str, Any]]:
    """Build, sign, and publish an account-capsule event to `relay`.

    `relay` MUST be provided by the caller. In this repo the only client shipped
    is `MockRelay`; tests use it exclusively. There is deliberately no default
    relay URL — publishing to a public relay is a separate gated act performed
    outside this module.

    `sealed_capsule_id` carries the ledger `capsule_id` of the SEALED account
    capsule (`account_capsule.seal_account_capsule`) into the published event so
    a reader can cross-check the relay copy against the on-the-record capsule.
    """
    event = build_account_event(account, key, sealed_capsule_id=sealed_capsule_id, created_at=created_at)
    result = relay.send_event(event)
    return event, result

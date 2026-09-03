# SPDX-License-Identifier: Apache-2.0
"""The STAGED, HELD live-publish path for the account-capsule Nostr event.

**Nothing in this repo calls this against a real relay.** Building and
test-relay-verifying the publish capability is in scope for B7; firing it at
a live public relay (relay.damus.io, relay.primal.net, nos.lol, ...) is
Steven's separate, explicit act, gated on his one-line nod after reviewing
the local test-relay transcript and the exact event shape below. No test in
this repo, no CI job, and no other module ever supplies a real relay URL to
this function.

The gate is structural, not a comment: `publish_account_capsule_live` raises
`LivePublishHeld` unless the caller passes BOTH a non-empty, Steven-provided
`relay_urls` list AND `i_have_stevens_go_ahead_for_a_public_relay=True`. There
is no default relay URL anywhere in this module or in `nostr_relay_client`.

What a live publish WOULD emit (for Steven's review before the nod):
  * **kind** — `nostr_account.KIND_ACCOUNT_CAPSULE` (31991, PROVISIONAL —
    see that constant's docstring for the adjacency reasoning and why it may
    be reassigned).
  * **content** — the JSON object `nostr_account.build_account_event` builds:
    the account's `to_value()` (schema/node_id/selection/derivation/coverage/
    sybil_residual/not_a_score) plus `durability` (the replaceable-listing
    disclaimer) and, when sealing, `sealed_capsule_id` + `sealed_note`.
  * **tags** — `[["d", "mesh-account"], ["k", "mesh-account"],
    ["account_digest", ...], ["coverage_root", ...], ["node_id", ...],
    ["witnessed", "0"|"1"]]`, plus `["sealed_capsule_id", ...]` when sealed.
  * **signing key** — the node's Nostr `SchnorrNostrKey` (BIP-340 Schnorr /
    secp256k1, x-only pubkey, NIP-01) — a key kept SEPARATE from the node's
    Ed25519 ledger/checkpoint key on purpose (different curves; the account's
    `node_id`/`coverage` fields bind the two identities for a reader).
`describe_live_publish_plan()` returns this exact shape as data, so a caller
(or a human) can print it without ever needing the gate open.
"""
from __future__ import annotations

from typing import Any

from account_capsule import AccountCapsule
from nostr_account import SchnorrNostrKey, build_account_event
from nostr_relay_client import WebsocketRelayClient

__all__ = [
    "LivePublishHeld",
    "describe_live_publish_plan",
    "publish_account_capsule_live",
]


class LivePublishHeld(RuntimeError):
    """Raised whenever a live publish is attempted without the explicit
    unlock. The code PATH exists (this module), but it structurally refuses
    to run until Steven's nod is recorded by the caller passing both required
    arguments — refusing is the default, not an opt-out."""


def describe_live_publish_plan(
    account: AccountCapsule,
    key: SchnorrNostrKey,
    *,
    sealed_capsule_id: str | None = None,
) -> dict[str, Any]:
    """Build (but never send) the exact event a live publish would emit, plus
    the signing pubkey — for Steven to eyeball before giving the nod. Signs
    the event locally (no network) so the reported `id`/`sig` are real, not
    illustrative."""
    event = build_account_event(account, key, sealed_capsule_id=sealed_capsule_id)
    return {
        "kind": event.kind,
        "kind_is_provisional": True,
        "pubkey": event.pubkey,
        "signing_key": "node Nostr key (SchnorrNostrKey) — separate from the Ed25519 ledger key",
        "tags": [list(t) for t in event.tags],
        "content": event.content,
        "id": event.id,
        "sig": event.sig,
        "would_publish_to": "NOWHERE — this is a dry-run description; no relay_urls were contacted",
    }


def publish_account_capsule_live(
    account: AccountCapsule,
    key: SchnorrNostrKey,
    relay_urls: list[str],
    *,
    sealed_capsule_id: str | None = None,
    i_have_stevens_go_ahead_for_a_public_relay: bool = False,
) -> list[tuple[str, dict[str, Any]]]:
    """Publish the account-capsule event to each URL in `relay_urls` over a
    real `WebsocketRelayClient`.

    HELD by construction: raises `LivePublishHeld` unless
    `i_have_stevens_go_ahead_for_a_public_relay=True` AND `relay_urls` is
    non-empty. This task never sets that flag, never supplies a relay list,
    and never calls this function — it exists so the capability is complete
    and reviewable, not so it can be exercised here.
    """
    if not i_have_stevens_go_ahead_for_a_public_relay:
        raise LivePublishHeld(
            "Live publish to a public relay is HELD pending Steven's explicit "
            "one-line nod on the B7 report (local test-relay transcript + the "
            "exact event shape from describe_live_publish_plan()). Pass "
            "i_have_stevens_go_ahead_for_a_public_relay=True only after that "
            "nod is given."
        )
    if not relay_urls:
        raise LivePublishHeld(
            "relay_urls must be a non-empty list of relay URLs Steven approved "
            "— there is no default relay URL in this module."
        )
    event = build_account_event(account, key, sealed_capsule_id=sealed_capsule_id)
    results = []
    for url in relay_urls:
        client = WebsocketRelayClient(url)
        result = client.send_event(event)
        results.append((url, result))
    return results

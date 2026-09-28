# SPDX-License-Identifier: Apache-2.0
"""Seam A2 -- the "announced key" registry a
record-push receiver checks a claimed sender's signature against.

**What this is, and isn't.** A capsule's own ``key_id``/``signature`` fields
prove "the holder of this key signed this exact capsule_id"
(``capsule_emit.signing.verify_capsule_signature``) -- they do NOT prove who
that key belongs to. This module is the missing half: a small, explicit,
operator-configured map from a mesh peer id to the ``key_id`` that peer is
KNOWN to sign with, so ``record_push.handle_record_push`` can refuse a push
that self-declares one identity (``X-Mesh-Requester-Id``, self-attested, same
discipline as ``evidence_server.py``'s own "relationship gate" note) while
actually signing with a different, unannounced key.

**Config, not discovery.** No peer-key discovery/exchange protocol exists in
this codebase yet -- an operator sets ``ADMISSION_POLICY_PEER_KEYS`` directly
on the node, same "operator sets env vars directly" pattern as
``share_policy.py``/``ADMISSION_POLICY_BLOCKED_MODELS``. The value is a JSON
object mapping peer id to that peer's ``key_id`` (raw Ed25519 public key,
hex) -- e.g. ``{"m3": "3a1f...", "m4": "9c02..."}``. A peer absent from this
map is simply unknown -- ``announced_key_for`` returns ``None``, never a
guess, and the caller must treat that as "cannot verify," never as "trust
it anyway."
"""
from __future__ import annotations

import json
import os

__all__ = ["ENV_PEER_KEYS", "announced_key_for", "peer_id_for_key"]

ENV_PEER_KEYS = "ADMISSION_POLICY_PEER_KEYS"


def announced_key_for(peer_id: str | None) -> str | None:
    """The ``key_id`` this node has been configured to trust for
    ``peer_id``, or ``None`` when ``peer_id`` is falsy, ``ADMISSION_POLICY_
    PEER_KEYS`` is unset, the value is not a JSON object, or ``peer_id``
    simply isn't in it -- every one of those is "cannot verify", never a
    guessed/default key."""
    if not peer_id:
        return None
    raw = os.environ.get(ENV_PEER_KEYS)
    if not raw:
        return None
    try:
        registry = json.loads(raw)
    except Exception:
        return None
    if not isinstance(registry, dict):
        return None
    key_id = registry.get(peer_id)
    return key_id if isinstance(key_id, str) and key_id else None


def peer_id_for_key(key_id: str | None) -> str | None:
    """The one announced peer whose key is ``key_id`` -- e.g. this node's own
    id from its own key. ``None`` when no peer, or more than one, announces
    it: never a guess."""
    if not key_id:
        return None
    try:
        registry = json.loads(os.environ.get(ENV_PEER_KEYS) or "{}")
    except Exception:
        return None
    if not isinstance(registry, dict):
        return None
    names = [peer for peer, key in registry.items() if key == key_id]
    return names[0] if len(names) == 1 else None

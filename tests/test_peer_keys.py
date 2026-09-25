# SPDX-License-Identifier: Apache-2.0
"""Tests for [mesh-closed-wiring-four-gaps] Seam A2's peer-key registry --
``peer_keys.announced_key_for``."""
from __future__ import annotations

import json

from peer_keys import ENV_PEER_KEYS, announced_key_for


def test_returns_the_registered_key_for_a_known_peer(monkeypatch):
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": "ab" * 32, "m4": "cd" * 32}))
    assert announced_key_for("m3") == "ab" * 32
    assert announced_key_for("m4") == "cd" * 32


def test_unknown_peer_returns_none(monkeypatch):
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": "ab" * 32}))
    assert announced_key_for("m4") is None


def test_unset_registry_returns_none_for_any_peer(monkeypatch):
    monkeypatch.delenv(ENV_PEER_KEYS, raising=False)
    assert announced_key_for("m3") is None


def test_empty_or_none_peer_id_returns_none(monkeypatch):
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": "ab" * 32}))
    assert announced_key_for("") is None
    assert announced_key_for(None) is None


def test_malformed_json_registry_returns_none_never_raises(monkeypatch):
    monkeypatch.setenv(ENV_PEER_KEYS, "not json")
    assert announced_key_for("m3") is None


def test_non_object_registry_returns_none_never_raises(monkeypatch):
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps(["m3", "ab" * 32]))
    assert announced_key_for("m3") is None

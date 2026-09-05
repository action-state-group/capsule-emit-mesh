#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-join-card] `capsule_sidecar.seal_join_card` -- the Python
sidecar mirror of the card-sealing path, end to end through REAL signing +
REAL ledger recording (not mocked), then re-read from disk and checked with
`join_card.card_consistency`.

Acceptance shape from the task: start the node -> card #1; load a second
model -> card #2 `supersedes` #1; exchanges before/after each check green
against the right card.

MODULE-POLLUTION / COLLECTION-ORDER GUARD: same hazard
`test_sidecar_disclosure_preimage.py` documents -- some sibling test files
stub `agent_action_capsule`/`model_identity` at collection time, gated on
`name not in sys.modules` at THAT file's own collection. A plain top-level
`import capsule_sidecar` here would freeze in whichever `load_manifest`
happened to be bound at THIS file's collection time (observed: a prior
alphabetically-earlier test file's `load_manifest = lambda p: {}` stub,
which silently made every `state.manifest` empty and broke both the model
list and, transitively, unrelated tests collected after this file). Every
import below is lazy, inside `_capsule_sidecar()`, called only at test-
EXECUTION time, by which point collection is finished.
"""
from __future__ import annotations

import importlib
import json
import pathlib
import sys
import tempfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

_POLLUTABLE_MODULES = [
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]


def _capsule_sidecar():
    """Import (or re-import) capsule_sidecar with the REAL dependency stack,
    undoing any collection-time stubbing a sibling test file left behind."""
    import capsule_sidecar as cs

    for name in _POLLUTABLE_MODULES:
        if name in sys.modules:
            importlib.reload(sys.modules[name])
    importlib.reload(cs)
    return cs


@pytest.fixture
def cs():
    return _capsule_sidecar()


def _make_state(cs, tmp_dir: pathlib.Path, *, model_id: str = "meta/Llama-3.2-3B", **overrides):
    manifest_path = tmp_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": model_id, "source_model": {"sha256": "e" * 64, "canonical_ref": model_id}})
    )
    return cs.default_state(
        ledger_dir=tmp_dir / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_dir / "keys",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        **overrides,
    )


def _ledger_lines(state) -> list[dict]:
    return [json.loads(line) for line in state.ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_seal_join_card_first_start_has_no_supersedes(cs):
    from advertisement import Advertisement

    tmp_dir = pathlib.Path(tempfile.mkdtemp())
    state = _make_state(
        cs, tmp_dir, advertisement=Advertisement(node_id="mesh-node-demo-1", model_id="meta/Llama-3.2-3B")
    )
    cap_id = cs.seal_join_card(state)

    assert cap_id is not None
    lines = _ledger_lines(state)
    assert len(lines) == 1
    card_block = lines[0]["model_attestation"]["compute_attestation"]["x-mesh-join-card-v1"]
    assert card_block["card"]["supersedes"] is None
    assert card_block["card"]["models"] == [{"name": "meta/Llama-3.2-3B", "weights_digest": None}]
    assert card_block["card"]["announcement_digest"] == state.advertisement.digest()


def test_seal_join_card_on_model_change_supersedes_the_first(cs):
    """[mesh-join-card] acceptance: start -> card #1; load a second model ->
    card #2 `supersedes` #1."""
    tmp_dir = pathlib.Path(tempfile.mkdtemp())
    state = _make_state(cs, tmp_dir)
    cap1_id = cs.seal_join_card(state)

    # Simulate loading a second model (this sidecar has no live manifest
    # reload path -- see seal_join_card's docstring -- so the test
    # mutates the loaded manifest directly, the same data a reload would
    # produce).
    state.manifest["model_id"] = "mistralai/Mistral-7B"
    cap2_id = cs.seal_join_card(state)
    assert cap2_id != cap1_id

    lines = _ledger_lines(state)
    assert len(lines) == 2
    card1 = lines[0]["model_attestation"]["compute_attestation"]["x-mesh-join-card-v1"]
    card2 = lines[1]["model_attestation"]["compute_attestation"]["x-mesh-join-card-v1"]
    assert card1["card"]["supersedes"] is None
    assert card2["card"]["supersedes"] == card1["card_digest"]
    assert card2["card"]["models"][0]["name"] == "mistralai/Mistral-7B"


def test_exchanges_before_and_after_a_model_change_check_green_against_the_right_card(cs):
    from join_card import STATUS_OK, card_consistency

    tmp_dir = pathlib.Path(tempfile.mkdtemp())
    state = _make_state(cs, tmp_dir)
    cs.seal_join_card(state)

    exchange1 = cs.build_capsule(
        state,
        client_nonce="n1",
        client_nonce_source="client_supplied",
        request_json={"model": "meta/Llama-3.2-3B"},
        request_digest="a" * 64,
        status="confirmed",
        response_digest="b" * 64,
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
    )
    signed1 = cs.sign_capsule(state, exchange1)
    cs.record_capsule(state, exchange1, signed1)

    state.manifest["model_id"] = "mistralai/Mistral-7B"
    cs.seal_join_card(state)

    exchange2 = cs.build_capsule(
        state,
        client_nonce="n2",
        client_nonce_source="client_supplied",
        request_json={"model": "mistralai/Mistral-7B"},
        request_digest="c" * 64,
        status="confirmed",
        response_digest="d" * 64,
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
    )
    signed2 = cs.sign_capsule(state, exchange2)
    cs.record_capsule(state, exchange2, signed2)

    result = card_consistency(_ledger_lines(state))
    assert result.ok is True
    assert [e.status for e in result.entries] == [STATUS_OK, STATUS_OK]
    # Each exchange checked against the card that was actually current for it,
    # not both against the final (Mistral) card.
    card_digests = {e.card_digest for e in result.entries}
    assert len(card_digests) == 2

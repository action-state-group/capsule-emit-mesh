# SPDX-License-Identifier: Apache-2.0
"""Red-team rung 1, attack 4b: the selective log seen from the requester's half.

REDTEAM-RUNG1.md attack 4 shows that a node which seals only its successes
keeps a perfectly witness-consistent log: rung 1 alone grades it residual.
That row names the closing mechanism (B6a, the requester-held half) but no
harness exercised it. These tests do, with the existing pieces only:

  * capsule_sidecar.py seals the provider's half and the requester's own half
    of each exchange, both carrying the same exchange_id;
  * the provider's selective ledger is checkpointed and witnessed exactly as in
    attack 4, so every integrity check stays green;
  * peer_accountability_tab.pair_cell, the Peers tab's pair column, folds the
    requester's halves against the provider's records.

Outcome recorded in REDTEAM-RUNG1.md row 4b:

  * a hidden exchange whose response carried an id -> the requester's half has
    no provider counterpart and the pair column counts it as missing (caught
    by the requester's half);
  * a hidden exchange whose response carried no id (an error object) -> the
    requester's half records exchange_id "unknown" and cannot be paired, so the
    omission stays invisible (residual, stated rather than assumed away).
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

import capsule_sidecar as cs
import checkpointing
from capsule_emit.checkpoint import CheckpointConfig, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource
from peer_accountability_tab import CELL_PRESENT, pair_cell

# Same module-pollution guard as test_requester_seal_exchange_correlation.py:
# sibling test files stub model_identity at collection time.
_POLLUTABLE_MODULES = ["model_identity"]


def _real_capsule_sidecar():
    for name in _POLLUTABLE_MODULES:
        importlib.reload(sys.modules[name])
    importlib.reload(cs)
    return cs


@pytest.fixture
def fake_witness(monkeypatch):
    """An honest in-process witness, as in test_redteam_rung1.py."""
    calls: list[bytes] = []

    def _fake_register_checkpoint(checkpoint_cose: bytes, ts_url, *, timeout=30.0):
        calls.append(checkpoint_cose)
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-hash-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)
    return calls


def _state(tmp_path: Path, *, role: str, node_id: str) -> "cs.NodeState":
    cs_mod = _real_capsule_sidecar()
    manifest_path = tmp_path / f"manifest-{node_id}.json"
    manifest_path.write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    return cs_mod.default_state(
        ledger_dir=tmp_path / f"ledger-{node_id}",
        manifest_path=manifest_path,
        keys_dir=tmp_path / f"keys-{node_id}",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
        role=role,
        node_id=node_id,
    )


def _seal(state: "cs.NodeState", response_json: dict, *, status: str, request_digest: str) -> dict:
    cs_mod = _real_capsule_sidecar()
    exchange_id, source = cs_mod.exchange_id_from_response(response_json)
    return cs_mod.build_capsule(
        state,
        client_nonce="n" * 32,
        client_nonce_source="client_supplied",
        request_json={"model": "test-model", "messages": [{"role": "user", "content": "hi"}], "temperature": 0.2},
        request_digest=request_digest,
        status=status,
        response_digest=cs_mod.digest_json(response_json),
        verdict_class="executed" if status == "confirmed" else "failed",
        disposition_decision="accept",
        latency_ms=1.0,
        exchange_id=exchange_id,
        exchange_id_source=source,
    )


def _response(i: int, *, ok: bool, with_id: bool = True) -> dict:
    if ok:
        return {"id": f"chatcmpl-{i}", "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}
    body: dict = {"error": {"message": "upstream timeout", "code": 504}}
    if with_id:
        body["id"] = f"chatcmpl-{i}"
    return body


def _run_exchanges(tmp_path: Path, responses: list[tuple[dict, bool]]) -> tuple[list[dict], list[dict], CheckpointState]:
    """Both sides observe every exchange; the provider seals only successes
    into a witnessed ledger. Returns (requester halves, provider records,
    provider checkpoint state)."""
    cs_mod = _real_capsule_sidecar()
    provider = _state(tmp_path, role=cs_mod.ROLE_PROVIDER, node_id="prov-1")
    requester = _state(tmp_path, role=cs_mod.ROLE_REQUESTER, node_id="req-1")

    ledger_dir = tmp_path / "provider-selective"
    ledger_dir.mkdir()
    log = JsonlLogSource(ledger_dir / "capsules.jsonl")
    cp_state = CheckpointState.load(
        ledger_dir=ledger_dir,
        log_source=log,
        cfg=CheckpointConfig(ts_urls=["https://witness.example"]),
        signer=Ed25519Signer(ledger_dir / "node-key.pem"),
        log_id="selective",
    )

    requester_halves: list[dict] = []
    provider_records: list[dict] = []
    for i, (response, ok) in enumerate(responses):
        status = "confirmed" if ok else "failed"
        digest = f"{i:064x}"
        requester_halves.append(_seal(requester, response, status=status, request_digest=digest))
        if ok:  # the selective node never seals a failure
            sealed = _seal(provider, response, status=status, request_digest=digest)
            provider_records.append(sealed)
            log.append(sealed)
    cp_state.reconnect()
    return requester_halves, provider_records, cp_state


def test_attack4b_selective_log_is_caught_by_the_requesters_half(tmp_path, fake_witness):
    """The provider's selective log stays witness-consistent, yet the
    requester's own halves name two exchanges the provider never sealed ->
    CAUGHT by the requester's half (counted as missing in the pair column)."""
    responses = [
        (_response(0, ok=True), True),
        (_response(1, ok=False), False),
        (_response(2, ok=True), True),
        (_response(3, ok=False), False),
    ]
    requester_halves, provider_records, cp_state = _run_exchanges(tmp_path, responses)

    # Rung 1 view of the provider alone: witnessed, root reproduces, clean.
    cp = cp_state.last_checkpoint
    assert cp is not None and cp.witnesses
    assert cp_state.mmr.root_at(cp.mmr_size).hex() == cp.root
    assert cp_state.witness_status().startswith("witnessed up to entry 2")

    # The requester's view: its own halves folded against the provider's.
    cell = pair_cell(requester_halves, requester_halves + provider_records)
    assert cell["verified"] == 2
    assert cell["missing"] == 2
    assert cell["state"] == CELL_PRESENT
    missing = sorted(d["exchange_id"] for d in cell["details"] if d["state"] != "verified")
    assert missing == ["chatcmpl-1", "chatcmpl-3"]


def test_attack4b_an_honest_log_leaves_nothing_missing(tmp_path, fake_witness):
    """Control: with nothing hidden, the same fold reports zero missing, so
    the count above comes from the omission and not from the fold."""
    responses = [(_response(0, ok=True), True), (_response(1, ok=True), True)]
    requester_halves, provider_records, _ = _run_exchanges(tmp_path, responses)
    cell = pair_cell(requester_halves, requester_halves + provider_records)
    assert cell["verified"] == 2
    assert cell["missing"] == 0


def test_attack4b_failure_without_a_response_id_stays_residual(tmp_path, fake_witness):
    """A failure the requester saw only as an id-less error object seals
    exchange_id "unknown", which never pairs. The hidden exchange is then
    invisible to the pair column too -> RESIDUAL for id-less failures."""
    responses = [
        (_response(0, ok=True), True),
        (_response(1, ok=False, with_id=False), False),
    ]
    requester_halves, provider_records, _ = _run_exchanges(tmp_path, responses)
    cell = pair_cell(requester_halves, requester_halves + provider_records)
    assert cell["verified"] == 1
    assert cell["missing"] == 0

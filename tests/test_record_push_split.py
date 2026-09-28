# SPDX-License-Identifier: Apache-2.0
"""A split's stage records, carried to the requester inside the record-push bundle.

The coordinator pushes its main record as a bundle with one more member,
``split_stage_records``: the stage records its receipt names. The door checks
every one before storing anything, holds them beside the main record, and the
requester's hop check then runs offline on what it holds.

The bundle is the Rust plugin's own (committed fixture; regenerate with the
ignored ``writes_the_split_bundle_fixture`` test in
``plugins/admission-policy/src/capsule_emit.rs``).

Mutants that must flip: a tampered carried record, a record carried twice,
an empty or non-list member, or too many records -> ``bundle_malformed``, and
NOTHING is stored (not even the main record).
"""
from __future__ import annotations

import copy
import json
import sys
import types
from pathlib import Path

import pytest

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import evidence_server as es
from mesh_split_stage import CarriedStageRecord, verify_split
from peer_keys import ENV_PEER_KEYS
from record_push import (
    MAX_SPLIT_STAGE_RECORDS,
    RECEIVED_CAPSULES_FILENAME,
    RECEIVED_SPLIT_STAGE_FILENAME,
    SPLIT_STAGE_RECORDS,
    handle_record_push,
)

FIXTURE = Path(__file__).parent / "fixtures" / "split-stage" / "rust-split-bundle.json"


@pytest.fixture
def door(tmp_path, monkeypatch):
    from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

    keys_dir = tmp_path / "keys"
    load_or_create_signing_key(keys_dir)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    state = es.EvidenceServerState(
        ledger_dir=ledger_path.parent, ledger_path=ledger_path, signing_key_path=keys_dir / NODE_KEY_FILENAME
    )
    bundle = json.loads(FIXTURE.read_text())
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"coordinator": bundle["capsule"]["key_id"]}))
    return state, bundle


def _push(state, bundle) -> dict:
    return handle_record_push(state, json.dumps(bundle).encode("utf-8"), sender_peer_id="coordinator")


def _lines(state, name: str) -> list[dict]:
    path = Path(state.ledger_dir) / name
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_the_rust_split_bundle_is_received_and_its_stage_records_held(door):
    state, bundle = door
    result = _push(state, bundle)
    assert result["status"] == "received", result
    held = _lines(state, RECEIVED_SPLIT_STAGE_FILENAME)
    assert [h["capsule"]["capsule_id"] for h in held] == [
        r["capsule_id"] for r in bundle[SPLIT_STAGE_RECORDS]
    ]
    assert all(h["main_capsule_id"] == bundle["capsule"]["capsule_id"] for h in held)


def test_the_requester_checks_the_hand_offs_offline_from_what_it_holds(door):
    state, bundle = door
    _push(state, bundle)
    main = _lines(state, RECEIVED_CAPSULES_FILENAME)[0]
    ca = main["model_attestation"]["compute_attestation"]
    carried = [
        CarriedStageRecord(
            capsule_id=h["capsule"]["capsule_id"],
            block=h["capsule"]["model_attestation"]["compute_attestation"]["x-mesh-stage-v1"],
        )
        for h in _lines(state, RECEIVED_SPLIT_STAGE_FILENAME)
    ]
    verdict = verify_split(ca["x-mesh-stage-v1"], ca["x-mesh-coordinator-receipt-v1"], carried)
    assert verdict["handoffs_agree"] is True
    assert [c["state"] for c in verdict["cells"]] == ["coordinator_slice", "ok", "ok"]


def _tampered(bundle: dict) -> dict:
    out = copy.deepcopy(bundle)
    out[SPLIT_STAGE_RECORDS][0]["model_attestation"]["compute_attestation"]["x-mesh-stage-v1"]["tokens"]["decode"] += 1
    return out


def _duplicated(bundle: dict) -> dict:
    out = copy.deepcopy(bundle)
    out[SPLIT_STAGE_RECORDS].append(copy.deepcopy(out[SPLIT_STAGE_RECORDS][0]))
    return out


def _with_member(value):
    def make(bundle: dict) -> dict:
        out = copy.deepcopy(bundle)
        out[SPLIT_STAGE_RECORDS] = value
        return out
    return make


@pytest.mark.parametrize(
    "mutate",
    [_tampered, _duplicated, _with_member([]), _with_member({})],
    ids=["tampered_record", "record_carried_twice", "empty_list", "not_a_list"],
)
def test_a_bad_carriage_refuses_the_whole_push_and_stores_nothing(door, mutate):
    state, bundle = door
    result = _push(state, mutate(bundle))
    assert result.get("reason") == "bundle_malformed", result
    assert _lines(state, RECEIVED_CAPSULES_FILENAME) == []
    assert _lines(state, RECEIVED_SPLIT_STAGE_FILENAME) == []


def test_more_records_than_the_bound_is_refused(door, monkeypatch):
    import record_push

    state, bundle = door
    assert len(bundle[SPLIT_STAGE_RECORDS]) == 2 <= MAX_SPLIT_STAGE_RECORDS
    monkeypatch.setattr(record_push, "MAX_SPLIT_STAGE_RECORDS", 1)
    assert _push(state, bundle).get("reason") == "bundle_malformed"
    assert _lines(state, RECEIVED_CAPSULES_FILENAME) == []


def test_the_same_main_record_without_the_member_is_an_ordinary_bundle(door):
    state, bundle = door
    plain = {k: v for k, v in bundle.items() if k != SPLIT_STAGE_RECORDS}
    assert _push(state, plain)["status"] == "received"
    assert _lines(state, RECEIVED_SPLIT_STAGE_FILENAME) == []


def test_a_subset_of_the_named_records_is_accepted(door):
    state, bundle = door
    partial = copy.deepcopy(bundle)
    partial[SPLIT_STAGE_RECORDS] = partial[SPLIT_STAGE_RECORDS][:1]
    assert _push(state, partial)["status"] == "received"
    assert len(_lines(state, RECEIVED_SPLIT_STAGE_FILENAME)) == 1

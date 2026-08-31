# SPDX-License-Identifier: Apache-2.0
"""B7 — the reputation account capsule and its Nostr publish path.

Covers:
  * building an account capsule (selection/derivation/coverage) over a THROWAWAY
    witnessed ledger, folding ONLY the checkpoint-covered range;
  * the served/success fold counts;
  * the Sybil-residual + example-predicate-only + not-a-score labeling shipping
    in the capsule;
  * Nostr event serialization + BIP-340 Schnorr signing (NIP-01), the
    parameterized-replaceable Kind 31991 + d-tag, and offline verify;
  * publishing to a MOCK relay only (never a public relay), with replaceable
    supersede semantics and bad-signature rejection;
  * the transparency-courtesy sealing declaration in the listing.

No network: the only relay is the in-process MockRelay; register_checkpoint is
monkeypatched to a local fake to witness the throwaway ledger.
"""
from __future__ import annotations

import json

import pytest

import checkpointing
from capsule_emit.checkpoint import CheckpointConfig, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource

import account_capsule as ac
import nostr_account as na

coincurve = pytest.importorskip("coincurve", reason="Nostr Schnorr signing needs coincurve")


# --------------------------------------------------------------------------- #
# Fixtures: a throwaway, witnessed capsule ledger                              #
# --------------------------------------------------------------------------- #
def _served_capsule(i: int, *, confirmed: bool = True) -> dict:
    return {
        "capsule_id": f"{i:064x}",
        "action_type": "decide",
        "effect": {
            "type": "inference_completion",
            "response_digest": f"resp{i:059x}",
            "status": "confirmed" if confirmed else "rejected",
        },
    }


def _requested_capsule(i: int) -> dict:
    return {
        "capsule_id": f"{i:064x}",
        "action_type": "decide",
        "provenance": {"role": "requester"},
        "effect": {"type": "request", "request_digest": f"req{i:060x}"},
    }


@pytest.fixture
def fake_witness(monkeypatch):
    calls = []

    def _fake_register_checkpoint(checkpoint_cose, ts_url, *, timeout=30.0):
        calls.append((checkpoint_cose, ts_url))
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)
    return calls


def _build_witnessed_ledger(tmp_path, capsules, *, witness=True):
    """Write `capsules` to a throwaway capsules.jsonl, MMR-checkpoint it, and
    (optionally) witness that checkpoint. Returns (capsules_list, latest_cp)."""
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir(parents=True)
    log = JsonlLogSource(ledger_dir / "capsules.jsonl")
    for c in capsules:
        log.append(c)
    ts_urls = ["https://ts.example"] if witness else []
    cfg = CheckpointConfig(cadence_entries=1, ts_urls=ts_urls)
    signer = Ed25519Signer(tmp_path / "node-key.pem")
    state = CheckpointState.load(
        ledger_dir=ledger_dir, log_source=log, cfg=cfg, signer=signer, log_id="log-b7"
    )
    cp = state.reconnect()  # anchor the whole tail in one checkpoint
    on_disk = [json.loads(line) for line in (ledger_dir / "capsules.jsonl").read_text().splitlines() if line.strip()]
    return on_disk, state.last_checkpoint


# --------------------------------------------------------------------------- #
# Account capsule: selection / derivation / coverage                          #
# --------------------------------------------------------------------------- #
def test_account_folds_only_witnessed_range(tmp_path, fake_witness):
    # 3 served (2 confirmed) capsules get witnessed; 2 more appended AFTER.
    witnessed = [
        _served_capsule(1, confirmed=True),
        _served_capsule(2, confirmed=True),
        _served_capsule(3, confirmed=False),
    ]
    on_disk, cp = _build_witnessed_ledger(tmp_path, witnessed)
    assert cp is not None and cp.witnesses  # really witnessed

    # Append un-anchored tail directly to the same ledger list the account sees.
    full_ledger = on_disk + [_served_capsule(4), _requested_capsule(5)]

    account = ac.build_account_capsule(node_id="node-b7", capsules=full_ledger, latest_checkpoint=cp)

    # selection: only the 3 checkpoint-covered entries, NOT the tail.
    assert account.covered_entries == 3
    assert account.selection_from_entry == 1
    assert account.selection_to_entry == 3
    # derivation: fold over the selected 3 only.
    assert account.fold.n_total == 3
    assert account.fold.n_served == 3
    assert account.fold.n_served_confirmed == 2  # entry 3 was not confirmed
    assert account.fold.n_requested == 0
    # coverage: pinned to the witnessed checkpoint root.
    assert account.coverage_root == cp.root
    assert account.coverage_mmr_size == cp.mmr_size
    assert account.coverage_witnessed is True
    assert "https://ts.example" in account.coverage_witnesses


def test_account_mixes_served_and_requested(tmp_path, fake_witness):
    caps = [_served_capsule(1), _requested_capsule(2), _served_capsule(3, confirmed=False)]
    on_disk, cp = _build_witnessed_ledger(tmp_path, caps)
    account = ac.build_account_capsule(node_id="n", capsules=on_disk, latest_checkpoint=cp)
    assert account.fold.n_served == 2
    assert account.fold.n_requested == 1
    assert account.fold.n_served_confirmed == 1


def test_no_checkpoint_yields_honestly_empty_account():
    caps = [_served_capsule(1), _served_capsule(2)]
    account = ac.build_account_capsule(node_id="n", capsules=caps, latest_checkpoint=None)
    assert account.covered_entries == 0
    assert account.fold.n_total == 0
    assert account.coverage_root == ""
    assert account.coverage_witnessed is False


def test_self_checkpointed_coverage_is_not_witnessed(tmp_path):
    caps = [_served_capsule(1), _served_capsule(2)]
    on_disk, cp = _build_witnessed_ledger(tmp_path, caps, witness=False)
    account = ac.build_account_capsule(node_id="n", capsules=on_disk, latest_checkpoint=cp)
    assert account.coverage_root == cp.root  # root still recorded
    assert account.coverage_witnessed is False  # but honestly not witnessed
    assert account.coverage_witnesses == []


def test_covered_clamped_to_entries_on_disk(tmp_path, fake_witness):
    caps = [_served_capsule(1), _served_capsule(2), _served_capsule(3)]
    on_disk, cp = _build_witnessed_ledger(tmp_path, caps)
    # Simulate a ledger shorter than the checkpoint claims (never fold phantoms).
    account = ac.build_account_capsule(node_id="n", capsules=on_disk[:1], latest_checkpoint=cp)
    assert account.covered_entries == 1
    assert account.fold.n_total == 1


# --------------------------------------------------------------------------- #
# Honesty labeling: not-a-score, Sybil residual, example-predicate-only        #
# --------------------------------------------------------------------------- #
def test_sybil_residual_carried_in_capsule(tmp_path, fake_witness):
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1)])
    account = ac.build_account_capsule(node_id="n", capsules=on_disk, latest_checkpoint=cp)
    val = account.to_value()
    assert val["sybil_residual"] == ac.SYBIL_RESIDUAL_TEXT
    assert "only as durable as identity" in val["sybil_residual"]
    assert "free to mint" in val["sybil_residual"]
    # and it survives serialization (round-trips through canonical bytes)
    assert json.loads(account.canonical_bytes())["sybil_residual"] == ac.SYBIL_RESIDUAL_TEXT


def test_account_says_not_a_score(tmp_path, fake_witness):
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1)])
    account = ac.build_account_capsule(node_id="n", capsules=on_disk, latest_checkpoint=cp)
    val = account.to_value()
    assert "not a score" in val["not_a_score"].lower() or "not a score" in val["not_a_score"].replace("_", " ").lower()
    assert "example_predicate" in val["not_a_score"]
    assert "own predicate" in val["derivation"]["note"]


def test_example_predicate_is_example_only_and_conservative(tmp_path, fake_witness):
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1), _served_capsule(2)])
    account = ac.build_account_capsule(node_id="n", capsules=on_disk, latest_checkpoint=cp)
    # witnessed + >=1 confirmed served -> example predicate true
    assert ac.example_predicate(account) is True
    # a non-witnessed account can never pass the example predicate
    on_disk2, cp2 = _build_witnessed_ledger(tmp_path / "b", [_served_capsule(1)], witness=False)
    account2 = ac.build_account_capsule(node_id="n", capsules=on_disk2, latest_checkpoint=cp2)
    assert ac.example_predicate(account2) is False


def test_example_predicate_docstring_states_not_default_policy():
    doc = ac.example_predicate.__doc__ or ""
    assert "EXAMPLE" in doc
    assert "NOT" in doc and "default" in doc and "routing" in doc


# --------------------------------------------------------------------------- #
# Nostr event: serialization, Schnorr signing, replaceable kind                #
# --------------------------------------------------------------------------- #
def _account(tmp_path, witness=True):
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1), _served_capsule(2)], witness=witness)
    return ac.build_account_capsule(node_id="node-b7", capsules=on_disk, latest_checkpoint=cp)


def test_event_is_replaceable_kind_with_d_tag(tmp_path, fake_witness):
    account = _account(tmp_path)
    key = na.SchnorrNostrKey.generate()
    evt = na.build_account_event(account, key)
    assert evt.kind == na.KIND_ACCOUNT_CAPSULE == 31991
    assert na.KIND_ACCOUNT_CAPSULE == na.KIND_MESH_DISCOVERY + 1  # adjacent to mesh-llm's 31990
    assert 30000 <= evt.kind <= 39999  # parameterized-replaceable range
    d_tags = [t for t in evt.tags if t[0] == "d"]
    assert d_tags == [["d", na.ACCOUNT_D_TAG]]


def test_event_id_and_schnorr_signature_verify_offline(tmp_path, fake_witness):
    account = _account(tmp_path)
    key = na.SchnorrNostrKey.generate()
    evt = na.build_account_event(account, key)
    # id is the sha256 over the NIP-01 canonical serialization
    assert evt.id == evt.compute_id()
    assert evt.pubkey == key.pubkey_hex
    # offline verify (recompute id + Schnorr verify against x-only pubkey)
    assert na.NostrEvent.verify_value(evt.to_value()) is True
    # tamper the content -> verify fails
    bad = evt.to_value()
    bad["content"] = bad["content"] + " "
    assert na.NostrEvent.verify_value(bad) is False


def test_event_content_carries_durability_disclaimer_and_coverage(tmp_path, fake_witness):
    account = _account(tmp_path)
    key = na.SchnorrNostrKey.generate()
    evt = na.build_account_event(account, key)
    content = json.loads(evt.content)
    assert "REPLACEABLE" in content["durability"]
    assert "WITNESS" in content["durability"]
    assert content["coverage"]["checkpoint_root"] == account.coverage_root
    assert content["sybil_residual"] == ac.SYBIL_RESIDUAL_TEXT
    # cross-check tags
    tag_map = {t[0]: t[1:] for t in evt.tags}
    assert tag_map["coverage_root"] == [account.coverage_root]
    assert tag_map["account_digest"] == [account.digest()]


def test_pubkey_must_match_signing_key(tmp_path, fake_witness):
    account = _account(tmp_path)
    key = na.SchnorrNostrKey.generate()
    other = na.SchnorrNostrKey.generate()
    evt = na.NostrEvent(pubkey=other.pubkey_hex, created_at=1, kind=31991, tags=[["d", "x"]], content="{}")
    with pytest.raises(ValueError):
        evt.finalize(key)


# --------------------------------------------------------------------------- #
# Mock-relay publish (NEVER a public relay)                                    #
# --------------------------------------------------------------------------- #
def test_publish_to_mock_relay_accepts_and_stores(tmp_path, fake_witness):
    account = _account(tmp_path)
    key = na.SchnorrNostrKey.generate()
    relay = na.MockRelay()
    assert relay.url.startswith("mock://")  # no public relay
    evt, result = na.publish_account_capsule(account, key, relay)
    assert result["ok"] is True
    stored = relay.latest_for(key.pubkey_hex)
    assert stored is not None and stored.id == evt.id


def test_mock_relay_replaceable_supersede(tmp_path, fake_witness):
    account = _account(tmp_path)
    key = na.SchnorrNostrKey.generate()
    relay = na.MockRelay()
    _, r1 = na.publish_account_capsule(account, key, relay, created_at=1000)
    _, r2 = na.publish_account_capsule(account, key, relay, created_at=2000)
    assert r1["ok"] and r2["ok"]
    assert r2["replaced"] == r1["id"]  # newer supersedes older in place
    assert len(relay.accepted) == 1  # exactly one live listing per (pubkey,kind,d)
    # an older event is rejected as replaced
    _, r3 = na.publish_account_capsule(account, key, relay, created_at=500)
    assert r3["ok"] is False and "replaced" in r3["message"]


def test_mock_relay_rejects_bad_signature(tmp_path, fake_witness):
    account = _account(tmp_path)
    key = na.SchnorrNostrKey.generate()
    relay = na.MockRelay()
    evt = na.build_account_event(account, key)
    evt.sig = "00" * 64  # forge
    result = relay.send_event(evt)
    assert result["ok"] is False
    assert "invalid" in result["message"]
    assert relay.latest_for(key.pubkey_hex) is None


def test_module_ships_no_public_relay_client():
    # Only MockRelay is exported; there is no default/public relay URL.
    assert not any("damus" in name.lower() or "relay.io" in name.lower() for name in dir(na))
    assert na.MockRelay().url == "mock://in-process"


# --------------------------------------------------------------------------- #
# Transparency-courtesy sealing declaration                                    #
# --------------------------------------------------------------------------- #
def test_transparency_courtesy_tags_declare_seal_and_sybil():
    tags = na.transparency_courtesy_tags()
    tag0 = {t[0]: t[1:] for t in tags}
    assert "zero-payload-retention" in tag0["seals"]
    assert tag0["sybil_residual"] == [ac.SYBIL_RESIDUAL_TEXT]
    assert "SEALS" in tag0["transparency"][0]


def test_merge_into_listing_adds_transparency_nondestructively():
    listing = {"invite_token": "abc", "serving": ["m1"], "node_count": 1}
    out = na.merge_into_listing(listing)
    assert out["invite_token"] == "abc"  # preserved
    assert out["serving"] == ["m1"]
    block = out["transparency"]
    assert block["seals"] is True
    assert block["payload_retention"] == "zero"
    assert block["sybil_residual"] == ac.SYBIL_RESIDUAL_TEXT
    assert "betrayal" in block["transparency_declaration"]

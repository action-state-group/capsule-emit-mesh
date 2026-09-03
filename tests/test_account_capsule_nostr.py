# SPDX-License-Identifier: Apache-2.0
"""B7 — the account capsule and its Nostr publish path.

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
from agent_action_capsule.verify import verify as verify_capsule

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
    assert evt.kind == na.KIND_ACCOUNT_CAPSULE
    # PROVISIONAL kind: pin it via adjacency to mesh-llm's 31990 discovery listing,
    # not the literal 31991 (which may change — see KIND_ACCOUNT_CAPSULE's comment).
    assert na.KIND_ACCOUNT_CAPSULE == na.KIND_MESH_DISCOVERY + 1
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
    evt = na.NostrEvent(pubkey=other.pubkey_hex, created_at=1, kind=na.KIND_ACCOUNT_CAPSULE, tags=[["d", "x"]], content="{}")
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


# --------------------------------------------------------------------------- #
# Seal closure: the account is SEALED as a capsule into the node's own ledger  #
# --------------------------------------------------------------------------- #
def _seal_into_ledger(ledger_path, account, *, prior_id=None):
    """Seal an account capsule (fyi self-assertion) and APPEND it to a real
    capsules.jsonl, exactly as a node would. Returns the sealed capsule dict."""
    cap = ac.seal_account_capsule(
        account,
        operator="op",
        developer="dev",
        signing_node_id=account.node_id,
        prior_account_capsule_id=prior_id,
    )
    log = JsonlLogSource(ledger_path)
    log.append(cap)
    return cap


def test_account_is_sealed_as_capsule_into_ledger(tmp_path, fake_witness):
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1), _served_capsule(2)])
    account = ac.build_account_capsule(node_id="node-b7", capsules=on_disk, latest_checkpoint=cp)

    cap = ac.seal_account_capsule(
        account, operator="op", developer="dev", signing_node_id="node-b7"
    )
    # It is a real capsule: fyi self-assertion, real capsule_id, passes verify().
    assert cap["action_type"] == "fyi"
    assert isinstance(cap["capsule_id"], str) and len(cap["capsule_id"]) == 64
    assert verify_capsule(cap).ok
    # The account fold + coverage rides verbatim as the subject.
    subj = cap["model_attestation"]["compute_attestation"][ac.ACCOUNT_SUBJECT_KEY]
    assert subj["account"] == account.to_value()
    assert subj["account_digest"] == account.digest()
    assert subj["sybil_residual"] == ac.SYBIL_RESIDUAL_TEXT
    assert "no self-reference" in subj["coverage_ordering"].lower()


def test_sealed_account_lands_in_capsules_jsonl_like_any_capsule(tmp_path, fake_witness):
    # Build a real witnessed ledger, then seal the account back INTO that same
    # capsules.jsonl — it must land as one more line, indistinguishable in shape
    # from any other capsule (real capsule_id, verifiable).
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir()
    ledger_path = ledger_dir / "capsules.jsonl"
    log = JsonlLogSource(ledger_path)
    for c in [_served_capsule(1), _served_capsule(2)]:
        log.append(c)
    on_disk = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]

    cfg = CheckpointConfig(cadence_entries=1, ts_urls=["https://ts.example"])
    signer = Ed25519Signer(tmp_path / "node-key.pem")
    state = CheckpointState.load(ledger_dir=ledger_dir, log_source=log, cfg=cfg, signer=signer, log_id="log-seal")
    state.reconnect()
    cp = state.last_checkpoint

    account = ac.build_account_capsule(node_id="node-b7", capsules=on_disk, latest_checkpoint=cp)
    cap = _seal_into_ledger(ledger_path, account)

    lines = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 3  # the two exchanges + the sealed account capsule
    last = lines[-1]
    assert last["capsule_id"] == cap["capsule_id"]
    assert last["action_type"] == "fyi"
    assert verify_capsule(last).ok
    # Honest ordering: the account's coverage is the checkpoint BEFORE this seal;
    # the seal is only covered by the NEXT checkpoint (no self-reference).
    assert account.coverage_mmr_size == cp.mmr_size
    assert last["model_attestation"]["compute_attestation"][ac.ACCOUNT_SUBJECT_KEY]["account"]["coverage"]["mmr_size"] == cp.mmr_size


def test_second_account_supersedes_first_both_in_log(tmp_path, fake_witness):
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1), _served_capsule(2)])
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"

    account1 = ac.build_account_capsule(node_id="node-b7", capsules=on_disk, latest_checkpoint=cp)
    cap1 = _seal_into_ledger(ledger_path, account1)

    # A later account (e.g. after more history) supersedes the first, citing it.
    account2 = ac.build_account_capsule(node_id="node-b7", capsules=on_disk, latest_checkpoint=cp)
    cap2 = _seal_into_ledger(ledger_path, account2, prior_id=cap1["capsule_id"])

    # BOTH remain in the append-only log.
    lines = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]
    ids = [l["capsule_id"] for l in lines]
    assert cap1["capsule_id"] in ids and cap2["capsule_id"] in ids
    # The later cites the earlier with the supersedes relation.
    assert cap1.get("chain") is None  # first account has no prior
    assert cap2["chain"]["parent_capsule_id"] == cap1["capsule_id"]
    assert cap2["chain"]["relation"] == ac.ACCOUNT_SUPERSEDES_RELATION == "supersedes"
    assert verify_capsule(cap2).ok


def test_nostr_event_carries_sealed_capsule_id(tmp_path, fake_witness):
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1), _served_capsule(2)])
    account = ac.build_account_capsule(node_id="node-b7", capsules=on_disk, latest_checkpoint=cp)
    cap = ac.seal_account_capsule(account, operator="op", developer="dev", signing_node_id="node-b7")

    key = na.SchnorrNostrKey.generate()
    evt = na.build_account_event(account, key, sealed_capsule_id=cap["capsule_id"])
    # The sealed capsule_id flows into both the content and a first-class tag so a
    # reader can pull the ledgered capsule and cross-check it.
    content = json.loads(evt.content)
    assert content["sealed_capsule_id"] == cap["capsule_id"]
    assert cap["capsule_id"] in content["sealed_note"]
    tag_map = {t[0]: t[1:] for t in evt.tags}
    assert tag_map["sealed_capsule_id"] == [cap["capsule_id"]]
    assert na.NostrEvent.verify_value(evt.to_value()) is True


def test_publish_carries_sealed_capsule_id_to_mock_relay(tmp_path, fake_witness):
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1)])
    account = ac.build_account_capsule(node_id="node-b7", capsules=on_disk, latest_checkpoint=cp)
    cap = ac.seal_account_capsule(account, operator="op", developer="dev", signing_node_id="node-b7")

    key = na.SchnorrNostrKey.generate()
    relay = na.MockRelay()
    evt, result = na.publish_account_capsule(account, key, relay, sealed_capsule_id=cap["capsule_id"])
    assert result["ok"] is True
    stored = relay.latest_for(key.pubkey_hex)
    assert stored is not None
    assert {t[0]: t[1:] for t in stored.tags}["sealed_capsule_id"] == [cap["capsule_id"]]


# --------------------------------------------------------------------------- #
# PR#65 ruling guardrails — account not score, no reputation naming,           #
# a grade never propagates into the account                                   #
# --------------------------------------------------------------------------- #
def test_account_carries_no_rating_or_score_field(tmp_path, fake_witness):
    """Steven's PR#65 ruling: this is an ACCOUNT of facts/properties, never a
    reputation score. Lock the top-level and nested shapes so no
    score/rating/grade field can be added without this test failing."""
    on_disk, cp = _build_witnessed_ledger(tmp_path, [_served_capsule(1), _served_capsule(2)])
    account = ac.build_account_capsule(node_id="n", capsules=on_disk, latest_checkpoint=cp)
    val = account.to_value()
    forbidden = ("score", "rating", "grade", "rank", "reputation_score", "trust_score")
    #: `not_a_score` is the ruling's own explicit negation key, not a score field.
    exempt_keys = {"not_a_score"}

    def _walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                lowered = k.lower()
                if k not in exempt_keys:
                    assert not any(f in lowered for f in forbidden), f"forbidden field name: {k}"
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(val)


def test_nostr_event_content_carries_no_rating_or_score_field(tmp_path, fake_witness):
    account = _account(tmp_path)
    key = na.SchnorrNostrKey.generate()
    evt = na.build_account_event(account, key)
    content = json.loads(evt.content)
    forbidden = ("score", "rating", "grade", "rank", "reputation_score", "trust_score")
    #: `not_a_score` is the ruling's own explicit negation key, not a score field.
    exempt_keys = {"not_a_score"}

    def _walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                lowered = k.lower()
                if k not in exempt_keys:
                    assert not any(f in lowered for f in forbidden), f"forbidden field name: {k}"
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(content)


def test_definition_never_reads_a_per_capsule_grade_field():
    """The fold's DEFINITION document names exactly the fields it reads
    (definition-as-data). A per-capsule evidentiary label like
    `cross_party_rung` / `full_bilateral` (mesh_record_verifier.py's
    mutuality grade) MUST NOT appear among them — a grade on an individual
    claim never propagates into the account that summarizes many claims."""
    reads = ac.MESH_ACCOUNT_DEFINITION.reads
    for field_name in reads:
        lowered = field_name.lower()
        assert "grade" not in lowered
        assert "rung" not in lowered
        assert "bilateral" not in lowered


def test_a_per_capsule_grade_field_does_not_change_the_fold(tmp_path, fake_witness):
    """End-to-end mutant: attach a `cross_party_rung`/`grade` label to source
    capsules (as mesh_record_verifier.derive_cross_party_rung would) and
    confirm the account's fold — and therefore the account itself — is
    byte-identical whether or not that label is present. A grade on a claim
    must never leak into, or be summarized by, the account."""
    plain = [_served_capsule(1), _served_capsule(2, confirmed=False)]
    graded = [dict(c, cross_party_rung="full_bilateral", grade="full_bilateral") for c in plain]

    on_disk_plain, cp_plain = _build_witnessed_ledger(tmp_path / "plain", plain)
    on_disk_graded, cp_graded = _build_witnessed_ledger(tmp_path / "graded", graded)

    account_plain = ac.build_account_capsule(node_id="n", capsules=on_disk_plain, latest_checkpoint=cp_plain)
    account_graded = ac.build_account_capsule(node_id="n", capsules=on_disk_graded, latest_checkpoint=cp_graded)

    assert account_plain.fold.to_value() == account_graded.fold.to_value()
    assert "grade" not in json.dumps(account_graded.to_value())
    assert "cross_party_rung" not in json.dumps(account_graded.to_value())


def test_no_reputation_naming_in_account_module_docstrings():
    """PR#65 ruling: drop any 'reputation' NAMING for this artifact (it is an
    account of facts, not a reputation score). The general Sybil-residual
    sentence ('Reputation is only as durable as identity...', shared verbatim
    with node_ownership.py and docs/TRUST-MODEL.md) is explanatory prose, not
    a name for this artifact, and is exempted."""
    for doc in (ac.__doc__, na.__doc__):
        assert "reputation account" not in (doc or "").lower()
        assert "reputation layer" not in (doc or "").lower()

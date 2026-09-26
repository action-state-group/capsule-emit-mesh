#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The acceptance test the CLOSED row
turns on: when a foreign sibling with a matching ``request_digest`` and valid
push provenance is present, the accountability pane GROUPS it with this node's
own half (through the ONE correlator, NOT its host-minted exchange_id) AND the
correlated pair satisfies the CLOSED gate's predicate -- while a
provenance-less / self-sealed sibling does NOT close even when its
request_digest matches (correlation feeds the gate, it never bypasses it).

WHAT THIS COVERS, AND THE BOUNDARY
----------------------------------
The CLOSED-state DECISION itself lives in the host pane's
``exchange-row-state.ts`` (``deriveRightCellState``): closed iff
``signatureOk === true && digestsCiteOurHalf(...)`` -- the bytes+signature+
digests-equal predicate this task must NOT touch. That predicate is verified in
the Rust/TS pane. What the PYTHON side owns -- and what this test proves -- is
the two prerequisites that gate reads:

  1. CORRELATION: the pushed foreign half (a DIFFERENT host-minted exchange_id,
     the SAME request_digest) lands in the SAME pane row / peer pair as this
     node's own half, via ``capsule_exchange_tab.exchange_correlator``. Before
     this task the pane keyed on exchange_id and split them into two OPEN rows
     that could never reconcile.
  2. THE PREDICATE-INPUTS ARE SATISFIED: for that correlated pair,
     ``digest_match_grade`` is VERIFIED (both request_digest AND response_digest
     cite our half -- exactly ``digestsCiteOurHalf``), and the foreign half
     carries real push provenance (received_from/via/received_at, signature_ok)
     -- the ONLY fact the gate trusts to treat a locally-held capsule as a
     verified counterparty half.

  3. THE PROVENANCE RULE HOLDS: a sibling with a matching request_digest but NO
     push provenance (self-sealed, never received through the door) gets no
     received-provenance record -- so the gate has nothing to close on. The
     real door (``record_push.handle_record_push``) is exercised to prove the
     provenance is granted only after signature verification, never fabricated.
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import evidence_server as es  # noqa: E402
from capsule_emit.signing import verify_capsule_signature  # noqa: E402
from capsule_exchange_tab import (  # noqa: E402
    STATE_VERIFIED,
    build_exchange_list_payload,
    digest_match_grade,
    exchange_correlator,
    group_exchanges,
)
from peer_accountability_tab import CELL_VERIFIED, pair_cell  # noqa: E402
from peer_keys import ENV_PEER_KEYS  # noqa: E402
from record_push import (  # noqa: E402
    RECEIVED_PROVENANCE_FILENAME,
    handle_record_push,
)

# The one request the two halves of this exchange BOTH observed at the wire and
# sealed identically -- the correlator that survives cross-node.
SHARED_REQUEST_DIGEST = "d" * 64
SHARED_RESPONSE_DIGEST = "e" * 64


def _mesh_half(*, capsule_id: str, role: str, exchange_id: str, served_by: str, requesting_party: str) -> dict:
    """A sidecar-shaped mesh half (serving_provenance + effect digests) --
    same shape ``test_capsule_exchange_tab``/``test_peer_accountability_tab``
    use for the pane machinery. Both halves of one exchange carry the SAME
    request/response digests but their OWN host-minted exchange_id."""
    poc = {
        "role": role,
        "serving_provenance": {
            "model": {"canonical_ref": "meta-llama/Llama-3.2-3B-Instruct", "architecture": "llama"},
            "hardware": {"gpu": "Apple M4 Max", "is_soc": True},
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "exchange_id": exchange_id,  # host-minted -- DIFFERENT per node
            "served_by_node_id": served_by,
            "requesting_party": requesting_party,
        },
        "evidence_refs": {"binary_attestation": None, "tee_attestation": None},
    }
    return {
        "spec_version": "draft-mih-scitt-agent-action-capsule-02",
        "format_version": "2",
        "capsule_id": capsule_id,
        "operator": "op",
        "timestamp": "2026-09-25T00:00:0" + ("0" if role == "requested" else "1") + "Z",
        "model_attestation": {
            "model_id": "meta-llama/Llama-3.2-3B-Instruct",
            "compute_attestation": {"x-mesh-poc-v1": poc},
        },
        "effect": {
            "request_digest": SHARED_REQUEST_DIGEST,
            "response_digest": SHARED_RESPONSE_DIGEST,
            "effect_attestation": "gate_executed",
        },
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }


def _local_and_foreign_halves() -> tuple[dict, dict]:
    """This node (m4) asked; the peer (m3) served. The two halves share the
    request/response digests but each carries its OWN host-minted exchange_id
    (the cross-node reality that broke exchange_id grouping)."""
    local = _mesh_half(
        capsule_id="a" * 64, role="requested", exchange_id="m4-exch-914b61c1", served_by="m3", requesting_party="m4"
    )
    foreign = _mesh_half(
        capsule_id="b" * 64, role="served", exchange_id="m3-exch-82777e20", served_by="m3", requesting_party="m4"
    )
    return local, foreign


# ---------------------------------------------------------------------------
# 1 + 2: the pane FIRES -- the pushed sibling correlates and the pair's
# digest_match is VERIFIED (the CLOSED gate's digestsCiteOurHalf input).
# ---------------------------------------------------------------------------


def test_pane_c_groups_the_pushed_sibling_into_one_reconciled_row():
    """Pane C: the foreign served half (different exchange_id, same
    request_digest) lands in the SAME row as this node's own asked half -- ONE
    row, both columns filled -- and its digest_match reconciles VERIFIED."""
    local, foreign = _local_and_foreign_halves()

    # Sanity: the two halves would NEVER group by their host-minted exchange_ids
    # (that was the bug); the ONE correlator groups them by request_digest.
    assert local["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"]["exchange_id"] != \
        foreign["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"]["exchange_id"]
    assert exchange_correlator(local) == exchange_correlator(foreign) == f"digest:{SHARED_REQUEST_DIGEST}"

    payload = build_exchange_list_payload([local], counterparty_records=[foreign])

    assert payload["row_count"] == 1  # ONE row, not two OPEN halves
    row = payload["rows"][0]
    assert row["mine"]["capsule_id"] == local["capsule_id"]
    assert row["theirs"]["capsule_id"] == foreign["capsule_id"]  # the pushed sibling filled the theirs column
    assert not row["unilateral"]
    # digestsCiteOurHalf: both request_digest AND response_digest agree.
    assert row["view"]["pair"]["digest_match"]["state"] == STATE_VERIFIED


def test_peers_pane_pair_cell_reconciles_the_pushed_sibling():
    """Peers pane (the third, previously-missed grouping site): pair_cell folds
    the pushed sibling into the SAME exchange and reports 1 reconciled, 0
    missing -- via the ONE correlator, not exchange_id."""
    local, foreign = _local_and_foreign_halves()
    all_records = [local, foreign]

    cell = pair_cell([local], all_records)

    assert cell["state"] == CELL_VERIFIED
    assert cell["verified"] == 1
    assert cell["missing"] == 0
    assert cell["failed"] == 0


def test_digest_match_is_the_unchanged_closed_predicate_input():
    """The pair's digest_match -- the exact digestsCiteOurHalf fact the CLOSED
    gate reads -- is VERIFIED for the correlated pair, and a single mutated
    digest flips it away from VERIFIED (the gate predicate is untouched: bytes
    still have to be equal)."""
    local, foreign = _local_and_foreign_halves()
    assert digest_match_grade(local, foreign)["state"] == STATE_VERIFIED

    tampered = copy.deepcopy(foreign)
    tampered["effect"]["response_digest"] = "f" * 64  # one byte off -> not closeable
    assert digest_match_grade(local, tampered)["state"] != STATE_VERIFIED


# ---------------------------------------------------------------------------
# 3: the provenance rule -- correlation feeds the gate, never bypasses it.
# The real door grants provenance ONLY after signature verification.
# ---------------------------------------------------------------------------


def _keys(tmp_path):
    from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

    keys_dir = tmp_path / "keys"
    load_or_create_signing_key(keys_dir)
    return keys_dir / NODE_KEY_FILENAME


def _signed_foreign_half(key_path) -> dict:
    """A REAL peer-signed served half (carries key_id + a verifying signature),
    minted through capsule_emit's own seal() -- the shape a real push carries."""
    import tempfile

    from capsule_emit import seal

    scratch = tempfile.mktemp(suffix="-pane-sibling-scratch.jsonl")
    capsule = seal(None, action="serve-half", operator="peer-org", anchor=False, ledger=scratch, signing_key_path=key_path).capsule
    return capsule


def _provenance_lines(ledger_dir) -> list[dict]:
    path = pathlib.Path(ledger_dir) / RECEIVED_PROVENANCE_FILENAME
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_pushed_sibling_gets_provenance_only_after_signature_verifies(tmp_path, monkeypatch):
    """The real door: a signature-verifying push from an announced peer is
    received AND granted the provenance triple the CLOSED gate requires. This
    is the provenance half of 'the pane fires on a pushed sibling'."""
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    ledger_path.write_bytes(b"")
    capsule = _signed_foreign_half(key_path)
    state = es.EvidenceServerState(
        ledger_dir=ledger_path.parent, ledger_path=ledger_path, signing_key_path=key_path, share_policy=None
    )
    assert verify_capsule_signature(capsule) is True
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": capsule["key_id"]}))

    result = handle_record_push(state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy, sender_peer_id="m3")

    assert result == {"status": "received"}
    prov = _provenance_lines(ledger_path.parent)
    assert len(prov) == 1
    assert prov[0]["capsule_id"] == capsule["capsule_id"]
    assert prov[0]["received_from"] == "m3"
    assert prov[0]["via"] == "push"
    assert prov[0]["received_at"]  # a real timestamp
    assert prov[0]["signature_ok"] is True


def test_provenance_less_sibling_grants_no_provenance_so_the_gate_cannot_close(tmp_path, monkeypatch):
    """A self-sealed sibling that never went through the door -- or whose
    identity does not verify -- earns NO received-provenance, so even a
    perfectly matching request_digest cannot make the CLOSED gate close: the
    gate reads received-provenance, and there is none. Correlation feeds the
    gate; it does not bypass it."""
    key_path = _keys(tmp_path)
    ledger_path = tmp_path / "ledger" / "capsules.jsonl"
    ledger_path.parent.mkdir(parents=True)
    ledger_path.write_bytes(b"")
    capsule = _signed_foreign_half(key_path)
    state = es.EvidenceServerState(
        ledger_dir=ledger_path.parent, ledger_path=ledger_path, signing_key_path=key_path, share_policy=None
    )
    # Push claims to be "m3" but m3 is announced with a DIFFERENT key -> identity
    # does not verify -> refused, NEVER a sibling, NEVER a provenance record.
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({"m3": "de" * 32}))

    result = handle_record_push(state, json.dumps(capsule).encode("utf-8"), policy=state.share_policy, sender_peer_id="m3")

    assert result.get("status") != "received"  # a signed Refusal, not a receipt
    assert "reason" in result  # refused, with an honest reason
    assert _provenance_lines(ledger_path.parent) == []  # nothing for the gate to close on
    assert ledger_path.read_bytes() == b""  # never folded in as a sibling either

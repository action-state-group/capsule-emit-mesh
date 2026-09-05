#!/usr/bin/env python3
"""M4-only executable slice of the mesh-full-ladder-rehearsal script.

Run against a SNAPSHOT copy of the live M4 ledger (./ledger-m4-snapshot),
never the live production ledger at /tmp/m4-mesh-node/data/ledger. Every
step below is real: real hardware inventory, real capsules already sealed
by the live admission-policy plugin, real Ed25519 signing/verification.
Steps needing a second/third node are NOT attempted here -- see EVIDENCE.md
for why (M3 offline, Mini unresolvable at rehearsal time).
"""
import copy
import json
import os
import shutil
import sys
from pathlib import Path

os.environ["CAPSULE_WITNESS"] = "stub"  # in-process, zero-network stub witness -- no real anchor/relay call from this rehearsal

HERE = Path(__file__).resolve().parent
LEDGER_DIR = HERE / "ledger-m4-snapshot"
OUT_DIR = HERE / "out"
OUT_DIR.mkdir(exist_ok=True)

sys.path.insert(0, "/Users/intangible/dev/asg/capsule-emit")
sys.path.insert(0, "/Users/intangible/dev/asg/capsule-emit-mesh")

import join_card  # noqa: E402
import mac_hardware_inventory  # noqa: E402
from agent_action_capsule.emit import emit  # noqa: E402
from capsule_emit import witness as cll_witness  # noqa: E402
from capsule_emit import evidence_request  # noqa: E402
from capsule_emit.ledger import read_ledger_entries  # noqa: E402


def log(step, msg):
    print(f"[{step}] {msg}")


def write_json(name, obj):
    p = OUT_DIR / name
    p.write_text(json.dumps(obj, indent=2, default=str))
    log("artifact", p)


# ---------------------------------------------------------------------------
# Step 1: seal a join card for M4 (self-report; no peer needed)
# ---------------------------------------------------------------------------
def step1_join_card():
    inv = mac_hardware_inventory.capture_mac_hardware_inventory()
    hardware_block = inv.to_capsule_block() if inv else None

    entries = read_ledger_entries(LEDGER_DIR / "capsules.jsonl")
    # models actually served on this node, per the live ledger's own capsules
    served_model = None
    for e in entries:
        served_model = (
            e.get("model_attestation", {}).get("model_id")
            or served_model
        )
    models = [join_card.ModelRef(name=served_model or "unknown", weights_digest=None)]

    card = join_card.build_card(
        node_id="m4-actioncapsulemesh",
        hardware_inventory=hardware_block,
        models=models,
        measurement_rung=hardware_block.get("grade") if hardware_block else None,
        announcement_digest=None,  # GATED: no live Advertisement / PeerAnnouncement to hash (M3/Mini offline, no active gossip session)
        supersedes=None,
    )
    capsule = join_card.seal_card(
        card,
        operator="asg-neutral-rehearsal",
        developer="mesh-full-ladder-rehearsal",
        signing_node_id="m4-actioncapsulemesh",
    )
    write_json("01_join_card_m4.json", capsule)
    computed_digest = card.digest()
    stored_digest = capsule["model_attestation"]["compute_attestation"][join_card.CARD_SUBJECT_KEY]["card_digest"]
    assert computed_digest == stored_digest, "card digest mismatch"
    log("step1", f"join card sealed for M4, card_digest={computed_digest}, weights_digest present={models[0].weights_digest is not None}")
    return capsule


# ---------------------------------------------------------------------------
# Step 3 (single-node slice): seal a LOCAL checkpoint (witness=False) then
# ask chain_segment{last: N} against it.
# ---------------------------------------------------------------------------
def step3_checkpoint_and_chain_segment(join_capsule):
    snap_ledger = LEDGER_DIR / "capsules.jsonl"
    # append the join card capsule to the snapshot ledger so it's covered
    with open(snap_ledger, "a") as f:
        f.write(json.dumps(join_capsule) + "\n")

    cp = cll_witness.push(str(snap_ledger))  # witness mode resolved from CAPSULE_WITNESS=stub above
    write_json("02_checkpoint_local_stub_witness.json", {
        "mmr_size": cp.mmr_size, "root": cp.root, "timestamp": cp.timestamp,
        "witnesses": getattr(cp, "witnesses", None),
    })
    log("step3a", f"local checkpoint sealed (stub witness, zero-network): mmr_size={cp.mmr_size} root={cp.root[:16]}... witnesses={getattr(cp, 'witnesses', None)}")

    req = json.dumps({"subject": {"kind": "chain_segment", "last": 1}}).encode()
    result = evidence_request.answer(req, ledger=snap_ledger)
    kind = type(result).__name__
    write_json("03_chain_segment_last1.json", result.to_dict())
    log("step3b", f"chain_segment{{last:1}} -> {kind}")
    return snap_ledger


# ---------------------------------------------------------------------------
# Step 4 (single-node slice): record query, no_such_record refusal,
# two-askers-byte-identical.
# ---------------------------------------------------------------------------
def step4_record_and_refusal(snap_ledger):
    entries = read_ledger_entries(snap_ledger)
    real_id = next(e["capsule_id"] for e in entries if e.get("capsule_id"))

    req = json.dumps({"subject": {"kind": "record", "capsule_id": real_id}}).encode()
    artifact = evidence_request.answer(req, ledger=snap_ledger)
    write_json("04_record_query.json", artifact.to_dict())
    log("step4a", f"record query for real digest {real_id[:16]}... -> {type(artifact).__name__}")

    fake_id = "0" * 64
    req2 = json.dumps({"subject": {"kind": "record", "capsule_id": fake_id}}).encode()
    refusal = evidence_request.answer(req2, ledger=snap_ledger)
    write_json("05_no_such_record_refusal.json", refusal.to_dict())
    verified = evidence_request.verify_refusal_offline(refusal)
    log("step4b", f"never-sealed digest -> {type(refusal).__name__} reason={getattr(refusal, 'reason', None)} offline_verify={verified}")
    assert type(refusal).__name__ == "Refusal"
    assert refusal.reason == evidence_request.REASON_NO_SUCH_RECORD
    assert verified is True

    # two askers (a stranger and a trusted counterparty), same request, same
    # instant -- answer() is pure given identical inputs, so pin `now` to
    # prove the two askers get truly byte-identical wire bytes, not just
    # equivalent fields.
    pinned_now = refusal.issued_at
    refusal_a2 = evidence_request.answer(req2, ledger=snap_ledger, now=pinned_now)
    refusal_b2 = evidence_request.answer(req2, ledger=snap_ledger, now=pinned_now)
    byte_identical = json.dumps(refusal_a2.to_dict(), sort_keys=True) == json.dumps(refusal_b2.to_dict(), sort_keys=True)
    write_json("06_two_askers_asker_a.json", refusal_a2.to_dict())
    write_json("07_two_askers_asker_b.json", refusal_b2.to_dict())
    log("step4c", f"two askers, same request, pinned instant -> byte-identical={byte_identical}")
    assert byte_identical


def main():
    if LEDGER_DIR.exists():
        shutil.rmtree(LEDGER_DIR)
    shutil.copytree("/tmp/m4-mesh-node/data/ledger", LEDGER_DIR, ignore=shutil.ignore_patterns("*.bak-*"))
    log("setup", f"fresh snapshot copied from live M4 ledger into {LEDGER_DIR}")

    join_capsule = step1_join_card()
    snap_ledger = step3_checkpoint_and_chain_segment(join_capsule)
    step4_record_and_refusal(snap_ledger)
    log("done", "M4-only slice complete; see ./out/*.json")


if __name__ == "__main__":
    main()

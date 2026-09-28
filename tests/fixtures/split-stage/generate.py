#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the shared split-stage fixtures.

    python3 tests/fixtures/split-stage/generate.py

Writes `fold-vectors.json`, `block-cases.json`, `receipt-cases.json` and
`hop-cases.json` next to this file. The Rust producer
(`plugins/capsule-producer/tests/split_stage_fixtures.rs`) and the Python
reference (`tests/test_mesh_split_stage.py`) both read them.

Every EXPECTED verdict below is written by hand from the design
(docs/DESIGN-split-stage-records.md §4.2, §7.2), never computed by either
implementation. The folds themselves are computed here with the reference
`fold_frames`, and the Rust side re-derives them from `fold-vectors.json`.
All values are synthetic.
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from typing import TypedDict  # noqa: E402

from mesh_split_stage import (  # noqa: E402
    Cell,
    LaneFold,
    LaneVerdict,
    SplitReceipt,
    SplitVerdict,
    StageBlock,
    StageDoc,
    fold_frames,
)

LaneFrames = dict[tuple[int, str], list[bytes]]


class Carried(TypedDict):
    capsule_id: str
    block: StageBlock


class Scenario(TypedDict):
    lane_frames: LaneFrames
    own: StageBlock
    receipt: SplitReceipt
    carried: list[Carried]


class FoldVector(TypedDict):
    name: str
    coordinator_node_id: str
    run_id: str
    request_id: str
    hop_index: int
    lane: str
    frames_hex: list[str]
    expect: LaneFold


class HopCase(TypedDict):
    name: str
    note: str
    own: StageBlock
    receipt: SplitReceipt
    carried: list[Carried]
    expect: SplitVerdict

COORD = "node-coordinator-c"
RUN = "mesh-split-1790000000000000000-g2"
REQ = "18446744073709551615"
PKG = "sha256:" + "ab" * 32
MANIFEST = "cd" * 32
SOURCE = "ef" * 32
TOPO = "topology-hash-0001"
NODES = ["node-coordinator-c", "node-b", "node-d", "node-e"]


def frames(tag: str, count: int) -> list[bytes]:
    return [f"{tag}-frame-{i}".encode() for i in range(count)]


def fold(fs: list[bytes], hop: int, lane: str) -> LaneFold:
    return fold_frames(fs, coordinator_node_id=COORD, run_id=RUN,
                       request_id=int(REQ), hop_index=hop, lane=lane)


def layers(k: int) -> tuple[int, int]:
    return 16 * k, 16 * (k + 1)


def lane_frames(n: int, mode: str) -> LaneFrames:
    """Synthetic frames for every lane of a split of `n` stages."""
    out: LaneFrames = {}
    for h in range(n - 1):
        out[(h, "forward")] = frames(f"fwd-h{h}", 4)
        out[(h, "reply")] = frames(f"rep-h{h}", 3) if mode == "relayed" else []
    if mode == "direct":
        out[(n - 1, "direct_return")] = frames("direct", 2)
    return out


def base_block(k: int, n: int, side: str, mode: str, terminal: str) -> StageBlock:
    start, end = layers(k)
    return {
        "v": 1, "side": side, "coordinator_node_id": COORD, "run_id": RUN,
        "request_id": REQ, "topology_hash": TOPO, "stage_index": k,
        "stage_count": n, "layer_start": start, "layer_end": end,
        "package_id": PKG, "manifest_sha256": MANIFEST,
        "source_model_sha256": SOURCE, "return_mode": mode,
        "direct_return": None, "terminal_state": terminal,
    }


def own_slice(n: int, mode: str, terminal: str, lf: LaneFrames) -> StageBlock:
    block = base_block(0, n, "coordinator", mode, terminal)
    block["downstream"] = {"sent": fold(lf[(0, "forward")], 0, "forward"),
                           "replies_received": fold(lf[(0, "reply")], 0, "reply")}
    if mode == "direct":
        block["direct_return"] = {"received": fold(lf[(n - 1, "direct_return")], n - 1, "direct_return")}
    block["tokens"] = {"prefill_received": 12, "decode": 4}
    return block


def stage_block(k: int, n: int, mode: str, terminal: str, lf: LaneFrames) -> StageBlock:
    block = base_block(k, n, "stage", mode, terminal)
    block["upstream"] = {"received": fold(lf[(k - 1, "forward")], k - 1, "forward"),
                         "replies_sent": fold(lf[(k - 1, "reply")], k - 1, "reply")}
    if k + 1 < n:
        block["downstream"] = {"sent": fold(lf[(k, "forward")], k, "forward"),
                               "replies_received": fold(lf[(k, "reply")], k, "reply")}
    if mode == "direct" and k + 1 == n:
        block["direct_return"] = {"sent": fold(lf[(n - 1, "direct_return")], n - 1, "direct_return")}
    block["tokens"] = {"prefill_received": 12, "decode": 4}
    return block


def record_id(k: int, variant: str = "") -> str:
    return format(k, "02x") * 31 + ("ff" if variant else "00")


def receipt(n: int, bundles: dict[int, str] | None = None) -> SplitReceipt:
    bundles = bundles or {}
    topology, stages = [], []
    for k in range(n):
        start, end = layers(k)
        topology.append({
            "seq": k, "hop_id": f"stage-{k}", "role": "coordinator" if k == 0 else "stage",
            "observation_point": None,
            "assignment": {"node_id": NODES[k], "layer_start": start, "layer_end": end, "package_id": PKG},
        })
        state = "not_requested" if k == 0 else bundles.get(k, "present")
        entry: StageDoc = {"hop_id": f"stage-{k}", "bundle": state}
        if state == "present":
            entry["bundle_ref"] = {"type": "capsule", "digest_alg": "SHA-256", "digest": record_id(k)}
        stages.append(entry)
    return {"v": 1, "kind": "mesh-coordinator-receipt", "run_id": RUN, "topology": topology,
            "stages": stages, "coordinator_node_id": COORD, "request_id": REQ,
            "stage_seal_deadline_ms": 2000}


def scenario(n: int = 3, mode: str = "relayed", terminal: str = "completed") -> Scenario:
    lf = lane_frames(n, mode)
    return {
        "lane_frames": lf,
        "own": own_slice(n, mode, terminal, lf),
        "receipt": receipt(n),
        "carried": [{"capsule_id": record_id(k), "block": stage_block(k, n, mode, terminal, lf)}
                    for k in range(1, n)],
    }


def lanes(
    n: int, mode: str, states: dict[tuple[int, str], str] | None = None, terminal: str = "completed"
) -> list[LaneVerdict]:
    """Expected lane list; every lane `agree` unless overridden in `states`."""
    states = states or {}
    completed = terminal == "completed"
    out: list[LaneVerdict] = []
    for h in range(n - 1):
        out.append({"hop_index": h, "lane": "forward", "required": True,
                    "state": states.get((h, "forward"), "agree")})
        reply_required = mode == "relayed" and completed
        default = "agree" if mode == "relayed" else "not_applicable"
        out.append({"hop_index": h, "lane": "reply", "required": reply_required,
                    "state": states.get((h, "reply"), default)})
    if mode == "direct":
        out.append({"hop_index": n - 1, "lane": "direct_return", "required": completed,
                    "state": states.get((n - 1, "direct_return"), "agree")})
    return out


def cells(n: int, overrides: dict[int, str] | None = None) -> list[Cell]:
    overrides = overrides or {}
    return [{"stage_index": 0, "state": "coordinator_slice"}] + [
        {"stage_index": k, "state": overrides.get(k, "ok")} for k in range(1, n)
    ]


def case(
    name: str, s: Scenario, *, cells_: list[Cell], lanes_: list[LaneVerdict], agree: bool,
    terminal: str = "completed", note: str = "",
) -> HopCase:
    return {
        "name": name, "note": note,
        "own": s["own"], "receipt": s["receipt"], "carried": s["carried"],
        "expect": {"cells": cells_, "lanes": lanes_, "handoffs_agree": agree, "terminal_state": terminal},
    }


def carried_block(s: Scenario, k: int) -> StageBlock:
    return next(c["block"] for c in s["carried"] if c["block"]["stage_index"] == k)


def hop_cases() -> list[HopCase]:
    out: list[HopCase] = []

    s = scenario(3, "relayed")
    out.append(case("relayed_all_agree", s, cells_=cells(3), lanes_=lanes(3, "relayed"), agree=True))

    s = scenario(3, "direct")
    out.append(case("direct_all_agree", s, cells_=cells(3), lanes_=lanes(3, "direct"), agree=True,
                    note="replies go straight to stage 0, so hop-by-hop reply lanes are empty and not needed"))

    s = scenario(2, "direct")
    out.append(case("two_stage_direct", s, cells_=cells(2), lanes_=lanes(2, "direct"), agree=True))

    s = scenario(3, "relayed")
    altered = list(s["lane_frames"][(1, "forward")])
    altered[2] = altered[2][:-1] + b"X"
    carried_block(s, 2)["upstream"]["received"] = fold(altered, 1, "forward")
    out.append(case("one_byte_changed", s, cells_=cells(3),
                    lanes_=lanes(3, "relayed", {(1, "forward"): "break"}), agree=False,
                    note="one byte of one frame differs between stage 1's sent and stage 2's received"))

    s = scenario(3, "relayed")
    swapped = list(s["lane_frames"][(1, "forward")])
    swapped[0], swapped[1] = swapped[1], swapped[0]
    carried_block(s, 1)["downstream"]["sent"] = fold(swapped, 1, "forward")
    out.append(case("swapped_frames", s, cells_=cells(3),
                    lanes_=lanes(3, "relayed", {(1, "forward"): "break"}), agree=False))

    s = scenario(3, "relayed")
    s["receipt"]["stages"][2] = {"hop_id": "stage-2", "bundle": "absent"}
    s["carried"] = [c for c in s["carried"] if c["block"]["stage_index"] != 2]
    out.append(case("missing_end_absent", s, cells_=cells(3, {2: "not_received"}),
                    lanes_=lanes(3, "relayed", {(1, "forward"): "gap", (1, "reply"): "gap"}), agree=False,
                    note="a missing end is a gap, never agreement"))

    s = scenario(3, "relayed")
    s["carried"] = [c for c in s["carried"] if c["block"]["stage_index"] != 1]
    out.append(case("cited_not_carried", s, cells_=cells(3, {1: "not_received"}),
                    lanes_=lanes(3, "relayed", {(0, "forward"): "gap", (0, "reply"): "gap",
                                                (1, "forward"): "gap", (1, "reply"): "gap"}),
                    agree=False))

    s = scenario(3, "relayed")
    s["own"]["downstream"]["replies_received"] = fold([], 0, "reply")
    carried_block(s, 1)["upstream"]["replies_sent"] = fold([], 0, "reply")
    out.append(case("required_lane_empty_both_ends", s, cells_=cells(3),
                    lanes_=lanes(3, "relayed", {(0, "reply"): "gap"}), agree=False,
                    note="a lane empty on both ends has nothing to compare"))

    s = scenario(3, "relayed")
    carried_block(s, 1)["upstream"]["received"] = fold(s["lane_frames"][(0, "forward")], 1, "forward")
    out.append(case("replayed_at_other_hop_index", s, cells_=cells(3),
                    lanes_=lanes(3, "relayed", {(0, "forward"): "break"}), agree=False,
                    note="the same frames folded for hop 1 do not stand for hop 0"))

    s = scenario(3, "relayed")
    carried_block(s, 2)["upstream"]["received"]["frames"] += 1
    out.append(case("equal_digest_unequal_count", s, cells_=cells(3),
                    lanes_=lanes(3, "relayed", {(1, "forward"): "malformed"}), agree=False))

    s = scenario(3, "relayed")
    carried_block(s, 2)["direct_return"] = {"sent": fold(frames("direct", 2), 2, "direct_return")}
    out.append(case("relayed_with_direct_return_rejected", s, cells_=cells(3, {2: "rejected"}),
                    lanes_=lanes(3, "relayed", {(1, "forward"): "gap", (1, "reply"): "gap"}), agree=False))

    s = scenario(3, "relayed")
    twin = copy.deepcopy(carried_block(s, 2))
    twin["tokens"]["decode"] = 5
    s["carried"].append({"capsule_id": record_id(2, "twin"), "block": twin})
    out.append(case("two_records_one_key", s, cells_=cells(3, {2: "conflict"}),
                    lanes_=lanes(3, "relayed", {(1, "forward"): "gap", (1, "reply"): "gap"}), agree=False,
                    note="neither record counts as present, and no hop involving stage 2 agrees"))

    s = scenario(3, "relayed")
    s["receipt"]["stages"][2] = {"hop_id": "stage-2", "bundle": "conflict", "bundle_refs": [
        {"type": "capsule", "digest_alg": "SHA-256", "digest": record_id(2)},
        {"type": "capsule", "digest_alg": "SHA-256", "digest": record_id(2, "twin")},
    ]}
    out.append(case("receipt_says_conflict", s, cells_=cells(3, {2: "conflict"}),
                    lanes_=lanes(3, "relayed", {(1, "forward"): "gap", (1, "reply"): "gap"}), agree=False))

    s = scenario(3, "relayed")
    carried_block(s, 2)["layer_start"] = 30
    out.append(case("assignment_disagrees", s, cells_=cells(3, {2: "disagrees"}),
                    lanes_=lanes(3, "relayed"), agree=True,
                    note="the hand-offs still agree; the stage cell shows the mismatch"))

    s = scenario(3, "relayed")
    s["receipt"]["stages"][1] = {"hop_id": "stage-1", "bundle": "not_requested"}
    out.append(case("not_requested_stage", s, cells_=cells(3, {1: "not_requested"}),
                    lanes_=lanes(3, "relayed", {(0, "forward"): "gap", (0, "reply"): "gap",
                                                (1, "forward"): "gap", (1, "reply"): "gap"}),
                    agree=False))

    s = scenario(3, "relayed", "timed_out")
    for k, block in [(0, s["own"])] + [(c["block"]["stage_index"], c["block"]) for c in s["carried"]]:
        if block.get("downstream"):
            block["downstream"]["replies_received"] = fold([], k, "reply")
        if block.get("upstream"):
            block["upstream"]["replies_sent"] = fold([], k - 1, "reply")
    out.append(case("stopped_early_agrees_on_truncated_stream", s, cells_=cells(3),
                    lanes_=lanes(3, "relayed", {(0, "reply"): "not_applicable", (1, "reply"): "not_applicable"},
                                 terminal="timed_out"),
                    agree=True, terminal="timed_out",
                    note="agreement is not completion: terminal_state is shown beside the line"))
    return out


# block_cases / receipt_cases build DELIBERATELY malformed documents (a
# number where a string belongs, a member the schema forbids, a missing
# required member), so they are plain JSON dicts, not the TypedDicts above.
def block_cases() -> list[dict]:
    s = scenario(3, "direct")
    own, b1, b2 = s["own"], carried_block(s, 1), carried_block(s, 2)
    lf = s["lane_frames"]

    def exchange(k: int, observed: dict | None) -> dict:
        block = base_block(k, 3, "coordinator", "direct", "completed")
        block["coordinator_term"] = 7
        block["data_path_observed"] = observed is not None
        if observed is not None:
            block["coordinator_observed"] = observed
        return block

    ex1 = exchange(1, {"downstream": copy.deepcopy(own["downstream"])})
    ex2 = exchange(2, {"direct_return": {"received": fold(lf[(2, "direct_return")], 2, "direct_return")}})

    def mutated(block: dict, **changes) -> dict:
        out = copy.deepcopy(block)
        for key, value in changes.items():
            if value is ...:
                out.pop(key, None)
            else:
                out[key] = value
        return out

    relayed_final = stage_block(2, 3, "relayed", "completed", lane_frames(3, "relayed"))
    return [
        {"name": "own_slice", "block": own, "valid": True},
        {"name": "middle_stage", "block": b1, "valid": True},
        {"name": "final_stage_direct", "block": b2, "valid": True},
        {"name": "exchange_stage_1_observed", "block": ex1, "valid": True},
        {"name": "exchange_final_direct_observed", "block": ex2, "valid": True},
        {"name": "exchange_middle_unobserved",
         "block": base_block(1, 4, "coordinator", "relayed", "completed") | {"coordinator_term": 7, "data_path_observed": False} | {"stage_index": 2},
         "valid": True},
        {"name": "stage_side_at_index_0", "block": mutated(b1, stage_index=0), "valid": False},
        {"name": "final_stage_with_downstream", "block": mutated(b2, downstream=b1["downstream"]), "valid": False},
        {"name": "middle_stage_without_downstream", "block": mutated(b1, downstream=...), "valid": False},
        {"name": "stage_without_upstream", "block": mutated(b1, upstream=...), "valid": False},
        {"name": "relayed_with_direct_return", "block": mutated(relayed_final, direct_return=b2["direct_return"]), "valid": False},
        {"name": "direct_final_without_direct_return", "block": mutated(b2, direct_return=None), "valid": False},
        {"name": "own_slice_direct_sent_not_received", "block": mutated(own, direct_return=b2["direct_return"]), "valid": False},
        {"name": "request_id_leading_zero", "block": mutated(b1, request_id="007"), "valid": False},
        {"name": "request_id_as_number", "block": mutated(b1, request_id=7), "valid": False},
        {"name": "request_id_above_u64", "block": mutated(b1, request_id="18446744073709551616"), "valid": False},
        {"name": "layer_end_not_after_start", "block": mutated(b1, layer_end=16), "valid": False},
        {"name": "unknown_terminal_state", "block": mutated(b1, terminal_state="finished"), "valid": False},
        {"name": "package_id_unprefixed", "block": mutated(b1, package_id="ab" * 32), "valid": False},
        {"name": "unknown_member", "block": mutated(b1, session_id="42"), "valid": False},
        {"name": "stage_record_with_exchange_fields", "block": mutated(b1, data_path_observed=True), "valid": False},
        {"name": "exchange_with_tokens", "block": mutated(ex1, tokens=b1["tokens"]), "valid": False},
        {"name": "exchange_stage_1_flag_false_but_observed", "block": mutated(ex1, stage_index=1, stage_count=4, return_mode="relayed", data_path_observed=False), "valid": False},
        {"name": "exchange_stage_1_unobserved", "block": mutated(ex1, data_path_observed=False, coordinator_observed=...), "valid": False},
        {"name": "exchange_without_term", "block": mutated(ex1, coordinator_term=...), "valid": False},
        {"name": "single_stage_split", "block": mutated(own, stage_count=1), "valid": False},
    ]


def receipt_cases() -> list[dict]:
    good = receipt(3)

    def with_stage(k: int, entry: dict) -> dict:
        out = copy.deepcopy(good)
        out["stages"][k] = entry
        return out

    ref = lambda d: {"type": "capsule", "digest_alg": "SHA-256", "digest": d}  # noqa: E731
    no_assignment = copy.deepcopy(good)
    del no_assignment["topology"][1]["assignment"]
    wrong_coordinator = copy.deepcopy(good)
    wrong_coordinator["topology"][0]["assignment"]["node_id"] = "node-b"
    reordered = copy.deepcopy(good)
    reordered["topology"][1], reordered["topology"][2] = reordered["topology"][2], reordered["topology"][1]
    return [
        {"name": "all_present", "receipt": good, "valid": True},
        {"name": "absent_and_not_requested", "receipt": with_stage(2, {"hop_id": "stage-2", "bundle": "absent"}), "valid": True},
        {"name": "conflict_two_refs", "receipt": with_stage(2, {"hop_id": "stage-2", "bundle": "conflict",
                                                                 "bundle_refs": [ref("e1" * 32), ref("e2" * 32)]}), "valid": True},
        {"name": "present_without_ref", "receipt": with_stage(1, {"hop_id": "stage-1", "bundle": "present"}), "valid": False},
        {"name": "absent_with_ref", "receipt": with_stage(1, {"hop_id": "stage-1", "bundle": "absent", "bundle_ref": ref("e1" * 32)}), "valid": False},
        {"name": "not_requested_with_ref", "receipt": with_stage(1, {"hop_id": "stage-1", "bundle": "not_requested", "bundle_ref": ref("e1" * 32)}), "valid": False},
        {"name": "one_record_cited_under_two_hops", "receipt": with_stage(2, {"hop_id": "stage-2", "bundle": "present", "bundle_ref": ref(record_id(1))}), "valid": False},
        {"name": "conflict_one_ref", "receipt": with_stage(2, {"hop_id": "stage-2", "bundle": "conflict", "bundle_refs": [ref("e1" * 32)]}), "valid": False},
        {"name": "conflict_repeated_ref", "receipt": with_stage(2, {"hop_id": "stage-2", "bundle": "conflict", "bundle_refs": [ref("e1" * 32), ref("e1" * 32)]}), "valid": False},
        {"name": "stage_0_present", "receipt": with_stage(0, {"hop_id": "stage-0", "bundle": "present", "bundle_ref": ref("e1" * 32)}), "valid": False},
        {"name": "unknown_bundle_state", "receipt": with_stage(1, {"hop_id": "stage-1", "bundle": "late"}), "valid": False},
        {"name": "missing_assignment", "receipt": no_assignment, "valid": False},
        {"name": "stage_0_not_the_coordinator", "receipt": wrong_coordinator, "valid": False},
        {"name": "topology_out_of_order", "receipt": reordered, "valid": False},
        {"name": "ref_digest_uppercase", "receipt": with_stage(1, {"hop_id": "stage-1", "bundle": "present", "bundle_ref": ref("E1" * 32)}), "valid": False},
    ]


def fold_vectors() -> list[FoldVector]:
    specs = [
        ("empty_forward", [], 0, "forward"),
        ("one_frame_reply", [b"\x00\x01\x02"], 1, "reply"),
        ("three_frames_forward", frames("v", 3), 0, "forward"),
        ("direct_return_lane", frames("d", 2), 2, "direct_return"),
    ]
    return [
        {"name": name, "coordinator_node_id": COORD, "run_id": RUN, "request_id": REQ,
         "hop_index": hop, "lane": lane, "frames_hex": [f.hex() for f in fs],
         "expect": fold(fs, hop, lane)}
        for name, fs, hop, lane in specs
    ]


def main() -> None:
    outputs = {
        "fold-vectors.json": fold_vectors(),
        "block-cases.json": block_cases(),
        "receipt-cases.json": receipt_cases(),
        "hop-cases.json": hop_cases(),
    }
    for name, data in outputs.items():
        (HERE / name).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
        print(f"wrote {name}: {len(data)} cases")


if __name__ == "__main__":
    main()

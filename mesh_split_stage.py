#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Split-inference stage records: the offline reference.

The Rust producer (`plugins/capsule-producer/src/stage.rs`,
`stage_verify.rs`) is the live implementation; this module is the reference
it is checked against (docs/DESIGN-split-stage-records.md, decision Q-D6).
Both run over the shared fixtures in `tests/fixtures/split-stage/`:

- `fold-vectors.json` -- the hop frame fold (§4.2), byte for byte;
- `hop-cases.json` -- the requester's hop check (§7.2): stage cells, per-lane
  hand-off states, and whether the run's hand-offs agree;
- `receipt-cases.json` -- the coordinator receipt's producer rules.

What `agree` means is narrow on purpose: both ends of one hop committed to
the same frames on one lane. Never that the stages are independent, or that
either computed its slice correctly (§0, §9).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any, TypedDict

from mesh_coordinator_receipt_emitter import BundleRef, StageAssignment, StageEntry, TopologyEntry
from mesh_record_verifier import TERMINAL_STATES

FRAME_FOLD_DOMAIN = b"skippy-stage-frames/v1"
LANES = ("forward", "reply", "direct_return")
RECEIPT_KIND = "mesh-coordinator-receipt"

_HEX = frozenset("0123456789abcdef")


class LaneFold(TypedDict):
    frames: int
    digest: str


class UpstreamHop(TypedDict):
    received: LaneFold
    replies_sent: LaneFold


class DownstreamHop(TypedDict):
    sent: LaneFold
    replies_received: LaneFold


class DirectReturn(TypedDict, total=False):
    sent: LaneFold
    received: LaneFold


class StageTokens(TypedDict):
    prefill_received: int
    decode: int


class CoordinatorObserved(TypedDict, total=False):
    downstream: DownstreamHop
    direct_return: DirectReturn


class StageBlock(TypedDict, total=False):
    """An `x-mesh-stage-v1` block. Which members are present depends on the
    block's position (§4.1); `validate_block` enforces it."""

    v: int
    side: str
    coordinator_node_id: str
    run_id: str
    request_id: str
    topology_hash: str
    stage_index: int
    stage_count: int
    layer_start: int
    layer_end: int
    package_id: str
    manifest_sha256: str
    source_model_sha256: str
    return_mode: str
    upstream: UpstreamHop
    downstream: DownstreamHop
    direct_return: DirectReturn | None
    tokens: StageTokens
    terminal_state: str
    coordinator_term: int
    data_path_observed: bool
    coordinator_observed: CoordinatorObserved


class TopologyDoc(TypedDict):
    seq: int
    hop_id: str
    role: str
    observation_point: str | None
    assignment: StageAssignment


class StageDoc(TypedDict, total=False):
    hop_id: str
    bundle: str
    bundle_ref: BundleRef
    bundle_refs: list[BundleRef]


class SplitReceipt(TypedDict):
    """An `x-mesh-coordinator-receipt-v1` block of a split request."""

    v: int
    kind: str
    run_id: str
    topology: list[TopologyDoc]
    stages: list[StageDoc]
    coordinator_node_id: str
    request_id: str
    stage_seal_deadline_ms: int


class Cell(TypedDict):
    stage_index: int
    state: str


class LaneVerdict(TypedDict):
    hop_index: int
    lane: str
    required: bool
    state: str


class SplitVerdict(TypedDict):
    cells: list[Cell]
    lanes: list[LaneVerdict]
    handoffs_agree: bool
    terminal_state: str


class StageBlockError(ValueError):
    """An `x-mesh-stage-v1` block that breaks the §4.1/§5 rules."""


class ReceiptError(ValueError):
    """An `x-mesh-coordinator-receipt-v1` block that breaks a producer rule."""


# ---------------------------------------------------------------------------
# The hop frame fold
# ---------------------------------------------------------------------------

def _lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def fold_frames(
    frames: list[bytes],
    *,
    coordinator_node_id: str,
    run_id: str,
    request_id: int,
    hop_index: int,
    lane: str,
    salt: bytes = b"",
) -> LaneFold:
    """h_0 over the lane's identity, then h_i = SHA-256(h_{i-1} || SHA-256(frame_i)).

    Every variable-length field is length-prefixed (u32 big-endian), so no
    two field sequences share a preimage. `hop_index` is the upstream
    stage's index for the forward and reply lanes, and the final stage's
    index for the direct return lane. The salt is empty in v0.
    """
    if lane not in LANES:
        raise ValueError(f"lane {lane!r} not in {LANES}")
    state = hashlib.sha256(
        FRAME_FOLD_DOMAIN
        + _lp(salt)
        + _lp(coordinator_node_id.encode())
        + _lp(run_id.encode())
        + struct.pack(">Q", request_id)
        + struct.pack(">I", hop_index)
        + _lp(lane.encode())
    ).digest()
    for frame in frames:
        state = hashlib.sha256(state + hashlib.sha256(frame).digest()).digest()
    return {"frames": len(frames), "digest": "sha256:" + state.hex()}


# ---------------------------------------------------------------------------
# Block rules
# ---------------------------------------------------------------------------

_BLOCK_FIELDS = {
    "v", "side", "coordinator_node_id", "run_id", "request_id", "topology_hash",
    "stage_index", "stage_count", "layer_start", "layer_end", "package_id",
    "manifest_sha256", "source_model_sha256", "return_mode", "upstream",
    "downstream", "direct_return", "tokens", "terminal_state",
    "coordinator_term", "data_path_observed", "coordinator_observed",
}
_REQUIRED_FIELDS = {
    "v", "side", "coordinator_node_id", "run_id", "request_id", "topology_hash",
    "stage_index", "stage_count", "layer_start", "layer_end", "package_id",
    "manifest_sha256", "source_model_sha256", "return_mode", "terminal_state",
}
_EXCHANGE_ONLY = ("coordinator_term", "data_path_observed", "coordinator_observed")


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and not set(value) - _HEX


def _prefixed(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _hex(value[7:], 64)


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def canonical_request_id(raw: Any) -> bool:
    return (
        isinstance(raw, str)
        and raw.isascii()
        and raw.isdigit()
        and (raw == "0" or not raw.startswith("0"))
        and int(raw) < 2**64
    )


def _fold(name: str, fold: Any) -> None:
    if not isinstance(fold, dict) or set(fold) != {"frames", "digest"}:
        raise StageBlockError(f"{name} must be exactly {{frames, digest}}")
    if not _count(fold["frames"]) or not _prefixed(fold["digest"]):
        raise StageBlockError(f"{name} must be a frame count and a sha256: digest")


def _pair(name: str, hop: Any, keys: tuple[str, str]) -> None:
    if not isinstance(hop, dict) or set(hop) != set(keys):
        raise StageBlockError(f"{name} must be exactly {set(keys)}")
    for key in keys:
        _fold(f"{name}.{key}", hop[key])


def _direct(name: str, direct: Any, want: str | None) -> None:
    if want is None:
        if direct is not None:
            raise StageBlockError(f"{name} must be null at this position")
        return
    if direct is None:
        raise StageBlockError(f"{name} is required at this position")
    if not isinstance(direct, dict) or set(direct) != {want}:
        raise StageBlockError(f"{name} must carry {want} only")
    _fold(f"{name}.{want}", direct[want])


def validate_block(block: Any) -> None:
    """Raise StageBlockError unless `block` is a valid x-mesh-stage-v1 block."""
    if not isinstance(block, dict):
        raise StageBlockError("block must be an object")
    unknown = set(block) - _BLOCK_FIELDS
    missing = _REQUIRED_FIELDS - set(block)
    if unknown or missing:
        raise StageBlockError(f"unknown={sorted(unknown)} missing={sorted(missing)}")
    if block["v"] != 1:
        raise StageBlockError("v must be 1")
    for name in ("coordinator_node_id", "run_id", "topology_hash"):
        if not isinstance(block[name], str) or not block[name]:
            raise StageBlockError(f"{name} must be non-empty")
    if not canonical_request_id(block["request_id"]):
        raise StageBlockError("request_id must be a canonical decimal u64 string")
    for name in ("stage_index", "stage_count", "layer_start", "layer_end"):
        if not _count(block[name]):
            raise StageBlockError(f"{name} must be a non-negative integer")
    k, n = block["stage_index"], block["stage_count"]
    if n < 2 or k >= n:
        raise StageBlockError("a split has stage_count >= 2 and stage_index < stage_count")
    if block["layer_end"] <= block["layer_start"]:
        raise StageBlockError("layer_end is exclusive and must exceed layer_start")
    if not _prefixed(block["package_id"]):
        raise StageBlockError("package_id must be sha256: + 64 lowercase hex")
    for name in ("manifest_sha256", "source_model_sha256"):
        if not _hex(block[name], 64):
            raise StageBlockError(f"{name} must be 64 lowercase hex")
    if block["terminal_state"] not in TERMINAL_STATES:
        raise StageBlockError("terminal_state is not in the closed set")
    mode = block["return_mode"]
    if mode not in ("direct", "relayed"):
        raise StageBlockError("return_mode must be direct or relayed")
    # Relayed return has no direct lane anywhere, so the position rules below
    # reject a non-null direct_return on every relayed block.
    direct = mode == "direct"
    final = k + 1 == n
    side = block["side"]

    if side == "stage":
        if k == 0:
            raise StageBlockError("a stage-side block starts at stage 1")
        _no_exchange_fields(block)
        if block.get("upstream") is None:
            raise StageBlockError("a stage past 0 must carry upstream")
        _pair("upstream", block["upstream"], ("received", "replies_sent"))
        if final and block.get("downstream") is not None:
            raise StageBlockError("the final stage has no downstream")
        if not final:
            if block.get("downstream") is None:
                raise StageBlockError("a stage before the last must carry downstream")
            _pair("downstream", block["downstream"], ("sent", "replies_received"))
        _direct("direct_return", block.get("direct_return"), "sent" if direct and final else None)
        _tokens(block)
    elif side == "coordinator" and k == 0:
        _no_exchange_fields(block)
        if block.get("upstream") is not None:
            raise StageBlockError("stage 0 has no upstream")
        if block.get("downstream") is None:
            raise StageBlockError("stage 0 must carry downstream")
        _pair("downstream", block["downstream"], ("sent", "replies_received"))
        _direct("direct_return", block.get("direct_return"), "received" if direct else None)
        _tokens(block)
    elif side == "coordinator":
        if any(block.get(f) is not None for f in ("upstream", "downstream", "direct_return", "tokens")):
            raise StageBlockError("a stage-exchange record carries no hop fields or tokens")
        if not _count(block.get("coordinator_term")):
            raise StageBlockError("a stage-exchange record must carry coordinator_term")
        observed_flag = block.get("data_path_observed")
        if not isinstance(observed_flag, bool):
            raise StageBlockError("a stage-exchange record must carry data_path_observed")
        can_observe = k == 1 or (direct and final)
        if observed_flag != can_observe:
            raise StageBlockError("data_path_observed must be true exactly for stage 1 "
                                  "and the final stage under direct return")
        observed = block.get("coordinator_observed")
        if not can_observe:
            if observed is not None:
                raise StageBlockError("coordinator_observed without data_path_observed")
            return
        if not isinstance(observed, dict) or set(observed) - {"downstream", "direct_return"}:
            raise StageBlockError("data_path_observed requires coordinator_observed")
        if k == 1:
            if "downstream" not in observed:
                raise StageBlockError("stage 1's exchange must carry the coordinator's downstream")
            _pair("coordinator_observed.downstream", observed["downstream"], ("sent", "replies_received"))
        elif "downstream" in observed:
            raise StageBlockError("only stage 1's exchange carries the coordinator's downstream")
        _direct("coordinator_observed.direct_return", observed.get("direct_return"),
                "received" if direct and final else None)
    else:
        raise StageBlockError("side must be stage or coordinator")


def _no_exchange_fields(block: StageBlock) -> None:
    if any(block.get(f) is not None for f in _EXCHANGE_ONLY):
        raise StageBlockError("stage-exchange fields on a block that is not one")


def _tokens(block: StageBlock) -> None:
    tokens = block.get("tokens")
    if not isinstance(tokens, dict) or set(tokens) != {"prefill_received", "decode"}:
        raise StageBlockError("tokens must be exactly {prefill_received, decode}")
    if not all(_count(v) for v in tokens.values()):
        raise StageBlockError("token counts must be non-negative integers")


def split_key(block: StageBlock) -> tuple[str, str, str]:
    return (block["coordinator_node_id"], block["run_id"], block["request_id"])


# ---------------------------------------------------------------------------
# Receipt rules
# ---------------------------------------------------------------------------

_RECEIPT_FIELDS = {
    "v", "kind", "run_id", "topology", "stages",
    "coordinator_node_id", "request_id", "stage_seal_deadline_ms",
}


def validate_receipt(receipt: Any) -> None:
    """Raise ReceiptError unless `receipt` is a valid split coordinator receipt.

    The base rules are the reference emitter's own dataclasses
    (`TopologyEntry`, `StageEntry`); the split rules sit on top.
    """
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_FIELDS:
        raise ReceiptError(f"receipt must be exactly {sorted(_RECEIPT_FIELDS)}")
    if receipt["v"] != 1 or receipt["kind"] != RECEIPT_KIND:
        raise ReceiptError("v must be 1 and kind mesh-coordinator-receipt")
    if not receipt["run_id"] or not receipt["coordinator_node_id"]:
        raise ReceiptError("run_id and coordinator_node_id must be non-empty")
    if not canonical_request_id(receipt["request_id"]):
        raise ReceiptError("request_id must be a canonical decimal u64 string")
    if not _count(receipt["stage_seal_deadline_ms"]):
        raise ReceiptError("stage_seal_deadline_ms must be a non-negative integer")
    topology, stages = receipt["topology"], receipt["stages"]
    if not isinstance(topology, list) or not isinstance(stages, list):
        raise ReceiptError("topology and stages must be lists")
    if len(topology) < 2 or len(stages) != len(topology):
        raise ReceiptError("a split has >= 2 stages and one stages[] entry per hop")
    try:
        entries = [TopologyEntry(**t) for t in topology]
        stage_entries = [
            StageEntry(
                hop_id=s["hop_id"],
                bundle=s["bundle"],
                bundle_ref=s.get("bundle_ref"),
                bundle_refs=tuple(s["bundle_refs"]) if "bundle_refs" in s else None,
            )
            for s in stages
        ]
        extra = [set(s) - {"hop_id", "bundle", "bundle_ref", "bundle_refs"} for s in stages]
    except (TypeError, KeyError, ValueError) as exc:
        raise ReceiptError(str(exc)) from exc
    if any(extra):
        raise ReceiptError("stages[] entries carry unknown members")
    cited: list[str] = []
    for k, (hop, stage) in enumerate(zip(entries, stage_entries)):
        role = "coordinator" if k == 0 else "stage"
        if (hop.seq, hop.hop_id, hop.role) != (k, f"stage-{k}", role):
            raise ReceiptError(f"topology[{k}] must be seq {k}, hop_id stage-{k}, role {role}")
        if hop.assignment is None:
            raise ReceiptError(f"topology[{k}] must carry its assignment")
        if k == 0 and hop.assignment["node_id"] != receipt["coordinator_node_id"]:
            raise ReceiptError("stage 0 is the coordinator's own slice")
        if stage.hop_id != hop.hop_id:
            raise ReceiptError(f"stages[{k}].hop_id must match topology[{k}]")
        if k == 0 and stage.bundle != "not_requested":
            raise ReceiptError("stage 0's bundle is not_requested")
        refs = ([stage.bundle_ref] if stage.bundle_ref else []) + list(stage.bundle_refs or ())
        cited.extend(r["digest"] for r in refs)
    if len(set(cited)) != len(cited):
        raise ReceiptError("one stage record is cited under more than one hop")


# ---------------------------------------------------------------------------
# The requester's hop check
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CarriedStageRecord:
    capsule_id: str
    block: Any


def _compare(a: LaneFold | None, b: LaneFold | None, required: bool) -> str:
    if a is None or b is None:
        return "gap"
    if a["frames"] == 0 and b["frames"] == 0:
        return "gap" if required else "not_applicable"
    if a["digest"] == b["digest"]:
        return "agree" if a["frames"] == b["frames"] else "malformed"
    return "break"


def verify_split(
    own: StageBlock,
    receipt: SplitReceipt,
    carried: list[CarriedStageRecord],
) -> SplitVerdict:
    """Stage cells, per-lane hand-off states, and the run-level line."""
    validate_block(own)
    validate_receipt(receipt)
    key = (receipt["coordinator_node_id"], receipt["run_id"], receipt["request_id"])
    if own["side"] != "coordinator" or own["stage_index"] != 0 or split_key(own) != key:
        raise ReceiptError("own slice is not stage 0 of this receipt's split")
    n = len(receipt["topology"])

    valid: dict[str, StageBlock] = {}
    rejected: set[str] = set()
    ids_by_stage: dict[int, set[str]] = {}
    for record in carried:
        try:
            validate_block(record.block)
        except StageBlockError:
            rejected.add(record.capsule_id)
            continue
        valid[record.capsule_id] = record.block
        if record.block["side"] == "stage" and split_key(record.block) == key:
            ids_by_stage.setdefault(record.block["stage_index"], set()).add(record.capsule_id)
    conflicted = {k for k, ids in ids_by_stage.items() if len(ids) > 1}

    cells = [{"stage_index": 0, "state": "coordinator_slice"}]
    blocks: list[StageBlock | None] = [own]
    for k in range(1, n):
        state, block = _cell(k, receipt, own, valid, conflicted, rejected, key)
        cells.append({"stage_index": k, "state": state})
        blocks.append(block)

    completed = own["terminal_state"] == "completed"
    relayed = own["return_mode"] == "relayed"
    lanes = []
    for h in range(n - 1):
        up = (blocks[h] or {}).get("downstream")
        down = (blocks[h + 1] or {}).get("upstream")
        lanes.append({
            "hop_index": h, "lane": "forward", "required": True,
            "state": _compare(up and up["sent"], down and down["received"], True),
        })
        reply_required = relayed and completed
        lanes.append({
            "hop_index": h, "lane": "reply", "required": reply_required,
            "state": _compare(down and down["replies_sent"], up and up["replies_received"], reply_required),
        })
    if not relayed:
        sent = ((blocks[n - 1] or {}).get("direct_return") or {}).get("sent")
        received = (own.get("direct_return") or {}).get("received")
        lanes.append({
            "hop_index": n - 1, "lane": "direct_return", "required": completed,
            "state": _compare(sent, received, completed),
        })
    handoffs_agree = all(l["state"] in ("agree", "not_applicable") for l in lanes) and any(
        l["state"] == "agree" for l in lanes
    )
    return {
        "cells": cells,
        "lanes": lanes,
        "handoffs_agree": handoffs_agree,
        "terminal_state": own["terminal_state"],
    }


def _cell(
    k: int,
    receipt: SplitReceipt,
    own: StageBlock,
    valid: dict[str, StageBlock],
    conflicted: set[int],
    rejected: set[str],
    key: tuple[str, str, str],
) -> tuple[str, StageBlock | None]:
    if k in conflicted:
        return "conflict", None
    entry = receipt["stages"][k]
    if entry["bundle"] == "not_requested":
        return "not_requested", None
    if entry["bundle"] == "conflict":
        return "conflict", None
    if entry["bundle"] != "present":
        return "not_received", None
    digest = entry["bundle_ref"]["digest"]
    if digest in rejected:
        return "rejected", None
    block = valid.get(digest)
    if block is None:
        return "not_received", None
    if (
        block["side"] != "stage"
        or block["stage_index"] != k
        or split_key(block) != key
        or block["stage_count"] != len(receipt["topology"])
    ):
        return "rejected", None
    assigned = receipt["topology"][k]["assignment"]
    matches = (
        (block["layer_start"], block["layer_end"], block["package_id"])
        == (assigned["layer_start"], assigned["layer_end"], assigned["package_id"])
        and block["return_mode"] == own["return_mode"]
    )
    return ("ok" if matches else "disagrees"), block

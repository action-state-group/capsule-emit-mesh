#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Per-`(self, counterparty)` monotone capsule sequencing (history proposal
§1: continuity is bilateral only). Every sealed capsule carries `seq` and
`prev_seq` for the pair it was sealed under, so a verifier can later check
that pair's stream for gaps (missing records) or regressions (a `seq` that
repeats or goes backward) WITHOUT trusting anything this node did not itself
sign. Mirrors ``capsule_producer::sequence`` (Rust) field-for-field so a
verifier never needs to special-case which language sealed a given capsule.

``SequenceCounterStore`` is a WRITE-SIDE convenience cache, not the source of
truth. It is persisted in a small JSON file beside the ledger
(``<ledger_dir>/sequence_counters.json``) purely so a restarted sidecar
resumes counting from where it left off instead of starting every pair back
at 1 -- which would itself look like a reset to a verifier. But the cache is
never trusted for continuity: ``verify_pair_continuity`` walks the SEALED
capsules themselves, in ledger order. A wiped or hand-edited cache file makes
this node issue ``seq=1`` again for a pair that already has higher ``seq``
values in the ledger; the verifier catches that regression from the capsule
stream alone and reports it as a broken pair, never a fresh start.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

__all__ = [
    "UNKNOWN_COUNTERPARTY",
    "pair_key",
    "pair_counterparty_authenticated",
    "SequenceCounterStore",
    "PairContinuity",
    "extract_pair_seq",
    "verify_pair_continuity",
]

#: Never invent a counterparty identity: missing/empty collapses to this
#: explicit, honest bucket rather than a fabricated node id.
UNKNOWN_COUNTERPARTY = "unknown"


def pair_key(self_id: str, counterparty_id: str | None) -> str:
    """Canonical `(self, counterparty)` key. A missing/empty counterparty
    collapses to `UNKNOWN_COUNTERPARTY` -- never fabricated, but still a
    real, stable bucket a verifier can reason about."""
    return f"{self_id}::{counterparty_id or UNKNOWN_COUNTERPARTY}"


def pair_counterparty_authenticated(pair: str) -> bool:
    """`False` iff *pair* is bucketed under `UNKNOWN_COUNTERPARTY` -- i.e. no
    authenticated (or at least self-reported-and-named) counterparty id was
    available when the records in this pair were sealed. [adv-stream-
    membership-authenticated]: this bucket is a legitimate, honest fallback
    for a genuinely unauthenticated exchange, but it is ALSO where a
    dishonest node can file exchanges it wants deniable while keeping a
    named pair's stream contiguous. Exposing this as an explicit boolean
    (rather than leaving callers to string-match `pair`) is what makes that
    bucket VISIBLE in continuity output instead of blending silently into
    the aggregate."""
    return not pair.endswith(f"::{UNKNOWN_COUNTERPARTY}")


class SequenceCounterStore:
    """Persists the last-issued `seq` per `(self, counterparty)` pair beside
    the ledger. See the module docstring for why this cache is never the
    source of truth for continuity.

    [adv-stream-membership-authenticated] `next_seq` is called from the
    sidecar's `ThreadingHTTPServer` request handler, so concurrent requests
    call it concurrently on the SAME store instance. An unlocked
    read-modify-write here lets two threads issue the same `seq` twice (a
    lost update -- indistinguishable from the reset-cache regression
    `verify_pair_continuity` exists to catch, except this one is a bug, not
    an attack), and `_save()`'s previous shared `.tmp` name let two threads'
    writes race each other (`FileNotFoundError` when one thread's
    `tmp.replace()` runs after another already consumed that same tmp path).
    Both are now serialized behind `self._lock`, and each `_save()` call
    writes its own uniquely-named tmp file, so concurrent callers can no
    longer step on each other's in-flight write."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._state: dict[str, int] = self._load()

    def _load(self) -> dict[str, int]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # Corrupt/unreadable cache -- never invent a value, start
            # counting from zero for every pair; verify_pair_continuity
            # (over the ledger, not this file) is what actually catches the
            # resulting regression.
            return {}
        return {str(k): int(v) for k, v in raw.items()}

    def _save(self) -> None:
        # Unique per call (pid + random token), never a fixed name shared by
        # every writer -- see the class docstring. Caller must hold `_lock`.
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        tmp.write_text(json.dumps(self._state, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def next_seq(self, self_id: str, counterparty_id: str | None) -> tuple[int, int | None]:
        """Issues the next `seq` for `(self_id, counterparty_id)`, returning
        it alongside the pair's previous `seq` (`None` the first time this
        store has seen the pair). Thread-safe: the read, increment, and save
        are one atomic critical section, so concurrent callers for the same
        or different pairs never lose an update or observe a torn file."""
        with self._lock:
            key = pair_key(self_id, counterparty_id)
            prev_seq = self._state.get(key)
            seq = (prev_seq or 0) + 1
            self._state[key] = seq
            self._save()
            return seq, prev_seq


@dataclass(frozen=True)
class PairContinuity:
    """Per-pair continuity finding. `continuity` mirrors the `history_card`
    convention (``"unbroken"`` / ``"broken at seq=<N>: <reason>"``) -- a
    REGRESSION (a `seq` at or below one already seen for the pair, which can
    only mean a reset or forgery, never a legitimate fresh start). A pure
    GAP (missing records, `seq` jumping forward by more than one) is softer:
    it increments `gaps_detected`, a labeled count and never a score, and
    does NOT by itself mark the pair broken.

    `counterparty_authenticated` is `False` exactly when `pair` is the
    `UNKNOWN_COUNTERPARTY` bucket (see `pair_counterparty_authenticated`) --
    a labeled fact, never a score, so a reader can tell "this stream has no
    named counterparty" apart from "this stream is broken" without parsing
    the pair string itself."""

    pair: str
    continuity: str
    gaps_detected: int
    records_checked: int
    counterparty_authenticated: bool


def _poc_block(capsule: dict[str, Any]) -> dict[str, Any]:
    return (
        capsule.get("model_attestation", {}).get("compute_attestation", {}).get("x-mesh-poc-v1", {}) or {}
    )


def extract_pair_seq(capsule: dict[str, Any]) -> tuple[str, str, int, int | None] | None:
    """Default extractor: reads the standard `serving_provenance` shape both
    the Rust plugin and this sidecar seal. `self` is always the node that
    sealed the record (`served_by_node_id` when this capsule's
    `serving_provenance.role` is `"provider"` -- or absent, which the Rust
    plugin's shape defaults to, since it only ever seals the provider half;
    `requesting_party` when `role == "requester"`). Returns `None` when the
    capsule carries no `seq` (an older record predating this feature) --
    such records are simply excluded from continuity checking, never
    assigned a fabricated seq.
    """
    serving_provenance = _poc_block(capsule).get("serving_provenance") or {}
    seq = serving_provenance.get("seq")
    if seq is None:
        return None
    role = serving_provenance.get("role", "provider")
    served_by_node_id = serving_provenance.get("served_by_node_id")
    requesting_party = serving_provenance.get("requesting_party")
    if role == "requester":
        self_id, counterparty_id = requesting_party, served_by_node_id
    else:
        self_id, counterparty_id = served_by_node_id, requesting_party
    return (
        self_id or UNKNOWN_COUNTERPARTY,
        counterparty_id or UNKNOWN_COUNTERPARTY,
        int(seq),
        serving_provenance.get("prev_seq"),
    )


def verify_pair_continuity(
    capsules: Iterable[dict[str, Any]],
    *,
    pair_extractor: Callable[[dict[str, Any]], tuple[str, str, int, int | None] | None] = extract_pair_seq,
    checkpoint_covered_count: int | None = None,
) -> dict[str, PairContinuity]:
    """Walks `capsules` IN THE ORDER GIVEN (ledger/bundle order -- never
    re-sorted, so an out-of-order delivery reads as a gap, not silently
    repaired) and reports `PairContinuity` per `(self, counterparty)` pair.

    `prev_seq` is READ, not just sealed, in two ways:

    - **Self-consistency**: a record's own `(seq, prev_seq)` must match what
      `SequenceCounterStore.next_seq` would have issued -- `prev_seq is None`
      iff `seq == 1`, else `prev_seq == seq - 1`. A record that violates this
      alone (a lying `prev_seq`, unrelated to whatever came before it in this
      walk) is `broken`, never silently `unbroken`.
    - **First-sighted-record check**: the first record this walk sees for a
      pair must itself claim `prev_seq is None` (a true genesis). One that
      claims a predecessor (self-consistent or not) reveals that the pair's
      PREFIX was dropped from what we were handed; every record from seq=1
      up to that claimed `prev_seq` is counted as a gap rather than treated
      as an untroubled fresh start.

    Neither check can reveal a dropped TRAIL -- a pair simply stopping mid-
    ledger looks identical to a pair whose last real exchange happened to be
    the most recent one. Catching that requires an outside anchor: pass
    `checkpoint_covered_count`, the number of pair-sequenced records a
    checkpoint over this same range attests to have existed. Fewer records
    actually walked than that count means the range we were handed is
    incomplete, and every pair's continuity in it is reported `broken`
    rather than a false `unbroken` built on a silently truncated view.
    """
    last_seq: dict[str, int] = {}
    gaps: dict[str, int] = {}
    broken: dict[str, str] = {}
    counts: dict[str, int] = {}

    for capsule in capsules:
        extracted = pair_extractor(capsule)
        if extracted is None:
            continue
        self_id, counterparty_id, seq, prev_seq = extracted
        key = pair_key(self_id, counterparty_id)
        counts[key] = counts.get(key, 0) + 1
        prior = last_seq.get(key)

        self_consistent = (prev_seq is None and seq <= 1) or (prev_seq is not None and prev_seq == seq - 1)
        if not self_consistent:
            broken.setdefault(key, f"broken at seq={seq}: prev_seq={prev_seq!r} does not precede it")

        if prior is None and prev_seq is not None:
            # First record this walk has seen for the pair, but it claims a
            # predecessor we never saw -- the prefix was dropped.
            gaps[key] = gaps.get(key, 0) + prev_seq
        elif prior is not None:
            if seq <= prior:
                broken.setdefault(key, f"broken at seq={seq}: not greater than prior seq={prior}")
            elif seq > prior + 1:
                gaps[key] = gaps.get(key, 0) + (seq - prior - 1)
        last_seq[key] = max(prior or 0, seq)

    total_checked = sum(counts.values())
    truncated = checkpoint_covered_count is not None and total_checked < checkpoint_covered_count

    return {
        key: PairContinuity(
            pair=key,
            continuity=broken.get(key)
            or (
                f"broken: checkpoint covers {checkpoint_covered_count} pair-sequenced records "
                f"but only {total_checked} were presented"
                if truncated
                else "unbroken"
            ),
            gaps_detected=gaps.get(key, 0),
            records_checked=count,
            counterparty_authenticated=pair_counterparty_authenticated(key),
        )
        for key, count in counts.items()
    }

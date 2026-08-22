# SPDX-License-Identifier: Apache-2.0
"""Layer 1-2 checkpointing for a mesh node's own capsule ledger.

Per the mesh architecture doc (`_work/mesh-llm-capsule-architecture-2026-08-21.md`
§3), a mesh node's assurance is layered and each layer is a strictly larger
install and a strictly stronger claim:

    LAYER 0  a signed capsule per exchange           -- INSTALLED (capsule_sidecar.py)
    LAYER 1  a local, append-only MMR over that log  -- THIS MODULE, opt-in
    LAYER 2  a periodic, signed checkpoint (32B root) -- THIS MODULE, opt-in
    LAYER 3  an independent witness co-signs it       -- register_checkpoint(), opt-in per URL

Nothing here is on by default. A node that never sets `checkpoint_config_path`
on its `NodeState` pays zero cost: `checkpointing` is only imported by
`capsule_sidecar.py` at module load (cheap -- no MMR is built, no file is
touched) until a `[checkpoint]` config is actually supplied, matching
`capsule_emit.checkpoint`'s own Layer-0-cost discipline.

This module supplies exactly the structural adapter `capsule_emit.checkpoint`
asks any log binding to implement (`LogSource`) over this repo's own
`capsules.jsonl` -- no MMR/checkpoint logic is vendored or reimplemented here.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capsule_emit.checkpoint import (
    CheckpointConfig,
    CheckpointError,
    CheckpointRecord,
    MmrLedger,
    due_for_checkpoint,
    emit_checkpoint,
    register_checkpoint,
)
from capsule_emit.checkpoint import leaf_count as _leaf_count_at_size

__all__ = [
    "JsonlRecord",
    "JsonlLogSource",
    "Ed25519Signer",
    "CheckpointState",
    "load_checkpoint_config",
    "describe_witness_state",
]


@dataclass(frozen=True)
class JsonlRecord:
    seq: int
    capsule_id: str
    capsule: dict[str, Any]


class JsonlLogSource:
    """Adapts capsule-emit-mesh's own append-only `capsules.jsonl` ledger to
    the `capsule_emit.checkpoint` `LogSource` shape (`append`/`scan`/`fetch`/
    `find_gaps`/`verify`; records exposing `.seq`/`.capsule_id`).

    `seq` is the 1-indexed line number: this ledger is already gapless and
    append-only per node (one line per exchange, `record_capsule`'s only
    writer), so line position IS the log sequence -- no separate counter.
    """

    def __init__(self, ledger_path: Path):
        self._ledger_path = ledger_path
        self._next_seq: int | None = None  # lazily counted from the file on first append

    def append(self, capsule: dict[str, Any], *, consequential: bool = True) -> JsonlRecord:
        if self._next_seq is None:
            self._next_seq = sum(1 for _ in self._lines()) + 1
        with self._ledger_path.open("a") as fh:
            fh.write(json.dumps(capsule, sort_keys=True) + "\n")
        seq = self._next_seq
        self._next_seq += 1
        return JsonlRecord(seq=seq, capsule_id=capsule["capsule_id"], capsule=capsule)

    def _lines(self) -> Iterator[str]:
        if not self._ledger_path.exists():
            return
        with self._ledger_path.open("r") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield line

    def scan(self, query: Any = None) -> Iterator[JsonlRecord]:
        for i, line in enumerate(self._lines(), start=1):
            capsule = json.loads(line)
            yield JsonlRecord(seq=i, capsule_id=capsule["capsule_id"], capsule=capsule)

    def fetch(self, capsule_id: str) -> JsonlRecord | None:
        for record in self.scan():
            if record.capsule_id == capsule_id:
                return record
        return None

    def verify(self, capsule_id: str) -> None:
        return None

    def find_gaps(self) -> list:
        return []


class Ed25519Signer:
    """Adapts a mesh node's existing Ed25519 signing key (the same key that
    signs its capsules, from `load_or_create_signing_key`) to
    `capsule_emit.checkpoint`'s `Signer` protocol -- one key, one identity,
    for both capsules and checkpoints."""

    def __init__(self, key_id: str, private_key_pem: bytes):
        from cryptography.hazmat.primitives import serialization

        self.key_id = key_id
        self._private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    def sign(self, digest_hex: str) -> str:
        signature = self._private_key.sign(bytes.fromhex(digest_hex))
        return signature.hex()


def load_checkpoint_config(config_path: Path) -> tuple[CheckpointConfig, str | None] | None:
    """Parse a `[checkpoint]` TOML table (same shape as
    `capsule_emit.checkpoint.emit.EXAMPLE_CONFIG_TOML`, plus an optional
    mesh-specific `log_id` key) into a `CheckpointConfig` + `log_id`.
    Returns `None` if the file has no `[checkpoint]` table -- checkpointing
    stays off, Layer 0 only."""
    import tomllib

    with config_path.open("rb") as fh:
        data = tomllib.load(fh)
    section = data.get("checkpoint")
    if section is None:
        return None
    cfg = CheckpointConfig.from_dict(section)
    return cfg, section.get("log_id")


def _read_last_checkpoint(checkpoints_path: Path) -> CheckpointRecord | None:
    if not checkpoints_path.exists():
        return None
    last_line = None
    with checkpoints_path.open("r") as fh:
        for line in fh:
            line = line.strip()
            if line:
                last_line = line
    if last_line is None:
        return None
    return CheckpointRecord.from_dict(json.loads(last_line))


@dataclass
class CheckpointState:
    """A mesh node's Layer 1-2 state: an MMR over its own capsule ledger,
    plus the periodic signed checkpoint and (optional) witness registration.
    """

    cfg: CheckpointConfig
    mmr: MmrLedger
    signer: Ed25519Signer
    log_id: str
    checkpoints_path: Path
    last_checkpoint: CheckpointRecord | None = None
    entries_since_checkpoint: int = 0

    @classmethod
    def load(
        cls,
        *,
        ledger_dir: Path,
        log_source: JsonlLogSource,
        cfg: CheckpointConfig,
        signer: Ed25519Signer,
        log_id: str,
    ) -> "CheckpointState":
        mmr = MmrLedger(log_source)
        mmr.sync()
        checkpoints_path = ledger_dir / "checkpoints.jsonl"
        last_checkpoint = _read_last_checkpoint(checkpoints_path)
        last_leaf_count = _leaf_count_at_size(last_checkpoint.mmr_size) if last_checkpoint else 0
        entries_since = mmr.leaf_count() - last_leaf_count
        return cls(
            cfg=cfg,
            mmr=mmr,
            signer=signer,
            log_id=log_id,
            checkpoints_path=checkpoints_path,
            last_checkpoint=last_checkpoint,
            entries_since_checkpoint=entries_since,
        )

    def record_appended(self) -> CheckpointRecord | None:
        """Call once a new capsule has landed in the wrapped ledger. Folds it
        into the MMR and checkpoints if the declared cadence says it's due.
        Returns the new checkpoint if one was emitted, else None."""
        added = self.mmr.sync()
        self.entries_since_checkpoint += added
        if due_for_checkpoint(self.cfg, self.entries_since_checkpoint):
            return self._checkpoint_now()
        return None

    def reconnect(self) -> CheckpointRecord | None:
        """Latest-checkpoint-on-reconnect (mesh architecture doc §4): an
        offline node keeps appending locally; on reconnect it submits ONE
        checkpoint committing everything accrued since the last witnessed
        one -- the consistency proof chains from that checkpoint's size, so
        the gap self-heals rather than needing one checkpoint per missed
        cadence tick. Ignores cadence: emits immediately if anything is
        uncommitted. Call once at startup, not per-request."""
        added = self.mmr.sync()
        self.entries_since_checkpoint += added
        if self.mmr.leaf_count() == 0:
            return None
        if self.last_checkpoint is not None:
            last_leaf_count = _leaf_count_at_size(self.last_checkpoint.mmr_size)
            if self.mmr.leaf_count() <= last_leaf_count:
                return None
        return self._checkpoint_now()

    def _checkpoint_now(self) -> CheckpointRecord:
        cp = emit_checkpoint(self.mmr, self.signer, log_id=self.log_id, prev=self.last_checkpoint)
        for ts_url in self.cfg.ts_urls:
            try:
                witness = register_checkpoint(cp, ts_url)
                cp.witnesses.append(witness)
            except CheckpointError as exc:
                # Registration is never on the serving path (TRUST-MODEL.md
                # §8.4): an unreachable TS means this checkpoint stays
                # locally-committed (self-checkpointed, not witnessed), not
                # that anything upstream of it fails.
                print(f"checkpoint registration with {ts_url} failed (staying self-checkpointed): {exc}")
        with self.checkpoints_path.open("a") as fh:
            fh.write(json.dumps(cp.to_dict(), sort_keys=True) + "\n")
        self.last_checkpoint = cp
        self.entries_since_checkpoint = 0
        return cp

    def witness_status(self) -> str:
        return describe_witness_state(self.last_checkpoint, self.mmr.leaf_count())


def describe_witness_state(cp: CheckpointRecord | None, current_entries: int) -> str:
    """The mesh doc's witness grading (self-checkpoint < peer-witnessed <
    independently witnessed), applied honestly to what a checkpoint actually
    achieved. Never says "witnessed" for a checkpoint no outside party has
    actually seen -- that distinction is exactly rung-2 D1's identity-
    limitation discipline, applied to logs instead of requesters. Peer-
    witnessing (carry()/compose() of another node's checkpoint capsule) is
    documented as the decentralized option in README but not built here --
    see the mesh architecture doc's posture ruling.

    `current_entries` and a checkpoint's own size are both rendered as leaf
    (capsule) counts, not the MMR's internal node count `mmr_size` actually
    carries -- an operator reads "up to entry 8", not an MMR node index.
    """
    if cp is None:
        return f"unwitnessed -- {current_entries} entries recorded locally, no checkpoint emitted yet"
    checkpointed_entries = _leaf_count_at_size(cp.mmr_size)
    lag = current_entries - checkpointed_entries
    lag_note = f" -- {lag} more entr{'y' if lag == 1 else 'ies'} appended since" if lag else ""
    if not cp.witnesses:
        return (
            f"self-checkpointed up to entry {checkpointed_entries} at {cp.timestamp}, "
            f"NOT independently witnessed{lag_note}"
        )
    urls = ", ".join(sorted({w.ts_url for w in cp.witnesses}))
    suffix = ", not yet witnessed" if lag else ""
    return f"witnessed up to entry {checkpointed_entries} at {cp.timestamp} by {urls}{lag_note}{suffix}"

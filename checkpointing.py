# SPDX-License-Identifier: Apache-2.0
"""Layer 1-2 checkpointing over a mesh node's capsule ledgers.

Per the mesh architecture doc (`_work/mesh-llm-capsule-architecture-2026-08-21.md`
§3), a mesh node's assurance is layered and each layer is a strictly larger
install and a strictly stronger claim:

    LAYER 0  a signed capsule per exchange           -- INSTALLED (capsule_sidecar.py /
                                                          the Rust plugin's ledger.rs)
    LAYER 1  a local, append-only MMR over that log  -- THIS MODULE, opt-in
    LAYER 2  a periodic, signed COSE-wire checkpoint  -- THIS MODULE, opt-in
             (`kind="cll-checkpoint"`, peak-list commitment,
             [cll-checkpoint-cose-wire]/[cll-commitment-interop])
    LAYER 3  an independent witness co-signs it       -- register_checkpoint(), opt-in per URL,
                                                          default target witness.agentactioncapsule.org

Nothing here is on by default. A node that never sets `checkpoint_config_path`
on its `NodeState` pays zero cost: `checkpointing` is only imported by
`capsule_sidecar.py` at module load (cheap -- no MMR is built, no file is
touched) until a `[checkpoint]` config is actually supplied, matching
`capsule_emit.checkpoint`'s own Layer-0-cost discipline.

This module supplies exactly the structural adapter `capsule_emit.checkpoint`
asks any log binding to implement (`LogSource`) over a `capsules.jsonl` file,
plus the COSE-wire checkpoint build/sign/register sequence -- no MMR/checkpoint/
COSE logic is vendored or reimplemented here, all of it comes from
`capsule_emit.checkpoint` (Amendment E: the CLL core is substrate a counterparty
needs to verify a log, so it lives in the neutral producer library, consumed
here through its public interface, never forked).

**Two single-writer logs, each independently checkpointed.** Per the mesh build
plan §4 A2/A3 (rev 3, LOCKED): a mesh node keeps two separate append-only
`capsules.jsonl` logs on disk -- the Python sidecar's own, and the Rust
plugin's (`plugins/capsule-producer/src/ledger.rs`) -- each with exactly one
writer. This module never becomes a second writer into the Rust-owned ledger:
`capsule_emit`'s own default checkpoint wiring (`push()`/`maybe_checkpoint()`)
persists each checkpoint's stamp back INTO the ledger it covers, which is
correct for a ledger `capsule_emit` itself owns but would corrupt the Rust
plugin's strict `Ledger::open()` replay (which requires every line to be a
chained, receipted capsule) if pointed at that file directly. `CheckpointState`
here instead uses the lower-level, equally-public primitives (`MmrLedger`,
`emit_checkpoint`, `checkpoint_to_cose`, `register_checkpoint` --
`docs/checkpoint.md`'s "Direct / manual use" section) and persists checkpoint
stamps to a SIBLING `checkpoints.jsonl` file, leaving the capsule ledger itself
untouched no matter which process/language wrote it. A node running both a
sidecar and the Rust plugin loads two independent `CheckpointState`s, one per
`ledger_dir`, at their own cadence (`capsule_sidecar.py`'s `--checkpoint-config`
/ `--plugin-checkpoint-config`).
"""
from __future__ import annotations

import json
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from capsule_emit.checkpoint import (
    DEFAULT_TS_URL,
    CheckpointConfig,
    CheckpointError,
    CheckpointRecord,
    MmrLedger,
    checkpoint_to_cose,
    due_for_checkpoint,
    emit_checkpoint,
    register_checkpoint,
)
from capsule_emit.checkpoint import leaf_count as _leaf_count_at_size
from capsule_emit.signing import LocalKeypairSigner

__all__ = [
    "JsonlRecord",
    "JsonlLogSource",
    "Ed25519Signer",
    "CheckpointState",
    "load_checkpoint_config",
    "describe_witness_state",
    "DEFAULT_TS_URL",
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

    def _lines(self) -> list[str]:
        if not self._ledger_path.exists():
            return []
        with self._ledger_path.open("r") as fh:
            return [line.strip() for line in fh if line.strip()]

    def scan(self, query: Any = None) -> Iterator[JsonlRecord]:
        # [bounce 2026-08-28] For a foreign-owned ledger (--plugin-ledger-dir:
        # the Rust plugin is this file's sole writer, a SEPARATE, concurrently
        # running process) a read here can land mid-append: the trailing line
        # on disk may be a partial write -- no closing brace, no newline yet.
        # Only the LAST line gets this tolerance: stop cleanly there instead
        # of raising, since the complete prefix already scanned is still a
        # valid, gapless log as of that point, and the torn tail is picked up
        # whole on the next scan once the writer finishes it. Real corruption
        # anywhere else in the file is NOT this case and must still raise --
        # silently dropping an interior bad line would hide a gap, not a race.
        lines = self._lines()
        for i, line in enumerate(lines, start=1):
            try:
                capsule = json.loads(line)
            except json.JSONDecodeError:
                if i == len(lines):
                    return
                raise
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
    """Adapts a mesh node's persisted Ed25519 signing key
    (`capsule_emit.signing.LocalKeypairSigner`, loaded from `key_path` -- the
    same `<keys_dir>/node-key.pem` file both `capsule_sidecar.load_or_create_signing_key`
    and the Rust plugin's `keys::load_or_create` read/write, so a keypair
    generated by either side loads cleanly here) to BOTH `Signer` shapes
    `capsule_emit.checkpoint` needs: the JSON checkpoint body's narrow
    `sign(digest_hex) -> str` (`capsule_emit.checkpoint.emit.Signer`, for
    `emit_checkpoint`) and the COSE wire form's `sign_cose_statement(...)`
    (`capsule_emit.signing.Signer`, for `checkpoint_to_cose`) -- one key, one
    identity, for capsule content, JSON checkpoints, and COSE checkpoints
    alike. `key_id` is `LocalKeypairSigner`'s own (the raw Ed25519 public key,
    hex-encoded) -- required, not cosmetic: `verify_checkpoint_signature_offline`
    reconstructs the public key straight from a checkpoint's `key_id` field, so
    it must be the real key, never an arbitrary label."""

    def __init__(self, key_path: str | Path):
        self._inner = LocalKeypairSigner(key_path)
        self.key_id = self._inner.key_id

    def sign(self, digest_hex: str) -> str:
        # Matches capsule_emit.witness._PersistedCheckpointSigner.sign and
        # verify_checkpoint_signature_offline exactly: the ASCII bytes of the
        # hex digest string are signed, not bytes.fromhex(digest_hex).
        signature_hex, _key_id = self._inner.sign(digest_hex.encode("ascii"))
        return signature_hex

    def sign_cose_statement(self, payload: bytes, **kwargs: Any) -> bytes:
        return self._inner.sign_cose_statement(payload, **kwargs)


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

    #: Monotonic clock, injectable for tests. A monotonic source (not wall
    #: time) is deliberate: the age leg of the cadence measures elapsed time
    #: since the first unwitnessed entry, which must not jump backward on an
    #: NTP step or DST change and must not double-anchor because the wall
    #: clock was corrected.
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)
    #: Monotonic timestamp of the FIRST currently-unwitnessed entry, or None
    #: when the log is fully caught up (nothing pending). This is what the
    #: age-based cadence measures against -- "300s since activity resumed",
    #: not "300s since the last checkpoint" -- so an idle node never anchors
    #: (only-if-new-activity) and the 5-minute clock only starts ticking once
    #: there is something new to anchor. Reset to None every time a checkpoint
    #: clears the backlog. Not restored across a restart: on load, any
    #: on-disk backlog is treated as pending-as-of-now, and reconnect() (which
    #: ignores the age leg) is the restart catch-up path, so nothing is lost.
    _pending_since: float | None = field(default=None, repr=False)

    @classmethod
    def load(
        cls,
        *,
        ledger_dir: Path,
        log_source: JsonlLogSource,
        cfg: CheckpointConfig,
        signer: Ed25519Signer,
        log_id: str,
        clock: Callable[[], float] = time.monotonic,
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
            clock=clock,
            # A pre-existing on-disk backlog is pending as of load time; the
            # age clock starts now. reconnect() commits it immediately anyway.
            _pending_since=(clock() if entries_since > 0 else None),
        )

    def record_appended(self) -> CheckpointRecord | None:
        """Call once a new capsule has landed in the wrapped ledger. Folds it
        into the MMR and checkpoints if the declared entry-count cadence says
        it's due. Returns the new checkpoint if one was emitted, else None.

        This is the per-append leg (entry count only): it never fires the
        time-based cadence -- that's `tick()`'s job, driven by a clock off the
        serving path. Keeping the two separate means a hot serving loop can
        call `record_appended()` on every capsule (cheap: an MMR fold + a
        count compare) without a `time.monotonic()` syscall per request, while
        the ~5-minute anchor clock runs in the background daemon. The privacy
        rationale (requirement 2) lives on the time leg: batching the witness
        anchor on a clock, never per-call, is what keeps activity timing/rate
        from leaking to the witness.
        """
        added = self.mmr.sync()
        self._note_pending(added)
        if due_for_checkpoint(self.cfg, self.entries_since_checkpoint):
            return self._checkpoint_now()
        return None

    def tick(self) -> CheckpointRecord | None:
        """The ~5-minute clock leg, called by the background daemon on its
        interval (never on the serving path). Syncs the MMR, then checkpoints
        if EITHER the entry-count cadence (`cadence_entries`) OR the age
        cadence (`cadence_seconds`, default 900 upstream / 300 for a mesh
        node) is due -- whichever comes first.

        Only-if-new-activity is structural, not a special case: `_pending_since`
        is None whenever the log is fully caught up, and `due_for_checkpoint`
        returns False for `entries_since_checkpoint == 0` regardless of age, so
        an idle interval anchors NOTHING (no empty-interval witness traffic, no
        heartbeat that would leak "this node is up but silent"). The clock only
        starts counting from the first unwitnessed entry, so a burst of activity
        at t=0 is anchored ~`cadence_seconds` later in one batch, not per call.
        """
        added = self.mmr.sync()
        self._note_pending(added)
        seconds_since = None if self._pending_since is None else self.clock() - self._pending_since
        if due_for_checkpoint(self.cfg, self.entries_since_checkpoint, seconds_since_last=seconds_since):
            return self._checkpoint_now()
        return None

    def checkpoint_on_shutdown(self) -> CheckpointRecord | None:
        """Anchor any uncommitted backlog on a clean shutdown, so a node's
        final interval isn't lost between the last clock tick and process exit.
        Same self-healing semantics as `reconnect()` (ignore cadence, one
        checkpoint for the whole tail); a no-op when nothing is pending.
        Registration is still best-effort: an unreachable witness leaves the
        tail self-checkpointed locally, never blocks shutdown."""
        return self.reconnect()

    def _note_pending(self, added: int) -> None:
        """Fold `added` new leaves into the pending count and start the age
        clock at the first unwitnessed entry (only-if-new-activity: the clock
        does not run while the log is caught up)."""
        self.entries_since_checkpoint += added
        if self.entries_since_checkpoint > 0 and self._pending_since is None:
            self._pending_since = self.clock()

    def reconnect(self) -> CheckpointRecord | None:
        """Latest-checkpoint-on-reconnect (mesh architecture doc §4): an
        offline node keeps appending locally; on reconnect it submits ONE
        checkpoint committing everything accrued since the last witnessed
        one -- the consistency proof chains from that checkpoint's size, so
        the gap self-heals rather than needing one checkpoint per missed
        cadence tick. Ignores cadence: emits immediately if anything is
        uncommitted. Call once at startup, not per-request."""
        added = self.mmr.sync()
        self._note_pending(added)
        if self.mmr.leaf_count() == 0:
            return None
        if self.last_checkpoint is not None:
            last_leaf_count = _leaf_count_at_size(self.last_checkpoint.mmr_size)
            if self.mmr.leaf_count() <= last_leaf_count:
                return None
        return self._checkpoint_now()

    def _checkpoint_now(self) -> CheckpointRecord:
        prev_before = self.last_checkpoint
        cp = emit_checkpoint(self.mmr, self.signer, log_id=self.log_id, prev=prev_before)

        # COSE-wire form ([cll-checkpoint-cose-wire]/[cll-commitment-interop]):
        # the witness's /checkpoints route is COSE-only (single-host ruling,
        # 2026-08-27) -- register_checkpoint no longer accepts a plain JSON
        # CheckpointRecord. Built the same way capsule_emit.witness's own
        # default wiring builds it (peak hashes at the new + prior size, plus
        # a real consistency proof when there is a prior checkpoint -- never
        # just the prev_size/prev_root fields, which verify_checkpoint_cose_offline
        # would otherwise have to trust unproven).
        checkpoint_cose: bytes | None = None
        try:
            new_peak_hashes = self.mmr.peak_hashes_at(cp.mmr_size)
            prev_peak_hashes = self.mmr.peak_hashes_at(prev_before.mmr_size) if prev_before is not None else None
            consistency_proof = (
                self.mmr.consistency_proof(prev_before.mmr_size, cp.mmr_size) if prev_before is not None else None
            )
            checkpoint_cose = checkpoint_to_cose(
                cp, self.signer, new_peak_hashes, prev_peak_hashes=prev_peak_hashes, consistency_proof=consistency_proof
            )
        except Exception as exc:  # noqa: BLE001 -- best-effort, mirrors capsule_emit.witness's own COSE build
            print(f"COSE-wire checkpoint serialization failed (staying JSON-only, self-attested): {exc}")

        for ts_url in self.cfg.ts_urls:
            if checkpoint_cose is None:
                print(f"skipping witness registration with {ts_url}: no COSE-wire checkpoint to send")
                break
            try:
                witness = register_checkpoint(checkpoint_cose, ts_url)
                cp.witnesses.append(witness)
            except CheckpointError as exc:
                # Registration is never on the serving path (TRUST-MODEL.md
                # §8.4): an unreachable TS means this checkpoint stays
                # locally-committed (self-checkpointed, not witnessed), not
                # that anything upstream of it fails.
                print(f"checkpoint registration with {ts_url} failed (staying self-checkpointed): {exc}")

        record = cp.to_dict()
        if checkpoint_cose is not None:
            # Sibling key, never folded into cp.to_dict()/cp.entry_digest()'s
            # coverage -- the COSE_Sign1 statement already self-authenticates
            # (capsule_emit.checkpoint.cose_wire.verify_checkpoint_cose_offline),
            # matching capsule_emit.witness._persist_checkpoint_stamp's own
            # additive-field convention.
            record["checkpoint_cose"] = checkpoint_cose.hex()
        with self.checkpoints_path.open("a") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        self.last_checkpoint = cp
        self.entries_since_checkpoint = 0
        # Backlog cleared: stop the age clock. It restarts (at that moment)
        # only when the next new entry lands -- so the ~5-minute window is
        # measured from the first NEW activity after this anchor, never as a
        # free-running heartbeat.
        self._pending_since = None
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

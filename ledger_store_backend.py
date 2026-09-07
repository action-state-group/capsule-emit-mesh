# SPDX-License-Identifier: Apache-2.0
"""Adopts ``checkpointed-local-log``'s ``cll.ledger.store.LedgerStore`` as
this repo's own capsule-ledger backend (``[mesh-ledger-store-migration]``).

**THE gate this module exists to satisfy**: every existing checkpoint
commits to raw ledger lines in append order as MMR leaves, and an MMR leaf
is ``cll.checkpoint.core.leaf_hash(bytes.fromhex(record.capsule_id))`` --
see ``cll/checkpoint/index.py``'s ``MmrLedger._index_record``. A leaf never
depends on how a line happens to be serialized on disk (key order,
separators) -- only on the capsule's own ``capsule_id`` and its ``seq``
position. ``LedgerStore.append()`` preserves an already-``capsule_id``-
carrying dict's id verbatim (``capsule.get("capsule_id") or
compute_capsule_id(capsule)``) and assigns ``seq`` by SQLite autoincrement
starting at 1, so importing an existing flat ledger's lines *in file order*
via :meth:`~cll.ledger.store.LedgerStore.import_jsonl` reproduces the exact
same leaf sequence a ``JsonlLogSource``-backed MMR already folded --
recomputing any historical checkpoint root from the migrated store is
therefore byte-identical to what is already persisted in the sibling
``checkpoints.jsonl``, regardless of storage backend. ``tests/
test_ledger_store_migration_invariance.py`` is the mechanical proof of this
for two real, git-tracked demo ledgers.

**Two single-writer logs, unaffected.** This module only ever touches the
sidecar's OWN ledger dir (``NodeState.ledger_dir`` in ``capsule_sidecar.py``)
-- never the Rust plugin's foreign-owned ``<plugin_ledger_dir>/
capsules.jsonl``, which stays exactly as it is today (a flat file, read via
``checkpointing.JsonlLogSource``, read-only from this process). Checkpoint
stamps also stay exactly where they already are, a SIBLING
``checkpoints.jsonl`` file next to whichever ledger backend is in use --
this module never folds a checkpoint stamp into the capsule stream (see
``checkpointing.py``'s own module docstring for why: the Rust plugin's
``Ledger::open()`` replay requires every ``capsules.jsonl`` line to be a
chained, receipted capsule).

**Store layout.** ``LedgerStore(root=ledger_dir, ...)`` uses ``ledger_dir``
itself as the store root: capsule lines move from the old flat
``ledger_dir/capsules.jsonl`` into ``ledger_dir/segments/seg-*.jsonl``, with
a derived ``ledger_dir/index.sqlite3`` + ``index.sqlite`` and a
``ledger_dir/manifest.json`` that a store-aware reader keys its detection
on. Every OTHER sibling file (``checkpoints.jsonl``, ``native_log.jsonl``,
``lifecycle_events.jsonl``, ``sequence_counters.json``, ``signed-
statements/``, ``disclosures/``) is untouched.

**Read-only flat-file fallback, labeled, never silent.** A ledger dir with
no ``manifest.json`` (an older node, a foreign-owned ledger the sidecar
merely inspects, or a static demo/test fixture that was never migrated) is
still fully readable via :func:`read_all_capsules` -- it logs a warning
identifying the fallback rather than silently degrading. Nothing in this
module ever WRITES the legacy flat format; the one-time importer
(:func:`import_flat_ledger_once`) is the only path that ever turns a flat
ledger into a store, and only for the ledger dir the sidecar itself owns
and is about to become the sole writer of.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from cll.ledger.segments import SegmentManifest
from cll.ledger.store import LedgerStore

__all__ = [
    "ARCHIVED_SEGMENT_KIND",
    "CORRELATION_FIELDS",
    "MANIFEST_FILENAME",
    "append_capsule",
    "as_ledger_dir",
    "import_flat_ledger_once",
    "is_store_ledger",
    "materialize_flat_view",
    "open_ledger_store",
    "open_log_source_for_checkpointing",
    "read_all_capsules",
    "read_capsules_page",
]

_LOG = logging.getLogger(__name__)

#: What ``cll.ledger.store.LedgerStore`` names its own bookkeeping file --
#: presence is exactly the store/flat discriminator every reader here (and
#: capsule-emit's own store-aware ``read_ledger``, once it lands) keys on.
MANIFEST_FILENAME = "manifest.json"

#: Declared once, here, so every open of this repo's store (sidecar startup,
#: the checkpoint daemon, a one-off checkpoint tool, a CLI reader) builds the
#: SAME lookup index content -- see ``LedgerStore.__init__``'s
#: ``correlation_fields`` docstring: a non-empty tuple is persisted to
#: ``lookup_config.json`` on first open and read back on every later open
#: that passes an empty one, so passing this constant everywhere is a
#: safety net, not a requirement.
CORRELATION_FIELDS: tuple[str, ...] = ("exchange_id", "capsule_id", "nonce", "counterparty")

#: Marks a synthesized entry in :func:`read_all_capsules`'s raw stream as an
#: unmounted (archived) segment this reader could not open -- never a
#: capsule. Mirrors ``capsule_emit.ledger``'s own ``NON_CAPSULE_KINDS``
#: convention (``checkpoint_stamp`` / ``disclosure_record`` / ``checkpoint_
#: witness_backfill``) so a future capsule-only filter here follows the
#: same shape.
ARCHIVED_SEGMENT_KIND = "archived_segment"

_LEGACY_FLAT_FILENAME = "capsules.jsonl"


def as_ledger_dir(path: Path) -> Path:
    """Normalize the two conventions this repo's CLIs use interchangeably
    for "where is the ledger": a ledger DIRECTORY (this module's own
    convention), or a path to the legacy flat file itself (``.../
    capsules.jsonl`` -- ``native_log_join.py --ledger``, ``trust_summary.py
    --ledger``, and others predate this migration and still document that
    convention). A bare filename match is enough here since this repo never
    names an actual ledger DIRECTORY ``capsules.jsonl``.
    """
    path = Path(path)
    return path.parent if path.name == _LEGACY_FLAT_FILENAME else path


def is_store_ledger(ledger_dir: Path) -> bool:
    """Whether ``ledger_dir`` has already been migrated to a
    :class:`~cll.ledger.store.LedgerStore` -- the store/flat discriminator
    every function in this module keys on."""
    return (as_ledger_dir(ledger_dir) / MANIFEST_FILENAME).exists()


def open_ledger_store(ledger_dir: Path, *, log_id: str = "") -> LedgerStore:
    """Open (creating if new) the :class:`~cll.ledger.store.LedgerStore` at
    ``ledger_dir``, with ``rotate_at_checkpoint=True`` and this repo's
    declared :data:`CORRELATION_FIELDS` -- the exact construction
    ``[mesh-ledger-store-migration]`` specifies. Callers that only need to
    READ (a CLI tool, a one-off checkpoint script) never need to attach a
    :class:`~cll.ledger.segments.Checkpointer` -- that is only required
    before an ``append()`` that would cross the segment's byte threshold;
    see ``capsule_sidecar.NodeState`` for where the live sidecar attaches
    one.
    """
    ledger_dir = as_ledger_dir(ledger_dir)
    return LedgerStore(root=ledger_dir, rotate_at_checkpoint=True, correlation_fields=CORRELATION_FIELDS, log_id=log_id)


def import_flat_ledger_once(ledger_dir: Path, store: LedgerStore, *, flat_filename: str = _LEGACY_FLAT_FILENAME) -> int:
    """One-time migration: if ``ledger_dir/flat_filename`` exists (a
    pre-migration flat ledger) and ``store`` is still empty, import every
    line into ``store``, in file order, via
    :meth:`~cll.ledger.store.LedgerStore.import_jsonl` -- preserving each
    capsule's own ``capsule_id`` untouched, which is what makes every
    historical MMR checkpoint recomputed from ``store`` byte-identical to
    what is already persisted in the sibling ``checkpoints.jsonl`` (see this
    module's docstring). The old flat file is renamed to
    ``<name>.pre-store-migration`` rather than deleted -- auditable and
    reversible, never silently discarded.

    Idempotent and safe to call on every startup: a no-op (returns ``0``)
    once the store already holds records, or when there was never a flat
    file to import in the first place (a brand-new node).
    """
    ledger_dir = as_ledger_dir(ledger_dir)
    flat_path = ledger_dir / flat_filename
    if not flat_path.exists():
        return 0
    if any(True for _ in store.scan()):
        return 0
    count = store.import_jsonl(flat_path, consequential=False)
    flat_path.rename(flat_path.with_name(flat_path.name + ".pre-store-migration"))
    _LOG.warning(
        "imported %d record(s) from legacy flat ledger %s into the LedgerStore at %s "
        "(old file preserved as %s)",
        count, flat_path, ledger_dir, flat_path.name + ".pre-store-migration",
    )
    return count


def open_log_source_for_checkpointing(ledger_dir: Path, *, log_id: str = "") -> Any:
    """The ``LogSource``-shaped object a ``checkpointing.CheckpointState``
    should fold into its MMR for ``ledger_dir`` -- a
    :class:`~cll.ledger.store.LedgerStore` if it has already been migrated,
    else the legacy ``checkpointing.JsonlLogSource`` (read-only flat-file
    fallback, labeled via a warning, never silent) for a foreign-owned or
    not-yet-migrated ledger dir (e.g. the Rust plugin's, which never
    migrates). Used by tools that read whichever backend a ledger dir
    already has, without themselves triggering a migration --
    ``checkpoint_daemon.py`` / ``checkpoint_ledger.py``; the sidecar's own
    startup (``capsule_sidecar.NodeState``) is the only place that performs
    :func:`import_flat_ledger_once`, since it alone owns and is about to
    become the sole writer of its ledger dir.
    """
    ledger_dir = as_ledger_dir(ledger_dir)
    if is_store_ledger(ledger_dir):
        return open_ledger_store(ledger_dir, log_id=log_id)
    from checkpointing import JsonlLogSource

    _LOG.warning(
        "%s has no %s -- checkpointing against it as a legacy flat ledger (read-only fallback)",
        ledger_dir, MANIFEST_FILENAME,
    )
    return JsonlLogSource(ledger_dir / _LEGACY_FLAT_FILENAME)


def _read_flat_capsules_page(
    ledger_dir: Path, *, limit: int | None, after_seq: int, flat_filename: str = _LEGACY_FLAT_FILENAME
) -> tuple[list[dict[str, Any]], int | None]:
    """:func:`read_capsules_page`'s flat-file branch. A flat ledger has no
    persisted ``seq`` column, so this assigns the same synthetic 1-based
    line-order ``seq`` :func:`_read_store_page` gets from the store, and
    stops reading lines the instant it has collected one more than
    ``limit`` -- a real I/O cap on a large legacy ledger, not just a
    post-hoc slice of an already-fully-read list.
    """
    path = ledger_dir / flat_filename
    if not path.exists():
        return [], None
    _LOG.warning(
        "%s has no %s -- reading %s as a legacy flat ledger (read-only fallback)",
        ledger_dir, MANIFEST_FILENAME, flat_filename,
    )
    fetch_cap = None if limit is None else limit + 1
    pairs: list[tuple[int, dict[str, Any]]] = []
    seq = 0
    with path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            seq += 1
            if seq <= after_seq:
                continue
            pairs.append((seq, json.loads(line)))
            if fetch_cap is not None and len(pairs) >= fetch_cap:
                break
    return _trim_page(pairs, limit)


def _trim_page(
    pairs: list[tuple[int, dict[str, Any]]], limit: int | None
) -> tuple[list[dict[str, Any]], int | None]:
    """Shared cursor trim: *pairs* was collected with one extra record past
    *limit* when a next page might exist (the ``fetch_cap = limit + 1``
    sentinel both branches use) -- this drops that sentinel and turns its
    presence into the ``next_after_seq`` cursor, so ``None`` unambiguously
    means "no more records" rather than "happened to stop exactly at the
    cap"."""
    next_after_seq = None
    if limit is not None and len(pairs) > limit:
        pairs = pairs[:limit]
        next_after_seq = pairs[-1][0]
    return [capsule for _seq, capsule in pairs], next_after_seq


def _read_store_page(
    ledger_dir: Path, *, limit: int | None, after_seq: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int | None]:
    """:func:`read_capsules_page`'s store branch -- the segment-walk
    :func:`read_all_capsules` used to do inline, extended with an
    ``after_seq`` cursor and a ``limit`` cap. Never touches
    :meth:`~cll.ledger.store.LedgerStore.scan` (which raises
    :class:`~cll.ledger.segments.SegmentUnmounted` for the WHOLE call the
    instant ANY segment anywhere in the log is archived) -- instead walks
    :meth:`~cll.ledger.store.LedgerStore.list_segments` in append order and
    resolves each MOUNTED segment's own ``[first_seq, last_seq]`` range via
    :meth:`~cll.ledger.store.LedgerStore.by_seq_range` (a bounded SQL lookup
    that only ever touches rows inside that one segment, and -- with a cap
    in play -- only the rows this page still needs), so one archived
    segment never blocks reading the records before or after it, and a
    capped page never opens more of the store than it has to.

    With ``limit=None`` and ``after_seq=0`` this reproduces the pre-paging
    ``_read_store_capsules`` behavior exactly: same segment walk, same
    archived-segment detection, same order -- :func:`read_all_capsules`
    calls it that way rather than keeping a second copy of this walk.
    """
    store = open_ledger_store(ledger_dir)
    try:
        fetch_cap = None if limit is None else limit + 1
        pairs: list[tuple[int, dict[str, Any]]] = []
        archived: list[dict[str, Any]] = []
        next_seq = 1
        for seg in store.list_segments():
            if fetch_cap is not None and len(pairs) >= fetch_cap:
                break
            if seg.manifest is not None:
                manifest = SegmentManifest.from_dict(json.loads((ledger_dir / seg.manifest).read_text()))
                next_seq = manifest.last_seq + 1
                if manifest.last_seq <= after_seq:
                    continue  # entirely before the requested window -- not a gap, just not asked for
                lo = max(manifest.first_seq, after_seq + 1)
                if seg.mounted:
                    hi = manifest.last_seq
                    if fetch_cap is not None:
                        hi = min(hi, lo + (fetch_cap - len(pairs)) - 1)
                    hits = store.by_seq_range(lo, hi)
                    pairs.extend((r.seq, r.capsule) for r in hits)
                else:
                    archived.append(
                        {
                            "kind": ARCHIVED_SEGMENT_KIND,
                            "segment": seg.name,
                            "first_seq": manifest.first_seq,
                            "last_seq": manifest.last_seq,
                            # [mesh-ui-ledger-finder] the segment's own closing
                            # date range -- read off its SegmentManifest (never
                            # moved on unmount, unlike the segment's .jsonl
                            # bytes), so the Finder can list "archived — mount
                            # to view" with a date range without opening the
                            # archived file.
                            "first_ts": manifest.first_ts,
                            "last_ts": manifest.last_ts,
                            "record_count": manifest.record_count,
                            "checkpoint_root": seg.checkpoint_root,
                            "mmr_size": seg.mmr_size,
                            "note": "archived -- mount to view",
                        }
                    )
            else:
                # The active, still-open segment -- always last in append
                # order, always mounted (an unmounted segment is by
                # definition closed). Its own upper bound isn't known without
                # a manifest, so ask for everything from where the previous
                # segment left off (bounded by the cap); by_seq_range is a
                # bounded SQL query, so this never touches an earlier,
                # possibly-archived segment.
                lo = max(next_seq, after_seq + 1)
                hi = lo + 10**9
                if fetch_cap is not None:
                    hi = min(hi, lo + (fetch_cap - len(pairs)) - 1)
                if hi >= lo:
                    hits = store.by_seq_range(lo, hi)
                    pairs.extend((r.seq, r.capsule) for r in hits)
        records, next_after_seq = _trim_page(pairs, limit)
        return records, archived, next_after_seq
    finally:
        store.close()


def read_capsules_page(
    ledger_dir: Path, *, limit: int | None = None, after_seq: int = 0
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int | None]:
    """Capped, paginated :func:`read_all_capsules`: at most *limit* capsule
    records with ``seq > after_seq``, in append order -- store-aware (keys
    on :func:`is_store_ledger`) with the same labeled, read-only flat-file
    fallback as :func:`read_all_capsules`.

    Returns ``(records, archived_segments, next_after_seq)``. ``next_after_seq``
    is the ``after_seq`` to pass for the following page, or ``None`` when
    this page reached the end of the log (never ``None`` merely because the
    page happened to land exactly on the cap -- a one-record lookahead
    disambiguates the two). ``archived_segments`` carries the same
    ``{kind, segment, first_seq, ...}`` gap descriptors as
    :func:`read_all_capsules`, scoped to segments whose range overlaps the
    requested window -- never raises
    :class:`~cll.ledger.segments.SegmentUnmounted`.

    ``limit=None`` (the default) returns everything from ``after_seq``
    onward in one page, same as calling :func:`read_all_capsules` with
    ``after_seq=0``.
    """
    ledger_dir = as_ledger_dir(ledger_dir)
    if is_store_ledger(ledger_dir):
        return _read_store_page(ledger_dir, limit=limit, after_seq=after_seq)
    records, next_after_seq = _read_flat_capsules_page(ledger_dir, limit=limit, after_seq=after_seq)
    return records, [], next_after_seq


def read_all_capsules(ledger_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Every capsule record in ``ledger_dir``, in append order --
    store-aware (keys on :func:`is_store_ledger`) with a labeled, read-only
    flat-file fallback for a ledger dir with no manifest.

    Returns ``(records, archived_segments)``. ``archived_segments`` is
    always ``[]`` for a flat ledger; for a store, it carries one
    ``{kind, segment, first_seq, last_seq, first_ts, last_ts, record_count,
    checkpoint_root, mmr_size, note}`` dict per unmounted segment this
    reader could not open -- never raises
    :class:`~cll.ledger.segments.SegmentUnmounted`, and
    never silently drops an archived segment's existence even though its
    content isn't available (the rotation-demo acceptance line: "unmount
    one -> readers report archived -- mount to view, never a 500").

    Thin, uncapped call to :func:`read_capsules_page` -- one segment-walk
    implementation shared by both entry points, never two that can drift.
    """
    records, archived, _next_after_seq = read_capsules_page(ledger_dir)
    return records, archived


def synthesize_checkpoint_stamp_lines(ledger_dir: Path) -> list[str]:
    """One ``capsule_emit.ledger.CHECKPOINT_STAMP_KIND`` JSON line per
    persisted checkpoint in ``ledger_dir/checkpoints.jsonl`` (``[]`` if that
    sibling file doesn't exist) -- the shape ``capsule_emit.witness.
    _persist_checkpoint_stamp`` writes for a self-checkpointed ledger.

    This repo's own checkpointing (``checkpointing.CheckpointState``, either
    over a flat ledger or this migration's ``LedgerStore``) deliberately
    keeps every checkpoint in that SIBLING file, out-of-band from the
    capsule stream -- see ``checkpointing.py``'s module docstring for why
    (the Rust plugin's strict ``Ledger::open()`` replay would break if a
    checkpoint-stamp line were interleaved into ``capsules.jsonl``).
    ``capsule_emit.bundle.bundle()`` (what ``evidence_request.answer()``
    dispatches to) only ever recognizes a checkpoint that arrives IN-BAND,
    though -- so a caller handing capsule-emit a flat view of this repo's
    ledger (:func:`materialize_flat_view`, ``evidence_server.
    _merged_evidence_view``) must fold these in after the real capsule
    lines, in checkpoint order, never interleaved before the leaves each
    one covers (which would shift every later leaf's ``seq`` and invalidate
    inclusion proofs the checkpoint never covered).
    """
    checkpoints_path = ledger_dir / "checkpoints.jsonl"
    if not checkpoints_path.exists():
        return []

    from capsule_emit.checkpoint import CheckpointRecord
    from capsule_emit.ledger import CHECKPOINT_STAMP_KIND

    stamp_lines: list[str] = []
    for raw in checkpoints_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        cp_line = json.loads(raw)
        checkpoint_cose_hex = cp_line.pop("checkpoint_cose", None)
        cp = CheckpointRecord.from_dict(cp_line)
        stamp_entry: dict[str, Any] = {
            "kind": CHECKPOINT_STAMP_KIND,
            "v": 1,
            "capsule_id": cp.entry_digest(),
            "checkpoint": cp.to_dict(),
        }
        if checkpoint_cose_hex is not None:
            stamp_entry["checkpoint_cose"] = checkpoint_cose_hex
        stamp_lines.append(json.dumps(stamp_entry, sort_keys=True))
    return stamp_lines


def materialize_flat_view(ledger_dir: Path) -> Path:
    """A flat JSONL file path holding every capsule in ``ledger_dir``, in
    append order, PLUS one synthesized in-band checkpoint-stamp line per
    entry in the sibling ``checkpoints.jsonl`` (see
    :func:`synthesize_checkpoint_stamp_lines`) -- for handing to a
    ``capsule_emit`` function that only understands a flat, self-
    checkpointed file (``read_ledger``, ``evidence_request.answer``,
    ``signing.resolve_signer``), without capsule-emit itself needing to
    learn this repo's store layout or its out-of-band checkpoint
    convention.

    Fast path: an already-flat ledger dir with no checkpoints.jsonl has
    nothing to bridge, so this returns the real ``capsules.jsonl`` path
    unchanged (no copy) -- matching pre-migration behavior exactly for a
    node that never adopted either the store or checkpointing. Otherwise a
    FRESH scratch tempfile, never cached (mirrors ``evidence_server.
    _merged_evidence_view``'s own "re-derive every call" discipline) -- the
    real ledger (store or flat) is never mutated. Archived segments are
    silently excluded from the flat view (the caller only ever gets what's
    actually mounted); a caller that needs to know about the gap should
    call :func:`read_all_capsules` directly instead.
    """
    ledger_dir = as_ledger_dir(ledger_dir)
    stamp_lines = synthesize_checkpoint_stamp_lines(ledger_dir)
    if not is_store_ledger(ledger_dir) and not stamp_lines:
        return ledger_dir / _LEGACY_FLAT_FILENAME

    records, _archived = read_all_capsules(ledger_dir)

    import tempfile

    fd, tmp_name = tempfile.mkstemp(prefix="ledger-flat-view-", suffix=".jsonl")
    tmp_path = Path(tmp_name)
    with open(fd, "w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
        for stamp_line in stamp_lines:
            fh.write(stamp_line + "\n")
    return tmp_path


def append_capsule(ledger_dir: Path, capsule: dict[str, Any]) -> None:
    """Append one already-sealed capsule dict to whichever ledger backend
    ``ledger_dir`` already has -- for a one-off write from a process that
    doesn't hold this ledger's long-lived store handle (e.g.
    ``adjudication_delivery.handle_delivery``, invoked per-HTTP-request by
    the standalone ``evidence_server.py``).

    No :class:`~cll.ledger.segments.Checkpointer` is attached for this
    one-off open, so IF this specific append happens to be the one that
    crosses the segment's byte threshold, it raises
    :class:`~cll.ledger.segments.SegmentRotationError` rather than silently
    skipping rotation -- loud, not a data-loss risk (the record is not
    written until rotation succeeds), and exceedingly rare in practice
    (256 MiB default threshold) for a delivery path this infrequent. The
    live sidecar's own append path (``capsule_sidecar.record_capsule``)
    goes through its own long-lived, checkpointer-attached store instead --
    see ``NodeState.__post_init__``.
    """
    ledger_dir = as_ledger_dir(ledger_dir)
    if is_store_ledger(ledger_dir):
        store = open_ledger_store(ledger_dir)
        try:
            store.append(capsule)
        finally:
            store.close()
        return
    from checkpointing import JsonlLogSource

    JsonlLogSource(ledger_dir / _LEGACY_FLAT_FILENAME).append(capsule)

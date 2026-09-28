"""Padding records in a node's ``capsules.jsonl`` (Evidence Layer -00 §12.1,
"What a Checkpoint Reveals").

Before a checkpoint leaves the node, the Rust plugin appends padding records
so the checkpoint's leaf count falls on a bucket boundary (see
``plugins/capsule-producer/src/padding.rs``). A padding record is one ledger
line -- ``{"capsule_id", "record_type": "padding", "epistemic_type":
"producer_claim", "store_nonce"}`` plus the local-only producer envelope --
and it sits OUTSIDE the chain: nothing links to it.

The rule for readers here: anything that folds the MMR, computes a leaf
position, or checks inclusion/consistency treats a padding line as an
ordinary leaf (never drop it before indexing). Anything that counts, lists,
summarises, or answers a ``record``/``correlation``/``exchange`` query
skips it.

PROVISIONAL: ``record_type: "padding"`` is reserved by the Evidence Layer -00
draft text; it is a provisional constant pending the evidence-layer privacy
considerations text.
"""

from __future__ import annotations

import os
from typing import Any, Iterable

#: The reserved ``record_type`` token (provisional -- see the module doc).
PADDING_RECORD_TYPE = "padding"


def is_padding_record(record: Any) -> bool:
    """True when *record* is a padding line (never a record to count)."""
    return isinstance(record, dict) and record.get("record_type") == PADDING_RECORD_TYPE


def without_padding(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """*records* in order, padding lines dropped. Only for counting/listing:
    never call this before computing a leaf position."""
    return [r for r in records if not is_padding_record(r)]


#: Set to ``1`` to let a Python checkpointer register UNPADDED checkpoints
#: with a witness anyway (a deliberate, per-process operator choice).
ALLOW_UNPADDED_WITNESSING_ENV = "CAPSULE_EMIT_MESH_ALLOW_UNPADDED_WITNESSING"


class UnpaddedWitnessingRefused(RuntimeError):
    """A Python checkpointer was configured to send checkpoints to a witness."""


def refuse_unpadded_witnessing(ts_urls: Iterable[str], *, who: str) -> None:
    """Gate for the Python checkpoint paths (``checkpoint_daemon.py``,
    ``checkpoint_ledger.py``, ``capsule_sidecar.py``'s own cadences).

    Only the Rust plugin pads its ledger before a checkpoint (Evidence Layer
    -00 §12.1). The Python checkpointers cut at whatever size the log has, so
    a checkpoint they hand to a witness reveals the exact record count
    between two checkpoints. A local-only checkpoint (no witness URL) never
    leaves the node through this path and stays allowed; witnessing is
    refused unless the operator sets ``ALLOW_UNPADDED_WITNESSING_ENV=1``."""
    urls = [u for u in ts_urls if u]
    if urls and os.environ.get(ALLOW_UNPADDED_WITNESSING_ENV) != "1":
        raise UnpaddedWitnessingRefused(
            f"{who}: refusing to register unpadded checkpoints with {', '.join(urls)} -- this Python "
            "checkpointer does not pad the log (Evidence Layer -00 §12.1), so a witness would learn the "
            "exact record count between checkpoints. Run the Rust plugin's checkpoint cadence instead, "
            f"drop the witness URL to stay local-only, or set {ALLOW_UNPADDED_WITNESSING_ENV}=1 to accept it."
        )

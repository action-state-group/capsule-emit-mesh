"""The default witness's public key, pinned for offline stamp verification.

checkpointed-local-log before 0.5 pinned its default witness
(``DEFAULT_TS_URL``) to its known key (``DEFAULT_TS_PUBLIC_KEY_PEM``) inside
``verify_witness_stamp_tristate``. From 0.5 it trusts only the keys a caller
passes, so every Mesh caller passes this pin explicitly and grades stamps as
before: WITNESSED under the default witness's key, INVALID for a receipt that
claims the default witness but does not verify under it, and UNVERIFIED for any
other witness. No other witness is pinned.
"""
from __future__ import annotations

from capsule_emit.checkpoint import emit as _checkpoint_emit


def default_witness_pin(ts_url: str | None) -> bytes | None:
    """The default witness's key when ``ts_url`` is the default witness, else
    ``None``. Read at call time, so a test that repoints the default witness is
    honored."""
    if ts_url == _checkpoint_emit.DEFAULT_TS_URL:
        return _checkpoint_emit.DEFAULT_TS_PUBLIC_KEY_PEM
    return None

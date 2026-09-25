# SPDX-License-Identifier: Apache-2.0
"""[mesh-sharing-policy-v0] The one sharing-policy object -- four switches,
one key. See ``docs/SHARING-POLICY.md`` (moved from the design note,
``_work/mesh-sharing-policy-history-and-money-2026-09-24.md`` §1) for the
full rationale; this module owns the SHAPE and the process-local env-var
bridge only.

Every sharing decision a node makes is one of four, and every default keys
on RELATIONSHIP (counterparty in the window), never on proximity, latency,
or any computed standing -- nothing here is a score, and nothing here ranks
anyone.

Each switch's actual enforcement lives where the decision is made, never
here: ``evidence_responder.py`` decides ``record``/``correlation``/
``chain_segment`` answers by ``history_segments``; ``record_push.py`` decides
push-at-completion by ``record_at_completion``; a future
``deliver_to_subjects`` gate (``[mesh-adjudications-on-history-card-design]``)
decides by ``adjudications``. This module never itself refuses or answers a
request.

**Backward-compatible by construction.** :func:`share_policy_from_env`
returns ``None`` -- "no policy configured, do not gate anything" -- when
NONE of the four ``ADMISSION_POLICY_SHARE_*``/``ADMISSION_POLICY_WITNESS``
env vars are set on this process. A node that has never touched sharing
policy configuration is unaffected by this module's existence, byte for
byte, including every caller that predates it. The moment ANY one of the
four is set, every field resolves to either its explicit value or this
module's own documented default -- never a partially-built policy object,
and an invalid enum value is a loud ``ValueError`` naming the offending
var, never a silent coercion to a default the operator did not ask for.
Whether/when a real deployment actually sets these vars -- i.e. whether the
documented defaults go live -- is the release decision the gate note on
[mesh-sharing-policy-v0] reserves for Steven; shipping this module does not
by itself flip anyone's runtime behavior.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = [
    "RECORD_AT_COMPLETION_VALUES",
    "HISTORY_SEGMENTS_VALUES",
    "ADJUDICATIONS_VALUES",
    "SharePolicy",
    "DEFAULT_SHARE_POLICY",
    "share_policy_from_env",
    "ENV_RECORD_AT_COMPLETION",
    "ENV_HISTORY_SEGMENTS",
    "ENV_ADJUDICATIONS",
    "ENV_WITNESS",
]

RECORD_AT_COMPLETION_VALUES = frozenset({"counterparty", "off"})
HISTORY_SEGMENTS_VALUES = frozenset({"counterparties", "prospective", "peers", "off"})
ADJUDICATIONS_VALUES = frozenset({"deliver_to_subjects", "off"})

#: Env vars this process reads its policy from -- named to match the Rust
#: `admission-policy` plugin's `config_schema` setting keys 1:1
#: (`plugins/admission-policy/src/main.rs`), same `ADMISSION_POLICY_*`
#: prefix convention as this repo's existing `ADMISSION_POLICY_BLOCKED_MODELS`/
#: `ADMISSION_POLICY_EVIDENCE_SERVER_URL`. **Known gap, not hidden**: the
#: plugin's `config_schema` only renders these in the host's own
#: Configuration > Plugins UI for an operator to edit -- there is no live
#: host-to-plugin-process config channel wired yet (mesh-llm 0.76 gives a
#: plugin its OWN declared config, not a generic passthrough to a sibling
#: process's env), so today an operator sets these directly in the node's
#: environment. Wiring the host's resolved config value into this process's
#: env is separate, later plumbing -- not a claim this module makes about
#: itself.
ENV_RECORD_AT_COMPLETION = "ADMISSION_POLICY_SHARE_RECORD_AT_COMPLETION"
ENV_HISTORY_SEGMENTS = "ADMISSION_POLICY_SHARE_HISTORY_SEGMENTS"
ENV_ADJUDICATIONS = "ADMISSION_POLICY_SHARE_ADJUDICATIONS"
ENV_WITNESS = "ADMISSION_POLICY_WITNESS"

_SHARE_ENV_VARS = (ENV_RECORD_AT_COMPLETION, ENV_HISTORY_SEGMENTS, ENV_ADJUDICATIONS, ENV_WITNESS)


@dataclass(frozen=True)
class SharePolicy:
    """One node's own copy of the four switches. ``witness`` is ``None`` for
    ``off`` (never the string ``"off"`` -- ``None`` is what every consumer
    checks for "witnessing is off"), else the witness service URL."""

    record_at_completion: str = "counterparty"
    history_segments: str = "prospective"
    adjudications: str = "deliver_to_subjects"
    witness: str | None = None


#: The documented defaults (design note §1), as a ready-to-use object for a
#: caller that wants "the defaults" without going through the env at all
#: (e.g. a test, or a caller that resolves policy some other way).
DEFAULT_SHARE_POLICY = SharePolicy()


def _read_enum(var: str, allowed: frozenset[str], default: str) -> str:
    raw = os.environ.get(var)
    if not raw:
        return default
    if raw not in allowed:
        raise ValueError(f"{var}={raw!r} is not one of {sorted(allowed)}")
    return raw


def share_policy_from_env() -> SharePolicy | None:
    """Build a :class:`SharePolicy` from this process's own environment, or
    ``None`` when none of the four vars are set at all -- see the module
    docstring's "backward-compatible by construction" note. Raises
    ``ValueError`` for a set-but-invalid enum value (``ENV_WITNESS`` is a
    free-form URL, never validated as an enum)."""
    if not any(os.environ.get(var) for var in _SHARE_ENV_VARS):
        return None
    return SharePolicy(
        record_at_completion=_read_enum(
            ENV_RECORD_AT_COMPLETION, RECORD_AT_COMPLETION_VALUES, DEFAULT_SHARE_POLICY.record_at_completion
        ),
        history_segments=_read_enum(
            ENV_HISTORY_SEGMENTS, HISTORY_SEGMENTS_VALUES, DEFAULT_SHARE_POLICY.history_segments
        ),
        adjudications=_read_enum(
            ENV_ADJUDICATIONS, ADJUDICATIONS_VALUES, DEFAULT_SHARE_POLICY.adjudications
        ),
        witness=os.environ.get(ENV_WITNESS) or None,
    )

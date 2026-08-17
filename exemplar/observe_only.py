#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
ObserveOnlyPlugin — mesh.openai.exchange.v1 exemplar, observe-only mode.

Subscribes to all three lifecycle phases.  Returns abstain at every decision
point.  Emits one HookRecord per phase.  Never influences the exchange.

BODY ACCESS DENIED BEHAVIOR
    If the host withholds body access (body_access_granted=False), this plugin
    raises BodyAccessDenied.  It does NOT silently return abstain.

    Why: an observe-only plugin that silently returns abstain when its body
    grant is missing is a fail-toward-reassurance shape.  It produces a
    confident decision (abstain, exchange continues) while observing nothing —
    the operator sees a green record with no indication that the observation
    was incomplete.  That is the exact failure this exemplar must not model.

    Returning abstain is only correct when the plugin actually observed the
    exchange.  If the observation is impossible, the plugin must say so loudly
    so the host can record the failure rather than a spurious success.
"""
from __future__ import annotations

import hashlib

from exemplar.plugin_contract import (
    ABSTAIN,
    CONTRACT,
    BodyAccessDenied,
    HookRecord,
    Manifest,
    PhaseContext,
    PluginDecision,
)

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = Manifest(
    contract=CONTRACT,
    endpoints=["/v1/chat/completions"],
    phases=["request_received", "backend_selected", "exchange_finished"],
    # Authorization and Cookie are intentionally absent — see #1331 acceptance.
    sanitized_headers=["content-type", "x-request-id"],
    decision_mode="observe_only",
    response_metadata={
        "include_exchange_id": True,
        "include_terminal_state": True,
    },
)


# ---------------------------------------------------------------------------
# Plugin implementation
# ---------------------------------------------------------------------------

class ObserveOnlyPlugin:
    """An observe-only plugin that records each phase and always returns abstain.

    The plugin never returns deny.  The host must be able to verify this
    property by inspecting plugin.records after a run — every record must
    have decision == "abstain".
    """

    manifest = MANIFEST

    def __init__(self) -> None:
        self.records: list[HookRecord] = []

    def on_phase(self, ctx: PhaseContext) -> PluginDecision:
        """Hook called by the host at each lifecycle phase.

        Returns abstain.  Raises BodyAccessDenied if the host withheld body
        access — not silently, because silently returning abstain while
        observing nothing is the fail-toward-reassurance shape this exemplar
        exists to document.
        """
        if not ctx.body_access_granted:
            raise BodyAccessDenied(
                f"observe-only plugin requires body access to record a "
                f"meaningful observation at phase={ctx.phase!r}; "
                f"host config withheld it for exchange_id={ctx.exchange_id!r}. "
                f"Returning abstain here would silently produce an empty "
                f"observation record — that is the fail-toward-reassurance "
                f"shape this plugin explicitly rejects."
            )

        body_digest = hashlib.sha256(ctx.body).hexdigest()
        record = HookRecord(
            exchange_id=ctx.exchange_id,
            phase=ctx.phase,
            decision=ABSTAIN,
            body_digest=body_digest,
            body_access_granted=True,
        )
        self.records.append(record)
        return ABSTAIN

    def clear(self) -> None:
        self.records.clear()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
AdmissionPolicyPlugin — mesh.openai.exchange.v1 exemplar, admission-policy mode.

Returns deny at REQUEST_RECEIVED when the request body names a blocked model.
The denied request never reaches the backend (BACKEND_DISPATCH is not reached).

DENIAL CONDITION
    Any request whose body contains {"model": "blocked-<anything>"} is denied.
    The condition is parsed from the body, not matched against a header or URL.
    This demonstrates that the plugin actually reads the body — not that it
    performs a surface-level gate based on something available without body
    access.

BODY ACCESS DENIED BEHAVIOR
    If the host withholds body access (body_access_granted=False), this plugin
    raises BodyAccessDenied.  It does NOT silently return abstain.

    Why: returning abstain when body access is denied would be fail-open.
    A request carrying a blocked model name would reach the backend unchecked.
    The operator would see a green record with no indication that the
    admission check was skipped entirely.  The only safe failure mode for an
    admission-policy plugin that cannot read the body is a loud error.
"""
from __future__ import annotations

import hashlib
import json

from exemplar.plugin_contract import (
    ABSTAIN,
    DENY,
    CONTRACT,
    BodyAccessDenied,
    HookRecord,
    Manifest,
    PhaseContext,
    PluginDecision,
)

# ---------------------------------------------------------------------------
# Denial condition
# ---------------------------------------------------------------------------

BLOCKED_MODEL_PREFIX = "blocked-"

# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

MANIFEST = Manifest(
    contract=CONTRACT,
    endpoints=["/v1/chat/completions"],
    phases=["request_received", "backend_selected", "exchange_finished"],
    # Authorization and Cookie are intentionally absent — see #1331 acceptance.
    sanitized_headers=["content-type", "x-request-id"],
    decision_mode="admission_policy",
    response_metadata={
        "include_exchange_id": True,
        "include_terminal_state": True,
        "include_deny_reason": True,
    },
)

# Stable OpenAI-shaped error body returned to the client on denial.
DENIAL_RESPONSE_BODY = (
    b'{"error":{"code":"policy_denied",'
    b'"message":"request rejected by plugin admission policy",'
    b'"type":"invalid_request_error","param":null}}'
)


# ---------------------------------------------------------------------------
# Plugin implementation
# ---------------------------------------------------------------------------

class AdmissionPolicyPlugin:
    """An admission-policy plugin that denies requests for blocked models.

    Denial fires only at REQUEST_RECEIVED and only when the body is parseable
    JSON with a "model" field that starts with BLOCKED_MODEL_PREFIX.  All
    other phases receive abstain.
    """

    manifest = MANIFEST

    def __init__(self) -> None:
        self.records: list[HookRecord] = []

    def on_phase(self, ctx: PhaseContext) -> PluginDecision:
        """Hook called by the host at each lifecycle phase.

        Raises BodyAccessDenied if the host withheld body access — returning
        abstain here would be fail-open: blocked requests would silently reach
        the backend.
        """
        if not ctx.body_access_granted:
            raise BodyAccessDenied(
                f"admission-policy plugin cannot evaluate policy at "
                f"phase={ctx.phase!r} without body access; "
                f"host config withheld it for exchange_id={ctx.exchange_id!r}. "
                f"Returning abstain would be fail-open: a request that should "
                f"have been denied would silently reach the backend."
            )

        if ctx.phase != "request_received":
            # Admission decisions are made only at REQUEST_RECEIVED.
            # Phases after dispatch use abstain unconditionally.
            self.records.append(HookRecord(
                exchange_id=ctx.exchange_id,
                phase=ctx.phase,
                decision=ABSTAIN,
                body_digest=hashlib.sha256(ctx.body).hexdigest(),
                body_access_granted=True,
            ))
            return ABSTAIN

        # --- REQUEST_RECEIVED: evaluate admission policy ---
        try:
            request = json.loads(ctx.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            # Malformed body: cannot evaluate safely.  Deny is the safe choice.
            record = HookRecord(
                exchange_id=ctx.exchange_id,
                phase=ctx.phase,
                decision=DENY,
                body_digest=None,
                body_access_granted=True,
                deny_reason=f"body_parse_failure: {exc}",
            )
            self.records.append(record)
            return DENY

        model = request.get("model", "")
        if isinstance(model, str) and model.startswith(BLOCKED_MODEL_PREFIX):
            deny_reason = f"blocked_model_prefix: {model!r} matches '{BLOCKED_MODEL_PREFIX}*' policy"
            record = HookRecord(
                exchange_id=ctx.exchange_id,
                phase=ctx.phase,
                decision=DENY,
                body_digest=hashlib.sha256(ctx.body).hexdigest(),
                body_access_granted=True,
                deny_reason=deny_reason,
            )
            self.records.append(record)
            return DENY

        self.records.append(HookRecord(
            exchange_id=ctx.exchange_id,
            phase=ctx.phase,
            decision=ABSTAIN,
            body_digest=hashlib.sha256(ctx.body).hexdigest(),
            body_access_granted=True,
        ))
        return ABSTAIN

    def clear(self) -> None:
        self.records.clear()

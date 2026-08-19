#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
openai_exchange_hook contract — mesh.openai.exchange.v1

Defines the manifest structure, per-call context, and decision protocol for
the openai_exchange_hook contract as described in mesh-llm#1331.

This module has NO dependency on the mock lifecycle host (mock_lifecycle_host.py)
or any other mesh-llm crate code.  It is the standalone interface definition that
a separately-scoped plugin ONLY needs in order to implement the contract.

MANIFEST IS A REQUEST, NOT A GRANT
    The Manifest block is a plugin's request for access.  The host evaluates
    it and may withhold body access, restrict header visibility, or refuse to
    load the plugin entirely, regardless of what the manifest declares.  A
    plugin MUST handle body_access_granted=False and fail LOUDLY — not silently
    return abstain while observing nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Contract identifier — must match exactly for the host to load the plugin.
# ---------------------------------------------------------------------------

CONTRACT = "mesh.openai.exchange.v1"


# ---------------------------------------------------------------------------
# Decision values
# ---------------------------------------------------------------------------

ABSTAIN = "abstain"
DENY    = "deny"

#: Type alias for the string a plugin returns from on_phase().
PluginDecision = str


# ---------------------------------------------------------------------------
# Manifest — the plugin's request for access
# ---------------------------------------------------------------------------

@dataclass
class Manifest:
    """The plugin's declared contract for the openai_exchange_hook.

    Each field is a REQUEST.  The host is free to grant a subset or nothing.
    Do not read these fields as "what the plugin will receive."

    contract          : must equal CONTRACT.  The host verifies this before
                        loading.
    endpoints         : which HTTP paths the plugin wants to see.
    phases            : which lifecycle phases the plugin wants to be called
                        for.  Values are LifecyclePhase string values:
                        "request_received", "backend_selected",
                        "exchange_finished".
    sanitized_headers : which request headers the plugin may read.  The host
                        strips all others — including any header not on this
                        list — before calling the plugin.  Authorization and
                        Cookie MUST NOT appear here (#1331 makes their
                        exclusion its own acceptance box).
    decision_mode     : "observe_only" or "admission_policy".  Signals the
                        host what kind of decisions the plugin intends to make.
                        observe_only plugins are not called at decision points
                        where the host cannot tolerate a latency budget hit;
                        admission_policy plugins are called pre-dispatch and
                        may return deny.
    response_metadata : which fields from the terminal exchange record the
                        plugin expects to receive after exchange_finished.
    """
    contract: str
    endpoints: list[str]
    phases: list[str]
    sanitized_headers: list[str]
    decision_mode: str
    response_metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# Host configuration — controls what the host actually grants
# ---------------------------------------------------------------------------

@dataclass
class HostConfig:
    """Host-side access policy for a loaded plugin.

    body_access_granted
        Whether the host will supply request/response body bytes to the
        plugin.  When False, PhaseContext.body is None and
        PhaseContext.body_access_granted is False.

        A plugin that returns abstain when body access is denied is the
        fail-toward-reassurance shape: it produces a confident decision
        (abstain) while observing nothing.  Both plugin implementations in
        this exemplar raise BodyAccessDenied instead.  The host treats that
        exception as a plugin error (EVIDENCE_UNAVAILABLE/internal_hook_failure),
        not as a decision.
    """
    body_access_granted: bool = True


# ---------------------------------------------------------------------------
# Phase context — what the host passes to on_phase()
# ---------------------------------------------------------------------------

@dataclass
class PhaseContext:
    """Context the host provides to the plugin at each lifecycle phase call.

    exchange_id
        Opaque identifier for this exchange.  Stable across all three phase
        calls for one exchange.
    phase
        The lifecycle phase at which this call occurs.  One of the string
        values from mock_lifecycle_host.LifecyclePhase.
    endpoint
        The HTTP path for this exchange (e.g. "/v1/chat/completions").
    sanitized_headers
        The subset of request headers the host grants to this plugin.
        Already filtered against Manifest.sanitized_headers AND the host's
        own policy.  Authorization and Cookie are never present.
    body
        The raw request body bytes at this phase, or None if the host has
        withheld body access (body_access_granted is False).
    body_access_granted
        Explicit signal from the host.  True means the host passed body bytes.
        False means the host chose not to.  A plugin MUST check this and
        raise BodyAccessDenied if it cannot function without the body.
    """
    exchange_id: str
    phase: str
    endpoint: str
    sanitized_headers: dict[str, str]
    body: bytes | None
    body_access_granted: bool


# ---------------------------------------------------------------------------
# Hook record — the plugin's internal log of each phase call
# ---------------------------------------------------------------------------

@dataclass
class HookRecord:
    """One entry in a plugin's internal observation log.

    Emitted by the plugin itself (not by the host) for each phase call.
    Records the decision the plugin returned so the test suite can verify
    that observe-only always returned abstain and admission-policy returned
    deny exactly when the condition was met.
    """
    exchange_id: str
    phase: str
    decision: PluginDecision
    body_digest: str | None   # sha256 hex of body bytes, or None
    body_access_granted: bool
    deny_reason: str | None = None
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class BodyAccessDenied(RuntimeError):
    """Raised by a plugin when the host withheld body access it requires.

    This is the LOUD failure the exemplar mandates.  A plugin that silently
    returns abstain when its body grant is missing is a fail-toward-reassurance
    shape — it produces a confident output (abstain) while observing nothing.

    The host must catch this exception and treat it as a plugin error
    (terminal_state=EVIDENCE_UNAVAILABLE, terminal_reason=internal_hook_failure).
    It is NOT a deny decision; it is a hook failure.

    The message must be informative enough that an operator can diagnose the
    issue from the error log alone, without reading the plugin source.
    """

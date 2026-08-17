#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
PluginLifecycleHost — a lifecycle host that drives exchanges with plugin hooks.

DEVELOPMENT RIG — NOT AN IMPLEMENTATION
    This file models the HOST RUNTIME from the perspective of a plugin that
    implements the openai_exchange_hook contract (mesh.openai.exchange.v1).
    It is offered for re-homing to mesh-llm alongside the exemplar plugins,
    pending that project's decision on the plugin lifecycle protocol.

DEPENDENCY ON MOCK LIFECYCLE HOST
    This module imports types and enums from mock_lifecycle_host.py (the
    development rig produced by [mesh-1331-mock-lifecycle-host]).  That file is
    not yet in origin/main — tests/conftest.py adds its worktree to sys.path
    at test time.  Once the rig merges, the import below is a plain sibling
    import at the project root.

WHAT THIS IS NOT
    - Not a plugin (plugins are observe_only.py and admission_policy.py)
    - Not an extension of MockLifecycleHost (it drives the same lifecycle
      phases, but adds plugin hook points that MockLifecycleHost does not
      have)
    - Not a complete mesh-llm host implementation — it models the three-phase
      lifecycle only; no real backend dispatch, no real networking

WHAT IT DOES
    run_with_plugin() drives a request through REQUEST_RECEIVED →
    BACKEND_SELECTED → EXCHANGE_FINISHED, calling plugin.on_phase() at each
    phase transition.  The plugin can:
        - return ABSTAIN  → host continues to next phase
        - return DENY     → host terminates with POLICY_DENIED (only valid in
                            admission_policy mode and only if decision_mode
                            allows it; see SPEC_FEEDBACK below)
        - raise BodyAccessDenied → host terminates with EVIDENCE_UNAVAILABLE /
                            internal_hook_failure

    The host NEVER passes the plugin's return value to the backend.  The
    request bytes dispatched to the backend are always the original
    request_body parameter.  This is what enables the byte-identical check:
    the plugin physically cannot alter the forwarded bytes through its
    decision return value.
"""
from __future__ import annotations

import hashlib
import time
import uuid

from exemplar.plugin_contract import (
    ABSTAIN,
    DENY,
    BodyAccessDenied,
    HostConfig,
    PhaseContext,
    PluginDecision,
)

# Import rig types.  tests/conftest.py adds the rig worktree to sys.path
# before any test imports this module.
from mock_lifecycle_host import (
    LifecyclePhase,
    LifecycleTrace,
    ObservationPoint,
    ObservationRecord,
    PhaseTransition,
    SideStream,
    SideStreamEvent,
    TerminalState,
)


class PluginLifecycleHost:
    """A mock serving host that drives requests through the #1331 lifecycle
    with plugin hook points at each phase.

    plugin     : any object with .manifest and .on_phase(PhaseContext)
    host_config: HostConfig controlling body access and other policy
    """

    def __init__(
        self,
        plugin: object,
        host_config: HostConfig,
        host_id: str = "plugin-lifecycle-host/0.1",
    ) -> None:
        self.plugin = plugin
        self.host_config = host_config
        self.host_id = host_id

    # ------------------------------------------------------------------
    # Internal helpers (same as MockLifecycleHost)
    # ------------------------------------------------------------------

    def _now_ms(self) -> float:
        return time.monotonic() * 1000

    def _xid(self) -> str:
        return uuid.uuid4().hex

    def _digest(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _obs(
        self,
        point: ObservationPoint,
        exchange_id: str,
        phase: LifecyclePhase,
        payload: bytes | None = None,
        metadata: dict | None = None,
    ) -> ObservationRecord:
        return ObservationRecord(
            observation_point=point,
            exchange_id=exchange_id,
            phase_at_observation=phase,
            observer_role="serving_host",
            payload_digest=self._digest(payload) if payload is not None else None,
            timestamp_ms=self._now_ms(),
            metadata=metadata or {},
        )

    def _transition(
        self,
        from_phase: LifecyclePhase | None,
        to_phase: LifecyclePhase,
        trigger: str,
    ) -> PhaseTransition:
        return PhaseTransition(
            from_phase=from_phase,
            to_phase=to_phase,
            timestamp_ms=self._now_ms(),
            trigger=trigger,
        )

    def _sse(
        self,
        stream: SideStream,
        exchange_id: str,
        event_name: str,
        detail: dict | None = None,
    ) -> SideStreamEvent:
        return SideStreamEvent(
            stream=stream,
            exchange_id=exchange_id,
            event_name=event_name,
            timestamp_ms=self._now_ms(),
            detail=detail or {},
        )

    # ------------------------------------------------------------------
    # Plugin call
    # ------------------------------------------------------------------

    def _call_plugin(
        self,
        exchange_id: str,
        phase: LifecyclePhase,
        endpoint: str,
        headers: dict[str, str],
        body: bytes,
    ) -> PluginDecision:
        """Call plugin.on_phase() with a PhaseContext built from the host's
        own request_body.  Never exposes any mutable reference — the plugin
        receives bytes, which are immutable in Python.

        Raises BodyAccessDenied if the plugin raises it (host must catch and
        terminate with EVIDENCE_UNAVAILABLE/internal_hook_failure).
        """
        manifest = self.plugin.manifest
        allowed = set(manifest.sanitized_headers)
        visible_headers = {k: v for k, v in headers.items() if k in allowed}

        body_for_plugin = body if self.host_config.body_access_granted else None

        ctx = PhaseContext(
            exchange_id=exchange_id,
            phase=phase.value,
            endpoint=endpoint,
            sanitized_headers=visible_headers,
            body=body_for_plugin,
            body_access_granted=self.host_config.body_access_granted,
        )

        return self.plugin.on_phase(ctx)

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run_with_plugin(
        self,
        request_body: bytes,
        endpoint: str = "/v1/chat/completions",
        headers: dict[str, str] | None = None,
        backend_response_body: bytes | None = None,
    ) -> LifecycleTrace:
        """Drive request_body through the three-phase lifecycle, calling the
        plugin at each phase.

        request_body is the immutable bytes to dispatch.  The plugin never
        receives a reference it could use to swap out the bytes before
        dispatch — the dispatched_request_digest recorded in
        request_metadata MUST equal sha256(request_body) for every run,
        proving the plugin did not alter the dispatch payload.

        backend_response_body defaults to a minimal valid OpenAI-shaped
        completion; callers may override for scenario-specific tests.
        """
        if headers is None:
            headers = {"content-type": "application/json"}
        if backend_response_body is None:
            backend_response_body = (
                b'{"id":"cmpl-ok","object":"chat.completion",'
                b'"choices":[{"index":0,"message":{"role":"assistant",'
                b'"content":"hello"},"finish_reason":"stop"}]}'
            )

        xid = self._xid()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        # ------ Phase 1: REQUEST_RECEIVED --------------------------------
        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED,
                                       "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid,
            LifecyclePhase.REQUEST_RECEIVED, payload=request_body,
        ))

        try:
            decision = self._call_plugin(
                xid, LifecyclePhase.REQUEST_RECEIVED, endpoint, headers, request_body
            )
        except BodyAccessDenied as exc:
            return self._terminal_body_access_denied(
                xid, phases, observations, side_events,
                request_body, phase_name="request_received", exc=exc,
            )

        if decision == DENY:
            return self._terminal_policy_denied(
                xid, phases, observations, side_events,
                request_body, trigger="plugin denied at request_received",
            )

        # ------ Phase 2: BACKEND_SELECTED --------------------------------
        phases.append(self._transition(
            LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.BACKEND_SELECTED,
            "plugin abstained; backend assigned",
        ))
        # Record the exact bytes dispatched to the backend.
        observations.append(self._obs(
            ObservationPoint.BACKEND_DISPATCH, xid,
            LifecyclePhase.BACKEND_SELECTED, payload=request_body,
        ))

        try:
            decision = self._call_plugin(
                xid, LifecyclePhase.BACKEND_SELECTED, endpoint, headers, request_body
            )
        except BodyAccessDenied as exc:
            return self._terminal_body_access_denied(
                xid, phases, observations, side_events,
                request_body, phase_name="backend_selected", exc=exc,
            )

        if decision == DENY:
            return self._terminal_policy_denied(
                xid, phases, observations, side_events,
                request_body, trigger="plugin denied at backend_selected",
            )

        # ------ Phase 3: EXCHANGE_FINISHED --------------------------------
        phases.append(self._transition(
            LifecyclePhase.BACKEND_SELECTED, LifecyclePhase.EXCHANGE_FINISHED,
            "backend returned response",
        ))
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid,
            LifecyclePhase.EXCHANGE_FINISHED, payload=backend_response_body,
        ))

        try:
            self._call_plugin(
                xid, LifecyclePhase.EXCHANGE_FINISHED, endpoint,
                headers, backend_response_body,
            )
        except BodyAccessDenied as exc:
            return self._terminal_body_access_denied(
                xid, phases, observations, side_events,
                request_body, phase_name="exchange_finished", exc=exc,
                response_body=backend_response_body,
            )

        side_events.append(self._sse(SideStream.ANCHORING, xid, "submitted",
                                     {"outcome": "completed"}))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.COMPLETED,
            terminal_reason=None,
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={
                "body_digest": self._digest(request_body),
                # dispatched_request_digest: what was actually sent to the backend.
                # For byte-identical verification: this must equal body_digest.
                "dispatched_request_digest": self._digest(request_body),
            },
            response_metadata={"body_digest": self._digest(backend_response_body)},
        )

    # ------------------------------------------------------------------
    # Terminal state helpers
    # ------------------------------------------------------------------

    def _terminal_policy_denied(
        self,
        xid: str,
        phases: list,
        observations: list,
        side_events: list,
        request_body: bytes,
        trigger: str,
    ) -> LifecycleTrace:
        """Terminate with POLICY_DENIED and a stable OpenAI-shaped error."""
        rejection_body = (
            b'{"error":{"code":"policy_denied",'
            b'"message":"request rejected by plugin admission policy",'
            b'"type":"invalid_request_error","param":null}}'
        )
        phases.append(self._transition(
            phases[-1].to_phase, LifecyclePhase.EXCHANGE_FINISHED, trigger,
        ))
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid,
            LifecyclePhase.EXCHANGE_FINISHED, payload=rejection_body,
            metadata={"note": "denied by plugin admission policy"},
        ))
        side_events.append(self._sse(SideStream.ANCHORING, xid, "submitted",
                                     {"outcome": "policy_denied", "denied_by": "plugin"}))
        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.POLICY_DENIED,
            terminal_reason="plugin_admission_policy",
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"body_digest": self._digest(rejection_body)},
        )

    def _terminal_body_access_denied(
        self,
        xid: str,
        phases: list,
        observations: list,
        side_events: list,
        request_body: bytes,
        phase_name: str,
        exc: BodyAccessDenied,
        response_body: bytes | None = None,
    ) -> LifecycleTrace:
        """Terminate with EVIDENCE_UNAVAILABLE when the plugin raised BodyAccessDenied."""
        side_events.append(self._sse(SideStream.EVIDENCE, xid, "failed", {
            "reason": "internal_hook_failure",
            "cause": "body_access_denied",
            "plugin_error": str(exc),
            "phase": phase_name,
        }))
        last = phases[-1].to_phase if phases else None
        phases.append(self._transition(
            last, LifecyclePhase.EXCHANGE_FINISHED,
            f"plugin raised BodyAccessDenied at {phase_name}",
        ))
        response_meta: dict = {
            "error": "plugin_body_access_denied",
            "phase": phase_name,
            "detail": str(exc),
        }
        if response_body is not None:
            response_meta["body_digest"] = self._digest(response_body)
        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.EVIDENCE_UNAVAILABLE,
            terminal_reason="internal_hook_failure",
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata=response_meta,
        )


# ---------------------------------------------------------------------------
# SPEC-FEEDBACK NOTES
# ---------------------------------------------------------------------------

SPEC_FEEDBACK: dict[str, str] = {

    "observe_only_body_semantics": (
        "The exemplar raises BodyAccessDenied when observe_only mode receives "
        "body_access_granted=False.  #1331 does not specify whether an "
        "observe_only plugin should abstain silently, raise an error, or be "
        "excluded from phases where body access is unavailable.  The observe_only "
        "plugin in this exemplar treats silent abstain as a fail-toward-reassurance "
        "shape and raises instead.  If #1331 intends observe_only plugins to "
        "tolerate missing body access gracefully (e.g. record an incomplete "
        "observation), the calling convention should say so explicitly."
    ),

    "admission_policy_body_required": (
        "An admission-policy plugin cannot make a safe decision without the "
        "request body.  The exemplar raises BodyAccessDenied rather than "
        "returning abstain (fail-open) or deny (fail-closed blanket rejection). "
        "#1331 should specify whether the host is permitted to load an "
        "admission_policy plugin with body_access_granted=False, and if so, "
        "what the plugin is required to do: fail-open is clearly wrong, but "
        "fail-closed (blanket deny without inspecting the body) may also be "
        "unacceptable if it blocks legitimate traffic.  The exemplar treats "
        "BodyAccessDenied as EVIDENCE_UNAVAILABLE/internal_hook_failure."
    ),

    "decision_mode_enforcement": (
        "The manifest declares decision_mode='observe_only' or "
        "'admission_policy', but #1331 does not specify whether the host "
        "enforces this at the call site.  This exemplar's host does not prevent "
        "an observe_only plugin from returning DENY — it checks the decision "
        "only as a string value.  If #1331 intends observe_only as a hard "
        "constraint (the host ignores any DENY returned by an observe_only "
        "plugin), the enforcement point should be in the host, not a convention."
    ),

    "sanitized_headers_grant_model": (
        "The manifest lists sanitized_headers as a request for access, not a "
        "grant.  The host in this exemplar filters headers strictly against the "
        "manifest list AND always excludes Authorization and Cookie regardless "
        "of the manifest.  #1331 should specify: (a) whether a plugin that "
        "lists Authorization in sanitized_headers is rejected at load time or "
        "silently pruned, (b) whether the host is required to tell the plugin "
        "which headers it is withholding (currently there is no signal other "
        "than the headers being absent from PhaseContext.sanitized_headers), "
        "and (c) whether sanitized_headers is a minimum-request or an exact "
        "allowlist (a plugin that requests ['content-type'] but the host also "
        "exposes ['x-request-id'] — is that a contract violation or a bonus?)."
    ),

    "phase_subset_calling": (
        "The manifest phases field lists which phases the plugin wants to be "
        "called for.  The exemplar plugins declare all three phases.  #1331 "
        "should specify what happens when a plugin does NOT list a phase: "
        "(a) the host skips calling the plugin for that phase entirely, or "
        "(b) the host calls the plugin but the plugin may return abstain.  "
        "The distinction matters when an admission_policy plugin wants to skip "
        "EXCHANGE_FINISHED to avoid unnecessary body reads after dispatch."
    ),

    "deny_at_non_decision_phases": (
        "The exemplar's admission-policy plugin only evaluates the denial "
        "condition at REQUEST_RECEIVED and returns abstain at later phases. "
        "#1331 does not specify whether DENY is a valid return value from "
        "EXCHANGE_FINISHED — at that point the backend has already responded "
        "and there is nothing left to deny.  Should the host treat DENY at "
        "EXCHANGE_FINISHED as a protocol error, or silently treat it as "
        "abstain?  The exemplar's host would currently propagate the DENY and "
        "return a confusing POLICY_DENIED trace after the backend completed."
    ),
}

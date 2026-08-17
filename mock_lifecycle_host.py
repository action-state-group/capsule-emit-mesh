#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
DEVELOPMENT RIG — NOT AN IMPLEMENTATION
========================================

This file is a development rig for mesh-llm/mesh-llm #1331's lifecycle
contract, offered for re-homing to the mesh-llm project or a neutral test-
fixture repository if it is useful there.

PURPOSE
    Exercise #1331's lifecycle state machine:
        request_received → backend_selected → exchange_finished
    ...the eight terminal states, the four observation points, and the side
    streams enumerated in #1332's diagram. Nothing here is a conformant
    implementation of the mesh-llm host protocol.  It is a scripted scenario
    harness for studying the contract and finding underspecified corners.

OBSERVATION POINT INTEGRITY RULE (#1331)
    "The host must not present a gateway observation as proof from the
    serving target."
    Enforced by ObservationRecord.assert_serving_host_provenance().

SIDE STREAMS
    Modelled from context (#1332 diagram not in this repo — see
    SPEC_FEEDBACK["side_streams_shape"] below).  Three candidates:
        anchoring_stream    — record submission to a transparency service
        delegation_stream   — verifying owner → node signing key chain
        evidence_stream     — collecting execution / hardware evidence

SPEC-FEEDBACK NOTES
    Underspecified corners that should be resolved in #1331/#1332 before a
    conformant implementation is written.  See SPEC_FEEDBACK at the bottom.
"""
from __future__ import annotations

import dataclasses
import enum
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Lifecycle phases
# Names taken verbatim from the task description and #1331 references; exact
# section numbers not independently verified — see SPEC_FEEDBACK["phase_names"].
# ---------------------------------------------------------------------------

class LifecyclePhase(enum.Enum):
    REQUEST_RECEIVED = "request_received"
    BACKEND_SELECTED = "backend_selected"
    EXCHANGE_FINISHED = "exchange_finished"


# ---------------------------------------------------------------------------
# Terminal states (#1331 — "eight terminal states")
# ---------------------------------------------------------------------------

class TerminalState(str, enum.Enum):
    COMPLETED             = "completed"
    POLICY_DENIED         = "policy_denied"
    REQUEST_INVALID       = "request_invalid"
    BACKEND_ERROR         = "backend_error"
    TRANSPORT_ERROR       = "transport_error"
    CLIENT_CANCELLED      = "client_cancelled"
    TIMED_OUT             = "timed_out"
    EVIDENCE_UNAVAILABLE  = "evidence_unavailable"


# SPEC FEEDBACK: #1331 lists both "evidence_unavailable" and
# "internal_hook_failure" in the eight-state enumeration (per the task
# description's "/" notation).  This rig treats them as one terminal state
# (EVIDENCE_UNAVAILABLE) with the sub-reason carried separately.  If #1331
# intends them as two distinct states the count is nine, not eight — see
# SPEC_FEEDBACK["terminal_state_count"].
INTERNAL_HOOK_FAILURE_REASON = "internal_hook_failure"


# ---------------------------------------------------------------------------
# Observation points (#1331)
# ---------------------------------------------------------------------------

class ObservationPoint(str, enum.Enum):
    GATEWAY_INGRESS       = "gateway_ingress"
    SERVING_HOST_INGRESS  = "serving_host_ingress"
    BACKEND_DISPATCH      = "backend_dispatch"
    CLIENT_EGRESS         = "client_egress"


# Which observation points belong to the gateway vs the serving host.
# A serving host's record MUST NOT contain a GATEWAY_INGRESS observation
# presented as the host's own evidence — that is the integrity rule.
_GATEWAY_OBSERVATIONS: frozenset[ObservationPoint] = frozenset({
    ObservationPoint.GATEWAY_INGRESS,
})
_HOST_OBSERVATIONS: frozenset[ObservationPoint] = frozenset({
    ObservationPoint.SERVING_HOST_INGRESS,
    ObservationPoint.BACKEND_DISPATCH,
    ObservationPoint.CLIENT_EGRESS,
})


# ---------------------------------------------------------------------------
# Side-stream kinds (#1332)
# ---------------------------------------------------------------------------

class SideStream(str, enum.Enum):
    ANCHORING   = "anchoring"    # submission to a transparency service
    DELEGATION  = "delegation"   # owner → node signing-key verification
    EVIDENCE    = "evidence"     # execution / hardware attestation collection


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ObservationPointIntegrityError(Exception):
    """Raised when a host tries to present a gateway observation as its own."""


class LifecycleProtocolError(Exception):
    """Raised when the lifecycle state machine is driven illegally."""


# ---------------------------------------------------------------------------
# ObservationRecord
# ---------------------------------------------------------------------------

@dataclass
class ObservationRecord:
    """One record from one observation point in one exchange.

    observer_role: "gateway" | "serving_host"
        Who produced this record.  Must be consistent with observation_point:
        GATEWAY_INGRESS records must have observer_role="gateway";
        SERVING_HOST_INGRESS / BACKEND_DISPATCH / CLIENT_EGRESS records must
        have observer_role="serving_host".
    """

    observation_point: ObservationPoint
    exchange_id: str
    phase_at_observation: LifecyclePhase
    observer_role: str          # "gateway" | "serving_host"
    payload_digest: str | None  # sha256 hex of the observed bytes, or None
    timestamp_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------

    def assert_serving_host_provenance(self) -> None:
        """Enforce #1331's observation-point integrity rule.

        "The host must not present a gateway observation as proof from the
        serving target."

        If this record was produced at GATEWAY_INGRESS but observer_role is
        "serving_host", the record is claiming that the serving host observed
        the gateway's vantage point — a structural provenance lie.
        """
        if (self.observation_point in _GATEWAY_OBSERVATIONS
                and self.observer_role == "serving_host"):
            raise ObservationPointIntegrityError(
                f"Integrity violation: observation_point="
                f"{self.observation_point.value!r} is a gateway observation "
                f"and cannot be presented with observer_role='serving_host'. "
                f"(exchange_id={self.exchange_id!r}) "
                f"A gateway observation is not proof from the serving target."
            )

    def is_gateway_observation(self) -> bool:
        return self.observation_point in _GATEWAY_OBSERVATIONS

    def is_host_observation(self) -> bool:
        return self.observation_point in _HOST_OBSERVATIONS


# ---------------------------------------------------------------------------
# SideStreamEvent
# ---------------------------------------------------------------------------

@dataclass
class SideStreamEvent:
    """One event on a side stream running alongside the main lifecycle."""

    stream: SideStream
    exchange_id: str
    event_name: str             # e.g. "submitted", "verified", "failed"
    timestamp_ms: float
    detail: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# PhaseTransition
# ---------------------------------------------------------------------------

@dataclass
class PhaseTransition:
    """One phase transition in the lifecycle."""

    from_phase: LifecyclePhase | None
    to_phase: LifecyclePhase
    timestamp_ms: float
    trigger: str  # human-readable reason


# ---------------------------------------------------------------------------
# LifecycleTrace
# ---------------------------------------------------------------------------

@dataclass
class LifecycleTrace:
    """Full trace of one exchange through the lifecycle.

    Produced by MockLifecycleHost after a scenario completes.
    """

    exchange_id: str
    terminal_state: TerminalState | None
    terminal_reason: str | None  # sub-reason (e.g. INTERNAL_HOOK_FAILURE_REASON)
    phases: list[PhaseTransition]
    observations: list[ObservationRecord]
    side_stream_events: list[SideStreamEvent]
    request_metadata: dict[str, Any]
    response_metadata: dict[str, Any]

    def reached_phase(self, phase: LifecyclePhase) -> bool:
        return any(t.to_phase == phase for t in self.phases)

    def observation_at(self, point: ObservationPoint) -> ObservationRecord | None:
        return next((o for o in self.observations if o.observation_point == point), None)

    def side_stream_events_for(self, stream: SideStream) -> list[SideStreamEvent]:
        return [e for e in self.side_stream_events if e.stream == stream]

    def assert_observation_point_integrity(self) -> None:
        """Verify no gateway observation is falsely presented as host evidence."""
        for obs in self.observations:
            obs.assert_serving_host_provenance()


# ---------------------------------------------------------------------------
# MockLifecycleHost
# ---------------------------------------------------------------------------

class MockLifecycleHost:
    """A mock serving host that drives a request through #1331's lifecycle.

    Scripted scenario methods return a LifecycleTrace.  They are intended for
    use in test scenarios; this class is the hook a real implementation would
    wire in.

    SPEC NOTE: This rig models the serving host, not the gateway.  In #1331
    the gateway has its own lifecycle; the serving host is the target of the
    gateway's forwarded request.  The interaction between gateway-side and
    host-side lifecycle records is underspecified — see
    SPEC_FEEDBACK["gateway_host_coordination"].
    """

    def __init__(self, host_id: str = "mock-serving-host/0.1"):
        self.host_id = host_id

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _now_ms(self) -> float:
        return time.monotonic() * 1000  # wall-time monotonic in ms

    def _make_exchange_id(self) -> str:
        return uuid.uuid4().hex

    def _digest(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _obs(
        self,
        point: ObservationPoint,
        exchange_id: str,
        phase: LifecyclePhase,
        payload: bytes | None = None,
        metadata: dict[str, Any] | None = None,
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
        detail: dict[str, Any] | None = None,
    ) -> SideStreamEvent:
        return SideStreamEvent(
            stream=stream,
            exchange_id=exchange_id,
            event_name=event_name,
            timestamp_ms=self._now_ms(),
            detail=detail or {},
        )

    # ------------------------------------------------------------------
    # Scenario: COMPLETED
    # ------------------------------------------------------------------

    def run_completed(self, request_body: bytes = b'{"model":"test","messages":[]}') -> LifecycleTrace:
        """Happy-path scenario: request received, backend selected, response
        returned, all observation points hit, all side streams active."""

        xid = self._make_exchange_id()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        # Phase 1: REQUEST_RECEIVED
        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid, LifecyclePhase.REQUEST_RECEIVED,
            payload=request_body,
        ))
        # Delegation check side stream
        side_events.append(self._sse(SideStream.DELEGATION, xid, "verified",
            {"chain": "owner→node", "result": "ok"}))

        # Phase 2: BACKEND_SELECTED
        phases.append(self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.BACKEND_SELECTED,
            "policy check passed; backend assigned"))
        observations.append(self._obs(
            ObservationPoint.BACKEND_DISPATCH, xid, LifecyclePhase.BACKEND_SELECTED,
            payload=request_body,
        ))
        side_events.append(self._sse(SideStream.EVIDENCE, xid, "collected",
            {"evidence_type": "execution_artifact_digest", "digest": "0" * 64}))

        # Phase 3: EXCHANGE_FINISHED
        response_body = b'{"id":"cmpl-ok","choices":[{"message":{"role":"assistant","content":"hello"}}]}'
        phases.append(self._transition(LifecyclePhase.BACKEND_SELECTED, LifecyclePhase.EXCHANGE_FINISHED,
            "backend returned response"))
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid, LifecyclePhase.EXCHANGE_FINISHED,
            payload=response_body,
        ))
        side_events.append(self._sse(SideStream.ANCHORING, xid, "submitted",
            {"log": "capsule-anchor", "status": "pending"}))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.COMPLETED,
            terminal_reason=None,
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"body_digest": self._digest(response_body)},
        )

    # ------------------------------------------------------------------
    # Scenario: POLICY_DENIED (pre-dispatch)
    # ------------------------------------------------------------------

    def run_policy_denied(self, request_body: bytes = b'{"model":"test","messages":[]}') -> LifecycleTrace:
        """Policy check at serving_host_ingress rejects the request before
        backend dispatch.  #1331 requirement: a refusal before dispatch is
        policy_denied, NOT backend_error — they are distinct terminal states.
        Observation: SERVING_HOST_INGRESS recorded; BACKEND_DISPATCH never reached.
        """

        xid = self._make_exchange_id()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid, LifecyclePhase.REQUEST_RECEIVED,
            payload=request_body,
        ))
        side_events.append(self._sse(SideStream.DELEGATION, xid, "verified",
            {"chain": "owner→node", "result": "ok"}))

        # Policy check fires — no backend_selected transition.
        phases.append(self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.EXCHANGE_FINISHED,
            "policy check rejected request before dispatch"))
        # CLIENT_EGRESS: the rejection is sent back to the client.
        rejection_body = b'{"error":{"code":"policy_denied","message":"request rejected by host policy"}}'
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid, LifecyclePhase.EXCHANGE_FINISHED,
            payload=rejection_body,
        ))
        side_events.append(self._sse(SideStream.ANCHORING, xid, "submitted",
            {"log": "capsule-anchor", "status": "pending", "outcome": "policy_denied"}))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.POLICY_DENIED,
            terminal_reason="host_policy_check_failed",
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"body_digest": self._digest(rejection_body)},
        )

    # ------------------------------------------------------------------
    # Scenario: REQUEST_INVALID
    # ------------------------------------------------------------------

    def run_request_invalid(self, request_body: bytes = b"not json at all") -> LifecycleTrace:
        """Malformed or schema-invalid request, rejected at ingress.
        Distinguished from POLICY_DENIED: this is a syntactic/structural
        failure, not a policy decision."""

        xid = self._make_exchange_id()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid, LifecyclePhase.REQUEST_RECEIVED,
            payload=request_body,
        ))

        # Parse failure — no delegation check needed, no backend selected.
        rejection_body = b'{"error":{"code":"request_invalid","message":"request body could not be parsed"}}'
        phases.append(self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.EXCHANGE_FINISHED,
            "request body failed validation"))
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid, LifecyclePhase.EXCHANGE_FINISHED,
            payload=rejection_body,
        ))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.REQUEST_INVALID,
            terminal_reason="json_parse_failure",
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"body_digest": self._digest(rejection_body)},
        )

    # ------------------------------------------------------------------
    # Scenario: BACKEND_ERROR
    # ------------------------------------------------------------------

    def run_backend_error(self, request_body: bytes = b'{"model":"test","messages":[]}') -> LifecycleTrace:
        """Backend returned a well-formed error after dispatch.  Distinguished
        from TRANSPORT_ERROR: the backend was reached and responded; from
        POLICY_DENIED: the request passed pre-dispatch policy.

        SPEC NOTE: The sidecar (capsule_sidecar.py) uses verdict_class=
        "errored" for backend errors, consistent with the observation that the
        node dispatched the request and received an error response.  #1331 should
        confirm that BACKEND_ERROR carries the same observation-point semantics —
        BACKEND_DISPATCH was reached, CLIENT_EGRESS carries the error. See
        SPEC_FEEDBACK["backend_error_vs_transport_error"].
        """

        xid = self._make_exchange_id()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid, LifecyclePhase.REQUEST_RECEIVED,
            payload=request_body,
        ))
        side_events.append(self._sse(SideStream.DELEGATION, xid, "verified",
            {"chain": "owner→node", "result": "ok"}))

        phases.append(self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.BACKEND_SELECTED,
            "policy passed; backend assigned"))
        observations.append(self._obs(
            ObservationPoint.BACKEND_DISPATCH, xid, LifecyclePhase.BACKEND_SELECTED,
            payload=request_body,
        ))

        # Backend returned an error response (e.g. OOM, model crash).
        error_response = b'{"error":{"code":"backend_error","message":"model runtime exception"}}'
        phases.append(self._transition(LifecyclePhase.BACKEND_SELECTED, LifecyclePhase.EXCHANGE_FINISHED,
            "backend returned error response"))
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid, LifecyclePhase.EXCHANGE_FINISHED,
            payload=error_response,
        ))
        side_events.append(self._sse(SideStream.EVIDENCE, xid, "partial",
            {"note": "evidence collection incomplete due to backend error"}))
        side_events.append(self._sse(SideStream.ANCHORING, xid, "submitted",
            {"log": "capsule-anchor", "status": "pending", "outcome": "backend_error"}))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.BACKEND_ERROR,
            terminal_reason="model_runtime_exception",
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"body_digest": self._digest(error_response)},
        )

    # ------------------------------------------------------------------
    # Scenario: TRANSPORT_ERROR
    # ------------------------------------------------------------------

    def run_transport_error(self, request_body: bytes = b'{"model":"test","messages":[]}') -> LifecycleTrace:
        """Network/transport failure before the backend could respond.
        Distinguished from BACKEND_ERROR: the backend was not reached or
        the connection was lost before a response was received.

        SPEC NOTE: If the backend process started but the connection broke
        mid-stream, is this TRANSPORT_ERROR or BACKEND_ERROR?  The
        distinction matters for evidence: BACKEND_DISPATCH may or may not
        have a response digest.  See SPEC_FEEDBACK["transport_error_boundary"].
        """

        xid = self._make_exchange_id()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid, LifecyclePhase.REQUEST_RECEIVED,
            payload=request_body,
        ))
        side_events.append(self._sse(SideStream.DELEGATION, xid, "verified",
            {"chain": "owner→node", "result": "ok"}))

        phases.append(self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.BACKEND_SELECTED,
            "policy passed; backend assigned"))
        # BACKEND_DISPATCH observed but no response digest available.
        observations.append(self._obs(
            ObservationPoint.BACKEND_DISPATCH, xid, LifecyclePhase.BACKEND_SELECTED,
            payload=None,  # request forwarded but no response received
            metadata={"note": "dispatch attempted; connection lost before response"},
        ))

        phases.append(self._transition(LifecyclePhase.BACKEND_SELECTED, LifecyclePhase.EXCHANGE_FINISHED,
            "transport failure — connection reset"))
        error_response = b'{"error":{"code":"transport_error","message":"connection reset by backend"}}'
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid, LifecyclePhase.EXCHANGE_FINISHED,
            payload=error_response,
        ))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.TRANSPORT_ERROR,
            terminal_reason="connection_reset",
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"body_digest": self._digest(error_response)},
        )

    # ------------------------------------------------------------------
    # Scenario: CLIENT_CANCELLED
    # ------------------------------------------------------------------

    def run_client_cancelled(self, request_body: bytes = b'{"model":"test","messages":[]}') -> LifecycleTrace:
        """Client closed the connection (or sent a cancel signal) before the
        exchange completed.  May occur at any phase after REQUEST_RECEIVED.

        SPEC NOTE: #1331 does not specify whether CLIENT_CANCELLED is detectable
        at BACKEND_DISPATCH (i.e. can the backend be told to abort mid-generation?)
        or only at CLIENT_EGRESS (i.e. we discover it when we try to write the
        response).  The distinction matters for billing and evidence completeness.
        See SPEC_FEEDBACK["client_cancelled_phase"].
        """

        xid = self._make_exchange_id()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid, LifecyclePhase.REQUEST_RECEIVED,
            payload=request_body,
        ))
        side_events.append(self._sse(SideStream.DELEGATION, xid, "verified",
            {"chain": "owner→node", "result": "ok"}))

        phases.append(self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.BACKEND_SELECTED,
            "policy passed; backend assigned"))
        observations.append(self._obs(
            ObservationPoint.BACKEND_DISPATCH, xid, LifecyclePhase.BACKEND_SELECTED,
            payload=request_body,
        ))

        # Client disconnected mid-generation — we still record what we can.
        phases.append(self._transition(LifecyclePhase.BACKEND_SELECTED, LifecyclePhase.EXCHANGE_FINISHED,
            "client disconnected before response was fully written"))
        # No CLIENT_EGRESS payload digest — connection was gone.
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid, LifecyclePhase.EXCHANGE_FINISHED,
            payload=None,
            metadata={"note": "client closed connection; response not delivered"},
        ))
        side_events.append(self._sse(SideStream.ANCHORING, xid, "submitted",
            {"log": "capsule-anchor", "status": "pending", "outcome": "client_cancelled"}))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.CLIENT_CANCELLED,
            terminal_reason="client_disconnected",
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"note": "no response delivered — client cancelled"},
        )

    # ------------------------------------------------------------------
    # Scenario: TIMED_OUT
    # ------------------------------------------------------------------

    def run_timed_out(self, request_body: bytes = b'{"model":"test","messages":[]}') -> LifecycleTrace:
        """The exchange exceeded its deadline before completion.

        SPEC NOTE: #1331 doesn't specify whether TIMED_OUT applies only to the
        overall exchange deadline or also to per-phase timeouts (e.g. backend
        selection timeout).  If a backend hangs and the host kills it, is that
        TIMED_OUT or BACKEND_ERROR?  See SPEC_FEEDBACK["timed_out_scope"].
        """

        xid = self._make_exchange_id()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid, LifecyclePhase.REQUEST_RECEIVED,
            payload=request_body,
        ))
        side_events.append(self._sse(SideStream.DELEGATION, xid, "verified",
            {"chain": "owner→node", "result": "ok"}))

        phases.append(self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.BACKEND_SELECTED,
            "policy passed; backend assigned"))
        observations.append(self._obs(
            ObservationPoint.BACKEND_DISPATCH, xid, LifecyclePhase.BACKEND_SELECTED,
            payload=request_body,
        ))

        # Deadline expired during generation — no usable response.
        phases.append(self._transition(LifecyclePhase.BACKEND_SELECTED, LifecyclePhase.EXCHANGE_FINISHED,
            "exchange deadline exceeded"))
        timeout_response = b'{"error":{"code":"timed_out","message":"exchange deadline exceeded"}}'
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid, LifecyclePhase.EXCHANGE_FINISHED,
            payload=timeout_response,
        ))
        side_events.append(self._sse(SideStream.ANCHORING, xid, "submitted",
            {"log": "capsule-anchor", "status": "pending", "outcome": "timed_out"}))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.TIMED_OUT,
            terminal_reason="exchange_deadline_exceeded",
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"body_digest": self._digest(timeout_response)},
        )

    # ------------------------------------------------------------------
    # Scenario: EVIDENCE_UNAVAILABLE (sub-reason: internal_hook_failure)
    # ------------------------------------------------------------------

    def run_evidence_unavailable(self, request_body: bytes = b'{"model":"test","messages":[]}') -> LifecycleTrace:
        """Evidence collection failed during or after exchange.

        The exchange itself may have completed (backend returned a response)
        but the host cannot produce a valid capsule because the evidence
        collection hook failed.

        SPEC NOTE: The task description lists this as "evidence_unavailable/
        internal_hook_failure".  This rig treats EVIDENCE_UNAVAILABLE as the
        terminal state and internal_hook_failure as a sub-reason.  If #1331
        intends INTERNAL_HOOK_FAILURE as a distinct terminal state, the eight-
        state enumeration is actually nine states.  See
        SPEC_FEEDBACK["terminal_state_count"].

        ADDITIONAL NOTE: It is unclear whether EVIDENCE_UNAVAILABLE means:
        (a) the evidence collection subsystem crashed (internal_hook_failure),
        (b) the evidence was sought but is genuinely not available (e.g. no TEE),
        (c) both.
        See SPEC_FEEDBACK["evidence_unavailable_scope"].
        """

        xid = self._make_exchange_id()
        phases: list[PhaseTransition] = []
        observations: list[ObservationRecord] = []
        side_events: list[SideStreamEvent] = []

        phases.append(self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "host received request"))
        observations.append(self._obs(
            ObservationPoint.SERVING_HOST_INGRESS, xid, LifecyclePhase.REQUEST_RECEIVED,
            payload=request_body,
        ))
        side_events.append(self._sse(SideStream.DELEGATION, xid, "verified",
            {"chain": "owner→node", "result": "ok"}))

        phases.append(self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.BACKEND_SELECTED,
            "policy passed; backend assigned"))
        observations.append(self._obs(
            ObservationPoint.BACKEND_DISPATCH, xid, LifecyclePhase.BACKEND_SELECTED,
            payload=request_body,
        ))

        # Backend completed but evidence hook threw.
        response_body = b'{"id":"cmpl-ok","choices":[{"message":{"role":"assistant","content":"ok"}}]}'
        phases.append(self._transition(LifecyclePhase.BACKEND_SELECTED, LifecyclePhase.EXCHANGE_FINISHED,
            "backend returned response; evidence hook failed"))
        observations.append(self._obs(
            ObservationPoint.CLIENT_EGRESS, xid, LifecyclePhase.EXCHANGE_FINISHED,
            payload=response_body,
        ))
        side_events.append(self._sse(SideStream.EVIDENCE, xid, "failed",
            {"reason": INTERNAL_HOOK_FAILURE_REASON, "detail": "evidence hook threw RuntimeError"}))
        # Anchoring still attempted; record carries incomplete evidence.
        side_events.append(self._sse(SideStream.ANCHORING, xid, "submitted",
            {"log": "capsule-anchor", "status": "pending",
             "outcome": "evidence_unavailable",
             "note": "record carries evidence_present=false; hook failure logged"}))

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.EVIDENCE_UNAVAILABLE,
            terminal_reason=INTERNAL_HOOK_FAILURE_REASON,
            phases=phases,
            observations=observations,
            side_stream_events=side_events,
            request_metadata={"body_digest": self._digest(request_body)},
            response_metadata={"body_digest": self._digest(response_body)},
        )

    # ------------------------------------------------------------------
    # Integrity violation scenario (for testing the check itself)
    # ------------------------------------------------------------------

    def run_gateway_observation_claimed_as_host(self, request_body: bytes = b'{"model":"test"}') -> LifecycleTrace:
        """Produces a DELIBERATELY INVALID trace that violates the observation-
        point integrity rule.

        A serving host builds a GATEWAY_INGRESS record with observer_role=
        "serving_host".  This is what #1331 prohibits: "the host must not
        present a gateway observation as proof from the serving target."

        The test for this scenario asserts that assert_observation_point_integrity()
        raises ObservationPointIntegrityError.
        """

        xid = self._make_exchange_id()

        # A real gateway observation — the gateway saw this at ingress.
        gateway_observation = ObservationRecord(
            observation_point=ObservationPoint.GATEWAY_INGRESS,
            exchange_id=xid,
            phase_at_observation=LifecyclePhase.REQUEST_RECEIVED,
            observer_role="gateway",            # correctly labelled
            payload_digest=self._digest(request_body),
            timestamp_ms=self._now_ms(),
        )

        # The violation: a host observation claiming to be the gateway's.
        fraudulent_observation = ObservationRecord(
            observation_point=ObservationPoint.GATEWAY_INGRESS,   # gateway point
            exchange_id=xid,
            phase_at_observation=LifecyclePhase.REQUEST_RECEIVED,
            observer_role="serving_host",       # but claiming host provenance!
            payload_digest=self._digest(request_body),
            timestamp_ms=self._now_ms(),
        )

        return LifecycleTrace(
            exchange_id=xid,
            terminal_state=TerminalState.COMPLETED,
            terminal_reason=None,
            phases=[
                self._transition(None, LifecyclePhase.REQUEST_RECEIVED, "received"),
                self._transition(LifecyclePhase.REQUEST_RECEIVED, LifecyclePhase.EXCHANGE_FINISHED, "done"),
            ],
            observations=[gateway_observation, fraudulent_observation],
            side_stream_events=[],
            request_metadata={},
            response_metadata={},
        )


# ---------------------------------------------------------------------------
# Nine host-integration scenarios (covering #1331's integration test surface)
# ---------------------------------------------------------------------------

def all_scenarios(host: MockLifecycleHost | None = None) -> list[tuple[str, LifecycleTrace]]:
    """Return (name, trace) pairs for the nine integration scenarios.

    SPEC NOTE: #1331 references "nine host-integration tests" but their exact
    names and scope are not published in this repo.  The nine scenarios below
    are inferred from the eight terminal states (one each) plus the observation-
    point integrity rule (one).  If #1331's integration suite has a different
    decomposition, this list needs revision.  See
    SPEC_FEEDBACK["nine_integration_tests"].
    """

    if host is None:
        host = MockLifecycleHost()

    return [
        ("completed",             host.run_completed()),
        ("policy_denied",         host.run_policy_denied()),
        ("request_invalid",       host.run_request_invalid()),
        ("backend_error",         host.run_backend_error()),
        ("transport_error",       host.run_transport_error()),
        ("client_cancelled",      host.run_client_cancelled()),
        ("timed_out",             host.run_timed_out()),
        ("evidence_unavailable",  host.run_evidence_unavailable()),
        # Ninth scenario: observation-point integrity (the fraudulent trace
        # must be detected, not silently accepted).
        ("gateway_obs_as_host_INVALID", host.run_gateway_observation_claimed_as_host()),
    ]


# ---------------------------------------------------------------------------
# SPEC-FEEDBACK NOTES
# ---------------------------------------------------------------------------

SPEC_FEEDBACK: dict[str, str] = {

    "terminal_state_count": (
        "Task description lists eight terminal states as: completed, policy_denied, "
        "request_invalid, backend_error, transport_error, client_cancelled, timed_out, "
        "evidence_unavailable/internal_hook_failure.  The '/' notation is ambiguous: "
        "are evidence_unavailable and internal_hook_failure two distinct terminal states "
        "(making nine, not eight) or is internal_hook_failure a sub-reason/cause of "
        "evidence_unavailable?  If nine, the spec text should say so; if eight, the "
        "spec should define when a hook failure leads to evidence_unavailable vs another "
        "state.  This rig treats them as one state with two names."
    ),

    "side_streams_shape": (
        "#1332 is referenced for 'side streams per #1332's diagram' but the diagram is "
        "not in this repo.  This rig models three candidate side streams (anchoring, "
        "delegation, evidence) inferred from the trust model and existing sidecar code.  "
        "If #1332's diagram specifies different streams, different cardinality, or "
        "different trigger points in the lifecycle, the rig's SideStream enum and the "
        "event timing in each scenario method need revision.  The spec should publish "
        "the diagram in a form accessible to external contributors."
    ),

    "nine_integration_tests": (
        "The task says the rig should 'cover their nine host-integration tests' from "
        "#1331, but the exact test names, preconditions, and acceptance criteria are not "
        "published here.  This rig maps nine scenarios to the eight terminal states + "
        "the observation-point integrity rule.  If #1331's nine tests are decomposed "
        "differently (e.g. two happy-path variants, or a split-inference test), the "
        "scenario list in all_scenarios() needs adjustment."
    ),

    "gateway_host_coordination": (
        "The lifecycle contract covers the SERVING HOST's view.  The GATEWAY has its "
        "own lifecycle (it routes, selects the host, forwards the request, and receives "
        "the response).  #1331 specifies both but this rig only models the serving host. "
        "Specifically: how does the gateway's GATEWAY_INGRESS record relate to the host's "
        "SERVING_HOST_INGRESS record?  Are they part of one compound lifecycle trace or "
        "two independent records joined by a correlation ID?  If they are separate records, "
        "what prevents a host from re-presenting a gateway's record as its own? "
        "(The integrity rule says it MUST NOT, but the enforcement mechanism is unspecified.)"
    ),

    "backend_error_vs_transport_error": (
        "The distinction between BACKEND_ERROR and TRANSPORT_ERROR depends on whether "
        "the backend process was reached and responded.  This rig models: "
        "BACKEND_ERROR = backend reached, returned a 4xx/5xx; "
        "TRANSPORT_ERROR = network failure before a response was received. "
        "But the boundary is unclear for mid-stream failures (backend started streaming, "
        "then connection dropped).  #1331 should specify: (a) what observation is present "
        "in each case, (b) whether a partial response digest is required for BACKEND_ERROR, "
        "and (c) whether TRANSPORT_ERROR can occur at BACKEND_DISPATCH or only at CLIENT_EGRESS."
    ),

    "transport_error_boundary": (
        "Narrow case: if the host sent the request to the backend and the backend "
        "started streaming tokens, then the connection reset — is the terminal state "
        "TRANSPORT_ERROR (transport layer failed) or BACKEND_ERROR (backend produced "
        "an incomplete/error output)?  The BACKEND_DISPATCH observation would have a "
        "payload digest (the sent request) but CLIENT_EGRESS would have none.  "
        "#1331 should define the rule."
    ),

    "client_cancelled_phase": (
        "CLIENT_CANCELLED can occur at any phase after REQUEST_RECEIVED.  If the client "
        "disconnects during BACKEND_SELECTED (while tokens are streaming), does the "
        "host: (a) immediately terminate the backend generation, (b) let it complete "
        "and record CLIENT_CANCELLED as the terminal state, or (c) something else?  "
        "The answer matters for billing (did the backend use compute?) and for evidence "
        "(is there a backend response digest?).  #1331 should specify the expected host "
        "behaviour on client disconnect at each phase."
    ),

    "timed_out_scope": (
        "TIMED_OUT is listed as a terminal state but #1331 does not specify whose "
        "deadline.  Candidates: (a) the exchange-level deadline set by the client or "
        "gateway, (b) per-phase timeouts (e.g. backend selection takes too long), "
        "(c) per-hop TTL on split inference.  If a backend hangs and the host kills "
        "the generation process, is that TIMED_OUT (host enforced a deadline) or "
        "BACKEND_ERROR (backend failed)?  This matters for observation: if TIMED_OUT "
        "means the host cancelled the backend, the BACKEND_DISPATCH observation may "
        "have no response digest, same as TRANSPORT_ERROR.  A state transition diagram "
        "with timeout edges would resolve this."
    ),

    "evidence_unavailable_scope": (
        "EVIDENCE_UNAVAILABLE (or INTERNAL_HOOK_FAILURE per the '/' notation) is listed "
        "as a terminal state.  It is unclear whether this means: "
        "(a) the evidence collection hook threw an exception (internal_hook_failure), "
        "(b) evidence was sought but genuinely unavailable (e.g. no TEE, no fingerprint), "
        "(c) anchoring to the transparency service failed, "
        "(d) any of the above.  "
        "If (b), it is NOT an error — it is an expected outcome for nodes without TEE "
        "hardware, and the record should render as evidence_present=false rather than as "
        "a failure.  If (a), it is an internal fault.  Conflating them obscures the "
        "three-state discipline (absent / present-unverified / checked) that the trust "
        "model requires.  #1331 should use separate terminal states or carry a "
        "distinguishing sub-reason field."
    ),

    "phase_names": (
        "The three phase names (request_received, backend_selected, exchange_finished) "
        "are taken verbatim from the task description and trust-model references to #1331. "
        "The exact casing, underscoring, and whether these appear as enum variants, string "
        "constants, or protobuf/JSON fields in #1331's specification are not verified here. "
        "Before using these names in a protocol field, confirm against the published spec."
    ),

    "observation_point_enforcement": (
        "The observation-point integrity rule ('the host must not present a gateway "
        "observation as proof from the serving target') is stated as a MUST-NOT but "
        "#1331 does not specify the enforcement mechanism.  This rig implements it as "
        "a runtime check on ObservationRecord.observer_role.  The spec should clarify: "
        "(a) how observer_role is established (is it set by the producer, or derived from "
        "the observation point?), (b) whether a verifier must check it (and what it does "
        "on failure), (c) whether the gateway's record and the host's record are always "
        "separate objects (which would make the forgery scenario structurally impossible "
        "rather than requiring a runtime check)."
    ),
}


# ---------------------------------------------------------------------------
# Standalone runner (summary mode)
# ---------------------------------------------------------------------------

def _run_summary() -> None:
    host = MockLifecycleHost()
    print("=== mock-lifecycle-host development rig ===")
    print("(development rig — not an implementation; offered for re-homing)")
    print()

    scenarios = all_scenarios(host)
    for name, trace in scenarios:
        terminal = trace.terminal_state.value if trace.terminal_state else "none"
        n_phases = len(trace.phases)
        n_obs = len(trace.observations)
        n_sse = len(trace.side_stream_events)
        print(f"  [{name}]")
        print(f"    terminal_state : {terminal}")
        print(f"    phases         : {n_phases}  "
              f"({', '.join(t.to_phase.value for t in trace.phases)})")
        print(f"    observations   : {n_obs}  "
              f"({', '.join(o.observation_point.value for o in trace.observations)})")
        print(f"    side_events    : {n_sse}")
        if name == "gateway_obs_as_host_INVALID":
            try:
                trace.assert_observation_point_integrity()
                print(f"    integrity      : PASS (UNEXPECTED — bug in rig)")
            except ObservationPointIntegrityError as exc:
                print(f"    integrity      : FAIL (EXPECTED) — {exc}")
        else:
            try:
                trace.assert_observation_point_integrity()
                print(f"    integrity      : ok")
            except ObservationPointIntegrityError as exc:
                print(f"    integrity      : ERROR (UNEXPECTED) — {exc}")
        print()

    print("=== SPEC FEEDBACK NOTES ===")
    for key, text in SPEC_FEEDBACK.items():
        # Print first sentence only for the summary.
        first_sentence = text.split(".")[0] + "."
        print(f"  [{key}]")
        print(f"    {first_sentence}")
    print()
    print(f"{len(scenarios)} scenarios run; "
          f"{len(SPEC_FEEDBACK)} spec-feedback notes recorded.")


if __name__ == "__main__":
    _run_summary()

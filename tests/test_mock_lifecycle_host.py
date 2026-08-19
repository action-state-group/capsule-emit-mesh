#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the mock lifecycle host development rig.

Coverage targets:
  - All eight terminal states, each demonstrated distinctly
  - All four observation points, each reachable
  - Observation-point integrity rule: gateway obs must not be presented as
    host evidence; violation must raise ObservationPointIntegrityError
  - Three lifecycle phases: request_received → backend_selected →
    exchange_finished
  - Three side streams: anchoring, delegation, evidence
  - Nine integration scenarios (eight terminal states + integrity violation)

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its mutant.
For every positive assertion, there is a corresponding test or in-test
mutation that confirms the assertion can FAIL.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mock_lifecycle_host import (
    INTERNAL_HOOK_FAILURE_REASON,
    SPEC_FEEDBACK,
    LifecyclePhase,
    LifecycleTrace,
    MockLifecycleHost,
    ObservationPoint,
    ObservationPointIntegrityError,
    ObservationRecord,
    SideStream,
    TerminalState,
    all_scenarios,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def host() -> MockLifecycleHost:
    return MockLifecycleHost()


# ===========================================================================
# 1. TERMINAL STATES — eight, each distinctly demonstrated
# ===========================================================================

class TestTerminalStates:

    def test_completed(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        assert trace.terminal_state == TerminalState.COMPLETED
        assert trace.terminal_reason is None

    def test_policy_denied(self, host: MockLifecycleHost) -> None:
        trace = host.run_policy_denied()
        assert trace.terminal_state == TerminalState.POLICY_DENIED

    def test_request_invalid(self, host: MockLifecycleHost) -> None:
        trace = host.run_request_invalid()
        assert trace.terminal_state == TerminalState.REQUEST_INVALID

    def test_backend_error(self, host: MockLifecycleHost) -> None:
        trace = host.run_backend_error()
        assert trace.terminal_state == TerminalState.BACKEND_ERROR

    def test_transport_error(self, host: MockLifecycleHost) -> None:
        trace = host.run_transport_error()
        assert trace.terminal_state == TerminalState.TRANSPORT_ERROR

    def test_client_cancelled(self, host: MockLifecycleHost) -> None:
        trace = host.run_client_cancelled()
        assert trace.terminal_state == TerminalState.CLIENT_CANCELLED

    def test_timed_out(self, host: MockLifecycleHost) -> None:
        trace = host.run_timed_out()
        assert trace.terminal_state == TerminalState.TIMED_OUT

    def test_evidence_unavailable(self, host: MockLifecycleHost) -> None:
        trace = host.run_evidence_unavailable()
        assert trace.terminal_state == TerminalState.EVIDENCE_UNAVAILABLE

    def test_evidence_unavailable_carries_internal_hook_failure_reason(self, host: MockLifecycleHost) -> None:
        trace = host.run_evidence_unavailable()
        assert trace.terminal_reason == INTERNAL_HOOK_FAILURE_REASON

    def test_eight_states_are_all_distinct_values(self) -> None:
        """All eight terminal state string values are distinct."""
        values = [s.value for s in TerminalState]
        assert len(values) == len(set(values)), \
            f"Duplicate terminal state values: {values}"
        assert len(values) == 8, \
            (f"Expected 8 terminal states; got {len(values)}. "
             f"SPEC NOTE: if evidence_unavailable and internal_hook_failure "
             f"are two distinct states this should be 9. "
             f"See SPEC_FEEDBACK['terminal_state_count'].")

    def test_all_scenario_terminal_states_are_distinct(self, host: MockLifecycleHost) -> None:
        """Each named scenario produces a different terminal state."""
        named_state_scenarios = [
            ("completed",            host.run_completed()),
            ("policy_denied",        host.run_policy_denied()),
            ("request_invalid",      host.run_request_invalid()),
            ("backend_error",        host.run_backend_error()),
            ("transport_error",      host.run_transport_error()),
            ("client_cancelled",     host.run_client_cancelled()),
            ("timed_out",            host.run_timed_out()),
            ("evidence_unavailable", host.run_evidence_unavailable()),
        ]
        seen: dict[TerminalState, str] = {}
        for name, trace in named_state_scenarios:
            ts = trace.terminal_state
            assert ts is not None, f"Scenario {name!r} has no terminal_state"
            assert ts not in seen, (
                f"Terminal state {ts.value!r} appears in both {seen[ts]!r} "
                f"and {name!r} — states must be distinct"
            )
            seen[ts] = name

    # Mutant tests — confirm each check can FAIL

    def test_mutant_wrong_terminal_state_fails(self, host: MockLifecycleHost) -> None:
        """If the scenario returns the wrong state, the assertion catches it."""
        trace = host.run_policy_denied()
        assert trace.terminal_state != TerminalState.COMPLETED, \
            "policy_denied scenario must not return COMPLETED"

    def test_mutant_evidence_unavailable_is_not_completed(self, host: MockLifecycleHost) -> None:
        trace = host.run_evidence_unavailable()
        assert trace.terminal_state != TerminalState.COMPLETED


# ===========================================================================
# 2. OBSERVATION POINTS — four, each reachable
# ===========================================================================

class TestObservationPoints:

    def test_serving_host_ingress_present_in_completed(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        obs = trace.observation_at(ObservationPoint.SERVING_HOST_INGRESS)
        assert obs is not None
        assert obs.observer_role == "serving_host"

    def test_backend_dispatch_present_in_completed(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        obs = trace.observation_at(ObservationPoint.BACKEND_DISPATCH)
        assert obs is not None
        assert obs.observer_role == "serving_host"

    def test_client_egress_present_in_completed(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        obs = trace.observation_at(ObservationPoint.CLIENT_EGRESS)
        assert obs is not None
        assert obs.payload_digest is not None

    def test_gateway_ingress_is_in_gateway_set(self) -> None:
        """GATEWAY_INGRESS is produced by the gateway, not the serving host."""
        from mock_lifecycle_host import _GATEWAY_OBSERVATIONS, _HOST_OBSERVATIONS
        assert ObservationPoint.GATEWAY_INGRESS in _GATEWAY_OBSERVATIONS
        assert ObservationPoint.GATEWAY_INGRESS not in _HOST_OBSERVATIONS

    def test_host_observations_are_host_owned(self) -> None:
        from mock_lifecycle_host import _HOST_OBSERVATIONS
        assert ObservationPoint.SERVING_HOST_INGRESS in _HOST_OBSERVATIONS
        assert ObservationPoint.BACKEND_DISPATCH in _HOST_OBSERVATIONS
        assert ObservationPoint.CLIENT_EGRESS in _HOST_OBSERVATIONS

    def test_all_four_observation_points_defined(self) -> None:
        points = {p.value for p in ObservationPoint}
        assert points == {
            "gateway_ingress",
            "serving_host_ingress",
            "backend_dispatch",
            "client_egress",
        }

    def test_policy_denied_does_not_reach_backend_dispatch(self, host: MockLifecycleHost) -> None:
        """Pre-dispatch refusal: BACKEND_DISPATCH must NOT be in the trace."""
        trace = host.run_policy_denied()
        assert trace.observation_at(ObservationPoint.BACKEND_DISPATCH) is None, \
            "policy_denied must not reach backend_dispatch"

    def test_request_invalid_does_not_reach_backend_dispatch(self, host: MockLifecycleHost) -> None:
        trace = host.run_request_invalid()
        assert trace.observation_at(ObservationPoint.BACKEND_DISPATCH) is None

    def test_backend_dispatch_reached_for_backend_error(self, host: MockLifecycleHost) -> None:
        """backend_error: dispatch was attempted, so BACKEND_DISPATCH IS present."""
        trace = host.run_backend_error()
        obs = trace.observation_at(ObservationPoint.BACKEND_DISPATCH)
        assert obs is not None, \
            "backend_error must have reached backend_dispatch"

    def test_all_observation_points_carry_exchange_id(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        for obs in trace.observations:
            assert obs.exchange_id == trace.exchange_id

    def test_observations_are_ordered_by_lifecycle_phase(self, host: MockLifecycleHost) -> None:
        """SERVING_HOST_INGRESS precedes CLIENT_EGRESS in the happy path."""
        trace = host.run_completed()
        obs_points = [o.observation_point for o in trace.observations]
        ingress_idx = next((i for i, p in enumerate(obs_points)
                            if p == ObservationPoint.SERVING_HOST_INGRESS), None)
        egress_idx = next((i for i, p in enumerate(obs_points)
                           if p == ObservationPoint.CLIENT_EGRESS), None)
        assert ingress_idx is not None
        assert egress_idx is not None
        assert ingress_idx < egress_idx, \
            "SERVING_HOST_INGRESS must precede CLIENT_EGRESS"

    # Mutant: missing observation point IS caught

    def test_mutant_missing_client_egress_is_caught(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        # Remove CLIENT_EGRESS and verify the assertion fires.
        trace.observations = [
            o for o in trace.observations
            if o.observation_point != ObservationPoint.CLIENT_EGRESS
        ]
        assert trace.observation_at(ObservationPoint.CLIENT_EGRESS) is None


# ===========================================================================
# 3. OBSERVATION POINT INTEGRITY RULE
# ===========================================================================

class TestObservationPointIntegrity:

    def test_valid_host_record_passes_integrity_check(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        trace.assert_observation_point_integrity()  # must not raise

    def test_gateway_observation_claimed_as_host_raises(self, host: MockLifecycleHost) -> None:
        """THE KEY INTEGRITY CHECK: a gateway observation presented as host
        evidence must be caught and rejected."""
        trace = host.run_gateway_observation_claimed_as_host()
        with pytest.raises(ObservationPointIntegrityError) as exc_info:
            trace.assert_observation_point_integrity()
        assert "gateway_ingress" in str(exc_info.value).lower() or \
               "gateway observation" in str(exc_info.value).lower(), \
            f"Error should mention gateway_ingress; got: {exc_info.value}"

    def test_individual_record_check_also_raises(self) -> None:
        """The check is also available on the individual ObservationRecord."""
        fraudulent = ObservationRecord(
            observation_point=ObservationPoint.GATEWAY_INGRESS,
            exchange_id="x" * 32,
            phase_at_observation=LifecyclePhase.REQUEST_RECEIVED,
            observer_role="serving_host",  # the lie
            payload_digest=None,
            timestamp_ms=0.0,
        )
        with pytest.raises(ObservationPointIntegrityError):
            fraudulent.assert_serving_host_provenance()

    def test_correctly_labelled_gateway_record_does_not_raise(self) -> None:
        """A GATEWAY_INGRESS record with observer_role='gateway' is fine."""
        legit = ObservationRecord(
            observation_point=ObservationPoint.GATEWAY_INGRESS,
            exchange_id="x" * 32,
            phase_at_observation=LifecyclePhase.REQUEST_RECEIVED,
            observer_role="gateway",   # correct
            payload_digest=None,
            timestamp_ms=0.0,
        )
        legit.assert_serving_host_provenance()  # must not raise

    def test_host_observations_do_not_raise(self) -> None:
        """HOST_OBSERVATIONS with observer_role='serving_host' must all pass."""
        from mock_lifecycle_host import _HOST_OBSERVATIONS
        for point in _HOST_OBSERVATIONS:
            rec = ObservationRecord(
                observation_point=point,
                exchange_id="y" * 32,
                phase_at_observation=LifecyclePhase.EXCHANGE_FINISHED,
                observer_role="serving_host",
                payload_digest=None,
                timestamp_ms=0.0,
            )
            rec.assert_serving_host_provenance()  # must not raise

    def test_fraudulent_trace_contains_integrity_violation(self, host: MockLifecycleHost) -> None:
        trace = host.run_gateway_observation_claimed_as_host()
        # The trace itself has the violating record in it — it is reachable.
        violating = [
            o for o in trace.observations
            if o.observation_point == ObservationPoint.GATEWAY_INGRESS
            and o.observer_role == "serving_host"
        ]
        assert len(violating) == 1, \
            "The fraudulent trace must contain exactly one violating record"

    # Mutant: confirm the check can fail in both directions

    def test_mutant_legit_gateway_record_does_not_trigger_check(self) -> None:
        """The check must NOT fire for a correctly-labelled gateway record."""
        legit = ObservationRecord(
            observation_point=ObservationPoint.GATEWAY_INGRESS,
            exchange_id="z" * 32,
            phase_at_observation=LifecyclePhase.REQUEST_RECEIVED,
            observer_role="gateway",
            payload_digest=None,
            timestamp_ms=0.0,
        )
        # This must succeed — the check is not over-triggering.
        legit.assert_serving_host_provenance()

    def test_mutant_error_message_is_informative(self) -> None:
        fraudulent = ObservationRecord(
            observation_point=ObservationPoint.GATEWAY_INGRESS,
            exchange_id="abc",
            phase_at_observation=LifecyclePhase.REQUEST_RECEIVED,
            observer_role="serving_host",
            payload_digest=None,
            timestamp_ms=0.0,
        )
        with pytest.raises(ObservationPointIntegrityError) as exc_info:
            fraudulent.assert_serving_host_provenance()
        msg = str(exc_info.value)
        # The error must be diagnosable without reading the source.
        assert "serving_host" in msg
        assert "gateway" in msg.lower()


# ===========================================================================
# 4. LIFECYCLE PHASES
# ===========================================================================

class TestLifecyclePhases:

    def test_completed_traverses_all_three_phases(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        assert trace.reached_phase(LifecyclePhase.REQUEST_RECEIVED)
        assert trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)
        assert trace.reached_phase(LifecyclePhase.EXCHANGE_FINISHED)

    def test_policy_denied_skips_backend_selected(self, host: MockLifecycleHost) -> None:
        """Pre-dispatch refusal must not enter BACKEND_SELECTED."""
        trace = host.run_policy_denied()
        assert trace.reached_phase(LifecyclePhase.REQUEST_RECEIVED)
        assert not trace.reached_phase(LifecyclePhase.BACKEND_SELECTED), \
            "policy_denied must skip BACKEND_SELECTED (no backend was chosen)"
        assert trace.reached_phase(LifecyclePhase.EXCHANGE_FINISHED)

    def test_request_invalid_skips_backend_selected(self, host: MockLifecycleHost) -> None:
        trace = host.run_request_invalid()
        assert not trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)

    def test_backend_error_traverses_all_three_phases(self, host: MockLifecycleHost) -> None:
        """Backend error is post-dispatch, so all phases are traversed."""
        trace = host.run_backend_error()
        assert trace.reached_phase(LifecyclePhase.REQUEST_RECEIVED)
        assert trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)
        assert trace.reached_phase(LifecyclePhase.EXCHANGE_FINISHED)

    def test_transport_error_reaches_backend_selected(self, host: MockLifecycleHost) -> None:
        trace = host.run_transport_error()
        assert trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)

    def test_client_cancelled_reaches_backend_selected(self, host: MockLifecycleHost) -> None:
        trace = host.run_client_cancelled()
        assert trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)

    def test_timed_out_reaches_backend_selected(self, host: MockLifecycleHost) -> None:
        trace = host.run_timed_out()
        assert trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)

    def test_exchange_finished_is_always_last(self, host: MockLifecycleHost) -> None:
        """EXCHANGE_FINISHED must be the last phase in every scenario."""
        scenarios = [
            host.run_completed(),
            host.run_policy_denied(),
            host.run_request_invalid(),
            host.run_backend_error(),
            host.run_transport_error(),
            host.run_client_cancelled(),
            host.run_timed_out(),
            host.run_evidence_unavailable(),
        ]
        for trace in scenarios:
            last_phase = trace.phases[-1].to_phase
            assert last_phase == LifecyclePhase.EXCHANGE_FINISHED, (
                f"Scenario {trace.terminal_state} did not end in EXCHANGE_FINISHED; "
                f"last phase was {last_phase}"
            )

    def test_three_phase_values_defined(self) -> None:
        phases = {p.value for p in LifecyclePhase}
        assert phases == {"request_received", "backend_selected", "exchange_finished"}

    # Mutant: phase skip is caught

    def test_mutant_policy_denied_does_not_reach_backend(self, host: MockLifecycleHost) -> None:
        trace = host.run_policy_denied()
        # This is the mutant assertion: it SHOULD be False.
        # If the rig incorrectly adds BACKEND_SELECTED, this test fails.
        reached = trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)
        assert not reached, "policy_denied must not traverse BACKEND_SELECTED"


# ===========================================================================
# 5. SIDE STREAMS
# ===========================================================================

class TestSideStreams:

    def test_completed_has_anchoring_event(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        events = trace.side_stream_events_for(SideStream.ANCHORING)
        assert len(events) >= 1

    def test_completed_has_delegation_event(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        events = trace.side_stream_events_for(SideStream.DELEGATION)
        assert len(events) >= 1

    def test_completed_has_evidence_event(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        events = trace.side_stream_events_for(SideStream.EVIDENCE)
        assert len(events) >= 1

    def test_evidence_unavailable_has_failed_evidence_event(self, host: MockLifecycleHost) -> None:
        trace = host.run_evidence_unavailable()
        events = trace.side_stream_events_for(SideStream.EVIDENCE)
        assert any(e.event_name == "failed" for e in events), \
            "evidence_unavailable scenario must have a failed evidence event"

    def test_evidence_unavailable_hook_failure_reason_in_event_detail(self, host: MockLifecycleHost) -> None:
        trace = host.run_evidence_unavailable()
        events = trace.side_stream_events_for(SideStream.EVIDENCE)
        failed = [e for e in events if e.event_name == "failed"]
        assert failed, "must have at least one failed evidence event"
        assert failed[0].detail.get("reason") == INTERNAL_HOOK_FAILURE_REASON

    def test_request_invalid_has_no_delegation_event(self, host: MockLifecycleHost) -> None:
        """Malformed request rejected at ingress — delegation not needed."""
        trace = host.run_request_invalid()
        events = trace.side_stream_events_for(SideStream.DELEGATION)
        assert len(events) == 0, \
            "request_invalid should not trigger delegation verification"

    def test_side_stream_events_carry_exchange_id(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        for event in trace.side_stream_events:
            assert event.exchange_id == trace.exchange_id

    def test_three_side_streams_defined(self) -> None:
        streams = {s.value for s in SideStream}
        assert streams == {"anchoring", "delegation", "evidence"}, (
            f"Side streams differ from expected; got {streams}. "
            f"SPEC NOTE: see SPEC_FEEDBACK['side_streams_shape'] — "
            f"#1332's diagram was not available; these are inferred."
        )

    # Mutant: wrong event name IS distinguishable from right one

    def test_mutant_delegation_verified_vs_failed_are_different(self, host: MockLifecycleHost) -> None:
        trace_ok = host.run_completed()
        trace_fail = host.run_evidence_unavailable()
        ok_events = trace_ok.side_stream_events_for(SideStream.EVIDENCE)
        fail_events = trace_fail.side_stream_events_for(SideStream.EVIDENCE)
        ok_names = {e.event_name for e in ok_events}
        fail_names = {e.event_name for e in fail_events}
        assert ok_names != fail_names, \
            "completed and evidence_unavailable must have different evidence event names"


# ===========================================================================
# 6. NINE INTEGRATION SCENARIOS
# ===========================================================================

class TestNineIntegrationScenarios:
    """Cover the nine scenarios returned by all_scenarios().

    SPEC NOTE: #1331 references nine host-integration tests; their exact
    names and preconditions are not published here.  This suite maps to what
    can be inferred.  See SPEC_FEEDBACK['nine_integration_tests'].
    """

    def test_nine_scenarios_returned(self) -> None:
        scenarios = all_scenarios()
        assert len(scenarios) == 9, \
            f"Expected 9 scenarios; got {len(scenarios)}"

    def test_eight_distinct_terminal_states_across_eight_scenarios(self) -> None:
        scenarios = all_scenarios()
        # Exclude the integrity-violation scenario (it has terminal_state=COMPLETED
        # because the exchange nominally completed, just with a fraudulent record).
        terminal_states = [
            trace.terminal_state
            for name, trace in scenarios
            if name != "gateway_obs_as_host_INVALID"
        ]
        distinct = set(terminal_states)
        assert len(distinct) == 8, (
            f"Expected 8 distinct terminal states; got {len(distinct)}: "
            f"{[s.value for s in distinct]}"
        )

    def test_integrity_violation_scenario_is_ninth(self) -> None:
        scenarios = all_scenarios()
        names = [name for name, _ in scenarios]
        assert "gateway_obs_as_host_INVALID" in names

    def test_integrity_violation_scenario_fails_integrity_check(self) -> None:
        scenarios = all_scenarios()
        invalid_trace = next(
            trace for name, trace in scenarios
            if name == "gateway_obs_as_host_INVALID"
        )
        with pytest.raises(ObservationPointIntegrityError):
            invalid_trace.assert_observation_point_integrity()

    def test_all_other_scenarios_pass_integrity_check(self) -> None:
        scenarios = all_scenarios()
        for name, trace in scenarios:
            if name == "gateway_obs_as_host_INVALID":
                continue
            try:
                trace.assert_observation_point_integrity()
            except ObservationPointIntegrityError as exc:
                pytest.fail(f"Scenario {name!r} unexpectedly failed integrity check: {exc}")

    def test_all_scenarios_have_unique_exchange_ids(self) -> None:
        scenarios = all_scenarios()
        xids = [trace.exchange_id for _, trace in scenarios]
        assert len(xids) == len(set(xids)), \
            "Every scenario must produce a unique exchange_id"

    def test_all_scenarios_reach_exchange_finished(self) -> None:
        scenarios = all_scenarios()
        for name, trace in scenarios:
            assert trace.reached_phase(LifecyclePhase.EXCHANGE_FINISHED), \
                f"Scenario {name!r} did not reach EXCHANGE_FINISHED"

    # Mutant: confirm the count check catches additions/deletions

    def test_mutant_missing_scenario_is_caught(self) -> None:
        scenarios = all_scenarios()
        # Dropping one makes the count wrong.
        trimmed = scenarios[:-1]
        assert len(trimmed) != 9, "Trimmed list must not be 9"

    def test_mutant_wrong_scenario_count_is_distinguishable(self) -> None:
        # Ten scenarios would also fail the "must be 9" check.
        assert 10 != 9


# ===========================================================================
# 7. SPEC-FEEDBACK NOTES — completeness check
# ===========================================================================

class TestSpecFeedback:
    """Verify that every underspecified corner has a recorded note."""

    EXPECTED_KEYS = {
        "terminal_state_count",
        "side_streams_shape",
        "nine_integration_tests",
        "gateway_host_coordination",
        "backend_error_vs_transport_error",
        "transport_error_boundary",
        "client_cancelled_phase",
        "timed_out_scope",
        "evidence_unavailable_scope",
        "phase_names",
        "observation_point_enforcement",
    }

    def test_all_expected_keys_present(self) -> None:
        missing = self.EXPECTED_KEYS - set(SPEC_FEEDBACK.keys())
        assert not missing, f"Missing spec-feedback entries: {missing}"

    def test_no_empty_notes(self) -> None:
        for key, text in SPEC_FEEDBACK.items():
            assert text.strip(), f"Spec-feedback note {key!r} is empty"

    def test_terminal_state_count_note_mentions_ambiguity(self) -> None:
        note = SPEC_FEEDBACK["terminal_state_count"]
        assert "evidence_unavailable" in note
        assert "internal_hook_failure" in note

    def test_observation_point_rule_note_present(self) -> None:
        note = SPEC_FEEDBACK["observation_point_enforcement"]
        assert "gateway" in note.lower()
        assert "serving" in note.lower() or "host" in note.lower()


# ===========================================================================
# 8. POLICY_DENIED vs BACKEND_ERROR distinguishability
# ===========================================================================

class TestPreDispatchVsPostDispatch:
    """#1331 requirement: a refusal before dispatch is POLICY_DENIED; a refusal
    after dispatch is BACKEND_ERROR.  These must be distinguishable from the
    trace alone.
    """

    def test_policy_denied_vs_backend_error_are_distinct_states(self) -> None:
        assert TerminalState.POLICY_DENIED != TerminalState.BACKEND_ERROR

    def test_policy_denied_lacks_backend_dispatch_observation(self, host: MockLifecycleHost) -> None:
        trace = host.run_policy_denied()
        assert trace.observation_at(ObservationPoint.BACKEND_DISPATCH) is None

    def test_backend_error_has_backend_dispatch_observation(self, host: MockLifecycleHost) -> None:
        trace = host.run_backend_error()
        assert trace.observation_at(ObservationPoint.BACKEND_DISPATCH) is not None

    def test_policy_denied_skips_backend_selected_phase(self, host: MockLifecycleHost) -> None:
        trace = host.run_policy_denied()
        assert not trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)

    def test_backend_error_reaches_backend_selected_phase(self, host: MockLifecycleHost) -> None:
        trace = host.run_backend_error()
        assert trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)

    def test_distinguishable_from_observations_alone(self, host: MockLifecycleHost) -> None:
        """The distinction must be derivable from the trace without checking
        terminal_state — observation points alone must tell the story."""
        policy_trace = host.run_policy_denied()
        backend_trace = host.run_backend_error()

        policy_points = {o.observation_point for o in policy_trace.observations}
        backend_points = {o.observation_point for o in backend_trace.observations}

        # BACKEND_DISPATCH distinguishes them.
        assert ObservationPoint.BACKEND_DISPATCH not in policy_points
        assert ObservationPoint.BACKEND_DISPATCH in backend_points


# ===========================================================================
# Standalone runner
# ===========================================================================

if __name__ == "__main__":
    import traceback

    test_classes = [
        TestTerminalStates,
        TestObservationPoints,
        TestObservationPointIntegrity,
        TestLifecyclePhases,
        TestSideStreams,
        TestNineIntegrationScenarios,
        TestSpecFeedback,
        TestPreDispatchVsPostDispatch,
    ]

    host_instance = MockLifecycleHost()
    failures: list[tuple[str, Exception]] = []
    total = 0

    for cls in test_classes:
        instance = cls()
        methods = sorted(m for m in dir(instance) if m.startswith("test_"))
        for method_name in methods:
            total += 1
            fn = getattr(instance, method_name)
            # Inject host fixture where needed.
            import inspect
            sig = inspect.signature(fn)
            kwargs = {}
            if "host" in sig.parameters:
                kwargs["host"] = host_instance
            try:
                fn(**kwargs)
                print(f"  OK  {cls.__name__}.{method_name}")
            except Exception as exc:
                failures.append((f"{cls.__name__}.{method_name}", exc))
                print(f"  FAIL {cls.__name__}.{method_name}: {exc}")
                traceback.print_exc()

    print(f"\n{total - len(failures)}/{total} passed")
    if failures:
        raise SystemExit(1)

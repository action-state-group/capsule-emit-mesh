#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record-side state and observation binding tests.

PURPOSE
    Demonstrate that the capsule RECORD — not the rig, not any runtime
    side-channel — is distinguishable across #1331's eight terminal states and
    four observation points to an offline verifier who has ONLY THE RECORD
    BYTES.

    The rig (mesh-1331-mock-lifecycle-host) produces the scenarios.
    This module proves the second half: for each scenario the emitted bytes
    carry enough information for mesh_record_verifier.verify_record_bytes() to
    reach the correct verdict.

WHAT IS TESTED
    1. 8×1 STATE TABLE — each of the eight terminal states verified from
       record bytes alone.  Mutant: one wrong state must be caught.
    2. 4×1 OBSERVATION TABLE — each of the four observation points verified
       from record bytes alone.  Mutant: one wrong point must be caught.
    3. TRANSCRIPT OVERFLOW — observer overflow represented as incomplete
       evidence.  Guard check: correct.
    4. DELIBERATELY-BROKEN TRUNCATION — truncated transcript with
       complete=True passes a naive verifier BEFORE the guard and is caught
       by the guarded verifier AFTER.  Both directions shown.
    5. VANTAGE-POINT DISTINGUISHABILITY — two records of the same exchange
       are JOINABLE (same exchange_id) AND DISTINGUISHABLE (different
       observation_point / local_peer_id).
    6. PROVENANCE CONFLICT — a gateway observation claimed by a serving-host
       peer is flagged in the verdict findings.

IMPORT STRATEGY
    The rig (mock_lifecycle_host) lives in the held worktree at
    ../_worktrees/capsule-emit-mesh/mesh-1331-mock-lifecycle-host.
    sys.path is extended at module load so the import resolves without
    installing or symlinking the rig.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

# ── Rig import ──────────────────────────────────────────────────────────────
# Build against the held rig worktree — QUEUE_PROTOCOL §5.
_RIG_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "mesh-1331-mock-lifecycle-host"
)
if str(_RIG_DIR) not in sys.path:
    sys.path.insert(0, str(_RIG_DIR))

from mock_lifecycle_host import (  # noqa: E402
    MockLifecycleHost,
    ObservationPoint,
    TerminalState,
)

# ── Record-side modules (in this worktree) ──────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mesh_record_emitter import (  # noqa: E402
    RecordNodeState,
    capsule_to_bytes,
    default_node_state,
    emit_from_trace,
    emit_lifecycle_record,
    make_transcript_summary,
)
from mesh_record_verifier import (  # noqa: E402
    GATEWAY_OBSERVATION_POINTS,
    HOST_OBSERVATION_POINTS,
    OBSERVATION_POINTS,
    TERMINAL_STATES,
    IncompleteTranscriptError,
    LifecycleVerdict,
    MissingExchangeId,
    UnknownObservationPoint,
    UnknownTerminalState,
    verify_record_bytes,
    verify_record_bytes_naive,
)


# ===========================================================================
# Shared fixtures
# ===========================================================================

@pytest.fixture(scope="module")
def host() -> MockLifecycleHost:
    return MockLifecycleHost()


@pytest.fixture
def node() -> RecordNodeState:
    """Fresh node state per test — independent signing keys, clean chain."""
    return default_node_state()


# ===========================================================================
# 1. 8×1 STATE TABLE
#    For each terminal state: emit → verify from record bytes → correct verdict.
#    Mutant: wrong state value must raise UnknownTerminalState.
# ===========================================================================

class TestEightStateTable:
    """Each row of the 8×1 table: one state, one record, one verified verdict."""

    @pytest.mark.parametrize("state_name,run_method", [
        ("completed",            "run_completed"),
        ("policy_denied",        "run_policy_denied"),
        ("request_invalid",      "run_request_invalid"),
        ("backend_error",        "run_backend_error"),
        ("transport_error",      "run_transport_error"),
        ("client_cancelled",     "run_client_cancelled"),
        ("timed_out",            "run_timed_out"),
        ("evidence_unavailable", "run_evidence_unavailable"),
    ])
    def test_state_verified_from_record_bytes(
        self,
        host: MockLifecycleHost,
        node: RecordNodeState,
        state_name: str,
        run_method: str,
    ) -> None:
        """RECORD BYTES → correct terminal_state verdict."""
        trace = getattr(host, run_method)()
        capsule = emit_from_trace(node, trace, local_peer_id="serving-host-A")
        record_bytes = capsule_to_bytes(capsule)

        verdict = verify_record_bytes(record_bytes)

        assert verdict.terminal_state == state_name, (
            f"Verifier reading record bytes returned terminal_state="
            f"{verdict.terminal_state!r}; expected {state_name!r}. "
            f"The record bytes must carry the state unambiguously."
        )

    def test_all_eight_states_distinct_in_records(
        self,
        host: MockLifecycleHost,
    ) -> None:
        """One record per state — all eight verdict values are distinct."""
        scenarios = [
            ("completed",            host.run_completed()),
            ("policy_denied",        host.run_policy_denied()),
            ("request_invalid",      host.run_request_invalid()),
            ("backend_error",        host.run_backend_error()),
            ("transport_error",      host.run_transport_error()),
            ("client_cancelled",     host.run_client_cancelled()),
            ("timed_out",            host.run_timed_out()),
            ("evidence_unavailable", host.run_evidence_unavailable()),
        ]
        seen: dict[str, str] = {}
        for state_name, trace in scenarios:
            node = default_node_state()
            capsule = emit_from_trace(node, trace, local_peer_id="serving-host-A")
            verdict = verify_record_bytes(capsule_to_bytes(capsule))
            assert verdict.terminal_state not in seen, (
                f"terminal_state {verdict.terminal_state!r} already seen in "
                f"{seen[verdict.terminal_state]!r}; all 8 must be distinct"
            )
            seen[verdict.terminal_state] = state_name

    # Mutant: unknown state value is caught
    def test_mutant_unknown_terminal_state_raises(self, node: RecordNodeState) -> None:
        """A record with a misspelled terminal_state must not silently verify."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",  # valid state to pass producer
            exchange_id="aabbccdd" * 4,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
        )
        # Inject a bad value directly into the bytes — simulating a corrupted record.
        block = capsule["model_attestation"]["compute_attestation"]["x-mesh-lifecycle-v1"]
        block["terminal_state"] = "invented_state"
        bad_bytes = capsule_to_bytes(capsule)

        with pytest.raises(UnknownTerminalState):
            verify_record_bytes(bad_bytes)

    # Mutant: bytes from a different state fail the wrong-state assertion
    def test_mutant_wrong_state_assertion_fails(
        self, host: MockLifecycleHost, node: RecordNodeState
    ) -> None:
        """policy_denied record must not verify as completed."""
        trace = host.run_policy_denied()
        capsule = emit_from_trace(node, trace, local_peer_id="serving-host-A")
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert verdict.terminal_state != "completed", (
            "policy_denied record must not report terminal_state='completed'"
        )

    def test_evidence_unavailable_carries_terminal_reason(
        self, host: MockLifecycleHost, node: RecordNodeState
    ) -> None:
        """evidence_unavailable record must carry terminal_reason in bytes."""
        trace = host.run_evidence_unavailable()
        capsule = emit_from_trace(node, trace, local_peer_id="serving-host-A")
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert verdict.terminal_state == "evidence_unavailable"
        assert verdict.terminal_reason == "internal_hook_failure", (
            "Sub-reason must be readable from record bytes alone."
        )

    def test_completed_has_no_terminal_reason(
        self, host: MockLifecycleHost, node: RecordNodeState
    ) -> None:
        trace = host.run_completed()
        capsule = emit_from_trace(node, trace, local_peer_id="serving-host-A")
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert verdict.terminal_reason is None


# ===========================================================================
# 2. 4×1 OBSERVATION TABLE
#    For each observation point: emit → verify from record bytes → correct verdict.
#    Mutant: wrong point value must raise UnknownObservationPoint.
# ===========================================================================

class TestFourObservationTable:
    """Each row of the 4×1 table: one obs point, one record, one verified verdict."""

    @pytest.mark.parametrize("obs_point,peer_id", [
        ("gateway_ingress",      "gateway-A"),
        ("serving_host_ingress", "serving-host-A"),
        ("backend_dispatch",     "serving-host-A"),
        ("client_egress",        "serving-host-A"),
    ])
    def test_observation_point_verified_from_record_bytes(
        self,
        host: MockLifecycleHost,
        node: RecordNodeState,
        obs_point: str,
        peer_id: str,
    ) -> None:
        """RECORD BYTES → correct observation_point verdict."""
        trace = host.run_completed()
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point=obs_point,
            exchange_id=trace.exchange_id,
            hop_id="hop-0",
            attempt=0,
            local_peer_id=peer_id,
            transcript=make_transcript_summary(3, 3),
        )
        record_bytes = capsule_to_bytes(capsule)
        verdict = verify_record_bytes(record_bytes)

        assert verdict.observation_point == obs_point, (
            f"Verifier reading record bytes returned observation_point="
            f"{verdict.observation_point!r}; expected {obs_point!r}."
        )
        assert verdict.local_peer_id == peer_id

    def test_all_four_observation_points_distinct(
        self, host: MockLifecycleHost
    ) -> None:
        """One record per obs point — all four verdict values are distinct."""
        trace = host.run_completed()
        combos = [
            ("gateway_ingress",      "gateway-A"),
            ("serving_host_ingress", "serving-host-A"),
            ("backend_dispatch",     "serving-host-A"),
            ("client_egress",        "serving-host-A"),
        ]
        seen: set[str] = set()
        for obs_point, peer_id in combos:
            node = default_node_state()
            capsule = emit_lifecycle_record(
                node,
                terminal_state="completed",
                observation_point=obs_point,
                exchange_id=trace.exchange_id,
                local_peer_id=peer_id,
                transcript=make_transcript_summary(3, 3),
            )
            verdict = verify_record_bytes(capsule_to_bytes(capsule))
            assert verdict.observation_point not in seen, (
                f"observation_point {verdict.observation_point!r} seen twice"
            )
            seen.add(verdict.observation_point)

    # Mutant: unknown obs point is caught
    def test_mutant_unknown_observation_point_raises(self, node: RecordNodeState) -> None:
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="serving_host_ingress",
            exchange_id="aa" * 16,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
        )
        block = capsule["model_attestation"]["compute_attestation"]["x-mesh-lifecycle-v1"]
        block["observation_point"] = "invented_point"
        with pytest.raises(UnknownObservationPoint):
            verify_record_bytes(capsule_to_bytes(capsule))

    # Mutant: wrong obs point is NOT misidentified
    def test_mutant_wrong_obs_point_fails_assertion(self, node: RecordNodeState) -> None:
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="backend_dispatch",
            exchange_id="bb" * 16,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert verdict.observation_point != "gateway_ingress"
        assert verdict.observation_point != "client_egress"


# ===========================================================================
# 3. TRANSCRIPT OVERFLOW — incomplete evidence represented correctly
# ===========================================================================

class TestTranscriptOverflow:
    """Observer overflow / disconnect → record says incomplete.

    #1331: "An observer overflow or disconnect is represented as incomplete
    evidence rather than a successful complete observation."
    """

    def test_overflow_record_says_incomplete(self, node: RecordNodeState) -> None:
        """8 events expected, 3 received → complete=False in record bytes."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="serving_host_ingress",
            exchange_id="cc" * 16,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(event_count=3, expected_count=8),
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert not verdict.transcript_complete, (
            "Overflow record must report transcript_complete=False from bytes."
        )
        assert verdict.transcript_event_count == 3
        assert verdict.transcript_expected_count == 8

    def test_complete_record_says_complete(self, node: RecordNodeState) -> None:
        """8 events expected and received → complete=True in record bytes."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="serving_host_ingress",
            exchange_id="dd" * 16,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(event_count=8, expected_count=8),
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert verdict.transcript_complete
        assert verdict.transcript_event_count == 8

    def test_unknown_count_record_says_incomplete(self, node: RecordNodeState) -> None:
        """Unknown expected count (observer disconnected) → complete=False."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="transport_error",
            observation_point="client_egress",
            exchange_id="ee" * 16,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(event_count=2, expected_count=None),
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert not verdict.transcript_complete
        assert verdict.transcript_expected_count is None


# ===========================================================================
# 4. DELIBERATELY-BROKEN TRUNCATION
#    The guard must fire.  Without the failing case the check proves nothing.
#
#    Phase A — BEFORE guard: naive verifier accepts the lie.
#    Phase B — AFTER guard: guarded verifier raises IncompleteTranscriptError.
# ===========================================================================

class TestDeliberatelyBrokenTruncation:
    """The two-phase demonstration required by QUEUE_PROTOCOL §7.

    A table with no failing case behind it does not meet acceptance.
    """

    @staticmethod
    def _make_lying_record(node: RecordNodeState) -> bytes:
        """Build a record that claims complete=True but has only 3 of 8 events.

        The emitter's producer invariant prevents this normally.  We use
        _override_complete=True (named explicitly) to bypass it, simulating a
        malicious or buggy producer.
        """
        lying_transcript = make_transcript_summary(
            event_count=3,
            expected_count=8,
            _override_complete=True,
        )
        assert lying_transcript.complete is True  # the lie is present
        assert lying_transcript.event_count == 3

        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="serving_host_ingress",
            exchange_id="ff" * 16,
            local_peer_id="serving-host-A",
            transcript=lying_transcript,
        )
        return capsule_to_bytes(capsule)

    def test_phase_a_naive_verifier_accepts_the_lie(self, node: RecordNodeState) -> None:
        """BEFORE the guard: verify_record_bytes_naive() returns True (the lie passes).

        This demonstrates WHY the guard is necessary.  A verifier that trusts
        the record's own complete flag cannot distinguish a truncated transcript
        from a complete one when the producer lies.
        """
        lying_bytes = self._make_lying_record(node)

        # Naive check — trusts the record's complete field directly.
        naive_result = verify_record_bytes_naive(lying_bytes)

        assert naive_result is True, (
            "PHASE A FAILURE: naive verifier should accept the lying record "
            "before the guard exists.  If this assertion fails, the 'before' "
            "phase of the two-phase demonstration is broken."
        )

    def test_phase_b_guarded_verifier_catches_the_lie(self, node: RecordNodeState) -> None:
        """AFTER the guard: verify_record_bytes() raises IncompleteTranscriptError.

        This is the check that proves the guard works.  The same record that
        phase A accepted is now rejected because the verifier checks internal
        consistency: complete=True AND event_count(3) < expected_count(8).
        """
        lying_bytes = self._make_lying_record(node)

        with pytest.raises(IncompleteTranscriptError) as exc_info:
            verify_record_bytes(lying_bytes)

        msg = str(exc_info.value)
        assert "complete=True" in msg or "complete" in msg.lower()
        assert "event_count" in msg or "3" in msg
        assert "expected_count" in msg or "8" in msg

    def test_phase_a_and_b_same_bytes(self, node: RecordNodeState) -> None:
        """Both phases operate on identical bytes — the difference is the guard."""
        lying_bytes = self._make_lying_record(node)

        # Phase A: passes
        naive_result = verify_record_bytes_naive(lying_bytes)
        assert naive_result is True

        # Phase B: same bytes, fails
        with pytest.raises(IncompleteTranscriptError):
            verify_record_bytes(lying_bytes)

    def test_emitter_safety_blocks_accidental_lie(self, node: RecordNodeState) -> None:
        """The emitter's producer invariant prevents the lie without _override_complete.

        This confirms the lie requires deliberate bypass — accidental truncation
        cannot produce a complete=True record through the normal emitter path.
        """
        from mesh_record_emitter import emit_lifecycle_record, make_transcript_summary

        normal_truncated = make_transcript_summary(event_count=3, expected_count=8)
        assert normal_truncated.complete is False  # safety holds

        # Emitting a record with this transcript should succeed with complete=False.
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="serving_host_ingress",
            exchange_id="11" * 16,
            local_peer_id="serving-host-A",
            transcript=normal_truncated,
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert not verdict.transcript_complete


# ===========================================================================
# 5. VANTAGE-POINT DISTINGUISHABILITY
#    Same exchange, two records, two vantage points.
#    JOINABLE: same exchange_id.
#    DISTINGUISHABLE: different observation_point / local_peer_id.
# ===========================================================================

class TestVantagePointDistinguishability:
    """#1331: exchange_id + hop_id + attempt + local_peer_id must make two
    records of the same exchange distinguishable AND joinable.
    """

    def test_two_records_same_exchange_joinable(self, host: MockLifecycleHost) -> None:
        """Two records with the same exchange_id are joinable."""
        trace = host.run_completed()
        exchange_id = trace.exchange_id

        node_gw = default_node_state("gateway-A")
        node_host = default_node_state("serving-host-A")

        capsule_gw = emit_lifecycle_record(
            node_gw,
            terminal_state="completed",
            observation_point="gateway_ingress",
            exchange_id=exchange_id,
            hop_id="hop-0",
            attempt=0,
            local_peer_id="gateway-A",
            transcript=make_transcript_summary(1, 1),
        )
        capsule_host = emit_lifecycle_record(
            node_host,
            terminal_state="completed",
            observation_point="serving_host_ingress",
            exchange_id=exchange_id,
            hop_id="hop-1",
            attempt=0,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
        )

        verdict_gw = verify_record_bytes(capsule_to_bytes(capsule_gw))
        verdict_host = verify_record_bytes(capsule_to_bytes(capsule_host))

        # Joinable: same exchange
        assert verdict_gw.is_joinable_with(verdict_host), (
            "Records of the same exchange must be joinable via exchange_id."
        )
        assert verdict_gw.exchange_id == verdict_host.exchange_id == exchange_id

    def test_two_records_same_exchange_distinguishable(
        self, host: MockLifecycleHost
    ) -> None:
        """Two records of the same exchange are distinguishable by vantage point."""
        trace = host.run_completed()
        exchange_id = trace.exchange_id

        node_gw = default_node_state("gateway-A")
        node_host = default_node_state("serving-host-A")

        capsule_gw = emit_lifecycle_record(
            node_gw,
            terminal_state="completed",
            observation_point="gateway_ingress",
            exchange_id=exchange_id,
            hop_id="hop-0",
            attempt=0,
            local_peer_id="gateway-A",
            transcript=make_transcript_summary(1, 1),
        )
        capsule_host = emit_lifecycle_record(
            node_host,
            terminal_state="completed",
            observation_point="serving_host_ingress",
            exchange_id=exchange_id,
            hop_id="hop-1",
            attempt=0,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
        )

        verdict_gw = verify_record_bytes(capsule_to_bytes(capsule_gw))
        verdict_host = verify_record_bytes(capsule_to_bytes(capsule_host))

        # Distinguishable: different vantage
        assert verdict_gw.is_distinguishable_from(verdict_host), (
            "Records from different vantage points must be distinguishable "
            "from record bytes alone."
        )
        assert verdict_gw.observation_point == "gateway_ingress"
        assert verdict_host.observation_point == "serving_host_ingress"
        assert verdict_gw.local_peer_id == "gateway-A"
        assert verdict_host.local_peer_id == "serving-host-A"
        assert verdict_gw.hop_id == "hop-0"
        assert verdict_host.hop_id == "hop-1"

    def test_joinable_and_distinguishable_simultaneously(
        self, host: MockLifecycleHost
    ) -> None:
        """BOTH properties hold for the same pair of records."""
        trace = host.run_completed()
        exchange_id = trace.exchange_id

        node_gw = default_node_state("gateway-A")
        node_host = default_node_state("serving-host-A")

        verdict_gw = verify_record_bytes(
            capsule_to_bytes(
                emit_lifecycle_record(
                    node_gw,
                    terminal_state="completed",
                    observation_point="gateway_ingress",
                    exchange_id=exchange_id,
                    hop_id="hop-0",
                    attempt=0,
                    local_peer_id="gateway-A",
                    transcript=make_transcript_summary(1, 1),
                )
            )
        )
        verdict_host = verify_record_bytes(
            capsule_to_bytes(
                emit_lifecycle_record(
                    node_host,
                    terminal_state="completed",
                    observation_point="serving_host_ingress",
                    exchange_id=exchange_id,
                    hop_id="hop-1",
                    attempt=0,
                    local_peer_id="serving-host-A",
                    transcript=make_transcript_summary(3, 3),
                )
            )
        )
        assert verdict_gw.is_joinable_with(verdict_host)       # same exchange
        assert verdict_gw.is_distinguishable_from(verdict_host)  # diff vantage

    # Mutant: records from DIFFERENT exchanges are NOT joinable
    def test_mutant_different_exchanges_not_joinable(self, host: MockLifecycleHost) -> None:
        trace_a = host.run_completed()
        trace_b = host.run_completed()  # fresh exchange_id each time
        assert trace_a.exchange_id != trace_b.exchange_id, (
            "Each run_completed() call must produce a unique exchange_id."
        )

        node_a = default_node_state()
        node_b = default_node_state()

        verdict_a = verify_record_bytes(
            capsule_to_bytes(emit_from_trace(node_a, trace_a, local_peer_id="serving-host-A"))
        )
        verdict_b = verify_record_bytes(
            capsule_to_bytes(emit_from_trace(node_b, trace_b, local_peer_id="serving-host-A"))
        )

        assert not verdict_a.is_joinable_with(verdict_b), (
            "Records from different exchanges must NOT be joinable."
        )

    # Mutant: same vantage = NOT distinguishable
    def test_mutant_same_vantage_not_distinguishable(self, host: MockLifecycleHost) -> None:
        trace = host.run_completed()
        node_a = default_node_state()
        node_b = default_node_state()

        verdict_a = verify_record_bytes(
            capsule_to_bytes(
                emit_lifecycle_record(
                    node_a,
                    terminal_state="completed",
                    observation_point="serving_host_ingress",
                    exchange_id=trace.exchange_id,
                    hop_id="hop-1",
                    attempt=0,
                    local_peer_id="serving-host-A",
                    transcript=make_transcript_summary(3, 3),
                )
            )
        )
        verdict_b = verify_record_bytes(
            capsule_to_bytes(
                emit_lifecycle_record(
                    node_b,
                    terminal_state="completed",
                    observation_point="serving_host_ingress",
                    exchange_id=trace.exchange_id,
                    hop_id="hop-1",
                    attempt=0,
                    local_peer_id="serving-host-A",  # same peer
                    transcript=make_transcript_summary(3, 3),
                )
            )
        )
        assert not verdict_a.is_distinguishable_from(verdict_b), (
            "Records with identical vantage fields must NOT be distinguishable — "
            "if they were, the distinguishability test would be vacuous."
        )


# ===========================================================================
# 6. PROVENANCE CONFLICT
#    gateway_ingress claimed by a serving-host peer → finding in verdict.
#    #1331: "the host must not present a gateway observation as proof from
#    the serving target."
# ===========================================================================

class TestProvenanceConflict:
    """Provenance conflict is detected from record bytes and recorded in findings."""

    def test_gateway_obs_claimed_by_serving_host_is_flagged(
        self, node: RecordNodeState
    ) -> None:
        """A record at gateway_ingress with a non-gateway peer_id is flagged."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="gateway_ingress",
            exchange_id="gg" * 16,
            hop_id="hop-0",
            attempt=0,
            local_peer_id="serving-host-B",  # non-gateway peer
            transcript=make_transcript_summary(1, 1),
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))

        assert verdict.findings, (
            "A gateway observation claimed by a non-gateway peer must produce "
            "at least one finding in the verdict."
        )
        # The finding must mention both gateway_ingress and the peer.
        combined = " ".join(verdict.findings).lower()
        assert "gateway" in combined
        assert "serving" in combined or "serving-host-b" in combined

    def test_gateway_obs_claimed_by_gateway_peer_is_clean(
        self, node: RecordNodeState
    ) -> None:
        """A record at gateway_ingress with a gateway peer_id is clean."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="gateway_ingress",
            exchange_id="hh" * 16,
            hop_id="hop-0",
            attempt=0,
            local_peer_id="gateway-A",
            transcript=make_transcript_summary(1, 1),
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert not verdict.findings, (
            f"Clean gateway record should have no findings; got: {verdict.findings}"
        )

    def test_host_obs_by_serving_host_peer_is_clean(
        self, node: RecordNodeState
    ) -> None:
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            observation_point="serving_host_ingress",
            exchange_id="ii" * 16,
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(3, 3),
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert not verdict.findings

    # Mutant: the check does NOT fire for host observations
    def test_mutant_host_obs_does_not_false_positive(
        self, node: RecordNodeState
    ) -> None:
        for obs_point in ("serving_host_ingress", "backend_dispatch", "client_egress"):
            capsule = emit_lifecycle_record(
                node,
                terminal_state="completed",
                observation_point=obs_point,
                exchange_id="jj" * 16,
                local_peer_id="serving-host-A",
                transcript=make_transcript_summary(3, 3),
            )
            verdict = verify_record_bytes(capsule_to_bytes(capsule))
            assert not verdict.findings, (
                f"Host obs point {obs_point!r} should not trigger provenance warning; "
                f"got: {verdict.findings}"
            )


# ===========================================================================
# 7. STRUCTURAL PROPERTIES — cross-cutting checks
# ===========================================================================

class TestStructuralProperties:

    def test_known_terminal_states_are_eight(self) -> None:
        assert len(TERMINAL_STATES) == 8

    def test_known_observation_points_are_four(self) -> None:
        assert len(OBSERVATION_POINTS) == 4

    def test_gateway_and_host_sets_partition_observation_points(self) -> None:
        assert GATEWAY_OBSERVATION_POINTS | HOST_OBSERVATION_POINTS == OBSERVATION_POINTS
        assert GATEWAY_OBSERVATION_POINTS & HOST_OBSERVATION_POINTS == frozenset()

    def test_record_bytes_are_valid_json(self, host: MockLifecycleHost, node: RecordNodeState) -> None:
        trace = host.run_completed()
        capsule = emit_from_trace(node, trace, local_peer_id="serving-host-A")
        record_bytes = capsule_to_bytes(capsule)
        parsed = json.loads(record_bytes)
        assert isinstance(parsed, dict)
        assert "capsule_id" in parsed

    def test_record_survives_round_trip(self, host: MockLifecycleHost, node: RecordNodeState) -> None:
        """Bytes → parse → verify_record_bytes → same verdict as direct check."""
        trace = host.run_policy_denied()
        capsule = emit_from_trace(node, trace, local_peer_id="serving-host-A")
        record_bytes = capsule_to_bytes(capsule)
        verdict = verify_record_bytes(record_bytes)
        assert verdict.terminal_state == "policy_denied"
        assert verdict.exchange_id == trace.exchange_id

    def test_each_record_has_unique_capsule_id(self, host: MockLifecycleHost) -> None:
        """Two distinct records produce distinct capsule_ids."""
        node_a = default_node_state()
        node_b = default_node_state()
        trace_a = host.run_completed()
        trace_b = host.run_policy_denied()
        cap_a = emit_from_trace(node_a, trace_a, local_peer_id="serving-host-A")
        cap_b = emit_from_trace(node_b, trace_b, local_peer_id="serving-host-A")
        assert cap_a["capsule_id"] != cap_b["capsule_id"]


# ===========================================================================
# 7. MISSING exchange_id — [mesh-rung12-adversarial-review] D2
# ===========================================================================
#
# emit_lifecycle_record() requires exchange_id as a mandatory keyword
# argument, so an honest producer cannot omit it. The verifier must still
# fail closed on a record that does (a malicious or corrupted one) rather
# than defaulting to "" — a value any number of unrelated broken/malicious
# records could collapse onto.

class TestMissingExchangeIdFailsClosed:

    def _capsule_missing_exchange_id(self, node: RecordNodeState) -> dict[str, Any]:
        """A well-formed record with exchange_id deleted from the block --
        simulates a malicious/corrupted record; emit_lifecycle_record()
        itself cannot produce one (exchange_id has no default)."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            exchange_id="temp-will-be-stripped",
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(1, 1),
        )
        block = capsule["model_attestation"]["compute_attestation"]["x-mesh-lifecycle-v1"]
        del block["exchange_id"]
        return capsule

    def test_mutant_missing_exchange_id_key_raises(self, node: RecordNodeState) -> None:
        """RED-before-green: before this fix, a missing exchange_id key
        silently defaulted to "" and verification proceeded. Now it must
        raise rather than silently collapse onto a shared correlator."""
        capsule = self._capsule_missing_exchange_id(node)
        with pytest.raises(MissingExchangeId):
            verify_record_bytes(capsule_to_bytes(capsule))

    def test_mutant_empty_string_exchange_id_raises(self, node: RecordNodeState) -> None:
        """An explicit exchange_id="" is exactly as unusable a correlator as
        a missing key -- must fail closed the same way."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            exchange_id="",
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(1, 1),
        )
        with pytest.raises(MissingExchangeId):
            verify_record_bytes(capsule_to_bytes(capsule))

    def test_normal_record_with_real_exchange_id_still_verifies(self, node: RecordNodeState) -> None:
        """The guard must not false-positive on the normal case."""
        capsule = emit_lifecycle_record(
            node,
            terminal_state="completed",
            exchange_id="a-real-exchange-id",
            local_peer_id="serving-host-A",
            transcript=make_transcript_summary(1, 1),
        )
        verdict = verify_record_bytes(capsule_to_bytes(capsule))
        assert verdict.exchange_id == "a-real-exchange-id"

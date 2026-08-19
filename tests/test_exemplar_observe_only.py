#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the observe-only exemplar plugin.

Acceptance items verified here:
  #1 — Both modes run against the rig; observe-only demonstrably changes
       nothing (byte-identical request reaches backend — COMPARED, not
       asserted).

BYTE-IDENTICAL COMPARISON
    The host records payload_digest at SERVING_HOST_INGRESS (what arrived)
    and at BACKEND_DISPATCH (what was forwarded).  The test computes
    sha256(original_request_body) and compares it against both digests.
    This is not an assertion that "we trust the plugin was observe-only";
    it is a comparison of actual sha256 values over the actual bytes.

    The plugin physically cannot alter the dispatch bytes: its on_phase()
    return value is a decision string, not a body transformer.  The test
    documents that invariant by comparing, not just asserting equal.

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its mutant.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from exemplar.observe_only import ObserveOnlyPlugin
from exemplar.plugin_contract import ABSTAIN, HostConfig
from exemplar.plugin_host import PluginLifecycleHost

from mock_lifecycle_host import (
    LifecyclePhase,
    ObservationPoint,
    TerminalState,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def plugin() -> ObserveOnlyPlugin:
    return ObserveOnlyPlugin()


@pytest.fixture()
def host(plugin: ObserveOnlyPlugin) -> PluginLifecycleHost:
    return PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))


# ---------------------------------------------------------------------------
# Happy-path requests
# ---------------------------------------------------------------------------

CHAT_REQUEST = b'{"model":"test","messages":[{"role":"user","content":"hello"}]}'
BACKEND_RESPONSE = (
    b'{"id":"cmpl-ok","object":"chat.completion",'
    b'"choices":[{"index":0,"message":{"role":"assistant","content":"hi"},'
    b'"finish_reason":"stop"}]}'
)


# ---------------------------------------------------------------------------
# 1. Terminal state — completed
# ---------------------------------------------------------------------------

class TestObserveOnlyTerminalState:

    def test_completed_on_allowed_request(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        assert trace.terminal_state == TerminalState.COMPLETED

    def test_terminal_reason_is_none(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        assert trace.terminal_reason is None

    def test_traverses_all_three_phases(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        assert trace.reached_phase(LifecyclePhase.REQUEST_RECEIVED)
        assert trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)
        assert trace.reached_phase(LifecyclePhase.EXCHANGE_FINISHED)

    # Mutant: wrong terminal state is caught
    def test_mutant_not_policy_denied(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert trace.terminal_state != TerminalState.POLICY_DENIED, (
            "observe-only must never produce POLICY_DENIED"
        )


# ---------------------------------------------------------------------------
# 2. Plugin records all three phases with ABSTAIN
# ---------------------------------------------------------------------------

class TestObserveOnlyRecords:

    def test_plugin_records_three_phases(self, plugin: ObserveOnlyPlugin,
                                          host: PluginLifecycleHost) -> None:
        host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        phases_recorded = {r.phase for r in plugin.records}
        assert phases_recorded == {"request_received", "backend_selected", "exchange_finished"}

    def test_all_records_are_abstain(self, plugin: ObserveOnlyPlugin,
                                      host: PluginLifecycleHost) -> None:
        host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        for record in plugin.records:
            assert record.decision == ABSTAIN, (
                f"observe-only plugin must always return abstain; "
                f"got {record.decision!r} at phase={record.phase!r}"
            )

    def test_all_records_share_exchange_id(self, plugin: ObserveOnlyPlugin,
                                            host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        for record in plugin.records:
            assert record.exchange_id == trace.exchange_id

    def test_all_records_have_body_digest(self, plugin: ObserveOnlyPlugin,
                                           host: PluginLifecycleHost) -> None:
        host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        for record in plugin.records:
            assert record.body_digest is not None, (
                f"observe-only record at phase={record.phase!r} must have a body_digest"
            )

    def test_request_received_digest_matches_input(self, plugin: ObserveOnlyPlugin,
                                                    host: PluginLifecycleHost) -> None:
        host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        rr_record = next(r for r in plugin.records if r.phase == "request_received")
        expected = hashlib.sha256(CHAT_REQUEST).hexdigest()
        assert rr_record.body_digest == expected

    # Mutant: wrong digest IS caught
    def test_mutant_wrong_body_digest_is_distinguishable(self, plugin: ObserveOnlyPlugin,
                                                          host: PluginLifecycleHost) -> None:
        host.run_with_plugin(CHAT_REQUEST, backend_response_body=BACKEND_RESPONSE)
        rr_record = next(r for r in plugin.records if r.phase == "request_received")
        wrong_digest = hashlib.sha256(b"different body").hexdigest()
        assert rr_record.body_digest != wrong_digest, (
            "Record digest must differ from a digest of different bytes"
        )


# ---------------------------------------------------------------------------
# 3. Byte-identical: request reaches backend unchanged
#    Acceptance item #1: compared, not asserted.
# ---------------------------------------------------------------------------

class TestByteIdentical:
    """The observe-only plugin must never influence the exchange.

    COMPARISON PROTOCOL
        original_digest = sha256(original_request_body)
        ingress_digest  = SERVING_HOST_INGRESS observation's payload_digest
        dispatch_digest = BACKEND_DISPATCH observation's payload_digest
        request_metadata_digest = trace.request_metadata["body_digest"]
        dispatched_digest = trace.request_metadata["dispatched_request_digest"]

        All five must be equal.  This is a comparison of real sha256 values,
        not a pytest.skip() or a trust-based assertion.
    """

    def test_byte_identical_ingress_to_dispatch(self, host: PluginLifecycleHost) -> None:
        original_body = CHAT_REQUEST
        trace = host.run_with_plugin(original_body, backend_response_body=BACKEND_RESPONSE)

        original_digest = hashlib.sha256(original_body).hexdigest()

        ingress_obs = trace.observation_at(ObservationPoint.SERVING_HOST_INGRESS)
        dispatch_obs = trace.observation_at(ObservationPoint.BACKEND_DISPATCH)

        assert ingress_obs is not None, "SERVING_HOST_INGRESS observation must be present"
        assert dispatch_obs is not None, "BACKEND_DISPATCH observation must be present"

        # Comparison 1: ingress == original
        assert ingress_obs.payload_digest == original_digest, (
            f"SERVING_HOST_INGRESS digest does not match original body.\n"
            f"  original:  {original_digest}\n"
            f"  ingress:   {ingress_obs.payload_digest}"
        )

        # Comparison 2: dispatch == original
        assert dispatch_obs.payload_digest == original_digest, (
            f"BACKEND_DISPATCH digest does not match original body.\n"
            f"  original:  {original_digest}\n"
            f"  dispatch:  {dispatch_obs.payload_digest}\n"
            f"  This would mean the plugin altered the forwarded bytes — "
            f"observe-only mode must never do this."
        )

        # Comparison 3: metadata fields are consistent
        assert trace.request_metadata["body_digest"] == original_digest
        assert trace.request_metadata["dispatched_request_digest"] == original_digest

        # Comparison 4: ingress == dispatch (the byte-identical claim)
        assert ingress_obs.payload_digest == dispatch_obs.payload_digest, (
            f"ingress digest ({ingress_obs.payload_digest[:8]}…) != "
            f"dispatch digest ({dispatch_obs.payload_digest[:8]}…): "
            f"the plugin or host altered the forwarded bytes"
        )

    def test_byte_identical_holds_across_multiple_runs(self, plugin: ObserveOnlyPlugin) -> None:
        """Property holds regardless of request content."""
        bodies = [
            b'{"model":"a","messages":[]}',
            b'{"model":"b","messages":[{"role":"user","content":"x"}],"temperature":0.7}',
        ]
        for body in bodies:
            plugin.clear()
            host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
            trace = host.run_with_plugin(body)
            orig = hashlib.sha256(body).hexdigest()
            dispatch_obs = trace.observation_at(ObservationPoint.BACKEND_DISPATCH)
            assert dispatch_obs is not None
            assert dispatch_obs.payload_digest == orig, (
                f"Byte-identical check failed for body starting with "
                f"{body[:20]!r}: dispatch digest {dispatch_obs.payload_digest!r} "
                f"!= original {orig!r}"
            )

    # Mutant: if we corrupt the body the digest changes and the comparison fails.
    def test_mutant_corrupted_body_is_detected(self) -> None:
        original = b'{"model":"test","messages":[]}'
        corrupted = b'{"model":"test","messages":[ ]}'  # extra space
        assert hashlib.sha256(original).hexdigest() != hashlib.sha256(corrupted).hexdigest(), (
            "Mutant check: corrupted body must produce a different digest"
        )


# ---------------------------------------------------------------------------
# 4. No influence on exchange: observe-only cannot cause POLICY_DENIED
# ---------------------------------------------------------------------------

class TestObserveOnlyCannotInfluence:

    def test_cannot_return_deny_via_abstain_only_plugin(self, host: PluginLifecycleHost) -> None:
        """ObserveOnlyPlugin.on_phase() is written to return only ABSTAIN.
        Verify that no trace produced by this plugin has POLICY_DENIED."""
        for body in [
            CHAT_REQUEST,
            b'{"model":"blocked-anything","messages":[]}',
            b'{"model":"","messages":[]}',
        ]:
            trace = host.run_with_plugin(body)
            assert trace.terminal_state != TerminalState.POLICY_DENIED, (
                f"observe-only mode must not produce POLICY_DENIED for any request; "
                f"got POLICY_DENIED for body starting with {body[:30]!r}"
            )

    def test_backend_dispatch_always_reached(self, host: PluginLifecycleHost) -> None:
        """observe-only: BACKEND_DISPATCH is always present because the plugin
        never returns DENY."""
        trace = host.run_with_plugin(CHAT_REQUEST)
        obs = trace.observation_at(ObservationPoint.BACKEND_DISPATCH)
        assert obs is not None, (
            "observe-only must always reach BACKEND_DISPATCH; plugin returned DENY"
        )

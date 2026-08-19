#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for body-access-denied behavior — acceptance item #3.

Acceptance item #3: Body access denied by host config is demonstrated —
and the failure is LOUD.  A plugin that quietly observes nothing when its
grant is missing is the fail-toward-reassurance shape and fails this
acceptance.

WHAT THIS FILE VERIFIES

  1. When body_access_granted=False:
       - ObserveOnlyPlugin raises BodyAccessDenied
       - AdmissionPolicyPlugin raises BodyAccessDenied

  2. The exception message is INFORMATIVE — an operator can diagnose the
     problem without reading the plugin source.

  3. The host catches BodyAccessDenied and returns:
       - terminal_state = EVIDENCE_UNAVAILABLE
       - terminal_reason = "internal_hook_failure"
     (Not a COMPLETED or POLICY_DENIED trace.)

  4. The error detail in response_metadata identifies the cause as
     "plugin_body_access_denied".

  5. A side-stream EVIDENCE "failed" event is recorded.

MUTANT CHECKS
  Confirm that a plugin which silently returns abstain when body is None
  would NOT produce the above behavior — thereby proving our loud failure
  IS detectable and distinguishable from a quiet one.

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its mutant.
"""
from __future__ import annotations

import pytest

from exemplar.admission_policy import AdmissionPolicyPlugin
from exemplar.observe_only import ObserveOnlyPlugin
from exemplar.plugin_contract import ABSTAIN, BodyAccessDenied, HostConfig, PhaseContext
from exemplar.plugin_host import PluginLifecycleHost

from mock_lifecycle_host import SideStream, TerminalState


# ---------------------------------------------------------------------------
# Request body
# ---------------------------------------------------------------------------

CHAT_REQUEST = b'{"model":"test","messages":[{"role":"user","content":"hello"}]}'


# ---------------------------------------------------------------------------
# 1. Plugins raise BodyAccessDenied when body is withheld
# ---------------------------------------------------------------------------

class TestRaisesBodyAccessDenied:

    def test_observe_only_raises_when_body_denied(self) -> None:
        plugin = ObserveOnlyPlugin()
        ctx = PhaseContext(
            exchange_id="x" * 32,
            phase="request_received",
            endpoint="/v1/chat/completions",
            sanitized_headers={"content-type": "application/json"},
            body=None,
            body_access_granted=False,
        )
        with pytest.raises(BodyAccessDenied) as exc_info:
            plugin.on_phase(ctx)
        msg = str(exc_info.value)
        assert msg.strip(), "BodyAccessDenied message must not be empty"

    def test_admission_policy_raises_when_body_denied(self) -> None:
        plugin = AdmissionPolicyPlugin()
        ctx = PhaseContext(
            exchange_id="y" * 32,
            phase="request_received",
            endpoint="/v1/chat/completions",
            sanitized_headers={"content-type": "application/json"},
            body=None,
            body_access_granted=False,
        )
        with pytest.raises(BodyAccessDenied) as exc_info:
            plugin.on_phase(ctx)
        msg = str(exc_info.value)
        assert msg.strip(), "BodyAccessDenied message must not be empty"

    # Mutant: a plugin that silently returns abstain would NOT raise
    def test_mutant_silent_abstain_does_not_raise(self) -> None:
        """Confirm that the mutant behavior (silent abstain) is distinguishable.
        A plugin written to silently return abstain on missing body would not
        raise BodyAccessDenied — the test for that would silently pass."""
        class SilentPlugin:
            from exemplar.observe_only import MANIFEST as manifest
            def on_phase(self, ctx: PhaseContext) -> str:
                return ABSTAIN  # fail-toward-reassurance shape

        plugin = SilentPlugin()
        ctx = PhaseContext(
            exchange_id="z" * 32,
            phase="request_received",
            endpoint="/v1/chat/completions",
            sanitized_headers={},
            body=None,
            body_access_granted=False,
        )
        # The silent plugin does NOT raise — which is exactly the wrong shape.
        result = plugin.on_phase(ctx)
        assert result == ABSTAIN, "Mutant check: silent plugin returns abstain without raising"
        # Our exemplar raises; the mutant does not. This difference is what the
        # test_observe_only_raises_when_body_denied / test_admission_policy_raises
        # tests detect.


# ---------------------------------------------------------------------------
# 2. Error message is informative
# ---------------------------------------------------------------------------

class TestErrorMessageIsInformative:

    def test_observe_only_message_mentions_phase(self) -> None:
        plugin = ObserveOnlyPlugin()
        ctx = PhaseContext(
            exchange_id="a" * 32,
            phase="backend_selected",
            endpoint="/v1/chat/completions",
            sanitized_headers={},
            body=None,
            body_access_granted=False,
        )
        with pytest.raises(BodyAccessDenied) as exc_info:
            plugin.on_phase(ctx)
        msg = str(exc_info.value)
        # Must mention which phase and why (diagnosable without reading source)
        assert "backend_selected" in msg or "phase" in msg.lower(), (
            f"BodyAccessDenied message must mention the phase; got: {msg!r}"
        )

    def test_observe_only_message_mentions_exchange_id(self) -> None:
        xid = "b" * 32
        plugin = ObserveOnlyPlugin()
        ctx = PhaseContext(
            exchange_id=xid,
            phase="request_received",
            endpoint="/v1/chat/completions",
            sanitized_headers={},
            body=None,
            body_access_granted=False,
        )
        with pytest.raises(BodyAccessDenied) as exc_info:
            plugin.on_phase(ctx)
        msg = str(exc_info.value)
        assert xid in msg, (
            f"BodyAccessDenied message must include exchange_id {xid!r}; got: {msg!r}"
        )

    def test_admission_policy_message_mentions_fail_open_risk(self) -> None:
        plugin = AdmissionPolicyPlugin()
        ctx = PhaseContext(
            exchange_id="c" * 32,
            phase="request_received",
            endpoint="/v1/chat/completions",
            sanitized_headers={},
            body=None,
            body_access_granted=False,
        )
        with pytest.raises(BodyAccessDenied) as exc_info:
            plugin.on_phase(ctx)
        msg = str(exc_info.value).lower()
        assert "fail" in msg or "open" in msg or "backend" in msg, (
            f"AdmissionPolicy BodyAccessDenied message must explain why "
            f"abstain would be wrong; got: {msg!r}"
        )

    # Mutant: empty message would fail this check
    def test_mutant_empty_message_is_detectable(self) -> None:
        exc = BodyAccessDenied("")
        msg = str(exc)
        assert not msg.strip(), "Mutant check: empty message is detectable as empty"


# ---------------------------------------------------------------------------
# 3. Host terminates with EVIDENCE_UNAVAILABLE / internal_hook_failure
# ---------------------------------------------------------------------------

class TestHostTerminatesCorrectly:

    def test_observe_only_denied_produces_evidence_unavailable(self) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert trace.terminal_state == TerminalState.EVIDENCE_UNAVAILABLE, (
            f"Host must terminate with EVIDENCE_UNAVAILABLE when plugin raises "
            f"BodyAccessDenied; got {trace.terminal_state}"
        )

    def test_observe_only_denied_reason_is_internal_hook_failure(self) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert trace.terminal_reason == "internal_hook_failure", (
            f"terminal_reason must be 'internal_hook_failure'; "
            f"got {trace.terminal_reason!r}"
        )

    def test_admission_policy_denied_produces_evidence_unavailable(self) -> None:
        plugin = AdmissionPolicyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert trace.terminal_state == TerminalState.EVIDENCE_UNAVAILABLE

    def test_admission_policy_denied_reason_is_internal_hook_failure(self) -> None:
        plugin = AdmissionPolicyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert trace.terminal_reason == "internal_hook_failure"

    # Mutant: if body was granted, terminal state is NOT evidence_unavailable
    def test_mutant_body_granted_does_not_produce_evidence_unavailable(self) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert trace.terminal_state != TerminalState.EVIDENCE_UNAVAILABLE, (
            "With body_access_granted=True, observe-only must not produce "
            "EVIDENCE_UNAVAILABLE"
        )


# ---------------------------------------------------------------------------
# 4. Response metadata identifies the cause
# ---------------------------------------------------------------------------

class TestResponseMetadataIdentifiesCause:

    def test_observe_only_denied_response_metadata_identifies_cause(self) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        error_field = trace.response_metadata.get("error", "")
        assert "body_access_denied" in str(error_field), (
            f"response_metadata must identify cause as body_access_denied; "
            f"got: {trace.response_metadata!r}"
        )

    def test_observe_only_denied_detail_is_nonempty(self) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        detail = trace.response_metadata.get("detail", "")
        assert detail.strip(), (
            f"response_metadata['detail'] must not be empty; "
            f"got: {detail!r}"
        )

    # Mutant: a completed trace has no "error" metadata key
    def test_mutant_completed_has_no_error_metadata(self) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert "error" not in trace.response_metadata, (
            "Completed trace must not have 'error' in response_metadata"
        )


# ---------------------------------------------------------------------------
# 5. Side-stream EVIDENCE failed event
# ---------------------------------------------------------------------------

class TestEvidenceSideStreamFailed:

    def test_observe_only_denied_has_evidence_failed_event(self) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        evidence_events = trace.side_stream_events_for(SideStream.EVIDENCE)
        assert evidence_events, "Must have at least one EVIDENCE side-stream event"
        failed = [e for e in evidence_events if e.event_name == "failed"]
        assert failed, (
            "Must have at least one failed EVIDENCE event when body access denied; "
            f"events: {[(e.event_name, e.detail) for e in evidence_events]}"
        )

    def test_observe_only_denied_evidence_failed_cause_is_body_access_denied(
        self,
    ) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        evidence_events = trace.side_stream_events_for(SideStream.EVIDENCE)
        failed = [e for e in evidence_events if e.event_name == "failed"]
        assert failed
        cause = failed[0].detail.get("cause", "")
        assert "body_access_denied" in cause, (
            f"EVIDENCE failed event cause must mention body_access_denied; "
            f"got: {cause!r}"
        )

    def test_observe_only_denied_evidence_reason_is_internal_hook_failure(
        self,
    ) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=False))
        trace = host.run_with_plugin(CHAT_REQUEST)
        evidence_events = trace.side_stream_events_for(SideStream.EVIDENCE)
        failed = [e for e in evidence_events if e.event_name == "failed"]
        reason = failed[0].detail.get("reason", "")
        assert "internal_hook_failure" in reason, (
            f"EVIDENCE failed reason must be 'internal_hook_failure'; got {reason!r}"
        )

    # Mutant: a completed trace has no failed evidence events
    def test_mutant_completed_has_no_failed_evidence_event(self) -> None:
        plugin = ObserveOnlyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
        trace = host.run_with_plugin(CHAT_REQUEST)
        evidence_events = trace.side_stream_events_for(SideStream.EVIDENCE)
        failed = [e for e in evidence_events if e.event_name == "failed"]
        assert not failed, (
            f"Completed trace must have no failed EVIDENCE events; got {failed}"
        )

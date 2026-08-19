#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the admission-policy exemplar plugin.

Acceptance items verified here:
  #2 — A denial shown stopping dispatch, returning a stable OpenAI-shaped error.

DENIAL CONDITION
    The plugin denies any request body that contains {"model": "blocked-<anything>"}.
    This is parsed from the body.  A plugin that cannot read the body cannot
    evaluate this condition — see test_exemplar_body_access_denied.py.

OPENAI-SHAPED ERROR
    The denial response has exactly the shape:
        {"error": {"code": "policy_denied",
                   "message": "request rejected by plugin admission policy",
                   "type": "invalid_request_error",
                   "param": null}}
    This is stable: the same bytes are returned on every denial.

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its mutant.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from exemplar.admission_policy import (
    BLOCKED_MODEL_PREFIX,
    DENIAL_RESPONSE_BODY,
    AdmissionPolicyPlugin,
)
from exemplar.plugin_contract import ABSTAIN, DENY, HostConfig
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
def plugin() -> AdmissionPolicyPlugin:
    return AdmissionPolicyPlugin()


@pytest.fixture()
def host(plugin: AdmissionPolicyPlugin) -> PluginLifecycleHost:
    return PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

ALLOWED_REQUEST = b'{"model":"test","messages":[{"role":"user","content":"hello"}]}'
BLOCKED_REQUEST = b'{"model":"blocked-gpt","messages":[{"role":"user","content":"hello"}]}'
BLOCKED_REQUEST_OTHER = b'{"model":"blocked-anything","messages":[]}'


# ---------------------------------------------------------------------------
# 1. Allowed request passes
# ---------------------------------------------------------------------------

class TestAdmissionPolicyAllowed:

    def test_allowed_request_completes(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(ALLOWED_REQUEST)
        assert trace.terminal_state == TerminalState.COMPLETED

    def test_allowed_request_reaches_backend(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(ALLOWED_REQUEST)
        obs = trace.observation_at(ObservationPoint.BACKEND_DISPATCH)
        assert obs is not None, "BACKEND_DISPATCH must be reached for allowed request"

    def test_allowed_request_traverses_all_phases(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(ALLOWED_REQUEST)
        assert trace.reached_phase(LifecyclePhase.REQUEST_RECEIVED)
        assert trace.reached_phase(LifecyclePhase.BACKEND_SELECTED)
        assert trace.reached_phase(LifecyclePhase.EXCHANGE_FINISHED)

    def test_allowed_request_plugin_records_abstain_at_rr(
        self, plugin: AdmissionPolicyPlugin, host: PluginLifecycleHost
    ) -> None:
        host.run_with_plugin(ALLOWED_REQUEST)
        rr_record = next((r for r in plugin.records if r.phase == "request_received"), None)
        assert rr_record is not None
        assert rr_record.decision == ABSTAIN

    # Mutant: allowed request must not be policy_denied
    def test_mutant_allowed_is_not_denied(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(ALLOWED_REQUEST)
        assert trace.terminal_state != TerminalState.POLICY_DENIED


# ---------------------------------------------------------------------------
# 2. Denied request stops dispatch
# ---------------------------------------------------------------------------

class TestAdmissionPolicyDenied:

    def test_blocked_request_is_denied(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(BLOCKED_REQUEST)
        assert trace.terminal_state == TerminalState.POLICY_DENIED, (
            f"blocked-model request must be POLICY_DENIED; got {trace.terminal_state}"
        )

    def test_denied_request_never_reaches_backend(self, host: PluginLifecycleHost) -> None:
        """THE KEY DISPATCH-STOP CHECK: BACKEND_DISPATCH must be absent."""
        trace = host.run_with_plugin(BLOCKED_REQUEST)
        obs = trace.observation_at(ObservationPoint.BACKEND_DISPATCH)
        assert obs is None, (
            f"Denied request must never reach BACKEND_DISPATCH; "
            f"observation was present: {obs}"
        )

    def test_denied_request_skips_backend_selected_phase(
        self, host: PluginLifecycleHost
    ) -> None:
        trace = host.run_with_plugin(BLOCKED_REQUEST)
        assert not trace.reached_phase(LifecyclePhase.BACKEND_SELECTED), (
            "Denied request must not enter BACKEND_SELECTED "
            "(no backend was assigned)"
        )

    def test_denial_terminal_reason(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(BLOCKED_REQUEST)
        assert trace.terminal_reason is not None
        assert "plugin" in trace.terminal_reason.lower() or "admission" in trace.terminal_reason.lower()

    def test_denial_anchoring_event_recorded(
        self, host: PluginLifecycleHost
    ) -> None:
        from mock_lifecycle_host import SideStream
        trace = host.run_with_plugin(BLOCKED_REQUEST)
        anchoring = trace.side_stream_events_for(SideStream.ANCHORING)
        assert anchoring, "Denial must produce an anchoring side-stream event"
        assert any(e.detail.get("outcome") == "policy_denied" for e in anchoring), (
            "Anchoring event outcome must be 'policy_denied'"
        )

    # Mutant: allowed model is NOT denied
    def test_mutant_allowed_model_not_denied(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(ALLOWED_REQUEST)
        assert trace.terminal_state != TerminalState.POLICY_DENIED, (
            "Non-blocked model must not be denied"
        )

    # Mutant: second blocked request body also denied
    def test_mutant_other_blocked_model_also_denied(
        self, host: PluginLifecycleHost
    ) -> None:
        trace = host.run_with_plugin(BLOCKED_REQUEST_OTHER)
        assert trace.terminal_state == TerminalState.POLICY_DENIED


# ---------------------------------------------------------------------------
# 3. Stable OpenAI-shaped error on denial
# ---------------------------------------------------------------------------

class TestDenialResponseShape:
    """Acceptance item #2: the denial returns a stable OpenAI-shaped error."""

    def test_denial_response_is_parseable_json(self, host: PluginLifecycleHost) -> None:
        trace = host.run_with_plugin(BLOCKED_REQUEST)
        # The response body is stored as the CLIENT_EGRESS observation's payload
        # and also as response_metadata["body_digest"].
        egress = trace.observation_at(ObservationPoint.CLIENT_EGRESS)
        assert egress is not None
        # CLIENT_EGRESS payload_digest must match DENIAL_RESPONSE_BODY
        expected_digest = hashlib.sha256(DENIAL_RESPONSE_BODY).hexdigest()
        assert egress.payload_digest == expected_digest, (
            f"CLIENT_EGRESS digest {egress.payload_digest!r} does not match "
            f"DENIAL_RESPONSE_BODY digest {expected_digest!r}"
        )

    def test_denial_response_body_shape(self) -> None:
        """The denial body itself must parse as a well-formed OpenAI error."""
        parsed = json.loads(DENIAL_RESPONSE_BODY.decode("utf-8"))
        error = parsed.get("error", {})
        assert error.get("code") == "policy_denied", (
            f"denial error code must be 'policy_denied'; got {error.get('code')!r}"
        )
        assert error.get("type") == "invalid_request_error", (
            f"denial error type must be 'invalid_request_error'; got {error.get('type')!r}"
        )
        assert isinstance(error.get("message"), str)
        assert "policy" in error["message"].lower()

    def test_denial_response_is_stable_across_runs(
        self, plugin: AdmissionPolicyPlugin
    ) -> None:
        """The same denial response is returned regardless of exchange_id."""
        digests: set[str] = set()
        for _ in range(3):
            plugin.clear()
            host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
            trace = host.run_with_plugin(BLOCKED_REQUEST)
            egress = trace.observation_at(ObservationPoint.CLIENT_EGRESS)
            assert egress is not None
            digests.add(egress.payload_digest)
        assert len(digests) == 1, (
            f"Denial response is not stable across runs: got {len(digests)} "
            f"distinct payload digests: {digests}"
        )

    # Mutant: a successful response has a different shape
    def test_mutant_success_response_differs_from_denial(self) -> None:
        plugin = AdmissionPolicyPlugin()
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
        trace = host.run_with_plugin(ALLOWED_REQUEST)
        egress = trace.observation_at(ObservationPoint.CLIENT_EGRESS)
        assert egress is not None
        deny_digest = hashlib.sha256(DENIAL_RESPONSE_BODY).hexdigest()
        assert egress.payload_digest != deny_digest, (
            "Success response must differ from denial response"
        )


# ---------------------------------------------------------------------------
# 4. Plugin records on denial
# ---------------------------------------------------------------------------

class TestAdmissionPolicyRecords:

    def test_denial_record_has_deny_decision(
        self, plugin: AdmissionPolicyPlugin, host: PluginLifecycleHost
    ) -> None:
        host.run_with_plugin(BLOCKED_REQUEST)
        rr_record = next((r for r in plugin.records if r.phase == "request_received"), None)
        assert rr_record is not None
        assert rr_record.decision == DENY

    def test_denial_record_has_deny_reason(
        self, plugin: AdmissionPolicyPlugin, host: PluginLifecycleHost
    ) -> None:
        host.run_with_plugin(BLOCKED_REQUEST)
        rr_record = next(r for r in plugin.records if r.phase == "request_received")
        assert rr_record.deny_reason is not None, "Denial record must carry a deny_reason"
        assert BLOCKED_MODEL_PREFIX in rr_record.deny_reason or "blocked" in rr_record.deny_reason.lower()

    def test_only_one_record_on_denial(
        self, plugin: AdmissionPolicyPlugin, host: PluginLifecycleHost
    ) -> None:
        """Denial at request_received: only one phase call occurs."""
        host.run_with_plugin(BLOCKED_REQUEST)
        assert len(plugin.records) == 1, (
            f"Denial at request_received must produce exactly 1 record; "
            f"got {len(plugin.records)}: {plugin.records}"
        )

    # Mutant: allowed request produces no denial record
    def test_mutant_allowed_request_has_no_deny_record(
        self, plugin: AdmissionPolicyPlugin, host: PluginLifecycleHost
    ) -> None:
        host.run_with_plugin(ALLOWED_REQUEST)
        deny_records = [r for r in plugin.records if r.decision == DENY]
        assert not deny_records, (
            f"Allowed request must produce no DENY records; got {deny_records}"
        )


# ---------------------------------------------------------------------------
# 5. Denial prefix logic
# ---------------------------------------------------------------------------

class TestBlockedModelPrefix:

    @pytest.mark.parametrize("model,should_deny", [
        ("blocked-gpt", True),
        ("blocked-anything", True),
        ("blocked-", True),
        ("test", False),
        ("gpt-4", False),
        ("blockedmodel", False),  # no hyphen — prefix match is exact
        ("", False),
    ])
    def test_prefix_logic(
        self, model: str, should_deny: bool, plugin: AdmissionPolicyPlugin
    ) -> None:
        body = json.dumps({"model": model, "messages": []}).encode("utf-8")
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
        trace = host.run_with_plugin(body)
        plugin.clear()
        if should_deny:
            assert trace.terminal_state == TerminalState.POLICY_DENIED, (
                f"model={model!r} should be denied; got {trace.terminal_state}"
            )
        else:
            assert trace.terminal_state == TerminalState.COMPLETED, (
                f"model={model!r} should be allowed; got {trace.terminal_state}"
            )

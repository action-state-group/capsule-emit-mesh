#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[adv-run-2-fix-batch] B2 regression: PluginLifecycleHost must enforce a
loaded plugin's declared manifest.decision_mode, not just check the returned
decision as a bare string.

Before the fix, a plugin whose manifest declared decision_mode="observe_only"
(the passive, lower-trust contract) could nonetheless return DENY at
REQUEST_RECEIVED or BACKEND_SELECTED and the host would honor it, escalating
the plugin to full admission control despite its declared mode
(SPEC_FEEDBACK["decision_mode_enforcement"] named this gap without fixing it).

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its mutant.
"""
from __future__ import annotations

import warnings

import pytest

from exemplar.plugin_contract import CONTRACT, DENY, HostConfig, Manifest
from exemplar.plugin_host import PluginLifecycleHost

from mock_lifecycle_host import ObservationPoint, TerminalState

CHAT_REQUEST = b'{"model":"test","messages":[{"role":"user","content":"hello"}]}'


class RogueDenyPlugin:
    """A plugin that declares an arbitrary decision_mode but always returns
    DENY — models a plugin lying about (or simply not honoring) its own
    manifest contract."""

    def __init__(self, decision_mode: str) -> None:
        self.manifest = Manifest(
            contract=CONTRACT,
            endpoints=["/v1/chat/completions"],
            phases=["request_received", "backend_selected", "exchange_finished"],
            sanitized_headers=["content-type"],
            decision_mode=decision_mode,
            response_metadata={},
        )

    def on_phase(self, ctx):
        return DENY


class TestObserveOnlyPluginCannotDeny:

    def test_observe_only_deny_does_not_terminate_the_exchange(self) -> None:
        plugin = RogueDenyPlugin(decision_mode="observe_only")
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            trace = host.run_with_plugin(CHAT_REQUEST)

        assert trace.terminal_state != TerminalState.POLICY_DENIED, (
            "an observe_only plugin's DENY must not terminate the exchange"
        )
        assert trace.terminal_state == TerminalState.COMPLETED
        assert any("decision_mode" in str(w.message) for w in caught), (
            "the mismatch between decision_mode and a returned DENY must be surfaced"
        )

    def test_observe_only_deny_still_reaches_backend_dispatch(self) -> None:
        plugin = RogueDenyPlugin(decision_mode="observe_only")
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert trace.observation_at(ObservationPoint.BACKEND_DISPATCH) is not None, (
            "an unhonored DENY must not prevent BACKEND_DISPATCH"
        )

    # Positive control: an admission_policy plugin's DENY IS honored — proves
    # the enforcement is decision_mode-gated, not a blanket "DENY never works."
    def test_admission_policy_deny_still_terminates_the_exchange(self) -> None:
        plugin = RogueDenyPlugin(decision_mode="admission_policy")
        host = PluginLifecycleHost(plugin, HostConfig(body_access_granted=True))
        trace = host.run_with_plugin(CHAT_REQUEST)
        assert trace.terminal_state == TerminalState.POLICY_DENIED

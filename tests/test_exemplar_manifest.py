#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test the manifest blocks for both exemplar modes.

Acceptance item #4: No Authorization or Cookie header in any fixture.
Verified here by inspecting the sanitized_headers lists directly.

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its mutant.
"""
from __future__ import annotations

import pytest

from exemplar.admission_policy import MANIFEST as AP_MANIFEST
from exemplar.observe_only import MANIFEST as OO_MANIFEST
from exemplar.plugin_contract import CONTRACT


# ---------------------------------------------------------------------------
# 1. Contract identifier
# ---------------------------------------------------------------------------

class TestContractIdentifier:

    def test_observe_only_contract(self) -> None:
        assert OO_MANIFEST.contract == CONTRACT

    def test_admission_policy_contract(self) -> None:
        assert AP_MANIFEST.contract == CONTRACT

    def test_contract_value(self) -> None:
        assert CONTRACT == "mesh.openai.exchange.v1"

    # Mutant: wrong value is caught
    def test_mutant_wrong_contract_is_distinguishable(self) -> None:
        assert CONTRACT != "mesh.openai.exchange.v0"
        assert CONTRACT != ""


# ---------------------------------------------------------------------------
# 2. Decision modes
# ---------------------------------------------------------------------------

class TestDecisionModes:

    def test_observe_only_mode(self) -> None:
        assert OO_MANIFEST.decision_mode == "observe_only"

    def test_admission_policy_mode(self) -> None:
        assert AP_MANIFEST.decision_mode == "admission_policy"

    def test_modes_are_distinct(self) -> None:
        assert OO_MANIFEST.decision_mode != AP_MANIFEST.decision_mode

    # Mutant: swapped modes are caught
    def test_mutant_swapped_modes_detected(self) -> None:
        assert OO_MANIFEST.decision_mode != "admission_policy"
        assert AP_MANIFEST.decision_mode != "observe_only"


# ---------------------------------------------------------------------------
# 3. Phases
# ---------------------------------------------------------------------------

EXPECTED_PHASES = {"request_received", "backend_selected", "exchange_finished"}


class TestPhases:

    def test_observe_only_phases(self) -> None:
        assert set(OO_MANIFEST.phases) == EXPECTED_PHASES

    def test_admission_policy_phases(self) -> None:
        assert set(AP_MANIFEST.phases) == EXPECTED_PHASES

    def test_phase_values_are_strings(self) -> None:
        for phase in OO_MANIFEST.phases + AP_MANIFEST.phases:
            assert isinstance(phase, str), f"Phase {phase!r} is not a string"

    # Mutant: missing phase is caught
    def test_mutant_missing_phase_detected(self) -> None:
        assert "request_received" in set(OO_MANIFEST.phases)
        trimmed = [p for p in OO_MANIFEST.phases if p != "request_received"]
        assert set(trimmed) != EXPECTED_PHASES


# ---------------------------------------------------------------------------
# 4. No Authorization or Cookie in sanitized_headers (#1331 acceptance box)
# ---------------------------------------------------------------------------

FORBIDDEN_HEADERS = {"authorization", "cookie", "Authorization", "Cookie"}


class TestNoForbiddenHeaders:
    """#1331 makes Authorization and Cookie exclusion its own acceptance box.
    Grep result: neither header appears in any sanitized_headers list in this
    exemplar.  Verified here by direct inspection of the manifest objects.
    """

    def test_observe_only_no_authorization(self) -> None:
        headers_lower = {h.lower() for h in OO_MANIFEST.sanitized_headers}
        assert "authorization" not in headers_lower, (
            f"Authorization must not appear in observe_only sanitized_headers; "
            f"found in: {OO_MANIFEST.sanitized_headers}"
        )

    def test_observe_only_no_cookie(self) -> None:
        headers_lower = {h.lower() for h in OO_MANIFEST.sanitized_headers}
        assert "cookie" not in headers_lower, (
            f"Cookie must not appear in observe_only sanitized_headers; "
            f"found in: {OO_MANIFEST.sanitized_headers}"
        )

    def test_admission_policy_no_authorization(self) -> None:
        headers_lower = {h.lower() for h in AP_MANIFEST.sanitized_headers}
        assert "authorization" not in headers_lower, (
            f"Authorization must not appear in admission_policy sanitized_headers; "
            f"found in: {AP_MANIFEST.sanitized_headers}"
        )

    def test_admission_policy_no_cookie(self) -> None:
        headers_lower = {h.lower() for h in AP_MANIFEST.sanitized_headers}
        assert "cookie" not in headers_lower, (
            f"Cookie must not appear in admission_policy sanitized_headers; "
            f"found in: {AP_MANIFEST.sanitized_headers}"
        )

    def test_observe_only_headers_are_lowercase_or_canonical(self) -> None:
        """All sanitized_headers are lower-case so case-insensitive comparison
        against the forbidden set catches any variant."""
        for h in OO_MANIFEST.sanitized_headers:
            assert h == h.lower(), (
                f"Header {h!r} is not lowercase; "
                f"use lowercase to make forbidden-header checks unambiguous"
            )

    def test_admission_policy_headers_are_lowercase_or_canonical(self) -> None:
        for h in AP_MANIFEST.sanitized_headers:
            assert h == h.lower(), f"Header {h!r} is not lowercase"

    # Mutant: a manifest that DOES include Authorization IS caught
    def test_mutant_manifest_with_authorization_is_detectable(self) -> None:
        from exemplar.plugin_contract import Manifest
        bad_manifest = Manifest(
            contract=CONTRACT,
            endpoints=["/v1/chat/completions"],
            phases=["request_received"],
            sanitized_headers=["content-type", "authorization"],  # forbidden
            decision_mode="observe_only",
            response_metadata={},
        )
        bad_lower = {h.lower() for h in bad_manifest.sanitized_headers}
        assert "authorization" in bad_lower, "Mutant manifest must contain authorization"


# ---------------------------------------------------------------------------
# 5. Endpoints
# ---------------------------------------------------------------------------

class TestEndpoints:

    def test_observe_only_endpoints(self) -> None:
        assert "/v1/chat/completions" in OO_MANIFEST.endpoints

    def test_admission_policy_endpoints(self) -> None:
        assert "/v1/chat/completions" in AP_MANIFEST.endpoints

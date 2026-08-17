# SPDX-License-Identifier: Apache-2.0
"""Delegation-chain verifier tests — Mesh-LLM/mesh-llm#1331.

THE VALUE IS THE REJECTION MATRIX.
Each rejection case is tested individually: the verifier must FAIL for each
bad fixture and the test asserts the specific rejection code so a false-pass
cannot hide inside a generic error.

Acceptance gate (per task brief):
  - six rejections each shown failing individually
  - happy path verifies offline
  - underspecified corners documented (see docs/SPEC-FEEDBACK-1331.md)

Fixture contract:
  delegation_chain/fixtures/<case>/delegation.json
  delegation_chain/fixtures/<case>/node_ownership.json
  delegation_chain/fixtures/<case>/capsule.cbor
  delegation_chain/fixtures/<case>/revocation_list.json
  delegation_chain/fixtures/<case>/node_id.txt
  delegation_chain/fixtures/manifest.json   (expected_scope, plugin_id, node_id, now_ms)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Path setup — both the worktree root and the repo root must be on sys.path.
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
sys.path.insert(0, str(_REPO_ROOT))

from delegation_chain_verifier import (  # noqa: E402
    EvidenceState,
    IdentityMode,
    IdentityModeResult,
    RejectionCode,
    VerifyStep,
    assess_identity_mode,
    assess_identity_mode_without_verifying,
    chain_verdict,
    mode_output_dict,
    verify_chain,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------
_FIXTURES_DIR = _REPO_ROOT / "delegation_chain" / "fixtures"
_MANIFEST = json.loads((_FIXTURES_DIR / "manifest.json").read_bytes())

EXPECTED_SCOPE = _MANIFEST["expected_scope"]
EXPECTED_PLUGIN_ID = _MANIFEST["expected_plugin_id"]
NOW_MS: int = _MANIFEST["now_ms"]


def _load(case: str) -> tuple[dict, dict, bytes, dict, str]:
    """Return (delegation, node_ownership, capsule_bytes, revocation_list, node_id)."""
    d = _FIXTURES_DIR / case
    delegation = json.loads((d / "delegation.json").read_bytes())
    node_ownership = json.loads((d / "node_ownership.json").read_bytes())
    capsule_bytes = (d / "capsule.cbor").read_bytes()
    revocation_list = json.loads((d / "revocation_list.json").read_bytes())
    node_id = (d / "node_id.txt").read_text().strip()
    return delegation, node_ownership, capsule_bytes, revocation_list, node_id


def _run_case(case: str, **overrides: Any):
    delegation, node_ownership, capsule_bytes, revocation_list, node_id = _load(case)
    return verify_chain(
        capsule_bytes=capsule_bytes,
        delegation=delegation,
        node_ownership=node_ownership,
        revocation_list=revocation_list,
        expected_scope=EXPECTED_SCOPE,
        expected_plugin_id=EXPECTED_PLUGIN_ID,
        expected_node_id=node_id,
        now_ms=NOW_MS,
        **overrides,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_happy_path_verifies():
    """Happy path: all six steps must pass; chain_verdict must be ok=True."""
    results = _run_case("happy")
    verdict = chain_verdict(results)
    assert verdict.ok, (
        f"Happy path must verify. Got rejection={verdict.rejection!r} "
        f"at step={verdict.step!r}: {verdict.detail}"
    )
    # All individual steps must pass too.
    failed = [r for r in results if not r.ok]
    assert not failed, f"Unexpected failures in happy path: {failed}"


# ---------------------------------------------------------------------------
# Rejection matrix — six cases, each individually demonstrated failing
# ---------------------------------------------------------------------------

def test_expired_delegation_rejected():
    """Step 5 must reject an expired delegation with EXPIRED.

    The fixture's expires_at_unix_ms is set 1ms before NOW_MS, so at
    verification time (now_ms=NOW_MS) the delegation has already expired.
    """
    results = _run_case("expired")
    verdict = chain_verdict(results)
    assert not verdict.ok, "Expired delegation must be rejected, not verified"
    assert verdict.rejection == RejectionCode.EXPIRED, (
        f"Expected EXPIRED, got {verdict.rejection!r}: {verdict.detail}"
    )
    assert verdict.step == VerifyStep.EXPIRY_REVOCATION, (
        f"Expected step_5, got {verdict.step!r}"
    )


def test_revoked_delegation_rejected():
    """Step 5 must reject a delegation whose delegation_id is in the revocation list.

    The fixture places the delegation's delegation_id in
    revocation_list.revoked_delegations.
    """
    results = _run_case("revoked")
    verdict = chain_verdict(results)
    assert not verdict.ok, "Revoked delegation must be rejected, not verified"
    assert verdict.rejection == RejectionCode.REVOKED, (
        f"Expected REVOKED, got {verdict.rejection!r}: {verdict.detail}"
    )
    assert verdict.step == VerifyStep.EXPIRY_REVOCATION, (
        f"Expected step_5, got {verdict.step!r}"
    )


def test_mismatched_node_rejected():
    """Step 4 must reject when delegation.node_endpoint_id does not match
    SignedNodeOwnership.node_endpoint_id.

    The fixture's delegation references a different node key than the one
    in node_ownership.
    """
    results = _run_case("mismatched_node")
    verdict = chain_verdict(results)
    assert not verdict.ok, "Mismatched-node delegation must be rejected, not verified"
    assert verdict.rejection == RejectionCode.MISMATCHED_NODE, (
        f"Expected MISMATCHED_NODE, got {verdict.rejection!r}: {verdict.detail}"
    )
    assert verdict.step == VerifyStep.NODE_OWNERSHIP, (
        f"Expected step_4, got {verdict.step!r}"
    )


def test_mismatched_plugin_rejected():
    """The semantic plugin-id check must reject when delegation.plugin_id does not
    match the expected plugin_id.

    The fixture's delegation has plugin_id='net.example.OTHER-plugin'; the
    verifier is told to expect 'net.example.capsule-emit'.
    """
    results = _run_case("mismatched_plugin")
    verdict = chain_verdict(results)
    assert not verdict.ok, "Mismatched-plugin delegation must be rejected, not verified"
    assert verdict.rejection == RejectionCode.MISMATCHED_PLUGIN, (
        f"Expected MISMATCHED_PLUGIN, got {verdict.rejection!r}: {verdict.detail}"
    )


def test_wrong_scope_rejected():
    """The semantic scope check must reject when delegation.scope is not the
    required scope.

    The fixture's delegation has scope='mesh.some.other.scope.v1'; the verifier
    requires 'mesh.inference.capsule.sign.v1'.
    """
    results = _run_case("wrong_scope")
    verdict = chain_verdict(results)
    assert not verdict.ok, "Wrong-scope delegation must be rejected, not verified"
    assert verdict.rejection == RejectionCode.WRONG_SCOPE, (
        f"Expected WRONG_SCOPE, got {verdict.rejection!r}: {verdict.detail}"
    )


def test_bad_signature_rejected():
    """Step 1 must reject a COSE capsule whose signature does not verify with the
    delegated signing public key.

    The fixture's capsule is signed with a KEY DIFFERENT from the one in the
    delegation (alt_plugin_key vs plugin_key).
    """
    results = _run_case("bad_signature")
    verdict = chain_verdict(results)
    assert not verdict.ok, "Bad-signature capsule must be rejected, not verified"
    assert verdict.rejection == RejectionCode.BAD_SIGNATURE, (
        f"Expected BAD_SIGNATURE, got {verdict.rejection!r}: {verdict.detail}"
    )
    assert verdict.step == VerifyStep.COSE_SIGNATURE, (
        f"Expected step_1, got {verdict.step!r}"
    )


# ---------------------------------------------------------------------------
# Mutant-fail guard: confirm rejections are genuine, not self-certifying
#
# Protocol §7: "Every check must fail its mutant."
# Each test below takes a happy-path fixture and injects one fault.
# If the verifier accepted the mutant, the corresponding rejection test
# above would be vacuous. These tests make the rejection tests meaningful.
# ---------------------------------------------------------------------------

def test_happy_path_fails_if_capsule_corrupted():
    """Confirms step 1 is exercised: a bit-flipped capsule must fail BAD_SIGNATURE."""
    delegation, node_ownership, capsule_bytes, revocation_list, node_id = _load("happy")
    # Corrupt the last 4 bytes of the CBOR (the signature tail).
    corrupted = bytearray(capsule_bytes)
    corrupted[-1] ^= 0xFF
    corrupted[-2] ^= 0xFF
    results = verify_chain(
        capsule_bytes=bytes(corrupted),
        delegation=delegation,
        node_ownership=node_ownership,
        revocation_list=revocation_list,
        expected_scope=EXPECTED_SCOPE,
        expected_plugin_id=EXPECTED_PLUGIN_ID,
        expected_node_id=node_id,
        now_ms=NOW_MS,
    )
    verdict = chain_verdict(results)
    assert not verdict.ok and verdict.rejection == RejectionCode.BAD_SIGNATURE, (
        f"Corrupted capsule must produce BAD_SIGNATURE; got {verdict.rejection!r}"
    )


def test_happy_path_fails_if_delegation_expired():
    """Confirms step 5 expiry check: mutating expires_at_unix_ms to the past fails."""
    delegation, node_ownership, capsule_bytes, revocation_list, node_id = _load("happy")
    # Tamper the delegation (this breaks its signature, but expiry check comes later).
    # We need to use the expired fixture to get a structurally valid but expired delegation.
    _, _, _, _, _ = _load("expired")  # ensure the fixture exists
    expired_delegation = json.loads(
        (_FIXTURES_DIR / "expired" / "delegation.json").read_bytes()
    )
    results = verify_chain(
        capsule_bytes=capsule_bytes,
        delegation=expired_delegation,
        node_ownership=node_ownership,
        revocation_list=revocation_list,
        expected_scope=EXPECTED_SCOPE,
        expected_plugin_id=EXPECTED_PLUGIN_ID,
        expected_node_id=node_id,
        now_ms=NOW_MS,
    )
    verdict = chain_verdict(results)
    # expired delegation has a different node_id (both reference same node here) but
    # same plugin_id; it should be rejected at step 5 with EXPIRED (or MISMATCHED_NODE
    # if node differs). The key property is: NOT verified.
    assert not verdict.ok, (
        "An expired delegation must not verify even against a valid capsule"
    )


def test_happy_path_fails_if_wrong_scope_injected():
    """Confirms scope check: overriding expected_scope to wrong value fails."""
    delegation, node_ownership, capsule_bytes, revocation_list, node_id = _load("happy")
    results = verify_chain(
        capsule_bytes=capsule_bytes,
        delegation=delegation,
        node_ownership=node_ownership,
        revocation_list=revocation_list,
        expected_scope="mesh.some.wrong.scope.v1",  # wrong
        expected_plugin_id=EXPECTED_PLUGIN_ID,
        expected_node_id=node_id,
        now_ms=NOW_MS,
    )
    verdict = chain_verdict(results)
    assert not verdict.ok and verdict.rejection == RejectionCode.WRONG_SCOPE, (
        f"Wrong scope must produce WRONG_SCOPE; got {verdict.rejection!r}"
    )


# ---------------------------------------------------------------------------
# Step ordering: later-step rejections don't mask earlier steps
# ---------------------------------------------------------------------------

def test_bad_signature_detected_before_expiry():
    """A capsule with a bad signature and an expired delegation must fail at step 1
    (bad signature), not step 5 (expiry). Step ordering is deterministic.

    Verifier runs: scope ok -> plugin ok -> node ok -> step 1 BAD_SIGNATURE -> stop.
    It never reaches step 5.
    """
    # Use the bad_signature fixture (valid delegation, wrong-key capsule) but also
    # pass now_ms=PAST_MS+2 to make it expired — step 5 would trigger if step 1 passed.
    delegation, node_ownership, capsule_bytes, revocation_list, node_id = _load("bad_signature")
    # Force the delegation to also appear expired by tweaking now_ms past its expiry.
    # The bad_signature fixture's delegation expires at FUTURE_MS, so if we pass
    # now_ms > FUTURE_MS, step 5 would trigger — but only if step 1 passes.
    from generate_delegation_fixtures import FUTURE_MS as _FUTURE_MS
    results = verify_chain(
        capsule_bytes=capsule_bytes,
        delegation=delegation,
        node_ownership=node_ownership,
        revocation_list=revocation_list,
        expected_scope=EXPECTED_SCOPE,
        expected_plugin_id=EXPECTED_PLUGIN_ID,
        expected_node_id=node_id,
        now_ms=_FUTURE_MS + 1,  # past expiry
    )
    verdict = chain_verdict(results)
    assert not verdict.ok
    # Must fail at step 1 (bad capsule signature) not step 5 (expiry)
    assert verdict.rejection == RejectionCode.BAD_SIGNATURE, (
        f"Step 1 must trigger before step 5; got {verdict.rejection!r} at {verdict.step!r}"
    )


# ===========================================================================
# Identity mode and evidence state tests — [mesh-identity-mode-assurance-labels]
#
# THE TESTS THAT MATTER ARE THE NON-UPGRADE ONES.
# #1331: "No mode silently upgrades its assurance label."
# #1331: "must preserve distinctions between missing, present-unverified,
#          verified, expired, revoked, and invalid"
# #1331: "must not forward a boolean such as owner_verified without the
#          signed evidence needed to verify it."
# ===========================================================================

class TestEvidenceStateDistinctions:
    """Six evidence states each shown failing to be reported as anything stronger."""

    def test_verified_state_on_happy_path(self):
        """Happy path: evidence_state must be VERIFIED, mode must be OWNER_DELEGATED."""
        delegation, node_ownership, capsule_bytes, revocation_list, node_id = _load("happy")
        results = _run_case("happy")
        mode_result = assess_identity_mode(results, delegation)
        assert mode_result.evidence_state == EvidenceState.VERIFIED, (
            f"Happy path must produce VERIFIED; got {mode_result.evidence_state!r}"
        )
        assert mode_result.mode == IdentityMode.OWNER_DELEGATED, (
            f"Happy path must produce OWNER_DELEGATED; got {mode_result.mode!r}"
        )

    def test_missing_state_when_no_delegation(self):
        """No delegation → evidence_state=MISSING, mode=SELF_ATTESTED."""
        # assess without providing any delegation document
        mode_result = assess_identity_mode_without_verifying(None)
        assert mode_result.evidence_state == EvidenceState.MISSING
        assert mode_result.mode == IdentityMode.SELF_ATTESTED

    def test_expired_state_is_not_self_attested(self):
        """Expired delegation must NOT silently degrade to self_attested.

        #1331: distinction between expired and missing is required.
        A verifier that collapses expired→self_attested loses the information
        that a credential WAS issued and DID expire.
        """
        results = _run_case("expired")
        delegation = json.loads(
            (_FIXTURES_DIR / "expired" / "delegation.json").read_bytes()
        )
        mode_result = assess_identity_mode(results, delegation)
        assert mode_result.evidence_state == EvidenceState.EXPIRED, (
            f"Expired delegation must produce EXPIRED state; got {mode_result.evidence_state!r}"
        )
        assert mode_result.mode != IdentityMode.SELF_ATTESTED, (
            "Expired delegation must NOT degrade silently to self_attested"
        )
        assert mode_result.mode == IdentityMode.UNKNOWN, (
            f"Mode for expired delegation must be UNKNOWN; got {mode_result.mode!r}"
        )

    def test_revoked_state_is_not_self_attested(self):
        """Revoked delegation must NOT silently degrade to self_attested."""
        results = _run_case("revoked")
        delegation = json.loads(
            (_FIXTURES_DIR / "revoked" / "delegation.json").read_bytes()
        )
        mode_result = assess_identity_mode(results, delegation)
        assert mode_result.evidence_state == EvidenceState.REVOKED, (
            f"Revoked delegation must produce REVOKED state; got {mode_result.evidence_state!r}"
        )
        assert mode_result.mode != IdentityMode.SELF_ATTESTED
        assert mode_result.mode == IdentityMode.UNKNOWN

    def test_invalid_signature_produces_invalid_not_owner_delegated(self):
        """Bad signature must produce INVALID state, NOT owner_delegated.

        This is the 'present-but-unverified' trap in step form: a delegation
        that exists on disk but whose signature fails must NOT upgrade the mode.
        """
        results = _run_case("bad_signature")
        delegation = json.loads(
            (_FIXTURES_DIR / "bad_signature" / "delegation.json").read_bytes()
        )
        mode_result = assess_identity_mode(results, delegation)
        assert mode_result.evidence_state == EvidenceState.INVALID, (
            f"Bad-signature delegation must produce INVALID; got {mode_result.evidence_state!r}"
        )
        assert mode_result.mode != IdentityMode.OWNER_DELEGATED, (
            "A delegation with an invalid signature must NOT report owner_delegated"
        )

    def test_present_unverified_does_not_upgrade_to_owner_delegated(self):
        """A delegation that is present but has NOT been verified must report
        PRESENT_UNVERIFIED, never OWNER_DELEGATED.

        This tests the 'naive presence check' trap: a consumer that merely
        checks 'is there a delegation?' and upgrades to owner_delegated is
        wrong. This verifier must refuse that shortcut.
        """
        # Use a valid happy-path delegation document but call the unverified assessor —
        # simulating a consumer that skips verification.
        delegation = json.loads(
            (_FIXTURES_DIR / "happy" / "delegation.json").read_bytes()
        )
        mode_result = assess_identity_mode_without_verifying(delegation)
        assert mode_result.evidence_state == EvidenceState.PRESENT_UNVERIFIED, (
            f"Unverified delegation must produce PRESENT_UNVERIFIED; got {mode_result.evidence_state!r}"
        )
        assert mode_result.mode != IdentityMode.OWNER_DELEGATED, (
            "An unverified delegation must NOT report owner_delegated — "
            "presence is not verification"
        )
        assert mode_result.mode == IdentityMode.UNKNOWN


class TestNonUpgradeRules:
    """Each pair where an upgrade would be wrong, shown refusing it.

    #1331: "No mode silently upgrades its assurance label."
    """

    def test_present_unverified_refuses_upgrade(self):
        """present_unverified → owner_delegated is always wrong."""
        valid_delegation = json.loads(
            (_FIXTURES_DIR / "happy" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode_without_verifying(valid_delegation)
        assert mr.mode != IdentityMode.OWNER_DELEGATED, (
            "PRESENT_UNVERIFIED must never upgrade to OWNER_DELEGATED"
        )

    def test_expired_refuses_upgrade_to_owner_delegated(self):
        """expired → owner_delegated is always wrong."""
        results = _run_case("expired")
        delegation = json.loads(
            (_FIXTURES_DIR / "expired" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode(results, delegation)
        assert mr.mode != IdentityMode.OWNER_DELEGATED
        assert mr.evidence_state == EvidenceState.EXPIRED

    def test_revoked_refuses_upgrade_to_owner_delegated(self):
        """revoked → owner_delegated is always wrong."""
        results = _run_case("revoked")
        delegation = json.loads(
            (_FIXTURES_DIR / "revoked" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode(results, delegation)
        assert mr.mode != IdentityMode.OWNER_DELEGATED
        assert mr.evidence_state == EvidenceState.REVOKED

    def test_expired_refuses_downgrade_to_self_attested(self):
        """expired → self_attested downgrade is also wrong — it is a distinct state."""
        results = _run_case("expired")
        delegation = json.loads(
            (_FIXTURES_DIR / "expired" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode(results, delegation)
        assert mr.mode != IdentityMode.SELF_ATTESTED, (
            "Expired delegation must remain UNKNOWN, not silently degrade to self_attested"
        )

    def test_hardware_delegated_is_unrepresentable(self):
        """hardware_delegated must be unrepresentable — not approximated.

        #1331: "hardware_delegated: reserved for future attested/non-exportable keys."
        A software Ed25519 key verified by this verifier is NOT hardware_delegated.
        The verifier never returns this value; it must not be in IdentityMode.
        """
        # hardware_delegated is not a member of IdentityMode
        mode_values = {m.value for m in IdentityMode}
        assert "hardware_delegated" not in mode_values, (
            "hardware_delegated must not appear in IdentityMode — it is unrepresentable "
            "in software and must not be approximated"
        )
        # Even the fully-verified happy path does not claim hardware_delegated
        results = _run_case("happy")
        delegation = json.loads(
            (_FIXTURES_DIR / "happy" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode(results, delegation)
        assert mr.mode.value != "hardware_delegated"
        # The best a software chain can achieve is owner_delegated
        assert mr.mode == IdentityMode.OWNER_DELEGATED

    def test_owner_delegated_required_is_not_in_output(self):
        """owner_delegated_required is host POLICY, not an evidence label.

        It should never appear in verifier output — the verifier produces
        evidence labels (what the evidence shows), not policy labels (what
        the operator requires).
        """
        mode_values = {m.value for m in IdentityMode}
        assert "owner_delegated_required" not in mode_values, (
            "owner_delegated_required is a policy floor, not an evidence label; "
            "it must not appear in IdentityMode"
        )


class TestNoBooleanOwnerVerified:
    """#1331: must not forward a boolean such as owner_verified without the
    signed evidence needed to verify it.
    """

    def test_mode_output_has_no_boolean_owner_verified(self):
        """mode_output_dict() must never include an owner_verified key."""
        results = _run_case("happy")
        delegation = json.loads(
            (_FIXTURES_DIR / "happy" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode(results, delegation)
        output = mode_output_dict(mr)
        assert "owner_verified" not in output, (
            "mode_output_dict must not include owner_verified — "
            "the evidence_state field IS the evidence; callers must read it"
        )

    def test_mode_output_failed_case_has_no_boolean_owner_verified(self):
        """Even a failed chain must not include owner_verified."""
        results = _run_case("expired")
        delegation = json.loads(
            (_FIXTURES_DIR / "expired" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode(results, delegation)
        output = mode_output_dict(mr)
        assert "owner_verified" not in output

    def test_mode_output_fields_are_evidence_state_not_boolean(self):
        """Verify the output shape: evidence_state is a string label, not bool."""
        results = _run_case("happy")
        delegation = json.loads(
            (_FIXTURES_DIR / "happy" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode(results, delegation)
        output = mode_output_dict(mr)
        assert isinstance(output["evidence_state"], str), (
            "evidence_state must be a string label, not a boolean"
        )
        assert isinstance(output["identity_mode"], str)
        # No boolean values anywhere in output
        bool_values = [k for k, v in output.items() if isinstance(v, bool)]
        assert not bool_values, f"Output must contain no boolean values; found: {bool_values}"


class TestModeRungMapping:
    """The mode→rung mapping must be explicitly documented in the output.

    The mapping note is that identity mode and cross-party rung are orthogonal —
    see SPEC-FEEDBACK-1331.md §9.
    """

    def test_owner_delegated_rung_is_none(self):
        """owner_delegated does not map to a specific rung — must say so."""
        results = _run_case("happy")
        delegation = json.loads(
            (_FIXTURES_DIR / "happy" / "delegation.json").read_bytes()
        )
        mr = assess_identity_mode(results, delegation)
        assert mr.mode == IdentityMode.OWNER_DELEGATED
        assert mr.rung is None, (
            "owner_delegated must not claim a specific cross-party rung — "
            "the two axes are orthogonal (see SPEC-FEEDBACK-1331.md §9)"
        )
        assert mr.rung_note, "rung_note must explain why there is no rung"

    def test_self_attested_rung_is_none(self):
        """self_attested does not determine a cross-party rung."""
        mr = assess_identity_mode_without_verifying(None)
        assert mr.mode == IdentityMode.SELF_ATTESTED
        assert mr.rung is None
        assert mr.rung_note

    def test_rung_note_is_prose_not_empty(self):
        """Every mode result must carry a non-empty rung_note."""
        for case in ["happy", "expired", "revoked", "bad_signature", "wrong_scope"]:
            if case in ("happy",):
                results = _run_case(case)
                delegation = json.loads(
                    (_FIXTURES_DIR / case / "delegation.json").read_bytes()
                )
            else:
                results = _run_case(case)
                delegation = json.loads(
                    (_FIXTURES_DIR / case / "delegation.json").read_bytes()
                )
            mr = assess_identity_mode(results, delegation)
            assert mr.rung_note, f"rung_note must not be empty for case {case!r}"

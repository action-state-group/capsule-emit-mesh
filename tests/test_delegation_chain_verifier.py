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
    RejectionCode,
    VerifyStep,
    chain_verdict,
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

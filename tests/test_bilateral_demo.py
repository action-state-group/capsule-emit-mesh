#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tests for the bilateral attestation demo.

Tests are structured around the negative-check mandate: every check must
fail its mutant. For the rung derivation specifically, each branch must be
reachable and the transition must be shown passing and failing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import types
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Stub the library deps so tests run without installing agent-action-capsule
# and scitt_cose (same pattern as test_forwarded_copy_and_keys.py).
# ---------------------------------------------------------------------------
for _name in [
    "scitt_cose",
    "agent_action_capsule",
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]:
    sys.modules.setdefault(_name, types.ModuleType(_name))

sys.modules["agent_action_capsule.canonical"].json_digest = (
    lambda v: hashlib.sha256(
        json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
)
for _n in ["Disposition", "EffectRecord"]:
    setattr(sys.modules["agent_action_capsule.contracts"], _n, object)
sys.modules["agent_action_capsule.emit"].emit = lambda **k: {}
sys.modules["agent_action_capsule.verify"].verify = lambda *a, **k: None
sys.modules["model_identity"].load_manifest = lambda p: {}
sys.modules["model_identity"].model_package_digest = lambda m: ""

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capsule_sidecar import (
    BilateralEvalResult,
    derive_cross_party_rung,
    evaluate_bilateral_attestation,
)
from bilateral_demo import (
    ClientKey,
    ClientAck,
    make_request_attestation,
    make_client_ack,
    verify_client_ack,
    get_cross_party,
)

from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Helper: build a valid request attestation for a given body.
# ---------------------------------------------------------------------------

def _valid_ra_headers(
    client_key: ClientKey,
    raw_body: bytes,
    request_json: dict,
    *,
    nonce: str | None = None,
) -> dict[str, str]:
    ra_b64, sig_b64, pub_b64 = make_request_attestation(
        client_key, raw_body, request_json, nonce=nonce
    )
    return {
        "x-capsule-request-attestation": ra_b64,
        "x-capsule-request-attestation-sig": sig_b64,
        "x-capsule-client-pubkey": pub_b64,
    }


def _body_and_json(max_tokens: int = 64) -> tuple[bytes, dict]:
    rj = {"model": "test-model", "messages": [{"role": "user", "content": "hello"}], "max_tokens": max_tokens}
    return json.dumps(rj).encode("utf-8"), rj


# ===========================================================================
# derive_cross_party_rung — all three branches, each mutant-tested
# ===========================================================================


def test_rung_unilateral_when_no_cross_party():
    """No cross_party block → unilateral_fallback."""
    rung = derive_cross_party_rung(None)
    assert rung == "unilateral_fallback", rung


def test_rung_unilateral_when_initiator_ref_absent():
    """cross_party present but initiator_ref null → unilateral_fallback.

    Mutant: if a producer could slip in a cross_party block without an
    initiator_ref and claim a higher rung, this check would pass it. It must
    not.
    """
    rung = derive_cross_party_rung({"initiator_ref": None, "correlator": "abc"})
    assert rung == "unilateral_fallback", rung


def test_rung_unilateral_when_initiator_ref_missing_key():
    """cross_party dict without initiator_ref key → unilateral_fallback."""
    rung = derive_cross_party_rung({"correlator": "abc"})
    assert rung == "unilateral_fallback", rung


def test_rung_acknowledged_receipt_with_initiator_ref_no_ack():
    """initiator_ref present, no ack → acknowledged_receipt."""
    rung = derive_cross_party_rung(
        {"initiator_ref": "a" * 64, "correlator": "nonce"},
        has_verified_ack=False,
    )
    assert rung == "acknowledged_receipt", rung


def test_rung_acknowledged_receipt_mutant_no_ack():
    """Mutant: has_verified_ack=True but initiator_ref absent → still unilateral.

    An ack without an initiator_ref cannot upgrade to acknowledged_receipt
    or full_bilateral — the initiator_ref is what commits the node to having
    seen the request attestation.
    """
    rung = derive_cross_party_rung({"initiator_ref": None}, has_verified_ack=True)
    assert rung == "unilateral_fallback", rung


def test_rung_full_bilateral():
    """initiator_ref present AND verified ack → full_bilateral."""
    rung = derive_cross_party_rung(
        {"initiator_ref": "b" * 64, "correlator": "nonce"},
        has_verified_ack=True,
    )
    assert rung == "full_bilateral", rung


def test_rung_ordering_is_strict():
    """Ordering invariant: unilateral < acknowledged < full_bilateral."""
    rungs = ["unilateral_fallback", "acknowledged_receipt", "full_bilateral"]
    # Each is a distinct string — never confusable.
    assert len(set(rungs)) == 3
    # Produce all three with the derivation function; check they're the right ones.
    assert derive_cross_party_rung(None) == rungs[0]
    assert derive_cross_party_rung({"initiator_ref": "x" * 64}) == rungs[1]
    assert derive_cross_party_rung({"initiator_ref": "x" * 64}, has_verified_ack=True) == rungs[2]


# ===========================================================================
# evaluate_bilateral_attestation — valid path and all failure modes
# ===========================================================================


def test_eval_absent_when_no_headers():
    """No bilateral headers → present=False (degraded path)."""
    raw, rj = _body_and_json()
    result = evaluate_bilateral_attestation({}, raw, rj)
    assert not result.present
    assert not result.valid
    assert result.initiator_ref is None


def test_eval_valid_happy_path():
    """Valid headers → present=True, valid=True, initiator_ref set."""
    key = ClientKey.generate()
    raw, rj = _body_and_json()
    headers = _valid_ra_headers(key, raw, rj)
    result = evaluate_bilateral_attestation(headers, raw, rj)
    assert result.present, result.fail_reason
    assert result.valid, result.fail_reason
    assert result.initiator_ref is not None
    assert len(result.initiator_ref) == 64  # sha256 hex


def test_eval_invalid_signature():
    """Corrupted signature → present=True, valid=False."""
    key = ClientKey.generate()
    raw, rj = _body_and_json()
    headers = _valid_ra_headers(key, raw, rj)
    # Flip one byte in the signature.
    sig_bytes = base64.urlsafe_b64decode(headers["x-capsule-request-attestation-sig"] + "==")
    bad_sig = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
    headers["x-capsule-request-attestation-sig"] = (
        base64.urlsafe_b64encode(bad_sig).rstrip(b"=").decode("ascii")
    )
    result = evaluate_bilateral_attestation(headers, raw, rj)
    assert result.present
    assert not result.valid
    assert "signature" in (result.fail_reason or "")


def test_eval_expired():
    """Expired attestation → present=True, valid=False."""
    key = ClientKey.generate()
    raw, rj = _body_and_json()
    # Build an attestation whose valid_until is in the past.
    now = datetime.now(timezone.utc)
    past = now - timedelta(seconds=10)
    ra = {
        "type": "x-capsule-poc-request-attestation/1",
        "request_digest": hashlib.sha256(raw).hexdigest(),
        "nonce": uuid.uuid4().hex,
        "timestamp": (now - timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
        "valid_until": past.isoformat().replace("+00:00", "Z"),
        "max_tokens": 64,
        "deadline_utc": past.isoformat().replace("+00:00", "Z"),
    }
    ra_bytes = json.dumps(ra, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = key.sign(ra_bytes)
    headers = {
        "x-capsule-request-attestation": base64.urlsafe_b64encode(ra_bytes).rstrip(b"=").decode("ascii"),
        "x-capsule-request-attestation-sig": base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii"),
        "x-capsule-client-pubkey": base64.urlsafe_b64encode(key.public_key_pem).rstrip(b"=").decode("ascii"),
    }
    result = evaluate_bilateral_attestation(headers, raw, rj)
    assert result.present
    assert not result.valid
    assert "expired" in (result.fail_reason or "")


def test_eval_request_digest_mismatch():
    """RA commits to different body than what arrived → valid=False."""
    key = ClientKey.generate()
    raw, rj = _body_and_json()
    different_raw = b'{"model":"other","messages":[]}'
    # Sign against different_raw but send raw.
    headers = _valid_ra_headers(key, different_raw, {"max_tokens": 64})
    result = evaluate_bilateral_attestation(headers, raw, rj)
    assert result.present
    assert not result.valid
    assert "request_digest" in (result.fail_reason or "")


def test_eval_max_tokens_bound_exceeded():
    """Request asks for more tokens than the RA authorized → valid=False."""
    key = ClientKey.generate()
    raw, rj = _body_and_json(max_tokens=128)  # request wants 128
    # Build RA authorizing only 64.
    now = datetime.now(timezone.utc)
    ra = {
        "type": "x-capsule-poc-request-attestation/1",
        "request_digest": hashlib.sha256(raw).hexdigest(),
        "nonce": uuid.uuid4().hex,
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "valid_until": (now + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
        "max_tokens": 64,  # only 64 authorized
        "deadline_utc": (now + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
    }
    ra_bytes = json.dumps(ra, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = key.sign(ra_bytes)
    headers = {
        "x-capsule-request-attestation": base64.urlsafe_b64encode(ra_bytes).rstrip(b"=").decode("ascii"),
        "x-capsule-request-attestation-sig": base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii"),
        "x-capsule-client-pubkey": base64.urlsafe_b64encode(key.public_key_pem).rstrip(b"=").decode("ascii"),
    }
    result = evaluate_bilateral_attestation(headers, raw, rj)
    assert result.present
    assert not result.valid
    assert "max_tokens" in (result.fail_reason or "")


def test_eval_missing_sig_header():
    """RA present but sig header missing → valid=False."""
    key = ClientKey.generate()
    raw, rj = _body_and_json()
    headers = _valid_ra_headers(key, raw, rj)
    del headers["x-capsule-request-attestation-sig"]
    result = evaluate_bilateral_attestation(headers, raw, rj)
    assert result.present
    assert not result.valid


def test_eval_initiator_ref_is_sha256_of_ra_bytes():
    """initiator_ref must be sha256 of the raw RA bytes."""
    key = ClientKey.generate()
    raw, rj = _body_and_json()
    headers = _valid_ra_headers(key, raw, rj)
    result = evaluate_bilateral_attestation(headers, raw, rj)
    assert result.valid
    # Re-derive the initiator_ref independently.
    ra_bytes = base64.urlsafe_b64decode(headers["x-capsule-request-attestation"] + "==")
    expected = hashlib.sha256(ra_bytes).hexdigest()
    assert result.initiator_ref == expected


# ===========================================================================
# Client ack verification
# ===========================================================================


def test_client_ack_valid():
    """Valid ack over the correct capsule_id and nonce → ok=True."""
    key = ClientKey.generate()
    capsule_id = "a" * 64
    nonce = uuid.uuid4().hex
    ack = make_client_ack(key, capsule_id, nonce)
    ok, reason = verify_client_ack(ack, capsule_id, nonce)
    assert ok, reason


def test_client_ack_wrong_capsule_id():
    """Ack references a different capsule_id → ok=False."""
    key = ClientKey.generate()
    nonce = uuid.uuid4().hex
    ack = make_client_ack(key, "a" * 64, nonce)
    ok, reason = verify_client_ack(ack, "b" * 64, nonce)
    assert not ok
    assert "action_capsule_id" in reason


def test_client_ack_wrong_nonce():
    """Ack nonce doesn't match the correlator → ok=False."""
    key = ClientKey.generate()
    capsule_id = "c" * 64
    ack = make_client_ack(key, capsule_id, "nonce-A")
    ok, reason = verify_client_ack(ack, capsule_id, "nonce-B")
    assert not ok
    assert "nonce" in reason


def test_client_ack_corrupted_sig():
    """Corrupted signature → ok=False."""
    key = ClientKey.generate()
    capsule_id = "d" * 64
    nonce = "n1"
    ack = make_client_ack(key, capsule_id, nonce)
    bad_sig = bytes([ack.sig[0] ^ 0xFF]) + ack.sig[1:]
    bad_ack = ClientAck(
        action_capsule_id=ack.action_capsule_id,
        request_nonce=ack.request_nonce,
        timestamp=ack.timestamp,
        ack_bytes=ack.ack_bytes,
        sig=bad_sig,
        public_key_pem=ack.public_key_pem,
    )
    ok, reason = verify_client_ack(bad_ack, capsule_id, nonce)
    assert not ok
    assert "signature" in reason


# ===========================================================================
# Distinguishability: bilateral and degraded records must never be confusable
# ===========================================================================


def test_bilateral_and_degraded_records_are_distinguishable():
    """A record with cross_party and one without must produce different rungs,
    and the difference must be detectable from the record bytes alone.
    """
    # Simulate the two capsule shapes (minimal dicts matching get_cross_party).
    bilateral_capsule_shape = {
        "model_attestation": {
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "cross_party": {
                        "initiator_ref": "e" * 64,
                        "correlator": "some-nonce",
                        "substantive": True,
                    }
                }
            }
        }
    }
    degraded_capsule_shape = {
        "model_attestation": {
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "cross_party": None  # explicitly absent
                }
            }
        }
    }

    cp_bilateral = get_cross_party(bilateral_capsule_shape)
    cp_degraded = get_cross_party(degraded_capsule_shape)

    rung_bilateral = derive_cross_party_rung(cp_bilateral)
    rung_degraded = derive_cross_party_rung(cp_degraded)

    assert rung_bilateral != rung_degraded, "rungs must differ"
    assert rung_bilateral in ("acknowledged_receipt", "full_bilateral")
    assert rung_degraded == "unilateral_fallback"

    # cross_party presence itself is a distinguishing marker.
    assert cp_bilateral is not None
    assert cp_degraded is None


# ===========================================================================
# Full end-to-end: run bilateral_demo.py as a subprocess so it gets the
# real library environment (not the module-level stubs above).
# ===========================================================================


def test_bilateral_demo_e2e():
    """Run bilateral_demo.py as a subprocess; confirm it exits 0 with all gates passing."""
    import subprocess

    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent.parent / "bilateral_demo.py")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"bilateral_demo.py exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    assert "Demo complete. All acceptance gates passed." in result.stdout, (
        f"Success marker not found in output:\n{result.stdout}"
    )
    # Verify both rungs appear in the output.
    assert "full_bilateral" in result.stdout
    assert "unilateral_fallback" in result.stdout


if __name__ == "__main__":
    # Run all tests manually (without pytest) by collecting and calling each.
    import traceback

    test_fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = []
    for fn in test_fns:
        try:
            fn()
            print(f"OK  {fn.__name__}")
        except Exception as exc:
            failures.append((fn.__name__, exc))
            print(f"FAIL {fn.__name__}: {exc}")
            traceback.print_exc()

    print(f"\n{len(test_fns) - len(failures)}/{len(test_fns)} passed")
    if failures:
        raise SystemExit(1)

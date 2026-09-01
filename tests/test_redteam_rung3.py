#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rung 3b — adversarial red-team of the Secure Enclave key-custody layer.

Where B4 (test_redteam_rung2.py, attacks 9-10) red-teamed the OWNER binding,
this module red-teams the KEY CUSTODY layer added on top of it
(sep_attestation.py). Same vocabulary as the earlier rungs:

    CAUGHT     -- the machinery rejects it / a hardware guarantee holds
    LABELED    -- not rejected, but named honestly in the record so a
                  verifier sees the degradation or the limitation
    RESIDUAL   -- it succeeds and the current rung has no handle to see it

The findings table is docs/REDTEAM-RUNG3.md. Each test below is the
executable evidence for one row.

SCOPE: 3b (key custody) only -- not 3a (os_measured) or 3c (tee_measured);
those rungs get their own red-team rows when they land.
"""
from __future__ import annotations

import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import sep_attestation as sepa  # noqa: E402

HAS_SEP_LAB = (
    platform.system() == "Darwin"
    and platform.machine() == "arm64"
    and shutil.which("swift") is not None
)


# ── Attack 11: key-extraction attempt ────────────────────────────────────────

@pytest.mark.skipif(not HAS_SEP_LAB, reason="needs a real Apple Silicon Secure Enclave + swift toolchain")
def test_attack11_key_extraction_attempt_is_caught():
    """CAUGHT. Ask Security.framework for the raw bytes of the SEP PRIVATE
    key itself (not the public key) via the helper's `extract-attempt`
    red-team-only subcommand. The Secure Enclave physically never releases
    private key material to any process -- this is a hardware guarantee, not
    an application-level choice sep_attestation.py makes, and this test
    demonstrates that directly rather than merely asserting our own code
    never calls the export API."""
    proc = subprocess.run(
        ["swift", str(sepa.HELPER_PATH), "extract-attempt"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    import json

    payload = json.loads(proc.stdout.strip())
    assert payload["ok"] is True
    assert payload["extraction_succeeded"] is False, (
        "if this ever flips to True, the Secure Enclave non-exportability "
        "guarantee this whole rung relies on has broken"
    )


def test_attack11b_helper_output_never_carries_private_material():
    """CAUGHT (defence in depth). Independent of the hardware guarantee
    above: sep_attestation.py's own parsing of the helper's `attest` output
    only ever reads public_key_x963_hex and signature_der_hex -- there is no
    code path that could forward a private key even if one were present."""
    import inspect

    source = inspect.getsource(sepa._sign_with_secure_enclave)
    assert "private" not in source.lower()


# ── Attack 12: attacker's-own-SEP-key claiming the node's owner_id ──────────

def test_attack12_attacker_own_key_claiming_owner_id_is_labeled(monkeypatch):
    """LABELED (documented gap, same family as rung-2's attack #10
    key-substitution). tee_key_custody_block() binds an owner_id STRING to
    whatever P-256 key produced the signature -- it does not, and cannot,
    prove that string is controlled by the party who holds the cited Ed25519
    owner key. An attacker with their OWN Secure-Enclave-or-software key can
    freely produce an internally-consistent, independently-verifiable
    tee_key_custody block claiming ANY owner_id string; the block verifies
    fine because verification only checks the signature against the
    EMBEDDED public key, never an external identity.

    This is not a bug to fix here -- it is the same owner_id<->key gap
    node_ownership.IDENTITY_LIMITATION_CAVEAT already documents for B4, and
    the same discipline applies: sep_attestation.TEE_KEY_CUSTODY_LABEL
    states plainly that this is a KEY-CUSTODY claim, not a party-binding
    one. Closed only by a third-party-issued credential / trusted root
    (out of scope, same as attack #10)."""
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: False)
    tmp = pathlib.Path(tempfile.mkdtemp())

    real_node_ed25519_pub = "aa" * 32
    attacker_ed25519_pub = "bb" * 32  # attacker controls a DIFFERENT Ed25519 key
    shared_owner_id = "owner-victim"  # attacker claims the SAME owner_id string

    genuine = sepa.tee_key_custody_block(
        tmp / "genuine",
        ed25519_public_key_hex=real_node_ed25519_pub,
        node_endpoint_id="node-real",
        owner_id=shared_owner_id,
    )
    forged = sepa.tee_key_custody_block(
        tmp / "attacker",
        ed25519_public_key_hex=attacker_ed25519_pub,
        node_endpoint_id="node-attacker-controlled",
        owner_id=shared_owner_id,  # same owner_id, different everything else
    )

    # Both are internally consistent / independently verifiable -- neither
    # rejects. This IS the finding, not a test bug.
    for block in (genuine, forged):
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(block["public_key_x963_hex"])
        )
        message = sepa.canonical_binding_bytes(
            owner_ed25519_public_key_hex=block["attests"]["owner_ed25519_public_key"],
            node_endpoint_id=block["attests"]["node_endpoint_id"],
            owner_id=block["attests"]["owner_id"],
        )
        pub.verify(bytes.fromhex(block["signature_der_hex"]), message, ec.ECDSA(hashes.SHA256()))

    assert genuine["attests"]["owner_id"] == forged["attests"]["owner_id"] == shared_owner_id
    assert genuine["public_key_x963_hex"] != forged["public_key_x963_hex"]

    # The gap must be LABELED, not silently accepted as party-binding proof.
    assert "does NOT attest" in genuine["label"] or "KEY-CUSTODY" in genuine["label"]
    assert genuine["label"] == forged["label"], "the honesty grade travels with every block, attacker's included"


# ── Attack 13: Secure-Enclave-absent host silently downgraded ───────────────

def test_attack13_sep_absent_downgrade_is_labeled_never_faked(monkeypatch):
    """LABELED. A host with no Secure Enclave (a VM, non-Apple hardware, or
    just no `swift` toolchain) must fall back to a software key AND say so
    -- custody must never read "secure_enclave" when the private key never
    touched hardware, and tee_protected must never be True for a software
    key."""
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: False)
    tmp = pathlib.Path(tempfile.mkdtemp())

    block = sepa.tee_key_custody_block(
        tmp,
        ed25519_public_key_hex="cc" * 32,
        node_endpoint_id="node-no-sep",
        owner_id=None,
    )

    assert block["custody"] == sepa.CUSTODY_SOFTWARE
    assert block["tee_protected"] is False
    assert block["software_fallback_reason"] not in (None, "")
    # The signature is still real and verifiable -- degraded custody, not a
    # degraded (fake) signature.
    pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(block["public_key_x963_hex"])
    )
    message = sepa.canonical_binding_bytes(
        owner_ed25519_public_key_hex="cc" * 32, node_endpoint_id="node-no-sep", owner_id=None
    )
    pub.verify(bytes.fromhex(block["signature_der_hex"]), message, ec.ECDSA(hashes.SHA256()))


def test_attack13b_helper_reporting_ok_true_is_required_for_hardware_claim(monkeypatch):
    """LABELED (defence in depth). Any helper response other than a clean
    {"ok": true, ...} with all required fields must fall back to software --
    a helper that crashes, times out, or returns a truncated/malformed
    payload must never be interpreted as a Secure Enclave success."""
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/true")

    class CrashedProc:
        returncode = 137  # SIGKILL-style abnormal exit
        stdout = ""
        stderr = "Segmentation fault"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: CrashedProc())
    result = sepa.sign_binding(b"probe")
    assert result.custody == sepa.CUSTODY_SOFTWARE
    assert result.tee_protected is False

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

import copy
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import node_ownership as no  # noqa: E402
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


# ── Attack 14 (merge-gate mutant): SEP-unaware verifier stays unaffected ────

def _recheck_from_record(record: dict, *, node_endpoint_id: str, now_unix_ms: int) -> no.OwnershipRecheck:
    """What a real, SEP-unaware verifier does: read ONLY the pre-existing
    ``signed_node_ownership`` sub-dict out of the sealed identity capsule and
    re-run the unmodified B4 check on it. Never looks at ``tee_key_custody`` --
    that field does not exist as far as this function is concerned."""
    who = record["model_attestation"]["compute_attestation"][no.OWNERSHIP_SUBJECT_KEY]
    ownership = no.SignedNodeOwnership.from_value(who["signed_node_ownership"])
    return no.recheck_ownership_validity(
        ownership, expected_node_endpoint_id=node_endpoint_id, now_unix_ms=now_unix_ms
    )


def test_attack14_sep_unaware_verifier_unaffected_by_tee_key_custody_tamper(monkeypatch):
    """CAUGHT -- this is the merge-gate mutant Steven named for #69: "a mutant
    proving an SEP-unaware verifier still verifies the Ed25519 record
    unchanged." ``tee_key_custody`` rides as an ADDITIVE sibling field next to
    the pre-existing B4 owner cert inside the sealed identity capsule
    (``node_ownership.seal_identity_capsule``); the pre-existing,
    SEP-unaware verifier (``node_ownership.recheck_ownership_validity``) reads
    only ``signed_node_ownership`` and has no code path that touches
    ``tee_key_custody`` at all.

    Evidence: seal a real identity capsule carrying both a valid owner cert
    AND a tee_key_custody block, re-derive the SAME SignedNodeOwnership from
    the capsule's own bytes and recheck it (PASS), then corrupt ONLY the
    tee_key_custody sibling field (flip a hex digit of its signature) and
    recheck AGAIN from the tampered record's bytes -- the result must be
    byte-for-byte IDENTICAL, not merely "still valid": a verifier that
    consulted tee_key_custody for its verdict (the mutant) would diverge
    here even though it should not.
    """
    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    node_endpoint_id = "42" * 32
    now = int(time.time() * 1000)
    claim = no.NodeOwnershipClaim(
        version=1,
        cert_id="cert-sep-mutant",
        owner_id="owner-sep-mutant",
        owner_sign_public_key=pub_hex,
        node_endpoint_id=node_endpoint_id,
        issued_at_unix_ms=now,
        expires_at_unix_ms=now + 60_000,
        node_label="studio",
        hostname_hint="host",
    )
    ownership = no.SignedNodeOwnership(
        claim=claim, signature=key.sign(no.canonical_claim_bytes(claim)).hex()
    )

    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: False)
    tee_block = sepa.tee_key_custody_block(
        pathlib.Path(tempfile.mkdtemp()),
        ed25519_public_key_hex=pub_hex,
        node_endpoint_id=node_endpoint_id,
        owner_id=claim.owner_id,
    )
    assert tee_block["custody"] == sepa.CUSTODY_SOFTWARE  # forced fallback above, not hardware-gated

    record = no.seal_identity_capsule(
        ownership,
        operator="op",
        developer="dev",
        signing_node_id=node_endpoint_id,
        tee_key_custody=tee_block,
    )

    before = _recheck_from_record(record, node_endpoint_id=node_endpoint_id, now_unix_ms=now)
    assert before.valid is True, before.reason

    tampered = copy.deepcopy(record)
    tampered_tee = tampered["model_attestation"]["compute_attestation"][no.OWNERSHIP_SUBJECT_KEY]["tee_key_custody"]
    good_sig_hex = tampered_tee["signature_der_hex"]
    tampered_tee["signature_der_hex"] = ("0" if good_sig_hex[0] != "0" else "1") + good_sig_hex[1:]
    assert tampered_tee["signature_der_hex"] != good_sig_hex

    after = _recheck_from_record(tampered, node_endpoint_id=node_endpoint_id, now_unix_ms=now)
    assert after == before, (
        "an SEP-unaware verifier must be blind to a tampered tee_key_custody "
        "sibling field -- corrupting it must change NEITHER the pass/fail "
        "verdict NOR any other field of the recheck result"
    )

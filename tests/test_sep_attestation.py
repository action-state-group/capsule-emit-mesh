#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rung 3b — Secure Enclave key-custody tests.

Covers sep_attestation.py end-to-end:

  1. Real hardware: on an Apple-Silicon host (this repo's own CI can't
     provide one -- skipped elsewhere), sign_binding() actually invokes the
     Secure Enclave via tools/sep_attestation_helper.swift and produces a
     signature that independently verifies -- proof, not trust, that the
     custody tier is real.
  2. Software fallback: when the Secure Enclave tier is unavailable (forced
     here so this test is host-independent), custody is honestly labeled
     "software", tee_protected is False, and software_fallback_reason is
     set -- never silently upgraded.
  3. Caching: tee_key_custody_block() signs once and reuses the cached
     attestation on a second call with the same (ed25519 key, node,
     owner_id) tuple; a changed tuple (key rotation) regenerates it.
  4. The helper's own failure modes (bad JSON, non-zero exit, missing
     fields) all degrade to the software tier rather than raising.
"""
from __future__ import annotations

import json
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


def _verify(block: dict) -> None:
    pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(block["public_key_x963_hex"])
    )
    message = sepa.canonical_binding_bytes(
        owner_ed25519_public_key_hex=block["attests"]["owner_ed25519_public_key"],
        node_endpoint_id=block["attests"]["node_endpoint_id"],
        owner_id=block["attests"]["owner_id"],
    )
    pub.verify(bytes.fromhex(block["signature_der_hex"]), message, ec.ECDSA(hashes.SHA256()))


# ── real hardware (this host) ───────────────────────────────────────────────

@pytest.mark.skipif(not HAS_SEP_LAB, reason="needs a real Apple Silicon Secure Enclave + swift toolchain")
def test_real_secure_enclave_signature_verifies():
    """No mocking: actually calls into the Secure Enclave and checks the
    returned signature against the returned public key."""
    tmp = pathlib.Path(tempfile.mkdtemp())
    block = sepa.tee_key_custody_block(
        tmp,
        ed25519_public_key_hex="ab" * 32,
        node_endpoint_id="node-real-sep",
        owner_id="owner-real",
    )
    assert block["custody"] == sepa.CUSTODY_SECURE_ENCLAVE
    assert block["tee_protected"] is True
    assert block["software_fallback_reason"] is None
    _verify(block)  # raises InvalidSignature if this is not a real, valid signature


@pytest.mark.skipif(not HAS_SEP_LAB, reason="needs a real Apple Silicon Secure Enclave + swift toolchain")
def test_real_secure_enclave_helper_never_exports_a_private_key():
    """The helper's own JSON output carries only public material -- no field
    named anything resembling a private key, ever."""
    tmp_msg = b"\x00" * 4
    proc = subprocess.run(
        ["swift", str(sepa.HELPER_PATH), "attest", tmp_msg.hex()],
        capture_output=True,
        text=True,
        timeout=15,
    )
    payload = json.loads(proc.stdout.strip())
    assert payload["ok"] is True
    for key in payload:
        assert "private" not in key.lower()
    # And the only public-key field present is the PUBLIC representation.
    assert payload["public_key_x963_hex"].startswith("04")  # uncompressed EC point


# ── software fallback (host-independent) ────────────────────────────────────

def test_software_fallback_is_honestly_labeled(monkeypatch):
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: False)
    tmp = pathlib.Path(tempfile.mkdtemp())
    block = sepa.tee_key_custody_block(
        tmp,
        ed25519_public_key_hex="cd" * 32,
        node_endpoint_id="node-sw",
        owner_id=None,
    )
    assert block["custody"] == sepa.CUSTODY_SOFTWARE
    assert block["tee_protected"] is False
    assert block["software_fallback_reason"]
    assert "tee_protected" in block["label"]
    _verify(block)  # software signature is still a real, valid ECDSA/P-256 signature


def test_helper_nonzero_exit_falls_back_to_software(monkeypatch):
    """A helper that fails cleanly (its own graceful {"ok":false,...} path)
    must never be treated as a Secure Enclave success."""
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/true")

    class FakeProc:
        returncode = 1
        stdout = '{"ok": false, "error": "no Secure Enclave on this Mac"}'
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    result = sepa.sign_binding(b"hello")
    assert result.custody == sepa.CUSTODY_SOFTWARE
    assert result.tee_protected is False
    assert "no Secure Enclave" in result.software_fallback_reason


def test_helper_malformed_json_falls_back_to_software(monkeypatch):
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/true")

    class FakeProc:
        returncode = 0
        stdout = "not json at all"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    result = sepa.sign_binding(b"hello")
    assert result.custody == sepa.CUSTODY_SOFTWARE
    assert result.tee_protected is False


def test_helper_missing_field_falls_back_to_software(monkeypatch):
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/true")

    class FakeProc:
        returncode = 0
        stdout = '{"ok": true, "custody": "secure_enclave"}'  # missing pubkey/sig
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    result = sepa.sign_binding(b"hello")
    assert result.custody == sepa.CUSTODY_SOFTWARE


def test_non_darwin_or_no_swift_is_software(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert sepa._secure_enclave_available() is False
    result = sepa.sign_binding(b"hello")
    assert result.custody == sepa.CUSTODY_SOFTWARE
    assert result.tee_protected is False


# ── caching ──────────────────────────────────────────────────────────────

def test_cache_reused_across_calls_no_resign(monkeypatch):
    tmp = pathlib.Path(tempfile.mkdtemp())
    calls = {"n": 0}
    real_sign = sepa.sign_binding

    def counting_sign(message):
        calls["n"] += 1
        return real_sign(message)

    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: False)
    monkeypatch.setattr(sepa, "sign_binding", counting_sign)

    first = sepa.tee_key_custody_block(
        tmp, ed25519_public_key_hex="11" * 32, node_endpoint_id="node-x", owner_id="o"
    )
    second = sepa.tee_key_custody_block(
        tmp, ed25519_public_key_hex="11" * 32, node_endpoint_id="node-x", owner_id="o"
    )
    assert calls["n"] == 1, "second call with the same identity must hit the cache"
    assert first == second


def test_cache_regenerates_on_ed25519_key_rotation(monkeypatch):
    tmp = pathlib.Path(tempfile.mkdtemp())
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: False)

    first = sepa.tee_key_custody_block(
        tmp, ed25519_public_key_hex="22" * 32, node_endpoint_id="node-y", owner_id="o"
    )
    second = sepa.tee_key_custody_block(
        tmp, ed25519_public_key_hex="33" * 32, node_endpoint_id="node-y", owner_id="o"
    )
    assert second["attests"]["owner_ed25519_public_key"] == "33" * 32
    assert second["public_key_x963_hex"] != first["public_key_x963_hex"]


def test_cache_regenerates_on_malformed_cache_file(monkeypatch):
    tmp = pathlib.Path(tempfile.mkdtemp())
    monkeypatch.setattr(sepa, "_secure_enclave_available", lambda: False)
    (tmp / sepa.CACHE_FILENAME).write_text("not json", encoding="utf-8")
    block = sepa.tee_key_custody_block(
        tmp, ed25519_public_key_hex="44" * 32, node_endpoint_id="node-z", owner_id=None
    )
    assert block["custody"] == sepa.CUSTODY_SOFTWARE
    _verify(block)


# ── honesty grade ────────────────────────────────────────────────────────

def test_label_distinguishes_key_custody_from_measurement():
    label = sepa.TEE_KEY_CUSTODY_LABEL
    assert "tee_protected" in label
    assert "os_measured" in label or "self_measured" in label
    assert "tee_measured" in label
    assert "does NOT attest" in label or "NOT attest" in label

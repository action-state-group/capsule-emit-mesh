# SPDX-License-Identifier: Apache-2.0
"""Regression tests for stranger_verify_bundle.py's signature-honesty invariant.

FALSE GREEN (adversarial review): a bundle that CONTAINS signed statements
(`signed-statements/*.cose`) but with NO issuer key supplied printed
`all capsules verify.ok: True` and `OVERALL: PASS` -- while no signature was
actually verified. Auto-discovery only looked in `<ledger>/../keys/`, so a
disclosed bundle whose pubkey sits at `<ledger>/node-key.pub.pem` skipped
signature verification yet still said PASS.

INVARIANT PINNED HERE: a bundle that carries signatures must never print
OVERALL: PASS without those signatures being verified. Either
  (a) auto-discovery finds an in-bundle pubkey and actually verifies -> PASS, or
  (b) no key is found -> the signed statement is UNVERIFIED, that capsule's
      verify.ok is degraded to False, and the top line is UNVERIFIED (not PASS,
      not a hard FAIL) so a human reading it is not misled.

Fixtures are generated in-test (a fresh Ed25519 key + one emitted capsule +
its detached COSE signed statement) so the test is self-contained and never
depends on any on-disk demo-run ledger state.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import stranger_verify_bundle as svb  # noqa: E402

pytest.importorskip("scitt_cose")
pytest.importorskip("agent_action_capsule.emit")


def _make_signed_bundle(bundle_dir: Path) -> bytes:
    """Emit one capsule, sign a detached COSE statement for it, and write a
    self-contained bundle (capsules.jsonl + signed-statements/<id>.cose).
    Returns the issuer PUBLIC key PEM (the caller decides where, if anywhere,
    to place it)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import scitt_cose
    from agent_action_capsule.emit import emit

    (bundle_dir / "signed-statements").mkdir(parents=True, exist_ok=True)

    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    capsule = emit(
        action_id="stranger-verify-test/1",
        action_type="fyi",
        operator="op",
        developer="dev",
        model_id="m",
        provider="mesh-llm",
        domain="action",
        provenance="collector",
    )
    (bundle_dir / "capsules.jsonl").write_text(json.dumps(capsule, sort_keys=True) + "\n")

    payload = json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode("utf-8")
    statement = scitt_cose.build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=priv_pem,
        issuer="mesh-node-demo-1",
        subject=capsule["capsule_id"],
        content_type=(
            "application/vnd.agent-action-capsule+json; "
            "profile=draft-mih-scitt-agent-action-capsule-02"
        ),
    )
    (bundle_dir / "signed-statements" / f"{capsule['capsule_id']}.cose").write_bytes(statement)
    return pub_pem


def test_signed_bundle_no_key_anywhere_is_unverified_not_pass(tmp_path):
    # A disclosed bundle that carries a signed statement but ships no pubkey and
    # has no sibling keys/ dir. Before the fix this printed OVERALL: PASS.
    bundle = tmp_path / "bundle"
    _make_signed_bundle(bundle)  # pubkey deliberately NOT written anywhere
    assert any((bundle / "signed-statements").glob("*.cose"))

    all_ok, any_unverified, lines = svb.verify_bundle(bundle, {})
    assert any_unverified is True
    # a signature-carrying capsule cannot read verify.ok=True while unchecked.
    assert all_ok is False
    report = "\n".join(lines)
    assert "UNVERIFIED:" in report
    assert "signature NOT checked" in report

    # main()'s top line is UNVERIFIED, never PASS, with a distinct exit code.
    rc = svb.main([str(bundle)])
    assert rc == 2  # UNVERIFIED, not 0 (PASS) and not 1 (hard FAIL)


def test_signed_bundle_with_in_ledger_pubkey_autodiscovers_and_verifies(tmp_path):
    # The default invocation must actually verify when the pubkey ships INSIDE
    # the bundle dir (the broadened auto-discovery), so an honest disclosed
    # bundle reads PASS for the right reason -- signatures checked.
    bundle = tmp_path / "bundle"
    pub_pem = _make_signed_bundle(bundle)
    (bundle / "node-key.pub.pem").write_bytes(pub_pem)

    resolved = svb._issuer_key_for(bundle, None)
    assert resolved == bundle / "node-key.pub.pem"

    all_ok, any_unverified, lines = svb.verify_bundle(bundle, {})
    report = "\n".join(lines)
    assert any_unverified is False
    assert "signature_verified=True" in report
    assert "UNVERIFIED:" not in report
    assert all_ok is True

    rc = svb.main([str(bundle)])
    assert rc == 0  # honest PASS -- signatures actually verified


def test_glob_pubkey_in_bundle_is_discovered(tmp_path):
    # Auto-discovery also finds an in-bundle pubkey under a non-canonical name
    # via <ledger>/*.pub.pem.
    bundle = tmp_path / "bundle"
    pub_pem = _make_signed_bundle(bundle)
    (bundle / "issuer.pub.pem").write_bytes(pub_pem)

    resolved = svb._issuer_key_for(bundle, None)
    assert resolved == bundle / "issuer.pub.pem"

    all_ok, any_unverified, lines = svb.verify_bundle(bundle, {})
    assert all_ok is True
    assert any_unverified is False
    assert "signature_verified=True" in "\n".join(lines)


def test_sibling_keys_layout_still_verifies(tmp_path):
    # The original sibling-keys layout still auto-discovers and verifies (no
    # regression): <root>/ledger + <root>/keys/node-key.pub.pem.
    root = tmp_path / "root"
    bundle = root / "ledger"
    pub_pem = _make_signed_bundle(bundle)
    keys = root / "keys"
    keys.mkdir(parents=True)
    (keys / "node-key.pub.pem").write_bytes(pub_pem)

    resolved = svb._issuer_key_for(bundle, None)
    assert resolved == keys / "node-key.pub.pem"

    all_ok, any_unverified, lines = svb.verify_bundle(bundle, {})
    assert all_ok is True
    assert any_unverified is False
    assert "signature_verified=True" in "\n".join(lines)

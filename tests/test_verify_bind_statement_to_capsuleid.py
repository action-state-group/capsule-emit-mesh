#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-verify-bind-statement-to-capsuleid] mutant tests.

Reproduces the exact adversarial-review findings ADV-1/ADV-2
(`_work/mesh-adversarial-review-2026-09-05.md`) against
`stranger_verify_bundle.py`'s and `capsule_mesh_view.py`'s detached-statement
verify, and pins the fix (QUEUE_PROTOCOL §7 -- every check must fail its
mutant, and must NOT fail the honest case):

ADV-1 (keyless relay tamper): a relay holding only the public disclosed
bundle -- NO signing key -- edits a field, recomputes the PUBLIC unkeyed
`capsule_id` over the tampered bytes, and renames the original honest
`.cose` to the new filename. `verify_transparent()` alone only proves SOME
statement signed by the issuer key exists; before the fix, neither tool
compared the statement's AUTHENTICATED subject back to the record's own
`capsule_id`, so this read `verify.ok=True` / `OVERALL: PASS`.

ADV-2 (absent signature fails open): a wholly fabricated capsule, self-
consistent `capsule_id`, NO `signed-statements/` at all.
`stranger_verify_bundle.py` returned `None` for "no statement to check" and
left `ok` at whatever the content-hash-only check gave it -- so this read
`OVERALL: PASS` (absence rendered as a pass). `capsule_mesh_view.py` already
failed closed here (pinned separately in
`test_mesh_view_verify_detached_cose.py::test_missing_detached_statement_reports_false_not_silently_true`);
this file adds the equivalent hard-failure pin for `stranger_verify_bundle.py`.

Both tools are exercised so a regression in either is caught -- the item's
mandate is to keep them identical.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import capsule_mesh_view as cmv  # noqa: E402
import stranger_verify_bundle as svb  # noqa: E402

pytest.importorskip("scitt_cose")
pytest.importorskip("agent_action_capsule.emit")


def _make_signed_bundle(bundle_dir: Path) -> tuple[dict, bytes]:
    """One emitted capsule + its detached COSE signed statement, written
    into ``bundle_dir``. Returns (capsule, issuer PUBLIC key PEM) -- the
    caller decides where, if anywhere, to place the pubkey. Mirrors
    test_stranger_verify_unverified.py's ``_make_signed_bundle``."""
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
        action_id="bind-capsuleid-test/1",
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
    return capsule, pub_pem


def _relay_tamper_and_rename(bundle_dir: Path, capsule: dict) -> str:
    """The exact ADV-1 attack -- NO key material needed. Flip a field,
    recompute the PUBLIC unkeyed capsule_id over the tampered bytes, rewrite
    capsules.jsonl with the tampered self-consistent record, and rename the
    original honestly-signed `.cose` to the new capsule_id's filename.
    Returns the new (tampered) capsule_id."""
    from agent_action_capsule import compute_capsule_id

    original_id = capsule["capsule_id"]
    tampered = dict(capsule)
    tampered["provider"] = "mesh-llm-TAMPERED"
    new_id = compute_capsule_id(tampered)
    tampered["capsule_id"] = new_id
    (bundle_dir / "capsules.jsonl").write_text(json.dumps(tampered, sort_keys=True) + "\n")

    (bundle_dir / "signed-statements" / f"{original_id}.cose").rename(
        bundle_dir / "signed-statements" / f"{new_id}.cose"
    )
    return new_id


class TestStrangerVerifyBundleADV1ADV2:
    def test_adv1_keyless_relay_tamper_rejected(self, tmp_path, capsys):
        bundle = tmp_path / "bundle"
        capsule, pub_pem = _make_signed_bundle(bundle)
        (bundle / "node-key.pub.pem").write_bytes(pub_pem)

        new_id = _relay_tamper_and_rename(bundle, capsule)

        all_ok, any_unverified, lines = svb.verify_bundle(bundle, {})
        report = "\n".join(lines)
        assert all_ok is False, report
        assert "SUBJECT MISMATCH" in report
        assert new_id in report
        assert any_unverified is False  # a checked-and-wrong signature, not "couldn't check"

        rc = svb.main([str(bundle)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "OVERALL: FAIL" in out
        assert "OVERALL: PASS" not in out

    def test_adv2_fabricated_capsule_no_signature_rejected(self, tmp_path, capsys):
        from agent_action_capsule.emit import emit

        bundle = tmp_path / "bundle"
        bundle.mkdir()
        capsule = emit(
            action_id="fabricated/1",
            action_type="fyi",
            operator="op",
            developer="dev",
            model_id="TOTALLY-FABRICATED-MODEL",
            provider="mesh-llm",
            domain="action",
            provenance="collector",
        )
        (bundle / "capsules.jsonl").write_text(json.dumps(capsule, sort_keys=True) + "\n")
        # Deliberately: no signed-statements/ directory at all.

        all_ok, any_unverified, lines = svb.verify_bundle(bundle, {})
        report = "\n".join(lines)
        assert all_ok is False, report
        assert "NO SIGNATURE" in report
        assert any_unverified is False  # a hard failure, not "couldn't check"

        rc = svb.main([str(bundle)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "OVERALL: FAIL" in out
        assert "OVERALL: PASS" not in out

    def test_honest_bundle_still_passes(self, tmp_path, capsys):
        # The fix must not break the honest path: a validly-signed statement
        # whose authenticated subject DOES match its record's capsule_id.
        bundle = tmp_path / "bundle"
        capsule, pub_pem = _make_signed_bundle(bundle)
        (bundle / "node-key.pub.pem").write_bytes(pub_pem)

        all_ok, any_unverified, lines = svb.verify_bundle(bundle, {})
        assert all_ok is True, "\n".join(lines)
        assert any_unverified is False

        rc = svb.main([str(bundle)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "OVERALL: PASS" in out


class TestCapsuleMeshViewADV1:
    def test_adv1_keyless_relay_tamper_rejected(self, tmp_path):
        root = tmp_path / "root"
        ledger_dir = root / "ledger"
        capsule, pub_pem = _make_signed_bundle(ledger_dir)
        keys = root / "keys"
        keys.mkdir(parents=True)
        (keys / "node-key.pub.pem").write_bytes(pub_pem)

        new_id = _relay_tamper_and_rename(ledger_dir, capsule)

        from capsule_emit.ledger import read_ledger

        records = read_ledger(ledger_dir / "capsules.jsonl")
        assert records[0]["capsule_id"] == new_id
        results = cmv.verify_results_for(records, ledger_dir=ledger_dir)

        assert results is not None
        assert results[0].ok is False
        assert any(f.code == "producer_signature_invalid" for f in results[0].findings)

    def test_honest_record_still_verifies_true(self, tmp_path):
        # The fix must not break the honest path here either.
        root = tmp_path / "root"
        ledger_dir = root / "ledger"
        capsule, pub_pem = _make_signed_bundle(ledger_dir)
        keys = root / "keys"
        keys.mkdir(parents=True)
        (keys / "node-key.pub.pem").write_bytes(pub_pem)

        from capsule_emit.ledger import read_ledger

        records = read_ledger(ledger_dir / "capsules.jsonl")
        results = cmv.verify_results_for(records, ledger_dir=ledger_dir)

        assert results is not None
        assert results[0].ok is True, results[0].findings

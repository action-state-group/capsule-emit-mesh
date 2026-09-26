#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""capsule_mesh_view's machine-view `verify` column over the two producer
signatures a sealed capsule carries.

A sealed capsule carries BOTH an inline producer-signature envelope
(`signature`/`key_id`, excluded from `capsule_id`) for peers AND a detached
`signed-statements/<capsule_id>.cose` Signed Statement for the anchor, both
made with the node's one signing key. These tests pin that invariant: each
signature verifies on its own, both name the same key, and a tampered
signature -- inline or detached -- flips verify to False (never silently
True).

MODULE-POLLUTION GUARD
    See tests/test_record_capsule_write_before_verify.py's docstring:
    sibling test files stub real `agent_action_capsule`/`model_identity`
    submodules into sys.modules at COLLECTION time. `_real_capsule_sidecar()`
    reloads the real modules immediately before use at EXECUTION time so
    this file always builds a genuine signed capsule regardless of
    collection order.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import capsule_mesh_view as cmv
from agent_action_capsule.verify import verify_store
from capsule_emit.signing import verify_capsule_signature
import capsule_sidecar as cs  # imported for real here so _POLLUTABLE_MODULES are registered before any stub-installing sibling file collects

# agent_action_capsule.canonical/contracts/emit/verify are bound for real by
# conftest.py's import-order guard before any test file collects -- they can
# never be the fake-module stand-ins a stubbing test file creates, so
# reloading them here bought nothing and cost identity: importlib.reload()
# rebuilds FloatInDigestError/UnsafeIntegerError as NEW class objects on
# every call, so any OTHER test's `pytest.raises(FloatInDigestError)` (bound
# at ITS OWN collection time, before this fixture ever runs) silently stops
# matching for the rest of the session. Only model_identity still needs
# healing here -- conftest.py deliberately leaves it stubbable (see its own
# docstring) for the tests that depend on the stub.
_POLLUTABLE_MODULES = [
    "model_identity",
]


def _real_capsule_sidecar():
    for name in _POLLUTABLE_MODULES:
        importlib.reload(sys.modules[name])
    importlib.reload(cs)
    return cs


def _build_recorded_capsule(tmp_path: Path):
    """A genuine sidecar-sealed capsule + ledger + detached .cose statement,
    the same shape capsule_sidecar.record_capsule() writes on the real
    serving path -- inline producer envelope included."""
    cs = _real_capsule_sidecar()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"model_id": "test-model", "source_model": {"sha256": "a" * 64}}))
    state = cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="0" * 64,
    )
    capsule = cs.build_capsule(
        state,
        client_nonce="n" * 32,
        client_nonce_source="sidecar_generated_fallback",
        request_json={"model": "test-model", "messages": []},
        request_digest="a" * 64,
        status="confirmed",
        response_digest="b" * 64,
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
    )
    signed_statement = cs.sign_capsule(state, capsule)
    cs.record_capsule(state, capsule, signed_statement)
    return state, capsule


class TestVerifyResultsForDetachedStatement:

    def test_sealed_capsule_carries_inline_envelope_excluded_from_capsule_id(self, tmp_path: Path) -> None:
        state, capsule = _build_recorded_capsule(tmp_path)
        assert "signature" in capsule and "key_id" in capsule
        statement_path = state.statements_dir / f"{capsule['capsule_id']}.cose"
        assert statement_path.exists()

        from ledger_store_backend import read_all_capsules

        records, _archived = read_all_capsules(state.ledger_dir)
        # The envelope is outside the content hash: the same capsule_id
        # verifies with the envelope attached and with it stripped.
        stripped = {k: v for k, v in records[0].items() if k not in ("signature", "key_id")}
        assert stripped["capsule_id"] == records[0]["capsule_id"]
        assert verify_store([stripped])[0].ok is True

        results = cmv.verify_results_for(records, ledger_dir=state.ledger_dir)
        assert results is not None
        assert results[0].ok is True, results[0].findings

    def test_detached_statement_still_verifies_on_its_own(self, tmp_path: Path) -> None:
        # With the inline envelope stripped, the viewer can only reach the
        # detached .cose -- it must verify by itself, and a byte-flipped
        # statement must not.
        state, capsule = _build_recorded_capsule(tmp_path)

        from ledger_store_backend import read_all_capsules

        records, _archived = read_all_capsules(state.ledger_dir)
        stripped = [{k: v for k, v in records[0].items() if k not in ("signature", "key_id")}]
        results = cmv.verify_results_for(stripped, ledger_dir=state.ledger_dir)
        assert results[0].ok is True, results[0].findings

        statement_path = state.statements_dir / f"{capsule['capsule_id']}.cose"
        raw = bytearray(statement_path.read_bytes())
        raw[-1] ^= 0xFF
        statement_path.write_bytes(bytes(raw))
        results = cmv.verify_results_for(stripped, ledger_dir=state.ledger_dir)
        assert results[0].ok is False
        assert any(f.code == "producer_signature_invalid" for f in results[0].findings)

    def test_inline_envelope_verifies_against_the_detached_statement_key(self, tmp_path: Path) -> None:
        state, capsule = _build_recorded_capsule(tmp_path)

        from cryptography.hazmat.primitives import serialization
        from ledger_store_backend import read_all_capsules

        issuer_pem = state.ledger_dir.parent / "keys" / "node-key.pub.pem"
        issuer_raw = serialization.load_pem_public_key(issuer_pem.read_bytes()).public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        assert capsule["key_id"] == issuer_raw.hex()

        records, _archived = read_all_capsules(state.ledger_dir)
        assert verify_capsule_signature(records[0]) is True
        # No ledger_dir: the inline envelope alone carries the verdict.
        results = cmv.verify_results_for(records)
        assert results[0].ok is True, results[0].findings

    def test_tampered_inline_signature_flips_verify_to_false(self, tmp_path: Path) -> None:
        # Mutant: a check that can only ever pass isn't a check. Flip the
        # last nibble of the inline COSE_Sign1 (inside the signature bytes);
        # the detached statement is still intact on disk, and must not
        # rescue it.
        state, _capsule = _build_recorded_capsule(tmp_path)

        from ledger_store_backend import read_all_capsules

        records, _archived = read_all_capsules(state.ledger_dir)
        sig = records[0]["signature"]
        records[0]["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        assert verify_capsule_signature(records[0]) is False

        results = cmv.verify_results_for(records, ledger_dir=state.ledger_dir)
        assert results[0].ok is False
        assert any(f.code == "producer_signature_invalid" for f in results[0].findings)

    def test_content_tamper_still_fails_even_with_a_valid_detached_statement(self, tmp_path: Path) -> None:
        # The detached-statement check must never override a genuine
        # content-hash/chain failure: signature-over-wrong-content is still
        # wrong content.
        state, capsule = _build_recorded_capsule(tmp_path)

        from ledger_store_backend import read_all_capsules

        records, _archived = read_all_capsules(state.ledger_dir)
        records[0]["capsule_id"] = "0" * 64  # no longer matches its own content

        results = cmv.verify_results_for(records, ledger_dir=state.ledger_dir)
        assert results[0].ok is False


class TestMachineViewRendersGreenForDetachedlySignedCapsules:

    def test_build_machine_view_row_is_witness_verified_true(self, tmp_path: Path) -> None:
        state, capsule = _build_recorded_capsule(tmp_path)

        from ledger_store_backend import read_all_capsules

        records, _archived = read_all_capsules(state.ledger_dir)
        verify_results = cmv.verify_results_for(records, ledger_dir=state.ledger_dir)
        rows = cmv.build_machine_view([(cmv.SOURCE_SIDECAR, records, verify_results)])

        assert len(rows) == 1
        assert rows[0]["capsule_id"] == capsule["capsule_id"]
        assert rows[0]["verify_ok"] is True

    def test_cli_view_renders_a_checkmark_for_a_real_signed_capsule(self, tmp_path: Path, capsys) -> None:
        state, capsule = _build_recorded_capsule(tmp_path)

        rc = cmv.main(["view", "--sidecar-log", str(state.ledger_path), "--no-logs"])
        out = capsys.readouterr().out

        assert rc == 0
        assert capsule["capsule_id"][:14] in out
        # its row carries a check mark, and no cross mark for this capsule.
        row_line = next(line for line in out.splitlines() if capsule["capsule_id"][:14] in line)
        assert "✓" in row_line
        assert "✗" not in row_line

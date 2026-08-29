#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-viewer-verify-detached-cose] regression: capsule_mesh_view's
machine-view `verify` column must check the DETACHED
`signed-statements/<capsule_id>.cose` Signed Statement, not just an inline
`signature`/`key_id` field neither the Rust plugin nor the Python sidecar
ever writes. Before the fix, every genuinely-signed mesh capsule reported
verify=✗ in the machine view (misleading -- honest fail-closed for the
wrong reason: the viewer never looked at the evidence that exists).

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its
mutant -- this file tampers a real .cose statement and confirms verify
flips to False, and confirms a missing statement also reports False (never
silently True).

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
import capsule_sidecar as cs  # imported for real here so _POLLUTABLE_MODULES are registered before any stub-installing sibling file collects

_POLLUTABLE_MODULES = [
    "agent_action_capsule.canonical",
    "agent_action_capsule.contracts",
    "agent_action_capsule.emit",
    "agent_action_capsule.verify",
    "model_identity",
]


def _real_capsule_sidecar():
    for name in _POLLUTABLE_MODULES:
        importlib.reload(sys.modules[name])
    importlib.reload(cs)
    return cs


def _build_recorded_capsule(tmp_path: Path):
    """A genuine sidecar-signed capsule + ledger + detached .cose statement,
    the same shape capsule_sidecar.record_capsule() writes on the real
    serving path -- no inline signature/key_id field."""
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

    def test_validly_signed_but_detached_capsule_verifies_true(self, tmp_path: Path) -> None:
        state, capsule = _build_recorded_capsule(tmp_path)
        assert "signature" not in capsule and "key_id" not in capsule, (
            "this repo's writers never embed an inline producer envelope -- "
            "if this assertion ever fails the fixture stopped exercising the "
            "detached-statement path this test targets"
        )

        from capsule_emit.ledger import read_ledger

        records = read_ledger(state.ledger_path)
        results = cmv.verify_results_for(records, ledger_dir=state.ledger_dir)

        assert results is not None
        assert results[0].ok is True, results[0].findings

    def test_missing_detached_statement_reports_false_not_silently_true(self, tmp_path: Path) -> None:
        state, capsule = _build_recorded_capsule(tmp_path)
        statement_path = state.statements_dir / f"{capsule['capsule_id']}.cose"
        statement_path.unlink()

        from capsule_emit.ledger import read_ledger

        records = read_ledger(state.ledger_path)
        results = cmv.verify_results_for(records, ledger_dir=state.ledger_dir)

        assert results[0].ok is False
        assert any(f.code == "producer_signature_invalid" for f in results[0].findings)

    def test_tampered_detached_statement_byte_flips_verify_to_false(self, tmp_path: Path) -> None:
        # QUEUE_PROTOCOL §7 mutant: a check that can only ever pass isn't a
        # check. Flip one byte inside the real .cose statement and confirm
        # the machine view goes red for it.
        state, capsule = _build_recorded_capsule(tmp_path)
        statement_path = state.statements_dir / f"{capsule['capsule_id']}.cose"
        raw = bytearray(statement_path.read_bytes())
        raw[-1] ^= 0xFF
        statement_path.write_bytes(bytes(raw))

        from capsule_emit.ledger import read_ledger

        records = read_ledger(state.ledger_path)
        results = cmv.verify_results_for(records, ledger_dir=state.ledger_dir)

        assert results[0].ok is False
        assert any(f.code == "producer_signature_invalid" for f in results[0].findings)

    def test_no_ledger_dir_falls_back_to_honest_false(self, tmp_path: Path) -> None:
        # A caller that never supplies ledger_dir has no way to find the
        # detached statement at all -- must stay fail-closed, not silently
        # treat "didn't look" as "passed".
        state, _capsule = _build_recorded_capsule(tmp_path)

        from capsule_emit.ledger import read_ledger

        records = read_ledger(state.ledger_path)
        results = cmv.verify_results_for(records)

        assert results[0].ok is False

    def test_content_tamper_still_fails_even_with_a_valid_detached_statement(self, tmp_path: Path) -> None:
        # The detached-statement check must never override a genuine
        # content-hash/chain failure: signature-over-wrong-content is still
        # wrong content.
        state, capsule = _build_recorded_capsule(tmp_path)

        from capsule_emit.ledger import read_ledger

        records = read_ledger(state.ledger_path)
        records[0]["capsule_id"] = "0" * 64  # no longer matches its own content

        results = cmv.verify_results_for(records, ledger_dir=state.ledger_dir)
        assert results[0].ok is False


class TestMachineViewRendersGreenForDetachedlySignedCapsules:

    def test_build_machine_view_row_is_witness_verified_true(self, tmp_path: Path) -> None:
        state, capsule = _build_recorded_capsule(tmp_path)

        from capsule_emit.ledger import read_ledger

        records = read_ledger(state.ledger_path)
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

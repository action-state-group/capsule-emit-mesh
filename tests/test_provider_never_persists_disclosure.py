#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-provider-no-body-persistence] CI enforcement: the provider role must
have NO code path that can write a disclosure preimage to disk -- structural,
not a runtime setting someone could flip back on.

This file is the STATIC half of the guarantee (source-level: every call to
persist_disclosure_preimage() in the serving path is gated on
`state.role == ROLE_REQUESTER`, and the function itself refuses to run for
role="provider"). test_sidecar_disclosure_preimage.py's
TestProviderRoleHasNoDisclosureWritePath is the RUNTIME half (an actual
provider-role seal leaves disclosures/ absent). Both must hold: a static
check alone could miss a call reached only via an indirect/aliased path; a
runtime check alone would not fail loudly the moment a future edit reties the
call to the provider path -- this test does.
"""
from __future__ import annotations

from pathlib import Path

CAPSULE_SIDECAR_PATH = Path(__file__).parent.parent / "capsule_sidecar.py"


def _source_lines() -> list[str]:
    return CAPSULE_SIDECAR_PATH.read_text(encoding="utf-8").splitlines()


def test_every_persist_disclosure_preimage_call_site_is_role_gated() -> None:
    """Every call to persist_disclosure_preimage(state, ...) in
    capsule_sidecar.py (excluding its own `def` line) must be immediately
    preceded by an `if state.role == ROLE_REQUESTER:` guard -- the provider
    half of a shared seal path must never reach this call.
    """
    lines = _source_lines()
    call_sites = [
        i for i, line in enumerate(lines)
        if "persist_disclosure_preimage(state" in line and "def persist_disclosure_preimage" not in lines[i]
    ]
    assert call_sites, "expected at least one persist_disclosure_preimage(state, ...) call site"

    for i in call_sites:
        preceding = "\n".join(lines[max(0, i - 3): i])
        assert "state.role == ROLE_REQUESTER" in preceding, (
            f"capsule_sidecar.py:{i + 1} calls persist_disclosure_preimage() without a preceding "
            "'if state.role == ROLE_REQUESTER:' guard -- the provider seal path must never reach "
            "this call (mesh-provider-no-body-persistence)"
        )


def test_persist_disclosure_preimage_body_refuses_non_requester_role() -> None:
    """Defense in depth: the function body itself must refuse to run for any
    role other than requester, so a caller mistake can't silently write."""
    source = CAPSULE_SIDECAR_PATH.read_text(encoding="utf-8")
    def_index = source.index("def persist_disclosure_preimage(")
    next_def_index = source.index("\ndef ", def_index + 1)
    body = source[def_index:next_def_index]
    assert "if state.role != ROLE_REQUESTER:" in body
    assert "raise RuntimeError" in body


def test_disclose_preimage_field_defaults_off() -> None:
    """Disclosure is opt-in, not opt-out -- the finding's audit was that
    disclose_preimage defaulted to True. Regression guard on the default."""
    source = CAPSULE_SIDECAR_PATH.read_text(encoding="utf-8")
    assert "disclose_preimage: bool = False" in source
    assert "disclose_preimage: bool = True" not in source


def test_cli_rejects_disclose_combined_with_provider_role() -> None:
    """--disclose + --role provider must error at the CLI layer, not just at
    construction time -- an immediate, actionable message for the operator."""
    source = CAPSULE_SIDECAR_PATH.read_text(encoding="utf-8")
    assert 'if args.role == ROLE_PROVIDER and args.disclose_preimage:' in source
    assert "parser.error(" in source

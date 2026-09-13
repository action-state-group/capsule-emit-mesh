# SPDX-License-Identifier: Apache-2.0
"""Cross-implementation pane-JSON parity pin, `test_mesh_llm_digest_parity.py`-
style: mesh-llm-host-runtime's new native (plugin-ledger) pane builders
(`capsule_panes_native.rs`, [mesh-C3-ledger-tab-reads-plugin-not-sidecar])
against this repo's own `accountability_pane_routes.build_pane_{a,b,c}_json`
reference, on the SAME fixture ledger directory.

Same discipline as the digest-parity test: this repo is the source of truth
for what the fields MEAN; mesh-llm's Rust suite (fork branch
`mesh-C3-ledger-tab-reads-plugin-not-sidecar`, off `acct-ui-rebuild`) pins the
identical values against the identical fixture (see
`crates/mesh-llm-host-runtime/src/api/routes/capsule_panes_native.rs`'s
`pane_a_matches_the_python_reference_on_a_plugin_shaped_fixture` /
`pane_b_matches_...`). If either side changes independently, re-run both and
update the frozen values together -- a silent divergence between them is
exactly the drift this test exists to surface.

Scope: this pins parity ONLY for the fields the Rust port's first cut
actually computes (see that file's module docs for the two tranches it
deliberately leaves `NOT_CHECKED`/absent/null: peer-fetch cells and the
cryptographic assurance map). It does not assert on those fields, and does
not assert on `text`/prose beyond the couple of fixed-format strings the
Rust port also reproduces.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import accountability_pane_routes as apr


class _StubNodeState:
    """Duck-typed stand-in for `capsule_sidecar.NodeState` -- the pane
    builders only ever read `.ledger_dir` / `.operator` / `.node_id` /
    `.checkpoint` off it (`accountability_pane_routes.py`'s own `_log_id_for`
    and the three `build_pane_*_json` functions), so a real NodeState (which
    opens sockets/threads) is not needed to exercise them."""

    def __init__(self, ledger_dir: Path, node_id: str = "test-node") -> None:
        self.ledger_dir = ledger_dir
        self.operator = None
        self.node_id = node_id
        self.checkpoint = None


# The exact fixture records mesh-llm's Rust test suite writes
# (`capsule_panes_native.rs`'s `fixture_record` helper) -- byte-for-byte the
# same shape, so both sides are reading identical bytes, not two similar-
# looking fixtures that happen to agree by coincidence.
RECORD_1 = {
    "capsule_id": "cap-1",
    "timestamp": "2026-09-01T00:00:00Z",
    "operator": "capsule-emit-mesh-poc-demo",
    "effect": {"request_digest": "req-1", "response_digest": "resp"},
    "model_attestation": {"compute_attestation": {"runtime": "x"}},
}
RECORD_2 = {
    "capsule_id": "cap-2",
    "timestamp": "2026-09-02T00:00:00Z",
    "operator": "capsule-emit-mesh-poc-demo",
    "effect": {"request_digest": "req-2", "response_digest": "resp"},
    "model_attestation": {"compute_attestation": {"runtime": "x"}},
    "chain": {"parent_capsule_id": "cap-1", "relation": "confirms"},
}


@pytest.fixture
def one_record_ledger(tmp_path: Path) -> Path:
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir()
    with open(ledger_dir / "capsules.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps(RECORD_1) + "\n")
    return ledger_dir


@pytest.fixture
def two_record_ledger(tmp_path: Path) -> Path:
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir()
    with open(ledger_dir / "capsules.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps(RECORD_1) + "\n")
        f.write(json.dumps(RECORD_2) + "\n")
    return ledger_dir


def test_pane_a_matches_the_rust_native_ports_frozen_fields(
    one_record_ledger: Path,
) -> None:
    """Pins the exact fields `capsule_panes_native::build_pane_a`'s
    `pane_a_matches_the_python_reference_on_a_plugin_shaped_fixture` test
    also pins, from the Python reference side."""
    payload = apr.build_pane_a_json(_StubNodeState(one_record_ledger))
    assert payload["witness_checkpoint_supplied"] is False
    assert payload["operator"] == "capsule-emit-mesh-poc-demo"
    row = payload["rows"][0]
    assert row["capsule_id"] == "cap-1"
    assert row["verify_ok"] is None
    # `friendly_model_name`'s unconditional last-resort fallback -- true
    # until the serving-provenance protocol PR lands on a plugin-written
    # record (capsule_mesh_viewer.py:365).
    assert row["model_claimed"] == "local model"
    assert row["hardware_claimed"] is None
    rungs = row["rungs"]
    assert rungs["freshness"]["state"] == "absent"
    assert rungs["cross_party"]["rung"] == "unilateral_fallback"
    assert rungs["runtime_binding"]["state"] == "absent"
    assert rungs["tee_citation"]["state"] == "absent"
    assert rungs["hardware_inventory"]["state"] == "absent"
    # `verify_ok is None` reads as "present, not yet independently
    # verified" -- never a fabricated PASS/FAIL.
    assert rungs["log_integrity"]["state"] == "present-unverified"


def test_pane_b_matches_the_rust_native_ports_frozen_fields(
    two_record_ledger: Path,
) -> None:
    payload = apr.build_pane_b_json(_StubNodeState(two_record_ledger))
    assert payload["peer_count"] == 1
    row = payload["rows"][0]
    assert row["exchange_count"] == 2
    assert row["first_seen"] == "2026-09-01T00:00:00Z"
    assert row["last_seen"] == "2026-09-02T00:00:00Z"
    assert row["node"]["state"] == "absent"
    assert row["node"]["text"] == (
        "no counterparty evidence for these 2 exchange(s) -- unattributed, "
        "not one identified peer"
    )
    assert row["rung"]["state"] == "unilateral"
    assert row["rung"]["rung"] == "unilateral_fallback"
    assert row["rung"]["distinct_rungs"] == ["unilateral_fallback"]
    assert row["role"]["state"] == "present"
    # Every record defaults to `label_role == "served"` for a plugin-
    # written record (capsule_mesh_view.py's `_DEFAULT_ROLE_BY_SOURCE`), so
    # from THIS node's perspective the direction is "they asked, we served".
    assert row["role"]["role"] == "them_to_you"
    assert row["role"]["them_to_you_count"] == 2
    assert row["role"]["you_to_them_count"] == 0
    assert row["pair"]["state"] == "absent"
    assert row["pair"]["missing"] == 0
    assert row["asked"]["state"] == "absent"
    assert row["asked"]["count"] == 0
    # Peer-fetch tranche -- deferred on BOTH sides (this repo's own
    # accountability_pane_routes.py docstring: "peer tranche is E9/E10,
    # deferred pending Steven's Q4 ruling"), never asserted for parity.
    assert row["history"]["state"] == "NOT_CHECKED"
    assert row["served"]["state"] == "NOT_CHECKED"
    assert row["verdicts"]["state"] == "NOT_CHECKED"


def test_pane_c_header_state_and_properties_are_the_one_documented_non_parity_gap(
    two_record_ledger: Path,
) -> None:
    """The Rust port's pane-c rows intentionally do NOT match Python here --
    `header_state`/`properties` need the cryptographic assurance map
    (content_binding/producer_signature/continuity), which this cut has not
    ported (capsule_panes_native.rs module docs, gap 2). This test pins that
    the REAL Python reference does NOT sit at the Rust port's placeholder
    values, so a future accidental "parity" claim on this field would be
    caught here first, before it reached the outbox."""
    payload = apr.build_pane_c_json(_StubNodeState(two_record_ledger))
    row = payload["rows"][0]
    # Real Python computes an actual header_state / properties map even
    # with no checkpoint -- content_binding/producer_signature/continuity
    # are all computable offline. The Rust port renders "absent"/None for
    # both instead (its one deliberate, documented gap).
    assert row["header_state"] != "absent"
    assert row["properties"] is not None
    # But the structural fields around it (what this cut DOES claim parity
    # on) still agree:
    assert row["exchange_key"] == "digest:req-2"
    assert row["role_tag"] == "SERVED"
    assert row["unilateral"] is True
    assert row["theirs"]["state"] == "absent"
    assert row["mine"]["state"] == "present-unverified"
    assert row["mine"]["capsule_id"] == "cap-2"

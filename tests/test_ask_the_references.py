# SPDX-License-Identifier: Apache-2.0
"""Tests for ``ask_history.py references <X>`` -- [mesh-ask-the-references],
discovery mechanism 1: how a stranger finds a verdict about node X that X
itself won't hold, with no new trusted party.

Rehearsal step 7 shape: GCP served M4 (an ordinary exchange, recorded on
GCP's own chain); M4 adjudicated GCP `contradicted:gcp`; GCP refused to
hold that verdict on its own chain (`policy_decline`); M4 sealed the
refusal as its own record instead. Stranger M3 discovers "m4" as one of
GCP's own counterparties from GCP's own (honest) exchange record, samples
it, asks M4's door `correlation{by: counterparty, value: gcp}`, and gets
back BOTH the verdict and the held refusal -- neither of which GCP's own
chain carries.

Uses a REAL, hermetic (loopback-only) stub Transparency Service --
``tests/_stub_receipt.py`` (copied verbatim from ``capsule-emit``'s own
test suite, same shared-helper shape ``test_bundle.py`` uses there) mints a
genuinely COSE-verifiable receipt, so checkpoints grade WITNESSED and
``verify_bundle`` actually returns ``ok=True`` -- ``CAPSULE_WITNESS=stub``
(the env-var short-circuit other tests in this repo use) deliberately mints
a garbled, non-CBOR receipt (proving the STUB MECHANICS work, never that a
third party saw anything), which makes ``verify_bundle`` correctly report
``ok=False`` on EVERY stub-witnessed checkpoint -- the wrong fixture for a
test that needs `run_references`'s own "never trust an unverified bundle"
gate to see real passing content.
"""
from __future__ import annotations

import http.server
import json
import sys
import threading
import types

_stubbed_model_identity = "model_identity" not in sys.modules
if _stubbed_model_identity:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest
from _stub_receipt import (
    TEST_TS_PUBLIC_KEY_PEM,
    build_stub_receipt_b64,
    checkpoint_dict_from_cose,
    checkpoint_entry_hash,
)
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from capsule_emit import seal, witness
from capsule_emit.checkpoint import emit as checkpoint_emit_mod

import ask_history as ah
import capsule_sidecar as cs
import evidence_server as es
from adjudication_delivery import seal_adjudication_ack_refused
from twin_adjudicator import (
    AdjudicationHalf,
    RefereeIdentity,
    RefereeResult,
    adjudicate,
    contradicted,
    seal_adjudication_capsule,
)

REQUEST_DIGEST = "a" * 64


@pytest.fixture(autouse=True)
def _clean_witness_state():
    witness._counts.clear()
    witness._armed_at.clear()
    witness._states.clear()
    witness._dispatch_locks.clear()
    witness._notice_printed = False
    yield
    witness._counts.clear()
    witness._armed_at.clear()
    witness._states.clear()
    witness._dispatch_locks.clear()
    witness._notice_printed = False


class _StubWitnessTSHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        if self.path != "/checkpoints":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        body = checkpoint_dict_from_cose(raw)
        entry_hash = checkpoint_entry_hash(body)
        resp = {
            "entry_hash": entry_hash,
            "receipt_b64": build_stub_receipt_b64(entry_hash),
            "leaf_index": 0,
            "tree_size": 1,
        }
        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def stub_witness(monkeypatch):
    """A REAL (loopback-only) stub Transparency Service pinned as the
    process's default witness -- checkpoints built under this fixture grade
    WITNESSED and pass `verify_bundle` in full, same as the acceptance
    scenario's real mesh nodes would against a real witness."""
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _StubWitnessTSHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    monkeypatch.delenv("CAPSULE_WITNESS", raising=False)
    monkeypatch.setattr(checkpoint_emit_mod, "DEFAULT_TS_URL", base_url)
    monkeypatch.setattr(checkpoint_emit_mod, "DEFAULT_TS_PUBLIC_KEY_PEM", TEST_TS_PUBLIC_KEY_PEM)
    yield base_url
    srv.shutdown()
    thread.join(timeout=5)


def _node_state(tmp_path, name: str):
    manifest_path = tmp_path / f"{name}-manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    checkpoint_config_path = tmp_path / f"{name}-checkpoint.toml"
    checkpoint_config_path.write_text(f'[checkpoint]\nlog_id = "{name}"\ncadence_entries = 1\n')
    return cs.default_state(
        ledger_dir=tmp_path / f"{name}-ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / f"{name}-keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
        checkpoint_config_path=checkpoint_config_path,
    )


def _seal_exchange(state, *, requesting_party: str, served_by_node_id: str, seq: int, prev_seq: int | None) -> str:
    """Seal one of GCP's own exchange records naming its counterparty --
    the honest, own-chain record ``discover_counterparties`` reads and
    ``verify_pair_continuity`` walks. Minted via capsule_emit's own
    ``seal()`` (a convenient, already-verified builder) into a scratch
    ledger it owns exclusively, then landed in the sidecar's REAL
    cll.ledger.store.LedgerStore -- ``state.log_source`` -- same pattern as
    [mesh-ledger-store-migration]'s test_evidence_responder.py."""
    import tempfile

    scratch_ledger = tempfile.mktemp(suffix="-capsule-emit-seal-scratch.jsonl")
    capsule = seal(
        None,
        action="served_half",
        operator="acme",
        anchor=False,
        ledger=scratch_ledger,
        signing_key_path=state.signing_key_path,
        extra_compute={
            "x-mesh-poc-v1": {
                "serving_provenance": {
                    "exchange_id": f"exch-seq-{seq}",
                    "role": "provider",
                    "requesting_party": requesting_party,
                    "served_by_node_id": served_by_node_id,
                    "seq": seq,
                    "prev_seq": prev_seq,
                }
            }
        },
    ).capsule
    state.log_source.append(capsule)
    return capsule["capsule_id"]


def _make_served_half(text: str, *, owner_id: str) -> tuple[dict, dict]:
    body = {"choices": [{"message": {"role": "assistant", "content": text}}]}
    from capsule_sidecar import digest_json

    digest = digest_json(body)
    effect = EffectRecord(status="confirmed", type="inference_completion", request_digest=REQUEST_DIGEST, response_digest=digest)
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed")
    capsule = emit(
        action_type="decide",
        operator="test-org",
        developer="mesh-node@v1",
        compute_attestation={"owner": {"owner_id": owner_id}},
        effect=effect,
        disposition=disposition,
        tool_name="serve_exchange",
    )
    disclosed = {"capsule_id": capsule["capsule_id"], "response_body": body, "response_text": text}
    return capsule, disclosed


def _seed(state, capsule: dict) -> None:
    """Land an already-built capsule dict in ``state``'s REAL
    cll.ledger.store.LedgerStore -- ``state.log_source``."""
    state.log_source.append(capsule)


def _build_gcp_caught_by_m4(tmp_path, *, prune_seq_1: bool = False):
    """Build GCP's ledger (an ordinary served exchange with M4, seq=1 then
    seq=2 -- or just seq=2 when *prune_seq_1*, simulating GCP dropping the
    earlier record) and M4's ledger (the adjudication `contradicted:gcp`
    plus the ack-refused record GCP declined to hold). Returns
    ``(gcp_state, m4_state, gcp_cids)``.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    gcp_state = _node_state(tmp_path, "gcp")
    m4_state = _node_state(tmp_path, "m4")

    cap_b, _disc_b = _make_served_half("goodbye world", owner_id="gcp")
    _seed(gcp_state, cap_b)

    gcp_cids = [cap_b["capsule_id"]]
    if not prune_seq_1:
        gcp_cids.append(
            _seal_exchange(gcp_state, requesting_party="m4", served_by_node_id="gcp", seq=1, prev_seq=None)
        )
    # seq=2/prev_seq=1 either way -- when pruned, this is the ONLY record
    # for the pair, still self-consistently claiming a seq=1 predecessor
    # that never landed in this ledger (the dropped-prefix gap).
    gcp_cids.append(
        _seal_exchange(gcp_state, requesting_party="m4", served_by_node_id="gcp", seq=2, prev_seq=1)
    )
    assert gcp_state.checkpoint.reconnect() is not None

    cap_a, _disc_a = _make_served_half("hello world", owner_id="m4")
    half_a = AdjudicationHalf.from_capsule_and_disclosure(cap_a, _disc_a)
    half_b = AdjudicationHalf.from_capsule_and_disclosure(cap_b, _disc_b)
    # [mesh-referee-attribution] Use an attributed referee so the sealed
    # adjudication capsule carries referee_id -- ack_refusals are only
    # counted when the referenced adjudication is attributed.
    outcome = adjudicate(
        half_a,
        half_b,
        referee=lambda a, b, c: RefereeResult(
            verdict=contradicted("gcp"),
            margin=c.margin,
            identity=RefereeIdentity(referee_id="m4-referee-node"),
        ),
    )
    adjudication = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")

    gcp_door_state = es.EvidenceServerState(
        ledger_dir=gcp_state.ledger_dir, ledger_path=gcp_state.ledger_path, signing_key_path=gcp_state.signing_key_path
    )
    from adjudication_delivery import handle_delivery

    refusal_dict = handle_delivery(gcp_door_state, json.dumps(adjudication).encode("utf-8"))
    assert refusal_dict["reason"] == "policy_decline"

    ack_refused = seal_adjudication_ack_refused(adjudication, refusal_dict, operator="test-org", developer="referee@v1")

    _seed(m4_state, adjudication)
    _seed(m4_state, ack_refused)
    assert m4_state.checkpoint.reconnect() is not None

    return gcp_state, m4_state, gcp_cids


def _run_server(state) -> tuple:
    server_state = es.EvidenceServerState(
        ledger_dir=state.ledger_dir, ledger_path=state.ledger_path, signing_key_path=state.signing_key_path
    )
    server = es.run_evidence_server(host="127.0.0.1", port=0, state=server_state)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Pure-function unit tests
# ---------------------------------------------------------------------------


def test_sample_reference_candidates_is_deterministic_and_capped():
    candidates = ["m4", "gcp-2", "aws", "azure"]
    a = ah.sample_reference_candidates(candidates, subject_node_id="gcp", k=2)
    b = ah.sample_reference_candidates(list(reversed(candidates)), subject_node_id="gcp", k=2)
    assert a == b
    assert len(a) == 2
    assert set(a) <= set(candidates)


def test_sample_reference_candidates_depends_only_on_subject_not_asker():
    candidates = ["m4", "aws"]
    as_asker_one = ah.sample_reference_candidates(candidates, subject_node_id="gcp", k=5)
    as_asker_two = ah.sample_reference_candidates(candidates, subject_node_id="gcp", k=5)
    assert as_asker_one == as_asker_two
    different_subject = ah.sample_reference_candidates(candidates, subject_node_id="aws", k=5)
    # Not required to differ, but the seed is provably subject-only: same
    # subject, same result, regardless of anything about who is calling.
    assert isinstance(different_subject, list)


def test_discover_counterparties_reads_nested_and_top_level_fields():
    receipts = [
        {"x-mesh-poc-v1": {"serving_provenance": {"served_by_node_id": "gcp", "requesting_party": "m4"}}},
        {"counterparty_ref": "aws"},
        {"x-mesh-poc-v1": {"serving_provenance": {"served_by_node_id": "gcp", "requesting_party": "unknown"}}},
        {"x-mesh-poc-v1": {"serving_provenance": {"served_by_node_id": "gcp", "requesting_party": "gcp"}}},
    ]

    class _FakeBundle:
        def __init__(self, receipt):
            self.receipt = receipt

    bundles = [_FakeBundle(r) for r in receipts]
    found = ah.discover_counterparties(bundles, exclude_node_id="gcp")
    assert found == ["aws", "m4"]


def test_classify_receipt_only_attributes_owner_naming_verdicts_to_x():
    tally = {"corroborated": 0, "contradicted": 0, "inconclusive": 0, "ack_refusals": 0}
    ah._classify_receipt_for_x(
        {"model_attestation": {"compute_attestation": {"adjudication": {"verdict": "contradicted:gcp"}}}},
        "gcp",
        tally,
    )
    ah._classify_receipt_for_x(
        {"model_attestation": {"compute_attestation": {"adjudication": {"verdict": "contradicted:aws"}}}},
        "gcp",
        tally,
    )
    # [mesh-referee-attribution] ack_refusals are only counted when the
    # adjudication_ack_refused block carries a non-empty referee_id --
    # i.e. the verdict originated from an identified referee.
    ah._classify_receipt_for_x(
        {"model_attestation": {"compute_attestation": {"adjudication_ack_refused": {"verdict": "contradicted:gcp", "referee_id": "node-xyz"}}}},
        "gcp",
        tally,
    )
    assert tally == {"corroborated": 0, "contradicted": 1, "inconclusive": 0, "ack_refusals": 1}


# ---------------------------------------------------------------------------
# End to end -- rehearsal step 7 acceptance
# ---------------------------------------------------------------------------


class TestReferencesEndToEnd:
    def test_stranger_gets_m4s_verdict_and_held_refusal_about_gcp(self, tmp_path, stub_witness):
        gcp_state, m4_state, gcp_cids = _build_gcp_caught_by_m4(tmp_path)

        gcp_server, gcp_thread, gcp_url = _run_server(gcp_state)
        m4_server, m4_thread, m4_url = _run_server(m4_state)
        try:
            result = ah.run_references(
                gcp_url,
                x_node_id="gcp",
                x_selector=f"{gcp_cids[0]}..{gcp_cids[-1]}",
                peer_map={"m4": m4_url},
                k=3,
            )
        finally:
            gcp_server.shutdown()
            m4_server.shutdown()
            gcp_thread.join(timeout=5)
            m4_thread.join(timeout=5)

        assert result.candidates_discovered == 1
        assert result.references_asked == 1
        assert result.references_answered == 1
        assert result.unreachable_references == []
        assert result.adjudications_about_x == {"corroborated": 0, "contradicted": 1, "inconclusive": 0}
        assert result.ack_refusals_about_x == 1

        pair = result.continuity["gcp::m4"]
        assert pair["continuity"] == "unbroken"
        assert pair["gaps_detected"] == 0

        assert result.history_card is not None
        published = result.history_card.to_value()
        assert published["references"]["asked"] == 1
        assert published["references"]["answered"] == 1
        assert published["references"]["adjudications_about_x"]["contradicted"] == 1
        assert published["references"]["ack_refusals_about_x"] == 1
        rendered = ah.render_references_result(result)
        assert "REFERENCES x=gcp" in rendered
        assert "ack_refusals_about_x=1" in rendered

    def test_gcp_never_holds_the_verdict_itself(self, tmp_path, stub_witness):
        """The point of the whole mechanism: GCP's OWN chain never carries
        the contradicted verdict or the ack-refused record -- only M4's
        does. If this ever stopped being true the `references` ask would
        be finding nothing new."""
        from ledger_store_backend import read_all_capsules

        gcp_state, _m4_state, _cids = _build_gcp_caught_by_m4(tmp_path)
        gcp_entries, _archived = read_all_capsules(gcp_state.ledger_dir)
        for entry in gcp_entries:
            block = (entry.get("model_attestation") or {}).get("compute_attestation") or {}
            assert "adjudication" not in block
            assert "adjudication_ack_refused" not in block

    def test_unreachable_reference_is_counted_not_raised(self, tmp_path, stub_witness):
        gcp_state, _m4_state, gcp_cids = _build_gcp_caught_by_m4(tmp_path)
        gcp_server, gcp_thread, gcp_url = _run_server(gcp_state)
        try:
            result = ah.run_references(
                gcp_url,
                x_node_id="gcp",
                x_selector=f"{gcp_cids[0]}..{gcp_cids[-1]}",
                peer_map={},  # m4's address deliberately not supplied
                k=3,
            )
        finally:
            gcp_server.shutdown()
            gcp_thread.join(timeout=5)

        assert result.references_asked == 1
        assert result.references_answered == 0
        assert result.unreachable_references == ["m4"]
        assert result.adjudications_about_x == {"corroborated": 0, "contradicted": 0, "inconclusive": 0}

    def test_x_refuses_its_own_pull_raises(self, tmp_path, stub_witness):
        gcp_state = _node_state(tmp_path, "gcp")
        # Never sealed/checkpointed -- the door has nothing to answer with.
        gcp_server_state = es.EvidenceServerState(
            ledger_dir=gcp_state.ledger_dir, ledger_path=gcp_state.ledger_path, signing_key_path=gcp_state.signing_key_path
        )
        server = es.run_evidence_server(host="127.0.0.1", port=0, state=gcp_server_state)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with pytest.raises(RuntimeError):
                ah.run_references(
                    f"http://127.0.0.1:{port}",
                    x_node_id="gcp",
                    x_selector="aa..bb",
                    peer_map={},
                    k=3,
                )
        finally:
            server.shutdown()
            thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Mutant: GCP prunes the M4 exchange from ITS OWN chain
# ---------------------------------------------------------------------------


class TestPruneMutant:
    def test_pruned_prefix_is_a_visible_gap_even_though_continuity_stays_unbroken(self, tmp_path, stub_witness):
        """The acceptance mutant: GCP drops the seq=1 exchange record with
        M4 from its own ledger before checkpointing. `continuity` alone
        reads "unbroken" either way (a dropped PREFIX is self-consistent,
        never a regression) -- `gaps_detected` is the field that actually
        surfaces the prune. A check that only looked at `continuity` would
        never catch this; this test fails if that ever regresses."""
        baseline_gcp, _m4, baseline_cids = _build_gcp_caught_by_m4(tmp_path / "baseline", prune_seq_1=False)
        pruned_gcp, _m4b, pruned_cids = _build_gcp_caught_by_m4(tmp_path / "pruned", prune_seq_1=True)

        baseline_server, baseline_thread, baseline_url = _run_server(baseline_gcp)
        pruned_server, pruned_thread, pruned_url = _run_server(pruned_gcp)
        try:
            baseline_result = ah.run_references(
                baseline_url,
                x_node_id="gcp",
                x_selector=f"{baseline_cids[0]}..{baseline_cids[-1]}",
                peer_map={},
                k=0,
            )
            pruned_result = ah.run_references(
                pruned_url,
                x_node_id="gcp",
                x_selector=f"{pruned_cids[0]}..{pruned_cids[-1]}",
                peer_map={},
                k=0,
            )
        finally:
            baseline_server.shutdown()
            pruned_server.shutdown()
            baseline_thread.join(timeout=5)
            pruned_thread.join(timeout=5)

        baseline_pair = baseline_result.continuity["gcp::m4"]
        pruned_pair = pruned_result.continuity["gcp::m4"]

        assert baseline_pair["continuity"] == "unbroken"
        assert baseline_pair["gaps_detected"] == 0

        # The mutant: continuity alone is indistinguishable from the honest
        # case (still "unbroken") -- gaps_detected is what actually moves.
        assert pruned_pair["continuity"] == "unbroken"
        assert pruned_pair["gaps_detected"] == 1

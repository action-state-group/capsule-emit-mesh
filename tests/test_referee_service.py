# SPDX-License-Identifier: Apache-2.0
"""The referee-signed verdict: ``referee_service.py`` (the referee's door
answers an adjudicate request) and ``adjudication_hold.py`` (a judged node's
door holds a delivered verdict).

Every record here is really signed, by one of three node keys (twins A and
B, referee R), and each node's key is announced under its node id, as on a
live mesh.
"""
from __future__ import annotations

import json
import sys
import types

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.signing import LocalKeypairSigner, sign_producer_envelope, verify_capsule_signature

import evidence_server as es
from adjudication_hold import (
    REASON_HALVES_MISATTRIBUTED,
    REASON_NOT_ABOUT_THIS_NODE,
    REASON_VERDICT_ALREADY_HELD,
    REASON_VERDICT_UNVERIFIED,
    RECEIVED_ADJUDICATIONS_FILENAME,
    REQUESTED_ADJUDICATIONS_FILENAME,
)
from capsule_sidecar import digest_json
from peer_keys import ENV_PEER_KEYS
from record_push import handle_record_push
from referee_service import (
    ADJUDICATION_VERDICT_MARKER,
    ISSUED_ADJUDICATIONS_FILENAME,
    REASON_HALF_UNVERIFIED,
    REASON_REFEREE_NOT_INDEPENDENT,
    REASON_REFEREE_RECORD_NOT_FOUND,
    REASON_REFEREE_UNNAMED,
    REASON_TWINS_DIFFER_IN_REQUEST,
    handle_adjudicate_request,
)
from share_policy import SharePolicy

A, B, R = "a" * 64, "b" * 64, "c" * 64
WEIGHTS = "d" * 64
PROMPT = {"messages": [{"role": "user", "content": "List the first five counting numbers."}]}


def _body(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _served(
    signer: LocalKeypairSigner, node: str, text: str, *, request_digest: str = "e" * 64, weights: str | None = WEIGHTS
) -> dict:
    """A provider's own served record of *text*, signed with its key."""
    capsule = emit(
        action_type="decide",
        operator="",
        developer="",
        compute_attestation={
            "x-mesh-poc-v1": {
                "role": "served",
                "serving_provenance": {"served_by_node_id": node, "model": {"weights_digest": weights}},
            }
        },
        effect=EffectRecord(
            status="confirmed",
            type="inference_completion",
            request_digest=request_digest,
            response_digest=digest_json(_body(text)),
        ),
        disposition=Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed"),
        tool_name="serve_exchange",
    )
    capsule["signature"], capsule["key_id"] = sign_producer_envelope(signer, capsule["capsule_id"])
    return capsule


class Mesh:
    def __init__(self, tmp_path, monkeypatch, *, announce_referee: bool = True):
        self.key_paths = {n: tmp_path / "keys" / f"{n[:1]}.pem" for n in (A, B, R)}
        self.keys = {n: LocalKeypairSigner(p) for n, p in self.key_paths.items()}
        announced = {n: s.key_id for n, s in self.keys.items() if announce_referee or n != R}
        monkeypatch.setenv(ENV_PEER_KEYS, json.dumps(announced))
        self.dirs = {}
        for n in (A, B, R):
            d = tmp_path / f"node-{n[:1]}" / "ledger"
            d.mkdir(parents=True)
            self.dirs[n] = d

    def state(self, node: str, *, share_policy=None) -> es.EvidenceServerState:
        d = self.dirs[node]
        return es.EvidenceServerState(
            ledger_dir=d,
            ledger_path=d / "capsules.jsonl",
            signing_key_path=self.key_paths[node],
            share_policy=share_policy,
        )

    def own(self, node: str, record: dict) -> None:
        with (self.dirs[node] / "capsules.jsonl").open("a") as fh:
            fh.write(json.dumps(record) + "\n")

    def served(self, node: str, text: str, **kw) -> dict:
        return self.add(node, _served(self.keys[node], node, text, **kw))

    def add(self, node: str, record: dict) -> dict:
        self.own(node, record)
        return record


def _request(half_a, text_a, half_b, text_b, referee_text, *, bracket="bracket-1") -> bytes:
    return json.dumps(
        {
            "subject": {"kind": "adjudicate"},
            "twin_bracket_id": bracket,
            "halves": [
                {"capsule": half_a, "request_body": PROMPT, "response_body": _body(text_a)},
                {"capsule": half_b, "request_body": PROMPT, "response_body": _body(text_b)},
            ],
            "referee_answer": {"request_body": PROMPT, "response_body": _body(referee_text)},
        }
    ).encode()


HONEST, FLIPPED = "1, 2, 3, 4, 5", "1, 2, 3, 999 5"


@pytest.fixture
def mesh(tmp_path, monkeypatch):
    return Mesh(tmp_path, monkeypatch)


def _doctored(mesh):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.served(B, FLIPPED)
    referee_record = mesh.served(R, HONEST)
    return half_a, half_b, referee_record


def test_the_referee_signs_a_verdict_citing_its_own_record(mesh):
    half_a, half_b, referee_record = _doctored(mesh)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, HONEST))

    assert out[ADJUDICATION_VERDICT_MARKER] == 1
    assert out["verdict"] == f"contradicted:{B}"
    assert out["referee_node_id"] == R
    assert out["referee_capsule_id"] == referee_record["capsule_id"]
    assert out["halves"] == [half_a["capsule_id"], half_b["capsule_id"]]

    verdict = out["verdict_capsule"]
    assert verify_capsule(verdict).ok and verify_capsule_signature(verdict)
    assert verdict["key_id"] == mesh.keys[R].key_id, "signed by the referee, not the requester"
    block = verdict["model_attestation"]["compute_attestation"]["adjudication"]
    assert block["referee_node_id"] == R
    assert block["referee_capsule_id"] == referee_record["capsule_id"]
    assert (block["half_a_node_id"], block["half_b_node_id"]) == (A, B)
    assert block["twin_bracket_id"] == "bracket-1"
    assert block["referee_prompt"] == "requester_attested"

    lines = (mesh.dirs[R] / ISSUED_ADJUDICATIONS_FILENAME).read_text().splitlines()
    assert len(lines) == 1
    assert not any("adjudication" in l for l in (mesh.dirs[R] / "capsules.jsonl").read_text().splitlines()), \
        "the door never writes the plugin's chain"


def test_a_repeated_request_returns_the_verdict_already_issued(mesh):
    half_a, half_b, _ = _doctored(mesh)
    body = _request(half_a, HONEST, half_b, FLIPPED, HONEST)
    first = handle_adjudicate_request(mesh.state(R), body)
    again = handle_adjudicate_request(mesh.state(R), body)
    assert again["verdict_capsule_id"] == first["verdict_capsule_id"]
    assert len((mesh.dirs[R] / ISSUED_ADJUDICATIONS_FILENAME).read_text().splitlines()) == 1


def test_text_the_signature_does_not_cover_is_refused(mesh):
    half_a, half_b, _ = _doctored(mesh)
    # B's real record, with B's answer rewritten to agree with A.
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, HONEST.replace("5", "6"), HONEST))
    assert out["reason"] == REASON_HALF_UNVERIFIED


def test_a_half_signed_by_an_unannounced_key_is_refused(mesh, tmp_path):
    half_a, _, _ = _doctored(mesh)
    stranger = LocalKeypairSigner(tmp_path / "keys" / "stranger.pem")
    forged_b = _served(stranger, B, FLIPPED)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, forged_b, FLIPPED, HONEST))
    assert out["reason"] == REASON_HALF_UNVERIFIED


def test_an_answer_the_referee_never_served_is_refused(mesh):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.served(B, FLIPPED)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, HONEST))
    assert out["reason"] == REASON_REFEREE_RECORD_NOT_FOUND


@pytest.mark.parametrize(
    "signer, server",
    [(A, R), (R, A)],
    ids=["signed-by-another-key", "names-another-server"],
)
def test_the_referee_record_must_be_served_and_signed_by_the_referee(mesh, signer, server):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.served(B, FLIPPED)
    mesh.own(R, _served(mesh.keys[signer], server, HONEST))
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, HONEST))
    assert out["reason"] == REASON_REFEREE_RECORD_NOT_FOUND


def test_a_twin_cannot_referee_itself(mesh):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.served(B, FLIPPED)
    mesh.served(A, HONEST)
    out = handle_adjudicate_request(mesh.state(A), _request(half_a, HONEST, half_b, FLIPPED, HONEST))
    assert out["reason"] == REASON_REFEREE_NOT_INDEPENDENT


def test_twins_that_answered_different_requests_are_refused(mesh):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.served(B, FLIPPED, request_digest="f" * 64)
    mesh.served(R, HONEST)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, HONEST))
    assert out["reason"] == REASON_TWINS_DIFFER_IN_REQUEST


def test_a_referee_that_is_not_announced_signs_nothing(tmp_path, monkeypatch):
    mesh = Mesh(tmp_path, monkeypatch, announce_referee=False)
    half_a, half_b, _ = _doctored(mesh)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, HONEST))
    assert out["reason"] == REASON_REFEREE_UNNAMED


def test_a_malformed_request_is_refused_never_raises(mesh):
    for body in (b"not json", b"{}", json.dumps({"subject": {"kind": "adjudicate"}, "halves": []}).encode()):
        assert handle_adjudicate_request(mesh.state(R), body)["reason"] == "request_malformed"


# --- delivery to the judged nodes ---------------------------------------------


def _issued(mesh):
    half_a, half_b, _ = _doctored(mesh)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, HONEST))
    return out["verdict_capsule"], half_a, half_b


def _deliver(state, verdict, *, courier=R):
    """As the door calls it: the node's own policy beside the body."""
    body = json.dumps({"adjudication_delivery": 1, "verdict_capsule": verdict}).encode()
    return handle_record_push(state, body, policy=state.share_policy, sender_peer_id=courier)


def test_a_judged_node_holds_a_verdict_about_its_own_record(mesh):
    verdict, _, half_b = _issued(mesh)
    out = _deliver(mesh.state(B), verdict)
    assert out["status"] == "received"
    facts = out["adjudication"]
    assert facts["verdict"] == f"contradicted:{B}"
    assert facts["referee_node_id"] == R
    assert facts["held_half_capsule_id"] == half_b["capsule_id"]
    held = (mesh.dirs[B] / RECEIVED_ADJUDICATIONS_FILENAME).read_text().splitlines()
    assert len(held) == 1 and json.loads(held[0])["verdict_capsule"] == verdict

    again = _deliver(mesh.state(B), verdict)
    assert again == out
    assert len((mesh.dirs[B] / RECEIVED_ADJUDICATIONS_FILENAME).read_text().splitlines()) == 1


def test_a_verdict_not_signed_by_the_referee_it_names_is_refused(mesh):
    verdict, _, _ = _issued(mesh)
    # A re-signs R's verdict: the verdict still names R.
    forged = dict(verdict)
    forged["signature"], forged["key_id"] = sign_producer_envelope(mesh.keys[A], verdict["capsule_id"])
    assert _deliver(mesh.state(B), forged)["reason"] == REASON_VERDICT_UNVERIFIED


def test_an_altered_verdict_is_refused(mesh):
    verdict, _, _ = _issued(mesh)
    altered = json.loads(json.dumps(verdict))
    altered["model_attestation"]["compute_attestation"]["adjudication"]["verdict"] = f"contradicted:{A}"
    assert _deliver(mesh.state(B), altered)["reason"] == REASON_VERDICT_UNVERIFIED


def test_a_verdict_about_other_nodes_is_refused(mesh, tmp_path):
    verdict, _, _ = _issued(mesh)
    stranger = tmp_path / "node-x" / "ledger"
    stranger.mkdir(parents=True)
    state = es.EvidenceServerState(
        ledger_dir=stranger, ledger_path=stranger / "capsules.jsonl", signing_key_path=tmp_path / "keys" / "x.pem"
    )
    assert _deliver(state, verdict)["reason"] == REASON_NOT_ABOUT_THIS_NODE


def _requester(tmp_path, *halves, asked=None):
    """A requester node M: it holds the providers' pushed halves and records
    the adjudicate requests it sent (as its plugin does)."""
    d = tmp_path / "node-m" / "ledger"
    d.mkdir(parents=True, exist_ok=True)
    (d / "received-capsules.jsonl").write_text("".join(json.dumps(h) + "\n" for h in halves))
    if asked is not None:
        referee, pair = asked
        (d / REQUESTED_ADJUDICATIONS_FILENAME).write_text(
            json.dumps({"referee": referee, "halves": pair, "twin_bracket_id": "bracket-1"}) + "\n"
        )
    return es.EvidenceServerState(ledger_dir=d, ledger_path=d / "capsules.jsonl", signing_key_path=tmp_path / "keys" / "m.pem")


def _resign(verdict, signer, change):
    """A verdict with *change* applied to its adjudication block, re-sealed
    and genuinely signed by *signer*."""
    from capsule_emit.canonicalization import compute_capsule_id

    out = json.loads(json.dumps(verdict))
    change(out["model_attestation"]["compute_attestation"]["adjudication"])
    del out["signature"], out["key_id"]
    out["capsule_id"] = compute_capsule_id(out)
    out["signature"], out["key_id"] = sign_producer_envelope(signer, out["capsule_id"])
    return out


def test_the_requester_holds_a_verdict_it_asked_for_about_both_halves_it_holds(mesh, tmp_path):
    verdict, half_a, half_b = _issued(mesh)
    pair = [half_a["capsule_id"], half_b["capsule_id"]]
    state = _requester(tmp_path, half_a, half_b, asked=(R, pair))
    assert _deliver(state, verdict)["status"] == "received"


def test_a_forged_referee_nobody_asked_cannot_rule_on_the_requester(mesh, tmp_path, monkeypatch):
    """The EM's blocker: an announced peer X, not a twin, mints signed
    contradictions about records the requester holds. None is held."""
    verdict, half_a, half_b = _issued(mesh)
    x = LocalKeypairSigner(tmp_path / "keys" / "x.pem")
    X = "9" * 64
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({**{n: k.key_id for n, k in mesh.keys.items()}, X: x.key_id}))
    state = _requester(tmp_path, half_a, half_b, asked=(R, [half_a["capsule_id"], half_b["capsule_id"]]))
    for n in range(3):
        forged = _resign(verdict, x, lambda b, n=n: b.update(
            referee_node_id=X, half_b_capsule_id=f"{n}" * 64, verdict=f"contradicted:{B}"))
        assert _deliver(state, forged)["reason"] == REASON_NOT_ABOUT_THIS_NODE
    assert not (state.ledger_dir / RECEIVED_ADJUDICATIONS_FILENAME).exists()


def test_the_requester_needs_both_halves_it_asked_about(mesh, tmp_path):
    verdict, half_a, half_b = _issued(mesh)
    state = _requester(tmp_path, half_a, asked=(R, [half_a["capsule_id"], half_b["capsule_id"]]))
    assert _deliver(state, verdict)["reason"] == REASON_NOT_ABOUT_THIS_NODE


def test_a_verdict_pinning_one_nodes_record_on_another_is_refused(mesh, tmp_path):
    verdict, half_a, half_b = _issued(mesh)
    swapped = _resign(verdict, mesh.keys[R], lambda b: b.update(
        half_a_node_id=B, half_b_node_id=A, verdict=f"contradicted:{A}"))
    state = _requester(tmp_path, half_a, half_b, asked=(R, [half_a["capsule_id"], half_b["capsule_id"]]))
    assert _deliver(state, swapped)["reason"] == REASON_HALVES_MISATTRIBUTED
    assert _deliver(mesh.state(B), swapped)["reason"] == REASON_HALVES_MISATTRIBUTED


def test_one_verdict_per_referee_and_pair_on_the_requester(mesh, tmp_path):
    verdict, half_a, half_b = _issued(mesh)
    state = _requester(tmp_path, half_a, half_b, asked=(R, [half_a["capsule_id"], half_b["capsule_id"]]))
    assert _deliver(state, verdict)["status"] == "received"
    second = _resign(verdict, mesh.keys[R], lambda b: b.update(verdict="inconclusive"))
    assert _deliver(state, second)["reason"] == REASON_VERDICT_ALREADY_HELD
    assert _deliver(state, verdict)["status"] == "received", "the same verdict again is answered, not refused"
    assert len((state.ledger_dir / RECEIVED_ADJUDICATIONS_FILENAME).read_text().splitlines()) == 1


def test_one_verdict_per_referee_and_own_record_on_a_provider(mesh, tmp_path, monkeypatch):
    """A provider never asked; any announced referee may rule on its own
    record, but only once per record -- never a pile-up."""
    verdict, _, half_b = _issued(mesh)
    x = LocalKeypairSigner(tmp_path / "keys" / "x.pem")
    X = "9" * 64
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({**{n: k.key_id for n, k in mesh.keys.items()}, X: x.key_id}))
    first = _resign(verdict, x, lambda b: b.update(referee_node_id=X, half_a_capsule_id="1" * 64))
    again = _resign(verdict, x, lambda b: b.update(referee_node_id=X, half_a_capsule_id="2" * 64))
    assert _deliver(mesh.state(B), first)["status"] == "received"
    assert _deliver(mesh.state(B), again)["reason"] == REASON_VERDICT_ALREADY_HELD


def test_a_verdict_about_a_record_this_node_merely_holds_is_not_its_own(mesh):
    """A holds only its own record; a verdict about B's record and a made-up
    one does not concern A."""
    verdict, _, _ = _issued(mesh)
    other = _resign(verdict, mesh.keys[R], lambda b: b.update(half_a_capsule_id="7" * 64))
    assert _deliver(mesh.state(A), other)["reason"] == REASON_NOT_ABOUT_THIS_NODE


def test_delivery_follows_the_record_at_completion_switch(mesh):
    verdict, _, _ = _issued(mesh)
    state = mesh.state(B, share_policy=SharePolicy(record_at_completion="off"))
    assert _deliver(state, verdict)["reason"] == "policy_decline"
    assert not (mesh.dirs[B] / RECEIVED_ADJUDICATIONS_FILENAME).exists()


def test_sampled_twins_get_a_signed_not_comparable_ruling(mesh):
    half_a, half_b, _ = _doctored(mesh)
    body = json.loads(_request(half_a, HONEST, half_b, FLIPPED, HONEST))
    for half in body["halves"]:
        half["request_body"] = {**PROMPT, "temperature": 0.7}
    out = handle_adjudicate_request(mesh.state(R), json.dumps(body).encode())
    assert out["verdict"] == "not_comparable", "never contradicted"
    verdict = out["verdict_capsule"]
    assert verdict["model_attestation"]["compute_attestation"]["adjudication"]["not_comparable_because"] == "sampled"
    assert verify_capsule_signature(verdict) and verdict["key_id"] == mesh.keys[R].key_id
    assert out["referee_capsule_id"] is None, "no referee answer decided it"
    # It is deliverable like any other ruling.
    assert _deliver(mesh.state(B), verdict)["adjudication"]["verdict"] == "not_comparable"


def test_a_referee_answer_matching_neither_twin_is_a_signed_inconclusive(mesh):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.served(B, FLIPPED)
    other = "1, 2, 3, 7, 5"
    referee_record = mesh.served(R, other)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, other))
    assert out["verdict"] == "inconclusive"
    assert out["referee_capsule_id"] == referee_record["capsule_id"]
    assert verify_capsule_signature(out["verdict_capsule"])


def test_the_verdict_carries_the_divergence_and_the_referee_answer_digest(mesh):
    half_a, half_b, _ = _doctored(mesh)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, HONEST))
    block = out["verdict_capsule"]["model_attestation"]["compute_attestation"]["adjudication"]
    assert block["divergence_index"] == 3
    assert block["referee_answer_digest"] == digest_json(_body(HONEST))


def test_agreeing_twins_are_corroborated_without_a_referee_answer(mesh):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.served(B, HONEST)
    body = json.loads(_request(half_a, HONEST, half_b, HONEST, HONEST))
    del body["referee_answer"]
    out = handle_adjudicate_request(mesh.state(R), json.dumps(body).encode())
    assert out["verdict"] == "corroborated"
    block = out["verdict_capsule"]["model_attestation"]["compute_attestation"]["adjudication"]
    assert "referee_answer_digest" not in block


def test_diverging_twins_without_a_referee_answer_are_refused(mesh):
    half_a, half_b, _ = _doctored(mesh)
    body = json.loads(_request(half_a, HONEST, half_b, FLIPPED, HONEST))
    del body["referee_answer"]
    out = handle_adjudicate_request(mesh.state(R), json.dumps(body).encode())
    assert out["reason"] == REASON_REFEREE_RECORD_NOT_FOUND


def test_an_unsigned_verdict_is_refused(mesh):
    verdict, _, _ = _issued(mesh)
    unsigned = {k: v for k, v in verdict.items() if k not in ("signature", "key_id")}
    assert _deliver(mesh.state(B), unsigned)["reason"] == REASON_VERDICT_UNVERIFIED


def test_a_verdict_contradicting_a_peer_outside_the_bracket_is_refused(mesh):
    """Signed by the real referee key, but naming a node that was not a twin."""
    from capsule_emit.canonicalization import compute_capsule_id

    verdict, _, _ = _issued(mesh)
    outside = json.loads(json.dumps(verdict))
    outside["model_attestation"]["compute_attestation"]["adjudication"]["verdict"] = "contradicted:" + "e" * 64
    del outside["signature"], outside["key_id"]
    outside["capsule_id"] = compute_capsule_id(outside)
    outside["signature"], outside["key_id"] = sign_producer_envelope(mesh.keys[R], outside["capsule_id"])
    assert verify_capsule_signature(outside), "the signature itself is genuine"
    assert _deliver(mesh.state(B), outside)["reason"] == REASON_VERDICT_UNVERIFIED


@pytest.mark.parametrize("weights_b, because", [("f" * 64, "weights_differ"), (None, "weights_unknown")])
def test_twins_on_different_or_unknown_weights_are_not_comparable(mesh, weights_b, because):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.add(B, _served(mesh.keys[B], B, FLIPPED, weights=weights_b))
    mesh.served(R, HONEST)
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, FLIPPED, HONEST))
    assert out["verdict"] == "not_comparable", "never contradicted"
    block = out["verdict_capsule"]["model_attestation"]["compute_attestation"]["adjudication"]
    assert block["not_comparable_because"] == because
    assert out["referee_capsule_id"] is None


def test_a_forged_half_is_still_refused_when_weights_differ(mesh):
    half_a = mesh.served(A, HONEST)
    half_b = mesh.add(B, _served(mesh.keys[B], B, FLIPPED, weights="f" * 64))
    out = handle_adjudicate_request(mesh.state(R), _request(half_a, HONEST, half_b, HONEST.replace("5", "6"), HONEST))
    assert out["reason"] == REASON_HALF_UNVERIFIED


def test_a_requesters_own_requested_record_is_not_a_record_it_served(mesh, tmp_path, monkeypatch):
    """M's own ledger holds its requested record, which names A as the
    server. A verdict about it is not about M's own serving."""
    verdict, _, _ = _issued(mesh)
    m_key = LocalKeypairSigner(tmp_path / "keys" / "m.pem")
    M = "6" * 64
    monkeypatch.setenv(ENV_PEER_KEYS, json.dumps({**{n: k.key_id for n, k in mesh.keys.items()}, M: m_key.key_id}))
    state = _requester(tmp_path)
    requested = _served(m_key, A, HONEST)  # M's own record, naming A as the server
    (state.ledger_dir / "capsules.jsonl").write_text(json.dumps(requested) + "\n")
    about_it = _resign(verdict, mesh.keys[R], lambda b: b.update(half_a_capsule_id=requested["capsule_id"]))
    assert _deliver(state, about_it)["reason"] == REASON_NOT_ABOUT_THIS_NODE

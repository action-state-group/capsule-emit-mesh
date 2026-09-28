# SPDX-License-Identifier: Apache-2.0
"""The requester's side (``referee_request.py``), end to end offline: the
requester's post goes straight to a real referee door handler, and the
referee's model call is stubbed with the answer its ledger holds."""
from __future__ import annotations

import json

import pytest

import referee_request
from referee_service import handle_adjudicate_request
from test_referee_service import A, B, FLIPPED, HONEST, PROMPT, R, Mesh, _body
from twin_adjudicator import AdjudicationHalf


@pytest.fixture
def mesh(tmp_path, monkeypatch):
    return Mesh(tmp_path, monkeypatch)


def _half(capsule, text, owner, *, request_body=PROMPT):
    return AdjudicationHalf(
        capsule=capsule,
        disclosed={"request_body": request_body, "response_body": _body(text)},
        owner_id=owner,
    )


def _ask(mesh, half_a, half_b, monkeypatch, *, referee_text=HONEST):
    calls = []

    def fake_call(half, comparison, **kw):
        calls.append(kw["target_peer_id"])
        return json.dumps({"messages": half.request_body["messages"], "temperature": 0}).encode(), _body(referee_text)

    monkeypatch.setattr(referee_request, "call_referee", fake_call)
    out = referee_request.request_verdict(
        half_a,
        half_b,
        referee_peer_id=R,
        local_api_base_url="http://unused",
        local_host_api="http://unused",
        plugin_name="unused",
        model="m",
        nonce="n1",
        twin_bracket_id="bracket-9",
        post=lambda peer, req: handle_adjudicate_request(mesh.state(peer), json.dumps(req).encode()),
    )
    return out, calls


def test_diverging_twins_come_back_with_the_referees_signed_verdict(mesh, monkeypatch):
    a, b = mesh.served(A, HONEST), mesh.served(B, FLIPPED)
    mesh.served(R, HONEST)
    out, calls = _ask(mesh, _half(a, HONEST, A), _half(b, FLIPPED, B), monkeypatch)
    assert calls == [R]
    assert out["verdict"] == f"contradicted:{B}"
    assert out["verdict_capsule"]["key_id"] == mesh.keys[R].key_id
    assert out["twin_bracket_id"] == "bracket-9"


def test_agreeing_twins_never_call_the_referees_model(mesh, monkeypatch):
    a, b = mesh.served(A, HONEST), mesh.served(B, HONEST)
    out, calls = _ask(mesh, _half(a, HONEST, A), _half(b, HONEST, B), monkeypatch)
    assert calls == [] and out["verdict"] == "corroborated"


def test_sampled_twins_are_not_comparable_without_a_referee_answer(mesh, monkeypatch):
    sampled = {**PROMPT, "temperature": 0.9}
    a, b = mesh.served(A, HONEST), mesh.served(B, FLIPPED)
    out, calls = _ask(mesh, _half(a, HONEST, A, request_body=sampled), _half(b, FLIPPED, B, request_body=sampled), monkeypatch)
    assert calls == [] and out["verdict"] == "not_comparable"

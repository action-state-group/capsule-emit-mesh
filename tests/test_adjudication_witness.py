# SPDX-License-Identifier: Apache-2.0
"""Tests for `adjudication_witness.py` -- discovery mechanism 2
(mesh-adjudication-witness-registration).

Registration/query against the witness are tested against a monkeypatched
`urlopen` (the witness is a separate service, `capsule-anchor`, reached only
over HTTP -- not a dependency of this repo): these tests assert the exact
request shape (URL, JSON body, base64 statement) this module sends and the
response shape it parses, matching `capsule-anchor`'s
`POST /transparency/register-statement` / `GET /transparency/statements`
contract.

`recompute_adjudication_from_witness` is pure/offline and is tested against
real sealed capsules built the same way `test_twin_adjudicator.py` does.

Negative-check mandate (QUEUE_PROTOCOL §7): the acceptance mutant --
"a forged verdict citing a half X never signed -> recompute fails at the
citation, labeled citation_unverified" -- gets its own test.
"""
from __future__ import annotations

import base64
import json
from io import BytesIO
from urllib.error import URLError

import pytest
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from scitt_cose.statement import parse_signed_statement

import adjudication_witness as aw
from capsule_sidecar import digest_json
from twin_adjudicator import (
    VERDICT_CORROBORATED,
    AdjudicationHalf,
    adjudicate,
    seal_adjudication_capsule,
)

REQUEST_DIGEST = "a" * 64


def _ed25519_keypair_pem() -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.serialization import PublicFormat

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )
    public_pem = key.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


def _ed25519_pem() -> bytes:
    return _ed25519_keypair_pem()[0]


def _response_body(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _make_half(text: str, *, owner_id: str | None) -> AdjudicationHalf:
    """Same fixture-builder shape as test_twin_adjudicator.py's `_make_half`."""
    body = _response_body(text)
    digest = digest_json(body)
    effect = EffectRecord(
        status="confirmed",
        type="inference_completion",
        request_digest=REQUEST_DIGEST,
        response_digest=digest,
    )
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed")
    compute_attestation = {"owner": {"owner_id": owner_id}} if owner_id is not None else {}
    capsule = emit(
        action_type="decide",
        operator="test-org",
        developer="mesh-node@v1",
        compute_attestation=compute_attestation,
        effect=effect,
        disposition=disposition,
        tool_name="serve_exchange",
    )
    disclosed = {"capsule_id": capsule["capsule_id"], "response_body": body, "response_text": text}
    return AdjudicationHalf.from_capsule_and_disclosure(capsule, disclosed)


@pytest.fixture()
def corroborated_fixture():
    """Two distinct-owner halves with identical transcripts -> corroborated,
    plus the sealed adjudication capsule built from them."""
    half_a = _make_half("the quick brown fox", owner_id="owner-a")
    half_b = _make_half("the quick brown fox", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)
    assert outcome.verdict == VERDICT_CORROBORATED
    adjudication_capsule = seal_adjudication_capsule(outcome, operator="test-org", developer="referee@v1")
    assert adjudication_capsule is not None
    return half_a, half_b, outcome, adjudication_capsule


# ---------------------------------------------------------------------------
# subjects_for_adjudication
# ---------------------------------------------------------------------------


def test_subjects_are_both_owners_for_corroborated(corroborated_fixture):
    half_a, half_b, outcome, _ = corroborated_fixture
    subjects = aw.subjects_for_adjudication(outcome, half_a, half_b)
    assert set(subjects) == {"owner-a", "owner-b"}


def test_subjects_are_both_owners_for_contradicted():
    half_a = _make_half("alpha", owner_id="owner-a")
    half_b = _make_half("beta", owner_id="owner-b")

    def referee(a, b, comparison):
        from twin_adjudicator import RefereeIdentity, RefereeResult, contradicted

        return RefereeResult(verdict=contradicted("owner-b"), margin=comparison.margin, identity=RefereeIdentity(referee_id="test-referee-node"))

    outcome = adjudicate(half_a, half_b, logprob_tau=0.0, referee=referee)
    assert outcome.verdict == "contradicted:owner-b"
    subjects = aw.subjects_for_adjudication(outcome, half_a, half_b)
    # BOTH providers, not just the one named in the verdict string.
    assert set(subjects) == {"owner-a", "owner-b"}


def test_no_subjects_for_inconclusive():
    half_a = _make_half("alpha", owner_id="owner-a")
    half_b = _make_half("beta", owner_id="owner-b")
    outcome = adjudicate(half_a, half_b)
    assert outcome.no_verdict_reason is None
    from twin_adjudicator import VERDICT_INCONCLUSIVE

    assert outcome.verdict == VERDICT_INCONCLUSIVE
    assert aw.subjects_for_adjudication(outcome, half_a, half_b) == []


# ---------------------------------------------------------------------------
# register_adjudication_witness / query_witness_subject -- wire shape
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_register_sends_correct_statement_and_parses_receipt(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data)
        return _FakeResponse({"entry_hash": "deadbeef" * 8, "receipt_b64": "cmVjZWlwdA=="})

    monkeypatch.setattr(aw, "urlopen", fake_urlopen)

    capsule_id = "11" * 32
    private_pem, public_pem = _ed25519_keypair_pem()
    result = aw.register_adjudication_witness(
        capsule_id,
        "node-gcp-key",
        ts_url="https://witness.example.org/",
        private_key_pem=private_pem,
        issuer="urn:test:requester",
    )

    assert captured["url"] == "https://witness.example.org/transparency/register-statement"
    statement_bytes = base64.b64decode(captured["body"]["signed_statement_b64"])
    parsed = parse_signed_statement(statement_bytes, public_key_pem=public_pem)
    assert parsed["signature_verified"] is True
    assert parsed["subject"] == "node-gcp-key"
    assert parsed["payload"] == bytes.fromhex(capsule_id)

    assert result.subject == "node-gcp-key"
    assert result.capsule_id == capsule_id
    assert result.ts_url == "https://witness.example.org"
    assert result.entry_hash == "deadbeef" * 8
    assert result.receipt_b64 == "cmVjZWlwdA=="


def test_query_witness_subject_url_encodes_and_parses_entries(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _FakeResponse(
            {
                "subject": "node with spaces",
                "entries": [
                    {
                        "entry_hash": "aa" * 32,
                        "capsule_id_digest": "bb" * 32,
                        "receipt_b64": "cmVjZWlwdA==",
                        "leaf_index": 3,
                        "tree_size": 4,
                    }
                ],
            }
        )

    monkeypatch.setattr(aw, "urlopen", fake_urlopen)

    entries = aw.query_witness_subject("https://witness.example.org", "node with spaces")
    assert "subject=node%20with%20spaces" in captured["url"]
    assert len(entries) == 1
    assert entries[0].entry_hash == "aa" * 32
    assert entries[0].capsule_id == "bb" * 32
    assert entries[0].leaf_index == 3
    assert entries[0].tree_size == 4


def test_query_witness_subject_empty_entries_is_not_an_error(monkeypatch):
    monkeypatch.setattr(
        aw, "urlopen", lambda req, timeout=None: _FakeResponse({"subject": "nobody", "entries": []})
    )
    assert aw.query_witness_subject("https://witness.example.org", "nobody") == []


def test_register_adjudication_capsule_witness_is_best_effort(monkeypatch):
    """One witness unreachable must not block registration at the others,
    and must not raise -- matches checkpointing.py's witness discipline."""
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if "unreachable" in req.full_url:
            raise URLError("connection refused")
        return _FakeResponse({"entry_hash": "aa" * 32, "receipt_b64": "cmVjZWlwdA=="})

    monkeypatch.setattr(aw, "urlopen", fake_urlopen)
    errors = []
    results = aw.register_adjudication_capsule_witness(
        "11" * 32,
        ["owner-a", "owner-b"],
        ts_urls=["https://good.example.org", "https://unreachable.example.org"],
        private_key_pem=_ed25519_pem(),
        issuer="urn:test:requester",
        on_error=lambda subject, ts_url, exc: errors.append((subject, ts_url)),
    )
    assert len(results) == 2  # one success per subject, at the good witness
    assert all(r.ts_url == "https://good.example.org" for r in results)
    assert len(errors) == 2  # one failure per subject, at the unreachable witness


# ---------------------------------------------------------------------------
# recompute_adjudication_from_witness -- pure, offline
# ---------------------------------------------------------------------------


def test_recompute_succeeds_when_both_halves_verify(corroborated_fixture):
    half_a, half_b, outcome, adjudication_capsule = corroborated_fixture
    capsules_by_id = {
        half_a.capsule["capsule_id"]: half_a.capsule,
        half_b.capsule["capsule_id"]: half_b.capsule,
    }
    result = aw.recompute_adjudication_from_witness(adjudication_capsule, capsules_by_id.get)

    assert result.status == aw.RECOMPUTED
    assert result.twin_owner_distinct is True
    assert result.declared_twin_owner_distinct is True
    assert result.verdict_consistent is True


def test_recompute_citation_unverified_when_cited_half_never_found(corroborated_fixture):
    _half_a, half_b, _outcome, adjudication_capsule = corroborated_fixture
    # Only half_b is available -- half_a was never handed over by anyone.
    result = aw.recompute_adjudication_from_witness(
        adjudication_capsule, {half_b.capsule["capsule_id"]: half_b.capsule}.get
    )
    assert result.status == aw.CITATION_UNVERIFIED
    assert result.reason == "half_a_not_found"


def test_recompute_citation_unverified_for_forged_cited_half(corroborated_fixture):
    """The acceptance mutant: register a verdict citing a half X never
    signed -> recompute fails at the citation, labeled citation_unverified.
    Simulated here by a fetch_capsule that hands back a TAMPERED half under
    the cited capsule_id -- exactly what "X never signed this" looks like
    to a stranger who only has the citation and a delivered blob."""
    half_a, half_b, _outcome, adjudication_capsule = corroborated_fixture
    forged_half_b = dict(half_b.capsule)
    forged_half_b["model_attestation"] = {
        **forged_half_b.get("model_attestation", {}),
        "compute_attestation": {"owner": {"owner_id": "attacker-owned"}},
    }
    # Still claims the same capsule_id (so it passes the id-match check) but
    # now fails its own signature verification -- a forged half.
    capsules_by_id = {
        half_a.capsule["capsule_id"]: half_a.capsule,
        half_b.capsule["capsule_id"]: forged_half_b,
    }
    result = aw.recompute_adjudication_from_witness(adjudication_capsule, capsules_by_id.get)
    assert result.status == aw.CITATION_UNVERIFIED
    assert result.reason == "half_b_forged"


def test_recompute_citation_unverified_when_returned_capsule_id_mismatches(corroborated_fixture):
    half_a, half_b, _outcome, adjudication_capsule = corroborated_fixture
    # half_a resolves correctly; half_b's lookup hands back a real,
    # validly-signed capsule -- just NOT the one that was actually asked
    # for (a substitution attack).
    capsules_by_id = {
        half_a.capsule["capsule_id"]: half_a.capsule,
        half_b.capsule["capsule_id"]: half_a.capsule,
    }
    result = aw.recompute_adjudication_from_witness(adjudication_capsule, capsules_by_id.get)
    assert result.status == aw.CITATION_UNVERIFIED
    assert result.reason == "half_b_capsule_id_mismatch"


def test_recompute_citation_unverified_when_adjudication_capsule_itself_is_forged(corroborated_fixture):
    _half_a, _half_b, _outcome, adjudication_capsule = corroborated_fixture
    forged = dict(adjudication_capsule)
    forged["operator"] = "someone-else"  # mutate post-seal -> capsule_id / signature no longer match
    result = aw.recompute_adjudication_from_witness(forged, lambda cid: None)
    assert result.status == aw.CITATION_UNVERIFIED
    assert result.reason == "adjudication_capsule_forged"


def test_recompute_citation_unverified_when_citation_missing():
    bare = emit(
        action_type="decide",
        operator="test-org",
        developer="referee@v1",
        disposition=Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="assessed"),
    )
    result = aw.recompute_adjudication_from_witness(bare, lambda cid: None)
    assert result.status == aw.CITATION_UNVERIFIED
    assert result.reason == "missing_half_citation"

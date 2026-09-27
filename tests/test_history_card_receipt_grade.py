# SPDX-License-Identifier: Apache-2.0
"""A history card's ``receipt_grades`` report a receipt grade (``-65537`` in
the COSE Receipt's protected header) only for a receipt that is bound to the
card's latest checkpoint and whose signature verifies under a key this
process already trusts: the caller's pinned key, or capsule-emit's built-in
default witness key.

``scitt_cose.verify_receipt`` fills ``protected_header_ext`` during its
structural decode, before the signature check, so reading the label from that
result alone lets anyone who can mint a COSE_Sign1 with their own key claim
``mmr-verified`` for a witness. These tests mint exactly that receipt and
require ``None`` for it, and the same for a genuine receipt replayed from
another checkpoint, while a genuine receipt for this checkpoint keeps its
grade under a pinned key. Unpinned, a key served at the ledger-recorded
``ts_url`` is never fetched or trusted: whoever writes the ledger chooses that
URL, so an attacker's server there serving the attacker's key must not turn a
self-signed ``mmr-verified`` receipt into a grade. Same rule, and the same
cases, as capsule-emit's ``tests/test_witness_receipt_grade.py``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import cbor2
import pytest
from capsule_emit.checkpoint import DEFAULT_TS_URL, CheckpointConfig, CheckpointRecord, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from scitt_cose import build_receipt, sign_sign1

from history_card import _receipt_grade, build_history_card, node_id_from_key_id, verify_history_card

#: COSE Receipt header labels, as scitt_cose.receipt defines them (verifiable
#: data structure / verifiable data proofs), and the private-use receipt-grade
#: label under test.
_HDR_VDS = 395
_HDR_VDP = 396
_VDS_RFC9162_SHA256 = 1
_VDP_INCLUSION_PROOFS = -1
_GRADE_LABEL = -65537


def _checkpoint(mmr_size: int) -> CheckpointRecord:
    return CheckpointRecord(
        v=1,
        kind="mmr_checkpoint",
        log_id="receipt-grade-test-log",
        mmr_size=mmr_size,
        root="11" * 32,
        prev_size=0,
        prev_root="",
        key_id="receipt-grade-test-key",
        timestamp="2026-09-26T00:00:00Z",
        signature="",
    )


def _entry_hash(cp: CheckpointRecord) -> str:
    """The entry hash a Transparency Service records for ``cp``, and what a
    stamp must carry to be bound to it."""
    return hashlib.sha256(bytes.fromhex(cp.digest())).hexdigest()


CHECKPOINT = _checkpoint(mmr_size=4)
OTHER_CHECKPOINT = _checkpoint(mmr_size=7)


def _keypair() -> tuple[bytes, bytes, bytes]:
    """(private PEM, public PEM, raw 32-byte public key) for a fresh Ed25519 key."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


WITNESS_PRIV, WITNESS_PUB, WITNESS_RAW = _keypair()
ATTACKER_PRIV, _ATTACKER_PUB, ATTACKER_RAW = _keypair()


def _receipt_b64(private_key_pem: bytes, grade: str | None, entry_hash: str) -> str:
    """A single-leaf RFC 9162 COSE Receipt over ``entry_hash``, signed with
    ``private_key_pem``, carrying ``grade`` at label -65537 when given. For a
    one-leaf tree the root is the RFC 9162 leaf hash and the audit path is
    empty. Without a grade this is byte-identical to
    ``scitt_cose.build_receipt`` (see
    ``test_hand_built_receipt_matches_build_receipt``); the grade is the
    extra protected label ``build_receipt`` has no parameter for."""
    root = hashlib.sha256(b"\x00" + bytes.fromhex(entry_hash)).digest()
    protected: dict[int, int | str] = {_HDR_VDS: _VDS_RFC9162_SHA256}
    if grade is not None:
        protected[_GRADE_LABEL] = grade
    inclusion_proof = cbor2.dumps([1, 0, []])
    receipt = sign_sign1(
        root,
        alg="EdDSA",
        private_key_pem=private_key_pem,
        protected=protected,
        unprotected={_HDR_VDP: {_VDP_INCLUSION_PROOFS: [inclusion_proof]}},
        detached=True,
    )
    return base64.b64encode(receipt).decode()


def _witness(
    ts_url: str,
    private_key_pem: bytes,
    grade: str | None,
    *,
    receipt_for: CheckpointRecord = CHECKPOINT,
    is_stub: bool = False,
) -> WitnessRecord:
    """A stamp whose entry hash and receipt are both for ``receipt_for``."""
    entry_hash = _entry_hash(receipt_for)
    return WitnessRecord(
        ts_url=ts_url,
        entry_hash=entry_hash,
        receipt_b64=_receipt_b64(private_key_pem, grade, entry_hash),
        leaf_index=0,
        tree_size=1,
        is_stub=is_stub,
    )


class _KeyServer:
    """A local HTTP server answering at the path a Transparency Service
    publishes its key on (``/anchor/authority-pubkey``) with ``raw_key``,
    counting every request -- the stand-in for a server the ledger's author
    controls. ``requests`` staying 0 shows the key was never fetched."""

    def __init__(self, raw_key: bytes) -> None:
        self.requests = 0
        key_server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                key_server.requests += 1
                body = json.dumps({"pubkey_hex": raw_key.hex()}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- stdlib signature
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> _KeyServer:
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def attacker_server() -> Iterator[_KeyServer]:
    with _KeyServer(ATTACKER_RAW) as server:
        yield server


@pytest.fixture
def witness_server() -> Iterator[_KeyServer]:
    with _KeyServer(WITNESS_RAW) as server:
        yield server


# -- the test receipts are the shape scitt_cose mints ------------------------


def test_hand_built_receipt_matches_build_receipt() -> None:
    entry_hash = _entry_hash(CHECKPOINT)
    reference = build_receipt(
        leaf_entry_hex=entry_hash,
        leaf_index=0,
        tree_entries_hex=[entry_hash],
        alg="EdDSA",
        log_private_key_pem=WITNESS_PRIV,
    )
    assert base64.b64decode(_receipt_b64(WITNESS_PRIV, None, entry_hash)) == reference


# -- pinned key -------------------------------------------------------------


def test_attacker_signed_mmr_verified_receipt_has_no_grade_under_pinned_key() -> None:
    forged = _witness("https://anchor.example", ATTACKER_PRIV, "mmr-verified")
    assert _receipt_grade(CHECKPOINT, forged, ts_pubkey_pem=WITNESS_PUB) is None


def test_genuine_receipt_keeps_its_grade_under_pinned_key() -> None:
    genuine = _witness("https://anchor.example", WITNESS_PRIV, "mmr-verified")
    assert _receipt_grade(CHECKPOINT, genuine, ts_pubkey_pem=WITNESS_PUB) == "mmr-verified"


def test_genuine_countersigned_observed_receipt_keeps_its_grade_under_pinned_key() -> None:
    genuine = _witness("https://rekor.example", WITNESS_PRIV, "countersigned-observed")
    assert _receipt_grade(CHECKPOINT, genuine, ts_pubkey_pem=WITNESS_PUB) == "countersigned-observed"


def test_genuine_receipt_replayed_from_another_checkpoint_has_no_grade_under_pinned_key() -> None:
    replayed = _witness("https://anchor.example", WITNESS_PRIV, "mmr-verified", receipt_for=OTHER_CHECKPOINT)
    assert _receipt_grade(OTHER_CHECKPOINT, replayed, ts_pubkey_pem=WITNESS_PUB) == "mmr-verified"
    assert _receipt_grade(CHECKPOINT, replayed, ts_pubkey_pem=WITNESS_PUB) is None


def test_grade_read_is_gated_on_its_own_verify_ok_not_only_on_the_verdict(monkeypatch) -> None:
    # Force the WITNESSED verdict for an attacker-signed receipt, as a drift
    # between the verdict's key choice and this function's would. The grade
    # must still be None: it is read only from a verify_receipt result whose
    # own ``ok`` is True under the trusted key, never from a failed verify
    # (scitt-cose releases before #53 fill ``protected_header_ext`` on one).
    import capsule_emit.checkpoint as checkpoint_mod

    monkeypatch.setattr(
        checkpoint_mod,
        "verify_witness_stamp_tristate",
        lambda *_a, **_k: (checkpoint_mod.StampVerdict.WITNESSED, []),
    )
    forged = _witness("https://anchor.example", ATTACKER_PRIV, "mmr-verified")
    assert _receipt_grade(CHECKPOINT, forged, ts_pubkey_pem=WITNESS_PUB) is None


def test_genuine_receipt_without_label_has_no_grade() -> None:
    unlabeled = _witness("https://anchor.example", WITNESS_PRIV, None)
    assert _receipt_grade(CHECKPOINT, unlabeled, ts_pubkey_pem=WITNESS_PUB) is None


def test_genuine_receipt_with_undefined_grade_value_has_no_grade() -> None:
    odd = _witness("https://anchor.example", WITNESS_PRIV, "fully-audited")
    assert _receipt_grade(CHECKPOINT, odd, ts_pubkey_pem=WITNESS_PUB) is None


def test_stub_witness_has_no_grade_even_with_genuine_signature() -> None:
    stub = _witness("https://anchor.example", WITNESS_PRIV, "mmr-verified", is_stub=True)
    assert _receipt_grade(CHECKPOINT, stub, ts_pubkey_pem=WITNESS_PUB) is None


# -- unpinned: no key is ever fetched ----------------------------------------


def test_attacker_ts_url_serving_attacker_key_gives_self_signed_receipt_no_grade(
    attacker_server: _KeyServer,
) -> None:
    forged = _witness(attacker_server.url, ATTACKER_PRIV, "mmr-verified")
    assert _receipt_grade(CHECKPOINT, forged) is None
    assert attacker_server.requests == 0


def test_genuine_receipt_at_an_unpinned_non_default_ts_url_has_no_grade(
    witness_server: _KeyServer,
) -> None:
    genuine = _witness(witness_server.url, WITNESS_PRIV, "mmr-verified")
    assert _receipt_grade(CHECKPOINT, genuine) is None
    assert witness_server.requests == 0


def test_receipt_signed_by_another_key_at_the_default_ts_url_has_no_grade() -> None:
    forged = _witness(DEFAULT_TS_URL, ATTACKER_PRIV, "mmr-verified")
    assert _receipt_grade(CHECKPOINT, forged) is None


# -- end to end: build_history_card / verify_history_card --------------------


def _real_chain(tmp_path) -> list[dict]:
    """A real two-checkpoint chain (COSE-wire signed, consistency-linked),
    witnessed by no one yet: the caller attaches the stamps under test to
    the latest checkpoint line."""
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=2, max_lag_entries=10_000, ts_urls=[])
    signer = Ed25519Signer(tmp_path / "node-a.pem")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id="log-a")
    made = 0
    n = 0
    while made < 2:
        log.append({"capsule_id": f"{n:064x}", "n": n})
        n += 1
        if state.record_appended() is not None:
            made += 1
    return [json.loads(line) for line in (tmp_path / "checkpoints.jsonl").read_text().splitlines()]


def test_card_grades_only_the_pinned_genuine_receipt_and_fetches_nothing(
    tmp_path, attacker_server: _KeyServer
) -> None:
    """The attack end to end: the latest checkpoint carries a genuine,
    bound, pinned-key ``mmr-verified`` receipt and an attacker's
    self-signed ``mmr-verified`` receipt at an attacker-controlled
    ``ts_url``. Only the genuine one is graded; the attacker's server is
    never contacted; the card verifies offline under the same pin and
    fails the match without it (its grade came from a key the verifier
    does not hold)."""
    lines = _real_chain(tmp_path)
    latest = CheckpointRecord.from_dict(lines[-1])
    genuine = _witness("https://anchor.example", WITNESS_PRIV, "mmr-verified", receipt_for=latest)
    forged = _witness(attacker_server.url, ATTACKER_PRIV, "mmr-verified", receipt_for=latest)
    lines[-1]["witnesses"] = [genuine.to_dict(), forged.to_dict()]
    node_id = node_id_from_key_id(lines[0]["key_id"])

    card = build_history_card(
        node_id=node_id, log_id="log-a", checkpoint_lines=lines, ts_pubkey_pem=WITNESS_PUB
    )
    assert card.receipt_grades == {"https://anchor.example": "mmr-verified", attacker_server.url: None}
    assert card.witness_words() == (
        "witnessed -- 2 receipts: ungraded (127.0.0.1), consistency-verified (anchor.example)"
    )
    assert attacker_server.requests == 0

    assert verify_history_card(card.to_value(), lines, ts_pubkey_pem=WITNESS_PUB).ok
    unpinned = verify_history_card(card.to_value(), lines)
    assert not unpinned.ok
    assert "recomputed card does not match the published card" in unpinned.errors
    assert attacker_server.requests == 0


def test_card_unpinned_grades_nothing_from_a_ledger_supplied_ts_url(
    tmp_path, attacker_server: _KeyServer
) -> None:
    lines = _real_chain(tmp_path)
    latest = CheckpointRecord.from_dict(lines[-1])
    lines[-1]["witnesses"] = [
        _witness(attacker_server.url, ATTACKER_PRIV, "mmr-verified", receipt_for=latest).to_dict()
    ]
    node_id = node_id_from_key_id(lines[0]["key_id"])

    card = build_history_card(node_id=node_id, log_id="log-a", checkpoint_lines=lines)
    assert card.receipt_grades == {attacker_server.url: None}
    assert "consistency-verified" not in card.witness_words()
    assert verify_history_card(card.to_value(), lines).ok
    assert attacker_server.requests == 0

# SPDX-License-Identifier: Apache-2.0
"""A history card says `witnessed` (and `temporal_provenance ==
"receipt_bounded"`) only for a witness receipt that is bound to that
checkpoint AND verifies under a key this process already holds: a pin the
caller passes in `witness_keys`, or the default witness key built into
`capsule_emit.checkpoint`.

The producer writes every witness row in `checkpoints.jsonl`, `ts_url`
included. So a row that merely exists proves nothing, and neither does a key
fetched from the row's own `ts_url`: an attacker who writes
`ts_url = <their server>` serves their own key there. These tests mint each
of those forgeries against a REAL checkpoint chain and require the card to
read "not witnessed" for all of them, while a genuine receipt under a pinned
key still reads witnessed.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from scitt_cose import sign_sign1

import checkpointing
from capsule_emit.checkpoint import (
    DEFAULT_TS_URL,
    CheckpointConfig,
    CheckpointRecord,
    WitnessRecord,
    verify_receipt_offline,
)
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource
from history_card import build_history_card, node_id_from_key_id, verify_history_card

#: COSE Receipt header labels (scitt_cose.receipt): verifiable data structure
#: and verifiable data proofs.
_HDR_VDS = 395
_HDR_VDP = 396
_VDS_RFC9162_SHA256 = 1
_VDP_INCLUSION_PROOFS = -1

WITNESS_URL = "https://witness-a.example"


def _keypair() -> tuple[bytes, bytes, bytes]:
    """(private PEM, public PEM, raw 32-byte public key) for a fresh Ed25519 key."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


WITNESS_PRIV, WITNESS_PUB, _WITNESS_RAW = _keypair()
ATTACKER_PRIV, ATTACKER_PUB, ATTACKER_RAW = _keypair()


def _entry_hash(line: dict) -> str:
    """The entry hash a Transparency Service records for this checkpoint line."""
    return hashlib.sha256(bytes.fromhex(CheckpointRecord.from_dict(line).digest())).hexdigest()


def _receipt_b64(private_key_pem: bytes, entry_hash: str) -> str:
    """A single-leaf RFC 9162 COSE Receipt over `entry_hash`, signed with
    `private_key_pem` -- the same construction capsule-emit's receipt-grade
    tests use. For a one-leaf tree the root is the RFC 9162 leaf hash and the
    audit path is empty."""
    root = hashlib.sha256(b"\x00" + bytes.fromhex(entry_hash)).digest()
    receipt = sign_sign1(
        root,
        alg="EdDSA",
        private_key_pem=private_key_pem,
        protected={_HDR_VDS: _VDS_RFC9162_SHA256},
        unprotected={_HDR_VDP: {_VDP_INCLUSION_PROOFS: [cbor2.dumps([1, 0, []])]}},
        detached=True,
    )
    return base64.b64encode(receipt).decode()


def _stamp(ts_url: str, private_key_pem: bytes, entry_hash: str) -> dict:
    return WitnessRecord(
        ts_url=ts_url,
        entry_hash=entry_hash,
        receipt_b64=_receipt_b64(private_key_pem, entry_hash),
        leaf_index=0,
        tree_size=1,
    ).to_dict()


@pytest.fixture
def chain(tmp_path, monkeypatch) -> list[dict]:
    """A REAL 3-checkpoint chain (COSE-wire signed, real consistency proofs),
    registered only with a stub witness. Each test writes the witness rows it
    needs onto these lines afterwards, which is exactly what a producer can do
    to its own `checkpoints.jsonl`."""

    def _stub_register(checkpoint_cose: bytes, ts_url: str, *, timeout: float = 30.0) -> WitnessRecord:
        return WitnessRecord(ts_url=ts_url, entry_hash="stub", receipt_b64="stub", leaf_index=0, tree_size=1, is_stub=True)

    monkeypatch.setattr(checkpointing, "register_checkpoint", _stub_register)
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=2, max_lag_entries=10_000, ts_urls=["https://unused.example"])
    state = CheckpointState.load(
        ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=Ed25519Signer(tmp_path / "node-a.pem"), log_id="log-a"
    )
    n = made = 0
    while made < 3:
        log.append({"capsule_id": f"{n:064x}", "n": n})
        n += 1
        if state.record_appended() is not None:
            made += 1
    return [json.loads(line) for line in (tmp_path / "checkpoints.jsonl").read_text().splitlines()]


def _with_witnesses(lines: list[dict], stamp_for) -> list[dict]:
    """A copy of `lines` whose every checkpoint carries exactly `stamp_for(i, line)`."""
    out = copy.deepcopy(lines)
    for i, line in enumerate(out):
        line["witnesses"] = [stamp_for(i, line)]
    return out


def _card(lines: list[dict], **kwargs):
    return build_history_card(
        node_id=node_id_from_key_id(lines[0]["key_id"]), log_id="log-a", checkpoint_lines=lines, since_size=0, **kwargs
    )


def _assert_not_witnessed(card) -> None:
    assert card.properties.continuity == "unbroken", "the forgery must not be hiding behind a broken chain"
    assert card.witnessed is False
    assert card.witnesses == []
    assert card.properties.temporal_provenance == "producer_asserted"
    assert card.to_value()["coverage"]["witnessed"] is False


# --------------------------------------------------------------------------- #
# The EM's rule: a key fetched from a ledger-supplied ts_url never counts.    #
# --------------------------------------------------------------------------- #


class _AttackerKeyServer(BaseHTTPRequestHandler):
    """Serves the ATTACKER's key at the path `verify_receipt_offline(...,
    ts_base_url=...)` fetches a Transparency Service key from, and counts
    every request, so the test can prove the card never asked."""

    hits: list[str] = []

    def do_GET(self) -> None:
        type(self).hits.append(self.path)
        if self.path != "/anchor/authority-pubkey":
            self.send_error(404)
            return
        body = json.dumps({"pubkey_hex": ATTACKER_RAW.hex()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


@pytest.fixture
def attacker_ts_url() -> Iterator[str]:
    _AttackerKeyServer.hits = []
    server = HTTPServer(("127.0.0.1", 0), _AttackerKeyServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_attacker_ts_url_serving_the_attackers_key_is_not_witnessed(chain, attacker_ts_url):
    """The ledger names `ts_url = <attacker server>`, the attacker signs the
    receipt, and the attacker's server serves the matching key. Fetch-and-trust
    would accept it (asserted below, so this test cannot pass vacuously); the
    card must not, and must not even contact the server."""
    forged = _with_witnesses(chain, lambda _i, line: _stamp(attacker_ts_url, ATTACKER_PRIV, _entry_hash(line)))

    fetched_ok, errors = verify_receipt_offline(
        WitnessRecord.from_dict(forged[-1]["witnesses"][0]), ts_base_url=attacker_ts_url
    )
    assert fetched_ok, f"precondition: fetch-and-trust accepts the attacker's receipt ({errors})"
    _AttackerKeyServer.hits = []

    _assert_not_witnessed(_card(forged))
    _assert_not_witnessed(_card(forged, witness_keys={WITNESS_URL: WITNESS_PUB}))
    assert _AttackerKeyServer.hits == [], "the card fetched a key from a ledger-supplied ts_url"


def test_published_card_claiming_the_attacker_ts_url_as_witness_fails_verify(chain, attacker_ts_url):
    """A publisher who hand-sets `coverage.witnessed` for the attacker-served
    witness is caught by the offline verifier's recompute, which re-verifies
    witnesses rather than copying them from the card."""
    forged = _with_witnesses(chain, lambda _i, line: _stamp(attacker_ts_url, ATTACKER_PRIV, _entry_hash(line)))
    published = _card(forged).to_value()
    published["coverage"]["witnessed"] = True
    published["coverage"]["witnesses"] = [attacker_ts_url]

    assert not verify_history_card(published, forged).ok
    assert _AttackerKeyServer.hits == []


# --------------------------------------------------------------------------- #
# The #179 mutants, ported: forged signer, wrong key, unbound receipt.        #
# --------------------------------------------------------------------------- #


def test_genuine_receipt_under_a_pinned_key_is_witnessed(chain):
    genuine = _with_witnesses(chain, lambda _i, line: _stamp(WITNESS_URL, WITNESS_PRIV, _entry_hash(line)))
    pins = {WITNESS_URL: WITNESS_PUB}
    card = _card(genuine, witness_keys=pins)

    assert card.witnessed is True
    assert card.witnesses == [WITNESS_URL]
    assert card.properties.temporal_provenance == "receipt_bounded"
    assert verify_history_card(card.to_value(), genuine, witness_keys=pins).ok


def test_genuine_receipt_without_its_pin_is_not_witnessed(chain):
    """Same genuine receipt, but this verifier holds no key for that ts_url:
    unverified, so not witnessed -- and a card published by someone who did
    hold the pin does not verify here, rather than being taken on its word."""
    genuine = _with_witnesses(chain, lambda _i, line: _stamp(WITNESS_URL, WITNESS_PRIV, _entry_hash(line)))
    _assert_not_witnessed(_card(genuine))

    published = _card(genuine, witness_keys={WITNESS_URL: WITNESS_PUB}).to_value()
    assert not verify_history_card(published, genuine).ok


def test_attacker_signed_receipt_at_a_pinned_ts_url_is_not_witnessed(chain):
    forged = _with_witnesses(chain, lambda _i, line: _stamp(WITNESS_URL, ATTACKER_PRIV, _entry_hash(line)))
    _assert_not_witnessed(_card(forged, witness_keys={WITNESS_URL: WITNESS_PUB}))


def test_attacker_signed_receipt_claiming_the_default_witness_is_not_witnessed(chain):
    """No pin needed: `DEFAULT_TS_URL` is checked against the key built into
    capsule_emit, which the attacker does not hold."""
    forged = _with_witnesses(chain, lambda _i, line: _stamp(DEFAULT_TS_URL, ATTACKER_PRIV, _entry_hash(line)))
    _assert_not_witnessed(_card(forged))


def test_pin_for_the_wrong_key_is_not_witnessed(chain):
    genuine = _with_witnesses(chain, lambda _i, line: _stamp(WITNESS_URL, WITNESS_PRIV, _entry_hash(line)))
    _assert_not_witnessed(_card(genuine, witness_keys={WITNESS_URL: ATTACKER_PUB}))


def test_genuine_receipt_replayed_from_another_checkpoint_is_not_witnessed(chain):
    """Each checkpoint carries the witness's genuine receipt for a DIFFERENT
    checkpoint in the chain: correctly signed, not bound to this one."""
    replayed = _with_witnesses(
        chain,
        lambda i, _line: _stamp(WITNESS_URL, WITNESS_PRIV, _entry_hash(chain[(i + 1) % len(chain)])),
    )
    _assert_not_witnessed(_card(replayed, witness_keys={WITNESS_URL: WITNESS_PUB}))


def test_one_verified_witness_is_listed_and_a_forged_sibling_is_not(chain, attacker_ts_url):
    """A forged row beside a genuine one: the card lists only the witness it
    could verify, never the attacker's ts_url."""
    mixed = copy.deepcopy(chain)
    for line in mixed:
        eh = _entry_hash(line)
        line["witnesses"] = [_stamp(WITNESS_URL, WITNESS_PRIV, eh), _stamp(attacker_ts_url, ATTACKER_PRIV, eh)]
    card = _card(mixed, witness_keys={WITNESS_URL: WITNESS_PUB})

    assert card.witnessed is True
    assert card.witnesses == [WITNESS_URL]
    assert _AttackerKeyServer.hits == []

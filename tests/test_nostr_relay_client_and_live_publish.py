# SPDX-License-Identifier: Apache-2.0
"""B7 — the REAL local test-relay round trip, and the HELD live-publish gate.

Two halves:

  1. `WebsocketRelayClient` against a real `nak serve` relay on localhost: a
     genuine client/server round trip over a socket (publish, fetch, verify),
     not the in-process `MockRelay`. Skipped if the `nak` binary is not on
     PATH — this is a local dev/test tool
     (https://github.com/fiatjaf/nak), not a hard dependency of the account
     capsule or its Nostr publish path, exactly like `MockRelay` remains the
     always-available path with no external process.

  2. `nostr_live_publish`'s gate: proves `publish_account_capsule_live`
     structurally refuses to run without both a non-empty `relay_urls` list
     AND the explicit go-ahead flag — no test here ever supplies a real relay
     URL or sets that flag to True together with one.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time

import pytest

import checkpointing
from capsule_emit.checkpoint import CheckpointConfig, WitnessRecord
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource

import account_capsule as ac
import nostr_account as na
import nostr_live_publish as nlp

coincurve = pytest.importorskip("coincurve", reason="Nostr Schnorr signing needs coincurve")
websockets = pytest.importorskip("websockets", reason="the local test-relay round trip needs websockets")

from nostr_relay_client import WebsocketRelayClient  # noqa: E402


def _served_capsule(i: int, *, confirmed: bool = True) -> dict:
    return {
        "capsule_id": f"{i:064x}",
        "action_type": "decide",
        "effect": {
            "type": "inference_completion",
            "response_digest": f"resp{i:059x}",
            "status": "confirmed" if confirmed else "rejected",
        },
    }


@pytest.fixture
def fake_witness(monkeypatch):
    calls = []

    def _fake_register_checkpoint(checkpoint_cose, ts_url, *, timeout=30.0):
        calls.append((checkpoint_cose, ts_url))
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)
    return calls


def _account(tmp_path, capsules):
    ledger_dir = tmp_path / "ledger"
    ledger_dir.mkdir(parents=True)
    log = JsonlLogSource(ledger_dir / "capsules.jsonl")
    for c in capsules:
        log.append(c)
    cfg = CheckpointConfig(cadence_entries=1, ts_urls=["https://ts.example"])
    signer = Ed25519Signer(tmp_path / "node-key.pem")
    state = CheckpointState.load(ledger_dir=ledger_dir, log_source=log, cfg=cfg, signer=signer, log_id="log-b7")
    cp = state.reconnect()
    on_disk = [json.loads(l) for l in (ledger_dir / "capsules.jsonl").read_text().splitlines() if l.strip()]
    return ac.build_account_capsule(node_id="node-b7", capsules=on_disk, latest_checkpoint=cp)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- #
# (1) Real local test relay (`nak serve`) — genuine network round trip        #
# --------------------------------------------------------------------------- #
requires_nak = pytest.mark.skipif(
    shutil.which("nak") is None,
    reason="the local test-relay round trip needs the 'nak' binary (brew install nak); "
    "MockRelay in nostr_account.py remains the always-available in-process path",
)


@pytest.fixture
def local_test_relay():
    """Start `nak serve` (a real, in-memory, localhost-only NIP-01 relay) on a
    free port and tear it down after the test. Never a public relay — `nak
    serve`'s only network surface is the loopback port it binds."""
    port = _free_port()
    proc = subprocess.Popen(
        ["nak", "serve", "--hostname", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"ws://127.0.0.1:{port}"
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("nak serve did not open its port in time")
        yield url
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@requires_nak
def test_publish_and_fetch_round_trip_against_local_relay(tmp_path, fake_witness, local_test_relay):
    account = _account(tmp_path, [_served_capsule(1), _served_capsule(2, confirmed=False)])
    cap = ac.seal_account_capsule(account, operator="op", developer="dev", signing_node_id="node-b7")
    key = na.SchnorrNostrKey.generate()
    event = na.build_account_event(account, key, sealed_capsule_id=cap["capsule_id"])

    client = WebsocketRelayClient(local_test_relay)
    sent = client.send_event(event)
    assert sent["ok"] is True

    fetched = client.fetch_replaceable(key.pubkey_hex, na.KIND_ACCOUNT_CAPSULE, na.ACCOUNT_D_TAG)
    assert fetched is not None
    # Nostr signature verifies on the bytes that came back over the wire.
    assert na.NostrEvent.verify_value(fetched) is True
    assert fetched["id"] == event.id
    # The account inside the fetched content verifies too.
    content = json.loads(fetched["content"])
    assert content["coverage"]["checkpoint_root"] == account.coverage_root
    assert account.verify() is True


@requires_nak
def test_local_relay_rejects_tampered_event(tmp_path, fake_witness, local_test_relay):
    account = _account(tmp_path, [_served_capsule(1)])
    key = na.SchnorrNostrKey.generate()
    event = na.build_account_event(account, key)
    # Tamper AFTER signing: the id/sig no longer match the content.
    event.content = event.content + " "

    client = WebsocketRelayClient(local_test_relay)
    result = client.send_event(event)
    assert result["ok"] is False


@requires_nak
def test_local_relay_rejects_event_from_a_key_that_did_not_sign_it(tmp_path, fake_witness, local_test_relay):
    account = _account(tmp_path, [_served_capsule(1)])
    key = na.SchnorrNostrKey.generate()
    other = na.SchnorrNostrKey.generate()
    event = na.build_account_event(account, key)
    event.sig = other.sign(bytes.fromhex(event.id))  # wrong key's signature

    client = WebsocketRelayClient(local_test_relay)
    result = client.send_event(event)
    assert result["ok"] is False


@requires_nak
def test_local_relay_replaceable_supersede(tmp_path, fake_witness, local_test_relay):
    account = _account(tmp_path, [_served_capsule(1)])
    key = na.SchnorrNostrKey.generate()
    client = WebsocketRelayClient(local_test_relay)

    evt1 = na.build_account_event(account, key, created_at=1_700_000_000)
    r1 = client.send_event(evt1)
    assert r1["ok"] is True

    evt2 = na.build_account_event(account, key, created_at=1_700_000_500)
    r2 = client.send_event(evt2)
    assert r2["ok"] is True

    fetched = client.fetch_replaceable(key.pubkey_hex, na.KIND_ACCOUNT_CAPSULE, na.ACCOUNT_D_TAG)
    assert fetched["id"] == evt2.id  # newer supersedes older, in place


def test_websocket_relay_client_has_no_default_url():
    with pytest.raises(TypeError):
        WebsocketRelayClient()  # url is required — no default anywhere


# --------------------------------------------------------------------------- #
# (2) The HELD live-publish gate — never exercised against a real relay here  #
# --------------------------------------------------------------------------- #
def test_publish_live_refuses_without_the_nod(tmp_path, fake_witness):
    account = _account(tmp_path, [_served_capsule(1)])
    key = na.SchnorrNostrKey.generate()
    with pytest.raises(nlp.LivePublishHeld):
        nlp.publish_account_capsule_live(account, key, ["wss://example-relay.invalid"])


def test_publish_live_refuses_with_the_nod_but_no_relays(tmp_path, fake_witness):
    account = _account(tmp_path, [_served_capsule(1)])
    key = na.SchnorrNostrKey.generate()
    with pytest.raises(nlp.LivePublishHeld):
        nlp.publish_account_capsule_live(
            account, key, [], i_have_stevens_go_ahead_for_a_public_relay=True
        )


def test_publish_live_flag_is_only_ever_set_true_inside_this_test_file():
    """Repo-wide guardrail: the go-ahead flag is set to `True` ONLY in the two
    guard tests above (which pair it with an empty `relay_urls`, so the
    function still refuses) — never in production code, a demo script, or
    any other test. That is what makes the live path HELD rather than merely
    defaulted off."""
    import pathlib

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    exempt = {pathlib.Path(__file__).resolve(), (repo_root / "nostr_live_publish.py").resolve()}
    needle = "i_have_stevens_go_ahead_for_a_public_relay=True"
    offending = []
    for py in repo_root.rglob("*.py"):
        if ".git" in py.parts or "__pycache__" in py.parts:
            continue
        if py.resolve() in exempt:
            continue
        if needle in py.read_text():
            offending.append(str(py))
    assert offending == [], f"live-publish go-ahead flag set True outside its guard tests: {offending}"


def test_describe_live_publish_plan_signs_locally_and_touches_no_network(tmp_path, fake_witness):
    account = _account(tmp_path, [_served_capsule(1), _served_capsule(2)])
    cap = ac.seal_account_capsule(account, operator="op", developer="dev", signing_node_id="node-b7")
    key = na.SchnorrNostrKey.generate()
    plan = nlp.describe_live_publish_plan(account, key, sealed_capsule_id=cap["capsule_id"])

    assert plan["kind"] == na.KIND_ACCOUNT_CAPSULE
    assert plan["kind_is_provisional"] is True
    assert plan["pubkey"] == key.pubkey_hex
    assert plan["would_publish_to"] == "NOWHERE — this is a dry-run description; no relay_urls were contacted"
    # The event is really signed (id/sig are the ones a relay would receive):
    # the Schnorr signature verifies over the id, the same check a relay does.
    assert coincurve.PublicKeyXOnly(bytes.fromhex(plan["pubkey"])).verify(
        bytes.fromhex(plan["sig"]), bytes.fromhex(plan["id"])
    )
    content = json.loads(plan["content"])
    assert content["sealed_capsule_id"] == cap["capsule_id"]

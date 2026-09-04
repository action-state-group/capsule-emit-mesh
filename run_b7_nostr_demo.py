#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""B7 end-to-end transcript: account capsule -> Nostr event -> LOCAL test
relay round trip, the three red-team mutants, and the staged/HELD
live-publish plan.

Run:
    python3 run_b7_nostr_demo.py | tee b7-nostr-demo/transcript.txt

Everything here is LOCAL and OFFLINE:
  * the witnessed ledger's "witness" is the same fake in-process stand-in
    tests/test_account_capsule_nostr.py uses -- no network TS call;
  * the Nostr relay is `nak serve` on 127.0.0.1, spawned and torn down by
    this script -- never a public relay;
  * the live-publish path (nostr_live_publish.py) is invoked ONLY to prove it
    refuses without Steven's nod, and to print the exact event a live publish
    would send -- built and signed locally, sent to no relay_urls.

This script IS the transcript for Steven's HOLD-for-review call: everything
above the "STAGED / HELD" banner ran for real; nothing below it touched a
network.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import checkpointing  # noqa: E402
from capsule_emit.checkpoint import CheckpointConfig, WitnessRecord  # noqa: E402
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource  # noqa: E402

import account_capsule as ac  # noqa: E402
import nostr_account as na  # noqa: E402
import nostr_live_publish as nlp  # noqa: E402
from nostr_relay_client import WebsocketRelayClient  # noqa: E402

DEMO_DIR = Path(__file__).parent / "b7-nostr-demo"
LEDGER_DIR = DEMO_DIR / "ledger"


def _p(title: str) -> None:
    print()
    print(f"=== {title} ===")


def _served(i: int, *, confirmed: bool = True) -> dict:
    return {
        "capsule_id": f"{i:064x}",
        "action_type": "decide",
        "effect": {
            "type": "inference_completion",
            "response_digest": f"resp{i:059x}",
            "status": "confirmed" if confirmed else "rejected",
        },
    }


def _requested(i: int) -> dict:
    return {
        "capsule_id": f"{i:064x}",
        "action_type": "decide",
        "provenance": {"role": "requester"},
        "effect": {"type": "request", "request_digest": f"req{i:060x}"},
    }


def _fake_register_checkpoint_factory():
    """The same in-process fake witness tests/test_account_capsule_nostr.py
    uses -- no network. Assigning it onto `checkpointing.register_checkpoint`
    works the same way `monkeypatch.setattr` does in the tests: the
    calls inside checkpointing.py resolve `register_checkpoint` as a module
    global at call time, not at import time."""
    calls: list = []

    def _fake(checkpoint_cose, ts_url, *, timeout=30.0):
        calls.append((checkpoint_cose, ts_url))
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    return _fake


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    if shutil.which("nak") is None:
        print("ERROR: this transcript needs the 'nak' Nostr relay CLI on PATH")
        print("  brew install nak   (or: go install github.com/fiatjaf/nak@latest)")
        return 1

    print("B7 -- account capsule -> Nostr publish path -- LOCAL TEST-RELAY TRANSCRIPT")
    print("Everything below is local/offline. No public relay is contacted.")

    # --- witnessed ledger ---------------------------------------------------
    _p("1. Build a witnessed capsule ledger")
    if LEDGER_DIR.exists():
        shutil.rmtree(LEDGER_DIR)
    LEDGER_DIR.mkdir(parents=True)
    log = JsonlLogSource(LEDGER_DIR / "capsules.jsonl")
    witnessed_capsules = [_served(1), _served(2), _served(3, confirmed=False), _requested(4)]
    for c in witnessed_capsules:
        log.append(c)

    checkpointing.register_checkpoint = _fake_register_checkpoint_factory()
    cfg = CheckpointConfig(cadence_entries=1, ts_urls=["https://ts.example.invalid"])
    signer = Ed25519Signer(LEDGER_DIR / "node-key.pem")
    state = CheckpointState.load(
        ledger_dir=LEDGER_DIR, log_source=log, cfg=cfg, signer=signer, log_id="b7-demo"
    )
    cp = state.reconnect()
    print(f"checkpoint root={cp.root} mmr_size={cp.mmr_size} witnessed={bool(cp.witnesses)}")

    # Append an UN-anchored tail AFTER the checkpoint -- must be excluded.
    unanchored_tail = [_served(5), _served(6, confirmed=False)]
    for c in unanchored_tail:
        log.append(c)
    on_disk = [json.loads(l) for l in (LEDGER_DIR / "capsules.jsonl").read_text().splitlines() if l.strip()]
    print(f"ledger now has {len(on_disk)} entries ({len(unanchored_tail)} appended AFTER the checkpoint)")

    # --- account capsule ------------------------------------------------------
    _p("2. Build the account capsule (checkpoint-covered range ONLY)")
    account = ac.build_account_capsule(node_id="b7-demo-node", capsules=on_disk, latest_checkpoint=cp)
    print(
        f"selection: entries {account.selection_from_entry}..{account.selection_to_entry} "
        f"(covered_entries={account.covered_entries} of {len(on_disk)} on disk)"
    )
    if account.covered_entries != len(witnessed_capsules):
        print("MUTANT CHECK: the un-anchored tail leaked into the account -- FAIL")
        return 1
    print(f"MUTANT CHECK: the {len(unanchored_tail)} un-anchored tail entries are NOT in the account -- PASS")
    print(json.dumps(account.to_value(), indent=2, sort_keys=True))

    # --- seal into ledger -------------------------------------------------------
    _p("3. Seal the account capsule into the node's own ledger")
    sealed = ac.seal_account_capsule(
        account, operator="b7-demo-operator", developer="b7-demo-dev", signing_node_id="b7-demo-node"
    )
    log.append(sealed)
    print(f"sealed capsule_id={sealed['capsule_id']}")

    # --- node Nostr key (SEPARATE from the Ed25519 ledger key) ------------------
    _p("4. Generate the node's Nostr signing key (separate from its Ed25519 ledger key)")
    nostr_key = na.SchnorrNostrKey.generate()
    print(f"ledger key (Ed25519 PEM): {LEDGER_DIR / 'node-key.pub.pem'}")
    print(f"Nostr key (secp256k1 Schnorr x-only pubkey, hex): {nostr_key.pubkey_hex}")
    print(
        "(the Nostr secret is generated in-memory for this demo and discarded at "
        "process exit -- never written to disk, same as any throwaway demo key)"
    )

    # --- local test relay ---------------------------------------------------------
    _p("5. Start a LOCAL test relay (`nak serve`, 127.0.0.1 only)")
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
        print(f"relay listening at {url} (localhost only)")

        client = WebsocketRelayClient(url)

        _p("6. Publish the account event to the local relay")
        event = na.build_account_event(account, nostr_key, sealed_capsule_id=sealed["capsule_id"])
        print(f"event kind={event.kind} id={event.id}")
        print(json.dumps(event.to_value(), indent=2, sort_keys=True))
        sent = client.send_event(event)
        print(f"relay OK response: {sent}")
        if not sent["ok"]:
            print("relay refused a legitimate event -- FAIL")
            return 1

        _p("7. Fetch the event back over the wire and verify")
        fetched = client.fetch_replaceable(nostr_key.pubkey_hex, na.KIND_ACCOUNT_CAPSULE, na.ACCOUNT_D_TAG)
        if fetched is None:
            print("event not found on relay -- FAIL")
            return 1
        sig_ok = na.NostrEvent.verify_value(fetched)
        print(f"fetched event id={fetched['id']} Nostr signature verifies: {sig_ok}")
        fetched_content = json.loads(fetched["content"])
        content_matches = fetched_content == json.loads(event.content)
        account_ok = account.verify()
        print(f"fetched content matches published account: {content_matches}")
        print(f"account.verify(): {account_ok}")
        if not (sig_ok and content_matches and account_ok):
            print("round trip did not verify cleanly -- FAIL")
            return 1

        _p("8. MUTANT: tampered account bytes -> verify FAILS")
        tampered = json.loads(fetched["content"])
        tampered["derivation"]["fold"]["n_served_confirmed"] = 999
        tampered_event = dict(fetched)
        tampered_event["content"] = json.dumps(tampered)
        tamper_sig_ok = na.NostrEvent.verify_value(tampered_event)
        print(f"tampered content, same claimed sig -- signature verify: {tamper_sig_ok} (expect False)")
        if tamper_sig_ok is not False:
            print("MUTANT CHECK: tampered account bytes were NOT rejected -- FAIL")
            return 1
        print("MUTANT CHECK: tampered account bytes are rejected -- PASS")

        _p("9. MUTANT: event signed by the WRONG key -> rejected by the relay")
        other_key = na.SchnorrNostrKey.generate()
        forged = na.NostrEvent(
            pubkey=nostr_key.pubkey_hex,
            created_at=event.created_at + 1,
            kind=event.kind,
            tags=event.tags,
            content=event.content,
        )
        forged.id = forged.compute_id()
        forged.sig = other_key.sign(bytes.fromhex(forged.id))  # signed by the WRONG key
        forged_result = client.send_event(forged)
        print(f"relay response to wrong-key-signed event: {forged_result} (expect ok=False)")
        if forged_result["ok"] is not False:
            print("MUTANT CHECK: wrong-key signature was NOT rejected -- FAIL")
            return 1
        print("MUTANT CHECK: wrong-key signature is rejected -- PASS")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        print("\nlocal test relay stopped.")

    # --- staged / HELD live publish --------------------------------------------
    _p("STAGED / HELD -- what a live publish WOULD emit (nothing below this line touches a network)")
    plan = nlp.describe_live_publish_plan(account, nostr_key, sealed_capsule_id=sealed["capsule_id"])
    print(json.dumps(plan, indent=2, sort_keys=True))

    print()
    print("Attempting nlp.publish_account_capsule_live(...) with NO go-ahead (expect refusal):")
    try:
        nlp.publish_account_capsule_live(account, nostr_key, ["wss://example-relay.invalid"])
        print("UNEXPECTED: live publish did not refuse!")
        return 1
    except nlp.LivePublishHeld as exc:
        print(f"REFUSED as expected: {exc}")

    print()
    print("This task fires NOTHING at nos.lol / relay.damus.io / relay.primal.net / any public relay.")
    print("Live publish requires Steven's relay_urls + explicit one-line nod (see nostr_live_publish.py).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

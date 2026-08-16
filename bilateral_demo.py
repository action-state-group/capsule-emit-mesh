#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Minimal bilateral attestation demo — four moves of draft-mih-agent-bilateral-attestation-01.

⚠ NON-CONFORMANT IDENTITY ROOT
The keys used here are self-generated and self-held. They are not bound to
any trusted root or third-party-issued credential. §4.1 of the draft states
that first-use acceptance of a self-held key MUST NOT be treated as conformant
bilateral attestation. This demo shows the mechanism, not a deployed
bilateral exchange. See README for the full limitation statement.

Usage:
  python3 bilateral_demo.py

Both paths (bilateral and degraded) are run and their records verified. The
cross_party_rung is derived from the evidence in each record — never asserted
by the producer. The degraded path must return unilateral_fallback, and that
derivation failing is the key test this demo exists to show.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parent))

import mock_mesh_node
from capsule_sidecar import (
    NodeState,
    BilateralEvalResult,
    BILATERAL_RA_HEADER,
    BILATERAL_RA_SIG_HEADER,
    BILATERAL_PUBKEY_HEADER,
    default_state,
    derive_cross_party_rung,
    run_sidecar,
)

from agent_action_capsule.verify import verify as verify_capsule

ROOT = Path(__file__).parent
MANIFEST_PATH = ROOT / "model-package" / "model-package.json"
KEYS_DIR = ROOT / "keys"
MOCK_PORT = 9341
SIDECAR_PORT = 8093
BILATERAL_LEDGER_DIR = ROOT / "bilateral-ledger"

IDENTITY_LIMITATION_NOTE = (
    "⚠ NON-CONFORMANT IDENTITY ROOT: The client and node keys in this demo "
    "are self-generated and self-held. They are not bound to any trusted root "
    "or third-party-issued credential. draft-mih-agent-bilateral-attestation-01 "
    "§4.1 states that first-use acceptance of a self-held key MUST NOT be "
    "treated as conformant bilateral attestation. This demonstrates the "
    "mechanism only."
)


# ---------------------------------------------------------------------------
# Client key and request attestation (Move 1)
# ---------------------------------------------------------------------------


@dataclass
class ClientKey:
    """An Ed25519 keypair for the bilateral client."""

    private_key: Ed25519PrivateKey
    public_key_pem: bytes  # PEM-encoded public key

    @classmethod
    def generate(cls) -> "ClientKey":
        key = Ed25519PrivateKey.generate()
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cls(private_key=key, public_key_pem=pub_pem)

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    def verify(self, sig: bytes, data: bytes) -> bool:
        try:
            self.private_key.public_key().verify(sig, data)
            return True
        except InvalidSignature:
            return False


def make_request_attestation(
    client_key: ClientKey,
    raw_body: bytes,
    request_json: dict,
    *,
    nonce: str | None = None,
    validity_seconds: int = 60,
) -> tuple[str, str, str]:
    """Build and sign a request attestation (Move 1).

    Returns three header values: (ra_b64url, sig_b64url, pubkey_b64url).

    The attestation commits to:
    - sha256 of the raw request body (so the node can verify the request has
      not been altered in transit)
    - a nonce (so the node cannot precompute or replay this attestation for a
      different request)
    - a timestamp and validity window
    - an authorization bound: max_tokens the client is authorizing
    """
    now = datetime.now(timezone.utc)
    valid_until = now + timedelta(seconds=validity_seconds)
    ra = {
        "type": "x-capsule-poc-request-attestation/1",
        "request_digest": hashlib.sha256(raw_body).hexdigest(),
        "nonce": nonce or uuid.uuid4().hex,
        "timestamp": now.isoformat().replace("+00:00", "Z"),
        "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
        "max_tokens": request_json.get("max_tokens") or request_json.get("max_completion_tokens") or 256,
        "deadline_utc": valid_until.isoformat().replace("+00:00", "Z"),
    }
    ra_bytes = json.dumps(ra, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_bytes = client_key.sign(ra_bytes)
    return (
        base64.urlsafe_b64encode(ra_bytes).rstrip(b"=").decode("ascii"),
        base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii"),
        base64.urlsafe_b64encode(client_key.public_key_pem).rstrip(b"=").decode("ascii"),
    )


# ---------------------------------------------------------------------------
# Client acknowledgment (Move 4)
# ---------------------------------------------------------------------------


@dataclass
class ClientAck:
    """The client's signed acknowledgment of the node's action capsule (Move 4)."""

    action_capsule_id: str
    request_nonce: str
    timestamp: str
    ack_bytes: bytes
    sig: bytes
    public_key_pem: bytes


def make_client_ack(
    client_key: ClientKey,
    capsule_id: str,
    request_nonce: str,
) -> ClientAck:
    """Sign an acknowledgment of the received action capsule (Move 4).

    The ack commits to the action capsule's capsule_id, establishing that the
    initiator has seen the node's response and is acknowledging this specific
    exchange. Together with the action capsule's initiator_ref, this closes the
    bilateral loop.
    """
    now = datetime.now(timezone.utc)
    ack_payload = {
        "type": "x-capsule-poc-client-ack/1",
        "action_capsule_id": capsule_id,
        "request_nonce": request_nonce,
        "timestamp": now.isoformat().replace("+00:00", "Z"),
    }
    ack_bytes = json.dumps(ack_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = client_key.sign(ack_bytes)
    return ClientAck(
        action_capsule_id=capsule_id,
        request_nonce=request_nonce,
        timestamp=now.isoformat().replace("+00:00", "Z"),
        ack_bytes=ack_bytes,
        sig=sig,
        public_key_pem=client_key.public_key_pem,
    )


def verify_client_ack(ack: ClientAck, capsule_id: str, correlator: str | None) -> tuple[bool, str]:
    """Verify the client ack and check it references the expected capsule and nonce.

    Returns (ok: bool, reason: str).
    """
    # Verify signature.
    try:
        pubkey = serialization.load_pem_public_key(ack.public_key_pem)
        pubkey.verify(ack.sig, ack.ack_bytes)
    except InvalidSignature:
        return False, "ack signature invalid"
    except Exception as exc:
        return False, f"ack signature error: {exc}"

    # Verify the ack references the correct capsule.
    if ack.action_capsule_id != capsule_id:
        return False, (
            f"ack.action_capsule_id={ack.action_capsule_id!r} "
            f"does not match capsule_id={capsule_id!r}"
        )

    # Verify the nonce matches the correlator in the action capsule's cross_party block.
    if correlator is not None and ack.request_nonce != correlator:
        return False, (
            f"ack.request_nonce={ack.request_nonce!r} "
            f"does not match cross_party.correlator={correlator!r}"
        )

    return True, "ack verified: same exchange, same nonce, signature valid"


# ---------------------------------------------------------------------------
# Exchange verification with rung derivation
# ---------------------------------------------------------------------------


def get_cross_party(capsule: dict) -> dict | None:
    """Extract the cross_party block from the capsule's x-mesh-poc-v1 extension."""
    ca = (capsule.get("model_attestation") or {}).get("compute_attestation") or {}
    poc = ca.get("x-mesh-poc-v1") or {}
    return poc.get("cross_party")


def verify_exchange(
    capsule: dict,
    client_ack: ClientAck | None = None,
) -> tuple[str, bool, list[str]]:
    """Derive the cross_party_rung and verify the exchange record.

    Returns (rung: str, all_ok: bool, findings: list[str]).

    The rung is DERIVED from the evidence in the capsule and (optionally) the
    client ack. It is never asserted by the producer — this function IS the
    derivation. Show it failing on the degraded path (unilateral_fallback) is
    the key test.
    """
    findings: list[str] = []

    # Class-1 capsule verification (hash integrity, format).
    result = verify_capsule(capsule)
    if not result.ok:
        for f in result.findings:
            findings.append(f"capsule verify: {f.check} — {f.detail}")

    cross_party = get_cross_party(capsule)

    # Check client ack if provided.
    ack_ok = False
    if client_ack is not None:
        correlator = cross_party.get("correlator") if cross_party else None
        ack_ok, ack_reason = verify_client_ack(
            client_ack,
            capsule_id=capsule["capsule_id"],
            correlator=correlator,
        )
        findings.append(f"client_ack: {ack_reason}")

    rung = derive_cross_party_rung(cross_party, has_verified_ack=ack_ok)
    all_ok = result.ok
    return rung, all_ok, findings


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------


def wait_for(url: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5)
            return
        except Exception:
            time.sleep(0.05)
    raise TimeoutError(f"server at {url} did not come up in time")


def _send_request(
    port: int,
    prompt: str,
    model_id: str,
    *,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, bytes, str | None]:
    """Send a chat completion request; return (status_code, body, capsule_id)."""
    body = json.dumps(
        {
            "model": model_id,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 64,
            "seed": 42,
        }
    ).encode("utf-8")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(
        url=f"http://127.0.0.1:{port}/v1/chat/completions",
        data=body,
        method="POST",
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read(), resp.headers.get("X-Capsule-Id")
    except urllib.error.HTTPError as exc:
        cid = exc.headers.get("X-Capsule-Id") if exc.headers else None
        return exc.code, exc.read(), cid


def run_bilateral_exchange(
    state: NodeState,
    client_key: ClientKey,
    prompt: str,
    log: list[str],
) -> tuple[dict, ClientAck]:
    """Move 1-4: one full bilateral exchange, returning (action_capsule, client_ack)."""
    # Move 1: build the request body and sign a request attestation over it.
    body_dict = {
        "model": state.manifest["model_id"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 64,
        "seed": 42,
    }
    raw_body = json.dumps(body_dict).encode("utf-8")
    nonce = uuid.uuid4().hex
    ra_b64, sig_b64, pubkey_b64 = make_request_attestation(
        client_key, raw_body, body_dict, nonce=nonce
    )

    bilateral_headers = {
        "Content-Type": "application/json",
        BILATERAL_RA_HEADER.title().replace("X-", "X-"): ra_b64,
        BILATERAL_RA_SIG_HEADER.title().replace("X-", "X-"): sig_b64,
        BILATERAL_PUBKEY_HEADER.title().replace("X-", "X-"): pubkey_b64,
    }
    # Use proper capitalisation that matches what the sidecar receives
    bilateral_headers = {
        "Content-Type": "application/json",
        "X-Capsule-Request-Attestation": ra_b64,
        "X-Capsule-Request-Attestation-Sig": sig_b64,
        "X-Capsule-Client-Pubkey": pubkey_b64,
    }

    req = urllib.request.Request(
        url=f"http://127.0.0.1:{SIDECAR_PORT}/v1/chat/completions",
        data=raw_body,
        method="POST",
        headers=bilateral_headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            resp_body = resp.read()
            capsule_id = resp.headers.get("X-Capsule-Id")
    except urllib.error.HTTPError as exc:
        status = exc.code
        resp_body = exc.read()
        capsule_id = exc.headers.get("X-Capsule-Id") if exc.headers else None

    log.append(f"[bilateral] status={status} capsule_id={capsule_id}")

    # Move 4: client acknowledges the action capsule.
    assert capsule_id, "sidecar must return X-Capsule-Id"
    client_ack = make_client_ack(client_key, capsule_id, nonce)
    log.append(f"[bilateral] client ack produced for capsule_id={capsule_id}")

    # Find the capsule in the emitted list.
    action_capsule = next(
        (c for c in state.emitted if c["capsule_id"] == capsule_id), None
    )
    assert action_capsule is not None, f"capsule {capsule_id} not found in state.emitted"
    return action_capsule, client_ack


def run_degraded_exchange(
    state: NodeState,
    prompt: str,
    log: list[str],
) -> dict:
    """Degraded path: no request attestation sent; node proceeds unilaterally."""
    req = urllib.request.Request(
        url=f"http://127.0.0.1:{SIDECAR_PORT}/v1/chat/completions",
        data=json.dumps(
            {
                "model": state.manifest["model_id"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 64,
                "seed": 43,
            }
        ).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            capsule_id = resp.headers.get("X-Capsule-Id")
    except urllib.error.HTTPError as exc:
        status = exc.code
        capsule_id = exc.headers.get("X-Capsule-Id") if exc.headers else None

    log.append(f"[degraded]  status={status} capsule_id={capsule_id}")

    action_capsule = next(
        (c for c in state.emitted if c["capsule_id"] == capsule_id), None
    )
    assert action_capsule is not None, f"capsule {capsule_id} not found in state.emitted"
    return action_capsule


def main() -> None:
    if BILATERAL_LEDGER_DIR.exists():
        shutil.rmtree(BILATERAL_LEDGER_DIR)
    BILATERAL_LEDGER_DIR.mkdir(parents=True)

    # Start mock node.
    mock_server = mock_mesh_node.ThreadingHTTPServer(
        ("127.0.0.1", MOCK_PORT), mock_mesh_node.Handler
    )
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    wait_for(f"http://127.0.0.1:{MOCK_PORT}/v1/models")

    # Runtime digest over the mock server source (honestly labeled as a fixture).
    import hashlib as _hashlib
    runtime_digest = _hashlib.sha256(
        Path(mock_mesh_node.__file__).read_bytes()
    ).hexdigest()

    state: NodeState = default_state(
        ledger_dir=BILATERAL_LEDGER_DIR,
        manifest_path=MANIFEST_PATH,
        keys_dir=KEYS_DIR,
        runtime_label="poc-fixture-backend(mock_mesh_node.py)",
        runtime_digest=runtime_digest,
    )
    sidecar_server = run_sidecar(
        listen_host="127.0.0.1",
        listen_port=SIDECAR_PORT,
        upstream_base=f"http://127.0.0.1:{MOCK_PORT}",
        state=state,
    )
    sidecar_thread = threading.Thread(target=sidecar_server.serve_forever, daemon=True)
    sidecar_thread.start()
    wait_for(f"http://127.0.0.1:{SIDECAR_PORT}/v1/models")

    # Generate a client keypair for this demo run.
    client_key = ClientKey.generate()

    log: list[str] = []

    def out(line: str) -> None:
        print(line)
        log.append(line)

    out("=" * 72)
    out("bilateral attestation demo — mechanism demonstration (mock node)")
    out("=" * 72)
    out(IDENTITY_LIMITATION_NOTE)
    out("")
    out(f"node_id={state.node_id}")
    out(f"model_id={state.manifest['model_id']}")
    out("")

    # -----------------------------------------------------------------------
    # Path A: full bilateral exchange (Moves 1–4)
    # -----------------------------------------------------------------------
    out("-" * 60)
    out("PATH A: bilateral (Moves 1–4)")
    out("-" * 60)
    out("Move 1: client signs request attestation (request_digest + nonce +")
    out("        timestamp + valid_until + max_tokens authorization bound)")
    out("Move 2: sidecar evaluates attestation before dispatch")
    out("Move 3: action capsule records cross_party.initiator_ref")
    out("Move 4: client receives capsule_id, signs acknowledgment")
    out("")

    bilateral_capsule, client_ack = run_bilateral_exchange(
        state, client_key, "Explain what bilateral attestation adds to a unilateral record.", log
    )

    cross_party_a = get_cross_party(bilateral_capsule)
    rung_a, ok_a, findings_a = verify_exchange(bilateral_capsule, client_ack)

    out("")
    out(f"action capsule_id: {bilateral_capsule['capsule_id']}")
    out(f"cross_party block present: {cross_party_a is not None}")
    if cross_party_a:
        out(f"  initiator_ref: {cross_party_a.get('initiator_ref')}")
        out(f"  correlator:    {cross_party_a.get('correlator')}")
        out(f"  substantive:   {cross_party_a.get('substantive')}")
    out(f"client ack produced: action_capsule_id={client_ack.action_capsule_id}")
    out(f"client ack nonce matches correlator: {client_ack.request_nonce == (cross_party_a or {}).get('correlator')}")
    for f in findings_a:
        out(f"  finding: {f}")
    out(f"")
    out(f"DERIVED cross_party_rung (PATH A): {rung_a}")
    out(f"capsule verify.ok: {ok_a}")

    # -----------------------------------------------------------------------
    # Path B: degraded (unilateral fallback) — no request attestation
    # -----------------------------------------------------------------------
    out("")
    out("-" * 60)
    out("PATH B: degraded — no request attestation sent")
    out("-" * 60)
    out("Client does not send bilateral headers. Node proceeds unilaterally.")
    out("The record has no cross_party block. The rung derivation MUST return")
    out("unilateral_fallback — this failing is the test.")
    out("")

    degraded_capsule = run_degraded_exchange(
        state, "Same question, sent without any request attestation.", log
    )

    cross_party_b = get_cross_party(degraded_capsule)
    rung_b, ok_b, findings_b = verify_exchange(degraded_capsule, client_ack=None)

    out("")
    out(f"action capsule_id: {degraded_capsule['capsule_id']}")
    out(f"cross_party block present: {cross_party_b is not None}")
    for f in findings_b:
        out(f"  finding: {f}")
    out(f"")
    out(f"DERIVED cross_party_rung (PATH B): {rung_b}")
    out(f"capsule verify.ok: {ok_b}")

    # -----------------------------------------------------------------------
    # Side-by-side comparison — never confusable
    # -----------------------------------------------------------------------
    out("")
    out("=" * 72)
    out("COMPARISON: bilateral vs degraded — must be distinguishable")
    out("=" * 72)
    out(f"  PATH A (bilateral)  cross_party_rung = {rung_a!r}")
    out(f"  PATH B (degraded)   cross_party_rung = {rung_b!r}")
    out(f"  Rungs differ:       {rung_a != rung_b}")
    out(f"  PATH A cross_party present: {cross_party_a is not None}")
    out(f"  PATH B cross_party present: {cross_party_b is not None}")
    out("")
    out("The rung is DERIVED from each record's own bytes — never asserted")
    out("by the producer. The degraded record has no cross_party evidence,")
    out("so the derivation returns unilateral_fallback regardless of what")
    out("a producer might claim.")

    # Write artifacts before offline verification so the offline pass can
    # load the stored client ack from disk (proving the round-trip works).
    (BILATERAL_LEDGER_DIR / "bilateral-capsule.json").write_text(
        json.dumps(bilateral_capsule, sort_keys=True, indent=2)
    )
    (BILATERAL_LEDGER_DIR / "degraded-capsule.json").write_text(
        json.dumps(degraded_capsule, sort_keys=True, indent=2)
    )
    ack_record = {
        "type": "x-capsule-poc-client-ack/1",
        "action_capsule_id": client_ack.action_capsule_id,
        "request_nonce": client_ack.request_nonce,
        "timestamp": client_ack.timestamp,
        "ack_bytes_b64": base64.urlsafe_b64encode(client_ack.ack_bytes).decode("ascii"),
        "sig_b64": base64.urlsafe_b64encode(client_ack.sig).decode("ascii"),
        "public_key_pem_b64": base64.urlsafe_b64encode(client_ack.public_key_pem).decode("ascii"),
    }
    (BILATERAL_LEDGER_DIR / "client-ack.json").write_text(json.dumps(ack_record, indent=2))

    # -----------------------------------------------------------------------
    # Offline-verify both capsules from the ledger JSONL (not from in-memory).
    # The JSONL alone is enough to verify capsule integrity and distinguish
    # the paths. To derive full_bilateral on capsule 1, the verifier also
    # loads the stored client-ack.json and verifies the ack's signature.
    # -----------------------------------------------------------------------
    out("")
    out("=" * 72)
    out("OFFLINE VERIFICATION from ledger JSONL + client-ack.json")
    out("=" * 72)
    out("Note: the JSONL capsule alone yields 'acknowledged_receipt' for")
    out("capsule 1 — the client ack is external evidence that upgrades to")
    out("'full_bilateral'. This is correct: the rung reflects what evidence")
    out("the verifier has in hand, not what the producer claimed.")
    out("")
    all_ok = True
    ledger_path = BILATERAL_LEDGER_DIR / "capsules.jsonl"
    with ledger_path.open() as fh:
        for line_num, line in enumerate(fh, start=1):
            cap = json.loads(line.strip())
            result = verify_capsule(cap)
            all_ok = all_ok and result.ok
            cp = get_cross_party(cap)
            # Capsule-only rung (no external ack):
            rung_capsule_only = derive_cross_party_rung(cp)
            out(
                f"  capsule {line_num} (capsule alone): verify.ok={result.ok} "
                f"cross_party_present={cp is not None} "
                f"derived_rung={rung_capsule_only!r} "
                f"capsule_id={cap['capsule_id']}"
            )

    # Now load the stored ack and re-derive for capsule 1.
    ack_path = BILATERAL_LEDGER_DIR / "client-ack.json"
    if ack_path.exists():
        ack_rec = json.loads(ack_path.read_text())
        stored_ack = ClientAck(
            action_capsule_id=ack_rec["action_capsule_id"],
            request_nonce=ack_rec["request_nonce"],
            timestamp=ack_rec["timestamp"],
            ack_bytes=base64.urlsafe_b64decode(ack_rec["ack_bytes_b64"] + "=="),
            sig=base64.urlsafe_b64decode(ack_rec["sig_b64"] + "=="),
            public_key_pem=base64.urlsafe_b64decode(ack_rec["public_key_pem_b64"] + "=="),
        )
        # Re-check capsule 1 with the stored ack.
        with ledger_path.open() as fh2:
            cap1 = json.loads(next(fh2).strip())
        cp1 = get_cross_party(cap1)
        correlator1 = cp1.get("correlator") if cp1 else None
        ack_ok_1, ack_reason_1 = verify_client_ack(stored_ack, cap1["capsule_id"], correlator1)
        rung_with_ack = derive_cross_party_rung(cp1, has_verified_ack=ack_ok_1)
        out(
            f"  capsule 1 (with stored ack): ack_verified={ack_ok_1} "
            f"({ack_reason_1[:60]}) derived_rung={rung_with_ack!r}"
        )
    out("")
    out(f"All capsules verify offline: {all_ok}")
    out("")
    out("Ledger and transcript written to bilateral-ledger/")
    out("")
    out("To re-run: python3 bilateral_demo.py")
    out("")

    # Write transcript (log was appended throughout; write it now).
    (BILATERAL_LEDGER_DIR / "bilateral-transcript.txt").write_text("\n".join(log) + "\n")

    sidecar_server.shutdown()
    mock_server.shutdown()

    # Acceptance gates.
    assert rung_a == "full_bilateral", f"PATH A must derive full_bilateral, got {rung_a!r}"
    assert rung_b == "unilateral_fallback", f"PATH B must derive unilateral_fallback, got {rung_b!r}"
    assert rung_a != rung_b, "bilateral and degraded records must produce different rungs"
    assert cross_party_a is not None, "bilateral capsule must carry cross_party block"
    assert cross_party_b is None, "degraded capsule must NOT carry cross_party block"
    assert ok_a, f"bilateral capsule must verify.ok=True; findings={findings_a}"
    assert ok_b, f"degraded capsule must verify.ok=True; findings={findings_b}"
    assert all_ok, "all capsules in ledger must verify offline"

    print("\nDemo complete. All acceptance gates passed.")


if __name__ == "__main__":
    main()

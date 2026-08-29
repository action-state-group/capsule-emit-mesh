#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Requester-side (Move 1 + Move 4) CLI: send one Move-1-attested chat
completion to a REAL mesh-llm node (any /v1/chat/completions endpoint --
a sidecar in front of it, or the plugin-gated host directly) and write a
Move-4 client acknowledgment for it.

This is `bilateral_demo.py`'s Move-1/Move-4 client logic (ClientKey,
make_request_attestation, make_client_ack -- reused, not reimplemented)
promoted to a standalone CLI so machine A can run it for real, against a
real machine B, instead of only inside that demo's in-process mock node.

Move 2 (attestation evaluation) and Move 3 (recording cross_party in the
served capsule) happen on B's side (capsule_sidecar.py's own logic) and are
not this script's concern -- this script is what A runs.

Usage:
    python3 send_bilateral_request.py --url http://<B-host>:PORT/v1/chat/completions \
        --model <model-id> --prompt "..." --out-dir <dir> [--client-key PATH]

Writes to --out-dir:
    client-key.pem              A's persistent Ed25519 identity (created if absent)
    client-ack-<capsule_id>.json   the Move-4 acknowledgment for this exchange

Prints the served capsule_id (however the endpoint surfaces it -- the
sidecar's `X-Capsule-Id` response header, or the plugin's
`.admission_policy.capsule_id` JSON field) and the HTTP status.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bilateral_demo import ClientKey, make_client_ack, make_request_attestation


def _load_or_create_client_key(key_path: Path) -> ClientKey:
    if key_path.exists():
        priv = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return ClientKey(private_key=priv, public_key_pem=pub_pem)
    key = ClientKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    priv_pem = key.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(priv_pem)
    key_path.chmod(0o600)
    return key


def _extract_capsule_id(status: int, headers, body: bytes) -> tuple[str | None, str]:
    """Return (capsule_id, where) -- checks the sidecar's response header
    first, then the plugin's JSON body shape (`.admission_policy.capsule_id`
    or `.admission_policy.capsule.capsule_id`), else (None, "not found")."""
    header_cid = headers.get("X-Capsule-Id")
    if header_cid:
        return header_cid, "X-Capsule-Id header"
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "not found (non-JSON body, no header)"
    admission = parsed.get("admission_policy") if isinstance(parsed, dict) else None
    if isinstance(admission, dict):
        if admission.get("capsule_id"):
            return admission["capsule_id"], "admission_policy.capsule_id"
        capsule = admission.get("capsule")
        if isinstance(capsule, dict) and capsule.get("capsule_id"):
            return capsule["capsule_id"], "admission_policy.capsule.capsule_id"
    return None, "not found (checked header + admission_policy.* body fields)"


def send_bilateral_request(
    *,
    url: str,
    model: str,
    prompt: str,
    client_key: ClientKey,
    max_tokens: int = 64,
    client_nonce: str | None = None,
    timeout: float = 30.0,
) -> dict:
    """Move 1: sign a request attestation over the body, send it, and
    (if the server surfaced a capsule_id) build the Move-4 ack.

    Returns a dict: status, capsule_id, capsule_id_source, ack (ClientAck or
    None), body (raw response bytes), request_nonce.
    """
    body_dict = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": max_tokens,
    }
    if client_nonce:
        body_dict["client_nonce"] = client_nonce
    raw_body = json.dumps(body_dict).encode("utf-8")
    nonce = uuid.uuid4().hex
    ra_b64, sig_b64, pubkey_b64 = make_request_attestation(client_key, raw_body, body_dict, nonce=nonce)

    headers = {
        "Content-Type": "application/json",
        "X-Capsule-Request-Attestation": ra_b64,
        "X-Capsule-Request-Attestation-Sig": sig_b64,
        "X-Capsule-Client-Pubkey": pubkey_b64,
    }
    req = urllib.request.Request(url=url, data=raw_body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            resp_body = resp.read()
            resp_headers = resp.headers
    except urllib.error.HTTPError as exc:
        status = exc.code
        resp_body = exc.read()
        resp_headers = exc.headers or {}

    capsule_id, capsule_id_source = _extract_capsule_id(status, resp_headers, resp_body)

    ack = None
    if capsule_id:
        ack = make_client_ack(client_key, capsule_id, nonce)

    return {
        "status": status,
        "capsule_id": capsule_id,
        "capsule_id_source": capsule_id_source,
        "ack": ack,
        "body": resp_body,
        "request_nonce": nonce,
    }


def write_ack(ack, out_dir: Path) -> Path:
    ack_record = {
        "type": "x-capsule-poc-client-ack/1",
        "action_capsule_id": ack.action_capsule_id,
        "request_nonce": ack.request_nonce,
        "timestamp": ack.timestamp,
        "ack_bytes_b64": base64.urlsafe_b64encode(ack.ack_bytes).decode("ascii"),
        "sig_b64": base64.urlsafe_b64encode(ack.sig).decode("ascii"),
        "public_key_pem_b64": base64.urlsafe_b64encode(ack.public_key_pem).decode("ascii"),
    }
    out_path = out_dir / f"client-ack-{ack.action_capsule_id}.json"
    out_path.write_text(json.dumps(ack_record, indent=2))
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="B's /v1/chat/completions endpoint")
    parser.add_argument("--model", required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--max-tokens", type=int, default=64)
    parser.add_argument("--client-nonce", default=None, help="mesh-llm's own client_nonce body field (separate from the bilateral request-attestation nonce)")
    parser.add_argument("--out-dir", required=True, help="where to persist A's client key + the Move-4 ack")
    parser.add_argument("--client-key", default=None, help="defaults to <out-dir>/client-key.pem")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = Path(args.client_key) if args.client_key else out_dir / "client-key.pem"
    client_key = _load_or_create_client_key(key_path)

    result = send_bilateral_request(
        url=args.url,
        model=args.model,
        prompt=args.prompt,
        client_key=client_key,
        max_tokens=args.max_tokens,
        client_nonce=args.client_nonce,
    )

    print(f"status={result['status']}")
    print(f"capsule_id={result['capsule_id']} (found via {result['capsule_id_source']})")
    if result["ack"] is not None:
        ack_path = write_ack(result["ack"], out_dir)
        print(f"Move-4 client ack written: {ack_path}")
        return 0
    print("WARNING: no capsule_id in the response -- no Move-4 ack written. "
          "See --url's response body:", file=sys.stderr)
    print(result["body"].decode("utf-8", errors="replace"), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

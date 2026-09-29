# SPDX-License-Identifier: Apache-2.0
"""Run the record-push corpus through the Python door (``record_push.py``)
and write its normalized answers.

    python tests/parity/record_push_python.py --out answers.json
    python tests/parity/record_push_python.py --golden   # rewrite golden/record_push.json

The answer format is the harness's contract with every implementation; it
is specified in ``README.md``. Each case runs on a fresh node, at the
corpus's fixed clock.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import hashlib  # noqa: E402

from capsule_emit.evidence_request import Refusal, verify_refusal_offline  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

import evidence_server as es  # noqa: E402
from peer_keys import ENV_PEER_KEYS  # noqa: E402
from record_push import handle_record_push  # noqa: E402
from share_policy import SharePolicy  # noqa: E402

sys.path.insert(0, str(HERE))
import parity_format  # noqa: E402

CORPUS = HERE / "corpus" / "record_push.json"
GOLDEN = HERE / "golden" / "record_push.json"
IMPLEMENTATION = "python-door"


def body_bytes(push: dict) -> bytes:
    """A push's body: ``body`` (UTF-8 text) or ``body_b64``."""
    if "body" in push:
        return push["body"].encode("utf-8")
    return base64.b64decode(push["body_b64"])


def _node_key(keys_dir: Path) -> tuple[Path, str]:
    from capsule_sidecar import NODE_KEY_FILENAME, load_or_create_signing_key

    load_or_create_signing_key(keys_dir)
    path = keys_dir / NODE_KEY_FILENAME
    private = serialization.load_pem_private_key(path.read_bytes(), None)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return path, public.hex()


def _line_counts(ledger_dir: Path) -> dict[str, int]:
    return {
        p.name: len(p.read_text(encoding="utf-8").splitlines())
        for p in sorted(ledger_dir.iterdir())
        if p.is_file()
    }


def _appended(ledger_dir: Path, before: dict[str, int]) -> dict[str, list]:
    out: dict[str, list] = {}
    for p in sorted(ledger_dir.iterdir()):
        if not p.is_file():
            continue
        lines = p.read_text(encoding="utf-8").splitlines()[before.get(p.name, 0):]
        if lines:
            out[p.name] = [json.loads(line) for line in lines]
    return out


def normalize_reply(reply: dict, body: bytes, node_key_id: str, now: str) -> dict:
    """The reply, with a refusal's signature checked rather than copied (each
    implementation signs with its own node key)."""
    if "reason" not in reply:
        return reply
    try:
        refusal = Refusal(
            request_digest=reply["request_digest"],
            reason=reply["reason"],
            issued_at=reply["issued_at"],
            key_id=reply["key_id"],
            sig=reply["sig"],
        )
        signed = refusal.key_id == node_key_id and verify_refusal_offline(refusal)
    except Exception:  # noqa: BLE001 -- an unreadable refusal is an unsigned one
        signed = False
    return {
        "refused": reply["reason"],
        "status": reply.get("status"),
        "signed_by_node": signed,
        "request_digest_is_body_sha256": reply.get("request_digest") == hashlib.sha256(body).hexdigest(),
        "issued_at_is_now": reply.get("issued_at") == now,
    }


def run_case(case: dict, now: str) -> list[dict]:
    node = case["node"]
    with tempfile.TemporaryDirectory(prefix="parity-") as scratch:
        scratch = Path(scratch)
        key_path, node_key_id = _node_key(scratch / "keys")
        ledger_dir = scratch / "ledger"
        ledger_dir.mkdir()
        ledger_path = ledger_dir / "capsules.jsonl"
        ledger_path.write_text("".join(json.dumps(r) + "\n" for r in node["own_records"]), encoding="utf-8")
        state = es.EvidenceServerState(
            ledger_dir=ledger_dir, ledger_path=ledger_path, signing_key_path=key_path
        )
        policy = (
            None
            if node["record_at_completion"] is None
            else SharePolicy(record_at_completion=node["record_at_completion"])
        )
        saved = os.environ.pop(ENV_PEER_KEYS, None)
        if node["peer_keys_env"] is not None:
            os.environ[ENV_PEER_KEYS] = node["peer_keys_env"]
        try:
            answers = []
            for p in case["pushes"]:
                raw = body_bytes(p)
                before = _line_counts(ledger_dir)
                reply = handle_record_push(state, raw, policy=policy, now=now, sender_peer_id=p["sender"])
                answers.append(
                    {
                        "reply": normalize_reply(reply, raw, node_key_id, now),
                        "appended": _appended(ledger_dir, before),
                    }
                )
            return answers
        finally:
            os.environ.pop(ENV_PEER_KEYS, None)
            if saved is not None:
                os.environ[ENV_PEER_KEYS] = saved


def run(corpus: dict) -> dict:
    return {
        "v": 1,
        "path": corpus["path"],
        "implementation": IMPLEMENTATION,
        "answers": {c["name"]: run_case(c, corpus["now"]) for c in corpus["cases"]},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path, help="write the answers here")
    group.add_argument("--golden", action="store_true", help="rewrite the golden answers")
    args = parser.parse_args()
    answers = run(json.loads(CORPUS.read_text(encoding="utf-8")))
    out = GOLDEN if args.golden else args.out
    parity_format.write(out, answers, "answers")
    print(f"wrote {len(answers['answers'])} case answers to {out}")


if __name__ == "__main__":
    main()

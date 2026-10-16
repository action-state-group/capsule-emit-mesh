#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""E15 -- an HTTP door on this node's evidence responder.

``evidence_responder.handle_evidence_request`` answers a
``draft-mih-agent-evidence-request-00`` request from one node's ledger and
node key. This module puts ``POST /evidence-request`` in front of it, so a
peer can ask and get back a signed artifact envelope (the interop profile's,
§6.2) or a signed refusal.

STANDALONE by design ([mesh-e15-evidence-http-route], Lane B): its own
module importing ``evidence_responder``, never wired into
``capsule_sidecar.py``'s own request handling, so it runs against whichever
ledger + node key a node names on the command line, sidecar running or not.

State this module needs from a node is exactly what
``evidence_responder.handle_evidence_request`` reads off its ``state``
argument -- ``ledger_dir`` and ``signing_key_path`` -- and nothing else
(no manifest, no runtime label, no advertisement). See
``EvidenceServerState``, deliberately lighter than
``capsule_sidecar.NodeState`` for that reason: this server answers evidence
requests, it never seals a capsule.

**The plugin's ledger.** The live serving path on a mesh node is the Rust
plugin, which owns ``<data_dir>/ledger/capsules.jsonl`` +
``signed-statements/``; ``capsule_sidecar.py``'s ``NodeState
.plugin_checkpoint`` wiring checkpoints that log READ-ONLY into a SIBLING
``checkpoints.jsonl``. The responder reads the records and that sibling file
itself (``evidence_responder.MeshEvidenceStore``) and never writes into the
plugin's directory, preserving the "two single-writer logs" invariant.

**Known scope limit** (documented, not hidden): an answer serves each
record's ledger line and proves it in the log (its inclusion under the
anchor checkpoint, the checkpoint's signature and consistency). A record
this repo's PYTHON producer sealed (``capsule_emit.seal()``) carries its
producer ``signature``/``key_id`` inline, so the line carries it too. The
Rust plugin instead signs a DETACHED COSE_Sign1 Signed Statement per capsule
(``signed-statements/<capsule_id>.cose``), which an answer does not carry.
So for a Rust-produced capsule an answer proves LOG integrity but not the
capsule's own producer signature. ``ask_history.py`` reports this
distinction rather than rounding a log-integrity pass up to a full verify.

Route:
    POST /evidence-request
        body = a -00 request (JSON: ``{subject, coverage, derivation?,
               deadline?, nonce?, route?}``).
        200 + the envelope or refusal in the JSON binding, with the
            fabric's additive ``status`` and the anchor's unsigned
            ``witness_receipts`` (``evidence_responder.answer_wire``) -- a refusal is a SIGNED answer, not an
            HTTP-level decline, so it is 200 too; an envelope carries
            ``artifact_digest``, a refusal ``reason``. A missing or empty
            ledger resolves to a signed refusal, never a 500.
    POST /evidence/deliver
        [mesh-adjudication-delivery-ack] -- body = a sealed twin-adjudication
        capsule's own canonical JSON bytes (opaque at this layer; see
        ``adjudication_delivery.py`` for the full contract). 200 +
        ``{"status": "received"}`` or a signed ``Refusal``
        (``request_malformed`` / ``policy_declined``) -- same
        signed-answer-always discipline as ``/evidence-request``, and the
        SAME ledger + node key ``EvidenceServerState`` already names; this
        route never opens a second ledger.
    GET /
        200 + a one-line human status. Carries no evidence -- in
        particular, never this node's own ledger filesystem path (that is
        local operational detail, not evidence, and telling a stranger
        where a file lives on this host is a gratuitous disclosure a
        neutral witness has no reason to make).
    anything else -> 404.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from adjudication_delivery import handle_delivery
from evidence_responder import answer_wire

__all__ = [
    "EvidenceServerState",
    "main",
    "make_evidence_handler",
    "run_evidence_server",
]


@dataclass(frozen=True)
class EvidenceServerState:
    """What ``handle_evidence_request``/``handle_delivery`` actually read
    off a node's state -- ``ledger_dir`` (the ledger DIRECTORY -- a
    ``cll.ledger.store.LedgerStore`` if migrated, else the legacy flat
    ``capsules.jsonl`` layout; see ``ledger_store_backend``), ``ledger_path``
    (kept for backward-compatible display/logging only -- never read for
    content, computed the same way ``capsule_sidecar.NodeState`` computes
    it) and ``signing_key_path`` (the node's own persisted Ed25519 key).
    Duck-type compatible with ``capsule_sidecar.NodeState`` (same three
    attribute names) without requiring everything else that dataclass needs
    to construct (a model manifest, a runtime label/digest, ...)."""

    ledger_dir: Path
    ledger_path: Path
    signing_key_path: Path


def make_evidence_handler(state: EvidenceServerState):
    """Build a BaseHTTPRequestHandler class closing over one node's state."""

    class EvidenceHandler(BaseHTTPRequestHandler):
        server_version = "capsule-evidence-server/0.1"

        def _write_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # BaseHTTPRequestHandler API names this do_POST
            path = self.path.strip("/")
            length = int(self.headers.get("Content-Length", "0") or "0")
            request_bytes = self.rfile.read(length) if length else b""

            if path == "evidence-request":
                try:
                    wire = answer_wire(state, request_bytes)
                except Exception as exc:  # noqa: BLE001 -- a broken local ledger, never the request
                    # Every request gets a signed answer except when this
                    # node's own ledger or checkpoints cannot be read; that is
                    # a server failure, reported as one rather than a dropped
                    # connection.
                    self._write_json(500, {"error": "ledger_unreadable", "detail": type(exc).__name__})
                    return
                self._write_json(200, wire)
                return

            if path == "evidence/deliver":
                # Delivery targets THIS node's own ledger directly (never
                # the plugin-ledger bridge's scratch view) -- a delivered
                # verdict is a NEW record this node holds, not a read
                # against an existing one.
                result = handle_delivery(state, request_bytes)
                self._write_json(200, result)
                return

            self._write_json(404, {"error": "not_found", "path": self.path})

        def do_GET(self) -> None:
            body = b"capsule-evidence-server: ready\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

    return EvidenceHandler


def run_evidence_server(
    *, host: str = "127.0.0.1", port: int = 8091, state: EvidenceServerState
) -> ThreadingHTTPServer:
    handler = make_evidence_handler(state)
    return ThreadingHTTPServer((host, port), handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--ledger-dir",
        required=True,
        help="this node's ledger directory -- a cll.ledger.store.LedgerStore if migrated "
        "([mesh-ledger-store-migration]), else a legacy flat capsules.jsonl -- e.g. this "
        "sidecar's own ledger_dir, or the Rust plugin's <data_dir>/ledger for the live serving "
        "path (its sibling checkpoints.jsonl is read, never written)",
    )
    parser.add_argument(
        "--node-key",
        required=True,
        help="path to this node's persisted Ed25519 signing key (node-key.pem) -- the SAME key "
        "every capsule on this ledger is already signed with",
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8091)
    args = parser.parse_args(argv)

    state = EvidenceServerState(
        ledger_dir=Path(args.ledger_dir),
        ledger_path=Path(args.ledger_dir) / "capsules.jsonl",
        signing_key_path=Path(args.node_key),
    )
    server = run_evidence_server(host=args.listen_host, port=args.listen_port, state=state)
    print(
        f"capsule evidence server listening on http://{args.listen_host}:{args.listen_port} "
        f"ledger={state.ledger_dir}"
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

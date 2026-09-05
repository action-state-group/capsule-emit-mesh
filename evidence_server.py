#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""E15 -- an HTTP door on the E14 evidence responder.

``evidence_responder.handle_evidence_request`` reaches ``capsule_emit.
evidence_request.answer()`` against one node's ledger + node key (E14,
capsule-emit#148; wired to a real ``NodeState`` in #83) -- but nothing can
REACH it from another node yet. This module is entirely ours: it puts
``POST /evidence-request`` in front of the SAME responder, unchanged, so a
peer can ask for a ``record``/``range`` and get back exactly what
``answer()`` returns -- an ``Artifact`` or a signed ``Refusal`` -- never a
new artifact shape, never beyond the bundle tier (never ``disclose()``).

STANDALONE by design ([mesh-e15-evidence-http-route], Lane B): its own
module importing ``evidence_responder``, never wired into
``capsule_sidecar.py``'s own request handling -- every Batch-1 item touches
that file, so this stays out of the merge-order queue and runs against
whichever ledger + node key a node names on the command line, sidecar
running or not.

State this module needs from a node is exactly what
``evidence_responder.handle_evidence_request`` reads off its ``state``
argument -- ``ledger_path`` and ``signing_key_path`` -- and nothing else
(no manifest, no runtime label, no advertisement). See
``EvidenceServerState``, deliberately lighter than
``capsule_sidecar.NodeState`` for that reason: this server answers evidence
requests, it never seals a capsule.

**The plugin-ledger bridge (Step 0 finding).** The live serving path on a
mesh node is the Rust plugin, which owns ``<data_dir>/ledger/capsules.jsonl``
+ ``signed-statements/`` -- ``capsule_sidecar.py``'s ``NodeState.
plugin_checkpoint`` wiring ([mesh-plugin-cll-consume] A2/A3) then
checkpoints that log READ-ONLY, into a SIBLING ``checkpoints.jsonl``
(``checkpointing.CheckpointState`` never becomes a second writer into a
ledger it does not own). ``capsule_emit.bundle.bundle()`` (what ``answer()``
dispatches to) only ever recognizes a checkpoint that arrives as an IN-BAND
``checkpoint_stamp``-kind leaf inside the SAME file it is bundling from
(``capsule_emit.witness.push()``'s convention, for a self-checkpointed
ledger) -- so pointed straight at the plugin's ``capsules.jsonl``, every
request refuses ``coverage_unsatisfiable``/``no_such_record``, even for a
record long since checkpointed, because ``bundle()`` can never see a
checkpoint that lives in a sibling file.

``_merged_evidence_view`` closes that gap, in-repo, without touching
``capsule-emit`` or the Rust plugin: given a ledger dir carrying a sibling
``checkpoints.jsonl``, it materializes a scratch JSONL file = the ledger's
own lines, unchanged, plus one synthesized ``checkpoint_stamp`` entry per
persisted checkpoint line, in the EXACT shape ``capsule_emit.witness.
_persist_checkpoint_stamp`` writes for a self-checkpointed ledger --
appended in checkpoint order, after the leaves each covers (never
interleaved before them, which would shift every later leaf's ``seq`` and
invalidate inclusion proofs the checkpoint never covered). An append-only
history tree's root at size S is a pure function of its first
``leaf_count(S)`` leaves, independent of anything appended after -- so a
trailing synthesized stamp reproduces the SAME root ``bundle()`` re-derives,
and the checkpoint's own signature/COSE-wire proof (computed once, for
real, by ``checkpointing.CheckpointState`` against the plugin's actual
bytes) verifies unchanged. Regenerated fresh on every request (never
cached, matching ``bundle()``'s own "re-derive from the ledger every call"
discipline) into a fresh ``tempfile`` -- never written back into the
plugin's own directory, preserving the "two single-writer logs" invariant.

**Known, honest scope limit this bridge does NOT close** (documented, not
hidden): ``capsule_emit.bundle.verify_bundle()``'s step-1 check expects a
capsule's OWN self-attested ``signature``/``key_id`` embedded inline --
that is this repo's PYTHON producer's convention (``capsule_emit.seal()``).
The Rust plugin instead signs a DETACHED COSE_Sign1 Signed Statement per
capsule (``signed-statements/<capsule_id>.cose``, verified today by
``stranger_verify_bundle.py``'s ``_transparent_check`` against a COPY of
the ledger dir) -- and a bundle-tier ``Artifact`` never carries that
detached statement (only the COVERING CHECKPOINT's own COSE wire form,
``Bundle.checkpoint_cose``). So for a Rust-produced capsule, a bundle-tier
answer proves LOG integrity (inclusion, non-tamper-since-checkpoint, the
checkpoint's own signature) but does NOT prove the individual capsule's OWN
producer signature -- that provenance question is out of the bundle tier's
reach entirely, not a bug in this bridge. ``ask_history.py`` reports this
distinction rather than rounding a log-integrity pass up to a full verify.

Route:
    POST /evidence-request
        body = the E14 request map (JSON: ``{subject, coverage?,
               derivation?, deadline?, nonce?}``).
        200 + the ``Artifact``/``Refusal`` JSON exactly as
            ``answer()``/``.to_dict()`` returns it -- a refusal is a SIGNED
            answer, not an HTTP-level decline, so it is 200 too;
            distinguish by the presence of ``bundles`` (Artifact) vs
            ``reason`` (Refusal). A missing/empty ledger resolves to a
            signed ``no_such_record`` refusal INSIDE ``answer()`` itself --
            never a 500.
    POST /evidence/deliver
        [mesh-adjudication-delivery-ack] -- body = a sealed twin-adjudication
        capsule's own canonical JSON bytes (opaque at this layer; see
        ``adjudication_delivery.py`` for the full contract). 200 +
        ``{"status": "received"}`` or a signed ``Refusal``
        (``request_malformed`` / ``policy_decline``) -- same
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
import tempfile
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from adjudication_delivery import handle_delivery
from evidence_responder import handle_evidence_request

__all__ = [
    "EvidenceServerState",
    "main",
    "make_evidence_handler",
    "run_evidence_server",
]


@dataclass(frozen=True)
class EvidenceServerState:
    """The two paths ``handle_evidence_request`` actually reads off a
    node's state -- ``ledger_path`` (the JSONL file, not its directory) and
    ``signing_key_path`` (the node's own persisted Ed25519 key). Duck-type
    compatible with ``capsule_sidecar.NodeState`` (same two attribute
    names) without requiring everything else that dataclass needs to
    construct (a model manifest, a runtime label/digest, ...)."""

    ledger_path: Path
    signing_key_path: Path


def _merged_evidence_view(ledger_path: Path) -> Path:
    """Return the path ``answer()``/``bundle()`` should actually read for
    ``ledger_path`` -- itself unchanged, UNLESS a sibling
    ``checkpoints.jsonl`` exists (the plugin-ledger read-only-checkpointed
    shape; see module docstring), in which case a fresh scratch file
    carrying ``ledger_path``'s own lines plus one synthesized
    ``checkpoint_stamp`` entry per persisted checkpoint is written and
    returned instead. Never mutates ``ledger_path`` or its directory.
    """
    checkpoints_path = ledger_path.parent / "checkpoints.jsonl"
    if not checkpoints_path.exists():
        return ledger_path

    from capsule_emit.checkpoint import CheckpointRecord
    from capsule_emit.ledger import CHECKPOINT_STAMP_KIND

    stamp_lines: list[str] = []
    for raw in checkpoints_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        cp_line = json.loads(raw)
        checkpoint_cose_hex = cp_line.pop("checkpoint_cose", None)
        cp = CheckpointRecord.from_dict(cp_line)
        stamp_entry: dict[str, Any] = {
            "kind": CHECKPOINT_STAMP_KIND,
            "v": 1,
            "capsule_id": cp.entry_digest(),
            "checkpoint": cp.to_dict(),
        }
        if checkpoint_cose_hex is not None:
            stamp_entry["checkpoint_cose"] = checkpoint_cose_hex
        stamp_lines.append(json.dumps(stamp_entry, sort_keys=True))

    if not stamp_lines:
        return ledger_path

    base = ledger_path.read_text(encoding="utf-8") if ledger_path.exists() else ""
    merged = base + ("" if base.endswith("\n") or not base else "\n") + "\n".join(stamp_lines) + "\n"

    fd, tmp_name = tempfile.mkstemp(prefix="evidence-view-", suffix=".jsonl")
    tmp_path = Path(tmp_name)
    with open(fd, "w", encoding="utf-8") as fh:
        fh.write(merged)
    return tmp_path


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
                effective_path = _merged_evidence_view(state.ledger_path)
                effective_state = EvidenceServerState(
                    ledger_path=effective_path, signing_key_path=state.signing_key_path
                )
                result = handle_evidence_request(effective_state, request_bytes)
                self._write_json(200, result.to_dict())
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
        help="directory containing capsules.jsonl -- e.g. this sidecar's own ledger_dir, or the "
        "Rust plugin's <data_dir>/ledger for the live serving path (auto-bridged if a sibling "
        "checkpoints.jsonl is present)",
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
        ledger_path=Path(args.ledger_dir) / "capsules.jsonl",
        signing_key_path=Path(args.node_key),
    )
    server = run_evidence_server(host=args.listen_host, port=args.listen_port, state=state)
    print(
        f"capsule evidence server listening on http://{args.listen_host}:{args.listen_port} "
        f"ledger={state.ledger_path}"
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

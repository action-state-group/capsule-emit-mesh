#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disclosure-on-request over HTTP: "give me the bundle for exchange/stage X".

`mesh_coordinator_bundle_flow.py` already models disclosure-on-request as a
plain callable (`StageNode`, `ask_stage_for_bundle`) so the 3-way demo and its
tests can run entirely in-process. This module is the thin wire wrapper for
when the coordinator and the stage node are two different processes (the
ask->verify quickstart): a node runs this as a tiny HTTP server in front of
whatever bundles it has already sealed, and the coordinator fetches them with
a plain GET instead of an in-process call. It adds NO new verification logic
— disclosure is still a bounded, offline-verifiable `StageBundle`, and it is
still `verify_coordinator_receipt` (mesh_coordinator_bundle_flow.py) that does
the actual proving on the coordinator side.

Route:
    GET /bundle/<run_id>/<hop_id>
        200 + StageBundle JSON (mesh_coordinator_bundle_flow.stage_bundle_to_dict
             shape) if this node has that hop's bundle for that run and
             chooses to disclose it.
        404 otherwise — declining is silent-by-design (mirrors
             `ask_stage_for_bundle` returning None): a 404 here is exactly a
             stage-node "no bundle" answer, never a false disclosure.
    GET /
        200 + a one-line human status (run_id + hops served), for a quick
             "is this thing up" check. Carries no evidence.

The reference `StageNode` this module ships (`directory_stage_node`) reads
each hop's bundle from `<bundles-dir>/<hop_id>.json`, written in advance by
whatever sealed the stage capsule (e.g. `capsule_sidecar.py`, or
`mesh_record_emitter.emit_lifecycle_record` directly). It answers ONLY for the
one `run_id` it was started with — a node running this quickstart endpoint
serves one run at a time, matching the single-run shape of the ask->verify
walkthrough.
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from mesh_coordinator_bundle_flow import StageBundle, StageNode, stage_bundle_to_dict

__all__ = [
    "directory_stage_node",
    "make_disclosure_handler",
    "run_disclosure_endpoint",
    "main",
]


def directory_stage_node(bundles_dir: Path, *, run_id: str) -> StageNode:
    """A `StageNode` that discloses whatever bundle files are on disk.

    Reads `<bundles_dir>/<hop_id>.json` (stage_bundle_to_dict shape) lazily on
    each ask, so a node can add a hop's bundle after this endpoint is already
    running. Declines (returns None) for any run_id other than the one this
    node was started for, and for any hop with no bundle file — three-state,
    never a false disclosure.
    """
    bundles_dir = Path(bundles_dir)

    def disclose(asked_run_id: str, hop_id: str) -> StageBundle | None:
        if asked_run_id != run_id:
            return None
        path = bundles_dir / f"{hop_id}.json"
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        bundle = StageBundle(
            hop_id=data["hop_id"],
            stage_capsule=data["stage_capsule"],
            inclusion_proof=data.get("inclusion_proof"),
        )
        if bundle.hop_id != hop_id:
            # The file on disk claims a different hop than its own filename —
            # refuse to disclose rather than answer a question with the wrong
            # bundle (ask_stage_for_bundle enforces the same rule in-process).
            return None
        return bundle

    return disclose


def make_disclosure_handler(node: StageNode, *, run_id: str, hop_ids: list[str]):
    """Build a BaseHTTPRequestHandler class closing over one node's disclosures."""

    class DisclosureHandler(BaseHTTPRequestHandler):
        server_version = "capsule-disclosure-endpoint/0.1"

        def _write_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # BaseHTTPRequestHandler API names this do_GET
            parts = [unquote(p) for p in self.path.strip("/").split("/") if p]
            if not parts:
                body = f"capsule-disclosure-endpoint: run_id={run_id} hops={hop_ids}\n".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if len(parts) == 3 and parts[0] == "bundle":
                asked_run_id, hop_id = parts[1], parts[2]
                bundle = node(asked_run_id, hop_id)
                if bundle is None:
                    self._write_json(404, {"error": "declined_or_absent", "run_id": asked_run_id, "hop_id": hop_id})
                    return
                self._write_json(200, stage_bundle_to_dict(bundle))
                return
            self._write_json(404, {"error": "not_found", "path": self.path})

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

    return DisclosureHandler


def run_disclosure_endpoint(
    *, host: str = "127.0.0.1", port: int = 8090, node: StageNode, run_id: str, hop_ids: list[str]
) -> ThreadingHTTPServer:
    handler = make_disclosure_handler(node, run_id=run_id, hop_ids=hop_ids)
    return ThreadingHTTPServer((host, port), handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, help="the run_id this endpoint answers disclosure asks for")
    parser.add_argument(
        "--bundles-dir",
        required=True,
        help="directory containing <hop_id>.json StageBundle files (see stage_bundle_to_dict shape)",
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8090)
    args = parser.parse_args(argv)

    bundles_dir = Path(args.bundles_dir)
    hop_ids = sorted(p.stem for p in bundles_dir.glob("*.json")) if bundles_dir.is_dir() else []
    node = directory_stage_node(bundles_dir, run_id=args.run_id)
    server = run_disclosure_endpoint(
        host=args.listen_host, port=args.listen_port, node=node, run_id=args.run_id, hop_ids=hop_ids
    )
    print(
        f"capsule disclosure endpoint listening on http://{args.listen_host}:{args.listen_port} "
        f"run_id={args.run_id} bundles_dir={bundles_dir} hops={hop_ids or '(none found yet)'}"
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

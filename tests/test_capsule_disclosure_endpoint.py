#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""capsule_disclosure_endpoint.py -- disclosure-on-request over the wire.

PURPOSE
    Prove `directory_stage_node` obeys the same three-state discipline
    `ask_stage_for_bundle` already enforces in-process (mesh_coordinator_
    bundle_flow.py): disclose only for the run/hop it was actually asked
    about, decline (None / HTTP 404) for anything else -- never a false
    disclosure -- and that the HTTP layer on top adds no new behavior beyond
    carrying that same answer over a socket.
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import capsule_disclosure_endpoint as cde
from mesh_coordinator_bundle_flow import StageBundle, stage_bundle_to_dict
from mesh_record_emitter import default_node_state, emit_lifecycle_record, make_transcript_summary

RUN_ID = "run-endpoint-test-0001"


def _seal(hop_id: str) -> dict:
    node = default_node_state(node_id=f"prov/{hop_id}")
    return emit_lifecycle_record(
        node,
        terminal_state="completed",
        exchange_id=RUN_ID,
        hop_id=hop_id,
        local_peer_id=f"host-{hop_id}",
        transcript=make_transcript_summary(2, 2),
    )


def _write_bundle(bundles_dir: Path, hop_id: str, sealed: dict) -> None:
    bundle = StageBundle(hop_id=hop_id, stage_capsule=sealed)
    (bundles_dir / f"{hop_id}.json").write_text(json.dumps(stage_bundle_to_dict(bundle)))


class TestDirectoryStageNode:
    def test_discloses_matching_hop(self, tmp_path):
        _write_bundle(tmp_path, "stage-0", _seal("stage-0"))
        node = cde.directory_stage_node(tmp_path, run_id=RUN_ID)
        bundle = node(RUN_ID, "stage-0")
        assert bundle is not None
        assert bundle.hop_id == "stage-0"

    def test_declines_wrong_run_id(self, tmp_path):
        _write_bundle(tmp_path, "stage-0", _seal("stage-0"))
        node = cde.directory_stage_node(tmp_path, run_id=RUN_ID)
        assert node("some-other-run", "stage-0") is None

    def test_declines_missing_hop_file(self, tmp_path):
        node = cde.directory_stage_node(tmp_path, run_id=RUN_ID)
        assert node(RUN_ID, "stage-0") is None

    def test_refuses_filename_hop_mismatch(self, tmp_path):
        # File named stage-1.json but the bundle inside claims hop stage-0 --
        # must refuse rather than answer the wrong hop under the right name.
        _write_bundle(tmp_path, "stage-0", _seal("stage-0"))
        (tmp_path / "stage-1.json").write_text((tmp_path / "stage-0.json").read_text())
        node = cde.directory_stage_node(tmp_path, run_id=RUN_ID)
        assert node(RUN_ID, "stage-1") is None


class TestHTTPServer:
    def test_get_bundle_200_and_get_unknown_404(self, tmp_path):
        _write_bundle(tmp_path, "stage-0", _seal("stage-0"))
        node = cde.directory_stage_node(tmp_path, run_id=RUN_ID)
        server = cde.run_disclosure_endpoint(host="127.0.0.1", port=0, node=node, run_id=RUN_ID, hop_ids=["stage-0"])
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/bundle/{RUN_ID}/stage-0", timeout=5) as resp:
                assert resp.status == 200
                body = json.loads(resp.read())
                assert body["hop_id"] == "stage-0"

            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/bundle/{RUN_ID}/stage-9", timeout=5)
                raise AssertionError("expected HTTPError 404")
            except urllib.error.HTTPError as exc:
                assert exc.code == 404

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
                assert resp.status == 200
        finally:
            server.shutdown()
            thread.join(timeout=5)

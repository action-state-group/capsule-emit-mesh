#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Ask->verify quickstart, over real HTTP, in one command.

`examples/coordinator_3way_demo.py` already proves the ask->verify mechanism
end to end, but entirely in-process (the coordinator calls the stage-node
functions directly). This script is the same 3-stage story, except the
stage-node runs as an actual `capsule_disclosure_endpoint.py` HTTP server and
the coordinator's receipt is verified by actually invoking
`capsule_coordinator_verify.py` as a subprocess — the two pieces a real
Mesh-LLM coordinator and a real stage node would run as separate processes.

No new sealing/verification logic here: this just wires the SAME
`mesh_record_emitter` / `mesh_coordinator_bundle_flow` calls the 3-way demo
uses into two real OS processes talking over a loopback socket, then runs the
verify CLI so you can see the exact command (and exact output) you'd run
against a real disclosure endpoint.

Run:  python3 examples/ask_verify_http_quickstart.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mesh_record_emitter import (
    default_node_state,
    emit_lifecycle_record,
    make_transcript_summary,
)
from mesh_coordinator_receipt_emitter import TopologyEntry, default_node_state as coord_state
from mesh_coordinator_bundle_flow import (
    StageBundle,
    compose_receipt_from_disclosures,
    stage_bundle_to_dict,
)

RUN_ID = "run-ask-verify-http-quickstart"
PORT = 8090
TOPOLOGY = [
    TopologyEntry(seq=0, hop_id="stage-0", role="provider", observation_point="serving_host_ingress"),
    TopologyEntry(seq=1, hop_id="stage-1", role="provider", observation_point="backend_dispatch"),
    TopologyEntry(seq=2, hop_id="stage-2", role="provider", observation_point="client_egress"),
]


def main() -> int:
    workdir = Path(tempfile.mkdtemp(prefix="ask-verify-quickstart-"))
    bundles_dir = workdir / "bundles"
    bundles_dir.mkdir()

    print(f"[1] Sealing 3 stage records (a real node would seal these itself) -> {bundles_dir}", flush=True)
    disclosures = {}
    for entry in TOPOLOGY:
        state = default_node_state(node_id=f"mesh-provider/{entry.hop_id}")
        sealed = emit_lifecycle_record(
            state,
            terminal_state="completed",
            observation_point=entry.observation_point,
            exchange_id=RUN_ID,
            hop_id=entry.hop_id,
            local_peer_id=f"serving-host-{entry.hop_id}",
            transcript=make_transcript_summary(4, 4),
        )
        bundle = StageBundle(hop_id=entry.hop_id, stage_capsule=sealed)
        disclosures[entry.hop_id] = bundle
        (bundles_dir / f"{entry.hop_id}.json").write_text(json.dumps(stage_bundle_to_dict(bundle)))

    receipt_path = workdir / "receipt.json"
    print(f"[2] Coordinator composes the signed receipt -> {receipt_path}", flush=True)
    receipt = compose_receipt_from_disclosures(
        coord_state(node_id="mesh-coordinator/skippy"), run_id=RUN_ID, topology=TOPOLOGY, disclosures=disclosures
    )
    receipt_path.write_text(json.dumps(receipt))

    print(f"[3] Starting a REAL disclosure endpoint on http://127.0.0.1:{PORT} (this node's stage bundles)", flush=True)
    endpoint = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve().parent.parent / "capsule_disclosure_endpoint.py"),
            "--run-id", RUN_ID,
            "--bundles-dir", str(bundles_dir),
            "--listen-port", str(PORT),
        ],
    )
    time.sleep(0.5)  # let the socket come up before the verify CLI asks it anything

    verify_cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent.parent / "capsule_coordinator_verify.py"),
        str(receipt_path),
    ] + [f"--bundle-url={t.hop_id}=http://127.0.0.1:{PORT}" for t in TOPOLOGY]

    print(f"\n[4] Coordinator asks the endpoint for each hop and verifies offline:\n    {' '.join(verify_cmd)}\n", flush=True)
    try:
        result = subprocess.run(verify_cmd, check=False)
    finally:
        endpoint.terminate()
        endpoint.wait(timeout=5)

    print(f"\n(scratch files kept at {workdir} -- delete when done)")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

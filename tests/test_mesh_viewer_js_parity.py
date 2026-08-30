# SPDX-License-Identifier: Apache-2.0
"""Digest parity: mesh_verify.js recomputes the SAME capsule_id the Python
reference (agent_action_capsule.compute_capsule_id) does.

mesh_verify.js's in-browser capsule_id recompute is the load-bearing "verifies
offline" claim of the viewer -- if the JS JCS/normalize port drifts from
canonical.py, the page would show a green check for bytes it never actually
re-derived. This test drives the real mesh_verify.js under node against real
mesh capsules and asserts byte-for-byte agreement with the Python id.

Skipped (not failed) when node is unavailable -- the repo's CI is a clean
Python venv with no node, so this runs locally and in any node-bearing CI, and
is a no-op elsewhere rather than a false red. The Python-side payload/shape
assertions live in test_capsule_mesh_viewer.py and always run.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from agent_action_capsule import compute_capsule_id

REPO = Path(__file__).resolve().parent.parent
JS = REPO / "mesh_viewer_static" / "mesh_verify.js"

# Real mesh capsules of both shapes actually shipped in this workspace.
_REAL_LEDGERS = [
    REPO / "ledger-live" / "capsules.jsonl",  # legacy flat shape
]


def _sample_capsules() -> list[dict]:
    caps: list[dict] = []
    for path in _REAL_LEDGERS:
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    caps.append(json.loads(line))
    # A synthetic nested-shape capsule (capsule-producer/0.2.0), so the test
    # covers the current serving_provenance{model,hardware,usage} shape even if
    # the flat ledger-live fixtures are the only ones checked in.
    nested = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-02",
        "format_version": "2",
        "operator": "op",
        "timestamp": "2026-08-30T00:00:00Z",
        "model_attestation": {
            "model_id": "allowed-test-model",
            "provider": "mesh-llm",
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "client_nonce": "n",
                    "serving_provenance": {
                        "served_by_node_id": "x" * 64,
                        "hardware": {"gpu": "Apple M4 Max", "vram_bytes": 28991029248, "is_soc": True},
                        "usage": {"prompt_tokens": 41, "completion_tokens": 2, "total_tokens": 43},
                    },
                }
            },
        },
        "effect": {"request_digest": "1" * 64, "response_digest": "2" * 64},
        "chain": {"parent_capsule_id": "p" * 64, "relation": "follows"},
    }
    nested["capsule_id"] = compute_capsule_id(nested)
    caps.append(nested)
    return caps


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available; JS parity is a local/CI-with-node check")
def test_js_recompute_matches_python_reference(tmp_path):
    caps = _sample_capsules()
    assert caps, "expected at least the synthetic nested capsule"
    caps_path = tmp_path / "caps.jsonl"
    caps_path.write_text("\n".join(json.dumps(c) for c in caps), encoding="utf-8")

    harness = tmp_path / "harness.mjs"
    harness.write_text(
        textwrap.dedent(
            f"""
            import fs from "fs";
            import vm from "vm";
            import crypto from "crypto";
            const js = fs.readFileSync({json.dumps(str(JS))}, "utf8");
            const sandbox = {{
              window: {{}},
              document: {{ readyState:"complete", addEventListener(){{}}, querySelector(){{return null;}}, getElementById(){{return null;}} }},
              location: {{ hash:"", href:"" }},
              crypto: {{ subtle: {{ async digest(a,b){{ const h=crypto.createHash("sha256"); h.update(Buffer.from(b)); return h.digest().buffer; }} }} }},
              TextEncoder, TextDecoder, atob:(s)=>Buffer.from(s,"base64").toString("binary"), console,
            }};
            vm.createContext(sandbox);
            vm.runInContext(js, sandbox);
            const caps = fs.readFileSync({json.dumps(str(caps_path))},"utf8").trim().split("\\n").map(l=>JSON.parse(l));
            const out = [];
            for (const c of caps) out.push(await sandbox.window.__mesh_recomputeCapsuleId(c));
            process.stdout.write(JSON.stringify(out));
            """
        ),
        encoding="utf-8",
    )

    result = subprocess.run(["node", str(harness)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    js_ids = json.loads(result.stdout)
    py_ids = [compute_capsule_id(c) for c in caps]
    stored = [c["capsule_id"] for c in caps]
    assert js_ids == py_ids == stored, (
        f"JS/Python/stored capsule_id divergence:\n js={js_ids}\n py={py_ids}\n stored={stored}"
    )

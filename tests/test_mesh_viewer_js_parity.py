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
        "format_version": "4",
        "canonicalization_id": "jcs",
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
    stored = [c["capsule_id"] for c in caps]
    # mesh_verify.js keeps both recompute branches (vintage format-2 jcs-n AND
    # format-4 jcs) so old permalinks stay verifiable offline. The Python
    # reference (agent_action_capsule) dropped the vintage branch outright
    # (agent-action-capsule#99, "Format-4-only canonical reference") -- its
    # compute_capsule_id raises on anything but format_version "4". So the
    # ledger-live/capsules.jsonl legacy-flat-shape entries (real, signed,
    # anchored historical records -- see ledger-live/README.md; their stored
    # capsule_id must never be rewritten) are only checked JS-vs-stored here.
    # The synthetic format-4 capsule above is the one that exercises the full
    # JS/Python/stored triple-check.
    assert js_ids == stored, f"JS/stored capsule_id divergence:\n js={js_ids}\n stored={stored}"
    for cap, js_id in zip(caps, js_ids):
        if cap.get("format_version") == "4":
            assert compute_capsule_id(cap) == js_id == cap["capsule_id"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available; JS parity is a local/CI-with-node check")
def test_js_served_facts_digest_matches_python_seal_construction(tmp_path):
    """The conversation block's response verify recomputes response_digest in
    the browser. It must be the SAME digest the Rust seal path binds
    (JCS of {model, usage}). Drive the real mesh_verify.js under node and
    compare to the Python `served_facts_digest`."""
    from capsule_mesh_viewer import served_facts_digest

    sp = {
        "model": "local-gguf/sha256-887fbdc66ab91eb5",
        "prompt_tokens": 46,
        "completion_tokens": 39,
        "total_tokens": 85,
    }
    py_digest = served_facts_digest(sp)
    assert py_digest is not None

    harness = tmp_path / "facts.mjs"
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
            const sp = {json.dumps(sp)};
            const d = await sandbox.window.__mesh_servedFactsDigest(sp);
            process.stdout.write(d);
            """
        ),
        encoding="utf-8",
    )
    result = subprocess.run(["node", str(harness)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == py_digest, (
        f"JS served-facts digest != Python: js={result.stdout.strip()} py={py_digest}"
    )

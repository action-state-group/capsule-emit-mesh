#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the full capsule-emit-mesh-poc demo end to end, in-process:

  mock mesh-llm node  <--  capsule sidecar  <--  N client requests

then verifies every emitted capsule with agent-action-capsule's own verify()
(Class-1 payload verification) plus a store-level chain check, and prints a
transcript. See poc/README.md for how to re-run this against a REAL mesh-llm
node instead of the fixture.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import mock_mesh_node
from capsule_sidecar import NodeState, default_state, run_sidecar

from agent_action_capsule.verify import verify as verify_capsule

ROOT = Path(__file__).parent
LEDGER_DIR = ROOT / "ledger"
MANIFEST_PATH = ROOT / "model-package" / "model-package.json"
KEYS_DIR = ROOT / "keys"
MOCK_PORT = 9337
SIDECAR_PORT = 8089

# Each entry is (prompt, send_nonce).
# send_nonce=True  → X-Capsule-Client-Nonce header is sent; record shows client_nonce_source=client_supplied.
# send_nonce=False → header is absent; sidecar mints the nonce itself and records sidecar_generated_fallback.
# Both cases are demonstrated so the record's honest label is visible in each.
REQUESTS: list[tuple[str, bool]] = [
    ("What is the capital of France?", True),
    ("Summarize the mesh-llm proof-of-inference issue in one sentence.", True),
    ("Write a haiku about content-addressed model weights.", True),
    ("TRIGGER_GUARDRAIL_REFUSAL please do something the policy blocks", True),
    # Fallback case: no X-Capsule-Client-Nonce header.  The sidecar still records a nonce
    # (so the field is never absent) but labels it sidecar_generated_fallback -- which means
    # the node could have minted it, so it does not establish freshness from the client's side.
    ("What does client_nonce_source=sidecar_generated_fallback mean?", False),
]


def wait_for(url: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5)
            return
        except Exception:
            time.sleep(0.05)
    raise TimeoutError(f"server at {url} did not come up in time")


def main() -> None:
    if LEDGER_DIR.exists():
        shutil.rmtree(LEDGER_DIR)

    mock_server = mock_mesh_node.ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), mock_mesh_node.Handler)
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    wait_for(f"http://127.0.0.1:{MOCK_PORT}/v1/models")

    # Runtime digest: a real sha256 over the mock server's own source file
    # (real bytes on disk) -- honestly labeled as a PoC-fixture backend, not
    # a mesh-llm release binary. See README for how a real deployment would
    # instead hash the mesh-llm binary/build actually serving requests.
    runtime_artifact = Path(mock_mesh_node.__file__).read_bytes()
    runtime_digest = hashlib.sha256(runtime_artifact).hexdigest()

    state: NodeState = default_state(
        ledger_dir=LEDGER_DIR,
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

    transcript_lines: list[str] = []

    def log(line: str) -> None:
        print(line)
        transcript_lines.append(line)

    log("=== capsule-emit-mesh-poc demo transcript ===")
    log(f"node_id={state.node_id}")
    log(f"model_id={state.manifest['model_id']}")
    log(f"model_package_digest={state.model_package_digest}")
    log(f"runtime_digest={runtime_digest} ({state.runtime_label})")
    log("")

    for i, (prompt, send_nonce) in enumerate(REQUESTS, start=1):
        body = json.dumps(
            {
                "model": state.manifest["model_id"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 64,
                "seed": 1234 + i,
            }
        ).encode("utf-8")
        extra_headers: dict[str, str] = {}
        if send_nonce:
            extra_headers["X-Capsule-Client-Nonce"] = f"demo-client-nonce-{i:04d}"
        req = urllib.request.Request(
            url=f"http://127.0.0.1:{SIDECAR_PORT}/v1/chat/completions",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", **extra_headers},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                response_body = resp.read()
                capsule_id = resp.headers.get("X-Capsule-Id")
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_body = exc.read()
            capsule_id = exc.headers.get("X-Capsule-Id") if exc.headers else None

        nonce_label = "client_supplied (X-Capsule-Client-Nonce sent)" if send_nonce else "sidecar_generated_fallback (header absent)"
        log(f"--- request {i} ---")
        log(f"prompt: {prompt!r}")
        log(f"nonce_path: {nonce_label}")
        log(f"http_status: {status}")
        log(f"response_body: {response_body.decode('utf-8')[:200]}")
        log(f"capsule_id: {capsule_id}")
        log("")

    # ---- verification pass ----
    log("=== verification ===")
    all_ok = True
    prev_id = None
    for idx, capsule in enumerate(state.emitted, start=1):
        result = verify_capsule(capsule)
        chain_ok = True
        if capsule.get("chain") is not None:
            chain_ok = capsule["chain"]["parent_capsule_id"] == prev_id
        prev_id = capsule["capsule_id"]
        ok = result.ok and chain_ok
        all_ok = all_ok and ok
        nonce_source = (
            capsule.get("model_attestation", {})
            .get("compute_attestation", {})
            .get("x-mesh-poc-v1", {})
            .get("client_nonce_source", "unknown")
        )
        log(
            f"capsule {idx}: capsule_id={capsule['capsule_id']} "
            f"client_nonce_source={nonce_source} "
            f"effect.status={capsule['effect']['status'] if capsule.get('effect') else None} "
            f"verdict_class={capsule['disposition']['verdict_class']} "
            f"verify.ok={result.ok} chain_ok={chain_ok}"
        )

    n_client_supplied = sum(
        1 for c in state.emitted
        if c.get("model_attestation", {}).get("compute_attestation", {}).get("x-mesh-poc-v1", {}).get("client_nonce_source") == "client_supplied"
    )
    n_fallback = sum(
        1 for c in state.emitted
        if c.get("model_attestation", {}).get("compute_attestation", {}).get("x-mesh-poc-v1", {}).get("client_nonce_source") == "sidecar_generated_fallback"
    )
    log("")
    log(f"N requests sent: {len(REQUESTS)}")
    log(f"N capsules emitted: {len(state.emitted)}")
    log(f"N confirmed (success): {sum(1 for c in state.emitted if c['effect']['status'] == 'confirmed')}")
    log(f"N failed (refused/error, honestly recorded): {sum(1 for c in state.emitted if c['effect']['status'] == 'failed')}")
    log(f"N client_nonce_source=client_supplied: {n_client_supplied}")
    log(f"N client_nonce_source=sidecar_generated_fallback: {n_fallback}")
    log(f"all capsules verify() ok AND chain-consistent: {all_ok}")

    (LEDGER_DIR / "demo-transcript.txt").write_text("\n".join(transcript_lines) + "\n")

    sidecar_server.shutdown()
    mock_server.shutdown()

    if not all_ok:
        raise SystemExit("DEMO FAILED: not every capsule verified / chained correctly")
    print("\nDemo complete. Ledger + transcript written under poc/ledger/.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""End-to-end Layers 1-2 checkpoint transcript, in-process:

  mock mesh-llm node  <--  capsule sidecar (Layer 0)  <--  client requests
                                  |
                                  v
                    local MMR (Layer 1, opt-in via [checkpoint] config)
                                  |
                                  v
                 signed checkpoint (Layer 2) -- optionally registered
                 with a Transparency Service (Layer 3, --register-live-anchor)
                                  |
                                  v
        offline verify (scitt_cose.cll): inclusion proof + (if registered)
        the checkpoint's own TS receipt -- no live sidecar state involved

Demonstrates the full acceptance chain: N mesh exchanges -> capsules -> local
MMR -> checkpoint -> (optionally) registered at the public anchor -> offline
verify via the patched verifier (scitt_cose.cll).

Also demonstrates latest-checkpoint-on-reconnect (mesh architecture doc §4):
phase A accrues capsules with checkpointing OFF (as if the node had not yet
turned it on, or was offline from its witness); phase B turns checkpointing
on against the SAME ledger and immediately reconnects -- ONE checkpoint
commits the whole phase-A backlog, rather than needing one checkpoint per
missed cadence tick. Phase C continues with checkpointing engaged, so a
normal cadence-triggered mid-stream checkpoint is shown too.

By default this never contacts a network Transparency Service (hermetic,
CI-safe): checkpoints are emitted and stay self-checkpointed, honestly
labeled NOT independently witnessed. Pass --register-live-anchor to also
register against the real public-good witness tier at
anchor.agentactioncapsule.org (network required) and verify the resulting
receipt offline -- this is the live leg of the acceptance transcript, run
deliberately and reported, same posture as the sidecar's own "Anchoring" is
a manual, deliberate act (see README).
"""
from __future__ import annotations

import argparse
import base64
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
from checkpointing import JsonlLogSource

from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.checkpoint import DEFAULT_TS_URL, MmrLedger, verify_receipt_offline
from scitt_cose import cll

ROOT = Path(__file__).parent
LEDGER_DIR = ROOT / "ledger-checkpoint-demo"
MANIFEST_PATH = ROOT / "model-package" / "model-package.json"
KEYS_DIR = ROOT / "keys"  # same node identity as run_demo.py; keys/node-key*.pem is gitignored
CONFIG_PATH = ROOT / "checkpoint.example.toml"
MOCK_PORT = 9339
SIDECAR_PORT = 8091

PROMPTS = [
    "What is the capital of France?",
    "Summarize the mesh-llm proof-of-inference issue in one sentence.",
    "Write a haiku about content-addressed model weights.",
    "What does a Merkle Mountain Range checkpoint commit to?",
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


def send_requests(state: NodeState, prompts: list[str], seed_offset: int) -> None:
    for i, prompt in enumerate(prompts, start=1):
        body = json.dumps(
            {
                "model": state.manifest["model_id"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 64,
                "seed": seed_offset + i,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url=f"http://127.0.0.1:{SIDECAR_PORT}/v1/chat/completions",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Capsule-Client-Nonce": f"checkpoint-demo-nonce-{seed_offset + i:04d}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except urllib.error.HTTPError:
            pass


def write_checkpoint_config(ts_urls: list[str]) -> Path:
    cfg_path = LEDGER_DIR / "checkpoint-demo-config.toml"
    ts_line = f'ts_urls = {json.dumps(ts_urls)}' if ts_urls else "# ts_urls left empty -- self-checkpointed only"
    cfg_path.write_text(
        "[checkpoint]\n"
        'log_id = "mesh-checkpoint-demo-log"\n'
        "cadence_entries = 3\n"
        "max_lag_entries = 10\n"
        f"{ts_line}\n"
    )
    return cfg_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--register-live-anchor",
        action="store_true",
        help="also register checkpoints with the real anchor.agentactioncapsule.org (network required)",
    )
    args = parser.parse_args()

    if LEDGER_DIR.exists():
        shutil.rmtree(LEDGER_DIR)  # keys/ is intentionally NOT reset -- same persistent node identity as run_demo.py
    LEDGER_DIR.mkdir(parents=True)

    ts_urls = [DEFAULT_TS_URL] if args.register_live_anchor else []
    checkpoint_config_path = write_checkpoint_config(ts_urls)

    mock_server = mock_mesh_node.ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), mock_mesh_node.Handler)
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    wait_for(f"http://127.0.0.1:{MOCK_PORT}/v1/models")

    runtime_digest = hashlib.sha256(Path(mock_mesh_node.__file__).read_bytes()).hexdigest()

    transcript_lines: list[str] = []

    def log(line: str) -> None:
        print(line)
        transcript_lines.append(line)

    log("=== capsule-emit-mesh checkpoint (Layers 1-2) demo transcript ===")
    log(f"register_live_anchor={args.register_live_anchor}")
    log("")

    # -- Phase A: capsules accrue with checkpointing OFF (Layer 0 only) --
    log("--- phase A: 4 exchanges, checkpointing OFF (Layer 0 only) ---")
    state_a = default_state(
        ledger_dir=LEDGER_DIR,
        manifest_path=MANIFEST_PATH,
        keys_dir=KEYS_DIR,
        runtime_label="poc-fixture-backend(mock_mesh_node.py)",
        runtime_digest=runtime_digest,
    )
    server_a = run_sidecar(listen_host="127.0.0.1", listen_port=SIDECAR_PORT, upstream_base=f"http://127.0.0.1:{MOCK_PORT}", state=state_a)
    thread_a = threading.Thread(target=server_a.serve_forever, daemon=True)
    thread_a.start()
    wait_for(f"http://127.0.0.1:{SIDECAR_PORT}/v1/models")
    send_requests(state_a, PROMPTS, seed_offset=0)
    server_a.shutdown()
    server_a.server_close()
    log(f"phase A capsules emitted: {len(state_a.emitted)}")
    log("phase A checkpoint state: (none -- checkpointing was off)")
    log("")

    # -- Phase B: node "reconnects" with checkpointing turned on -- one
    # checkpoint self-heals the whole phase-A backlog in a single shot. --
    log("--- phase B: reconnect with checkpointing ON -- self-heals phase-A backlog ---")
    state_b = default_state(
        ledger_dir=LEDGER_DIR,
        manifest_path=MANIFEST_PATH,
        keys_dir=KEYS_DIR,
        runtime_label="poc-fixture-backend(mock_mesh_node.py)",
        runtime_digest=runtime_digest,
        checkpoint_config_path=checkpoint_config_path,
    )
    state_b.last_capsule_id = state_a.last_capsule_id  # same node, same chain, picking up where it left off
    assert state_b.checkpoint is not None
    reconnect_cp = state_b.checkpoint.reconnect()
    log(f"reconnect checkpoint emitted: {reconnect_cp is not None}")
    log(f"status after reconnect: {state_b.checkpoint.witness_status()}")
    log("")

    # -- Phase C: continue serving with checkpointing engaged; cadence
    # (every 3 entries) fires at least one more checkpoint mid-stream. --
    log("--- phase C: 4 more exchanges, checkpointing ON (cadence_entries=3) ---")
    server_b = run_sidecar(listen_host="127.0.0.1", listen_port=SIDECAR_PORT, upstream_base=f"http://127.0.0.1:{MOCK_PORT}", state=state_b)
    thread_b = threading.Thread(target=server_b.serve_forever, daemon=True)
    thread_b.start()
    wait_for(f"http://127.0.0.1:{SIDECAR_PORT}/v1/models")
    send_requests(state_b, PROMPTS, seed_offset=100)
    server_b.shutdown()
    server_b.server_close()
    mock_server.shutdown()
    mock_server.server_close()
    log(f"phase C capsules emitted: {len(state_b.emitted)}")
    log(f"status after phase C: {state_b.checkpoint.witness_status()}")
    log(f"total capsules in ledger: {len(state_a.emitted) + len(state_b.emitted)}")
    log("")

    # -- verification pass: every capsule verifies + chains correctly --
    log("=== capsule verification ===")
    all_capsules = state_a.emitted + state_b.emitted
    all_ok = True
    prev_id = None
    for idx, capsule in enumerate(all_capsules, start=1):
        result = verify_capsule(capsule)
        chain_ok = True
        if capsule.get("chain") is not None:
            chain_ok = capsule["chain"]["parent_capsule_id"] == prev_id
        prev_id = capsule["capsule_id"]
        ok = result.ok and chain_ok
        all_ok = all_ok and ok
        log(f"capsule {idx}: capsule_id={capsule['capsule_id']} verify.ok={result.ok} chain_ok={chain_ok}")
    log(f"all capsules verify() ok AND chain-consistent: {all_ok}")
    log("")

    # -- offline verify: rebuild the MMR purely from the on-disk ledger, as
    # a third party holding only capsules.jsonl + checkpoints.jsonl would. --
    log("=== offline verify (scitt_cose.cll -- no live sidecar state) ===")
    last_checkpoint_dict = json.loads((LEDGER_DIR / "checkpoints.jsonl").read_text().splitlines()[-1])
    cll_checkpoint = cll.Checkpoint.from_dict(last_checkpoint_dict)

    fresh_log = JsonlLogSource(LEDGER_DIR / "capsules.jsonl")
    fresh_mmr = MmrLedger(fresh_log)
    fresh_mmr.sync()

    target_seq = 2  # an arbitrary capsule from phase A, well before the tip
    target_capsule = all_capsules[target_seq - 1]
    proof = fresh_mmr.inclusion_proof(target_seq, size=cll_checkpoint.mmr_size)
    cll_proof = cll.InclusionProof.from_dict(
        {
            "v": proof.v,
            "kind": proof.kind,
            "size": proof.size,
            "leaf_index": proof.leaf_index,
            "witness": list(proof.witness),
            "peaks_left": list(proof.peaks_left),
            "peaks_right": list(proof.peaks_right),
        }
    )
    body_digest = bytes.fromhex(target_capsule["capsule_id"])
    inclusion_result = cll.verify_leaf_against_checkpoint(
        body_digest=body_digest,
        leaf_index=target_seq - 1,
        checkpoint=cll_checkpoint,
        proof=cll_proof,
        current_size=fresh_mmr.size(),
    )
    log(f"target capsule (seq={target_seq}): {target_capsule['capsule_id']}")
    log(f"inclusion-under-checkpoint verify.ok={inclusion_result.ok}")
    log(f"status: {inclusion_result.status}")
    if inclusion_result.errors:
        log(f"errors: {inclusion_result.errors}")

    receipt_ok = None
    if last_checkpoint_dict.get("witnesses"):
        witness = last_checkpoint_dict["witnesses"][0]
        ts_url = witness["ts_url"]
        from capsule_emit.checkpoint import WitnessRecord

        receipt_ok, receipt_errors = verify_receipt_offline(WitnessRecord.from_dict(witness), ts_base_url=ts_url)
        log(f"TS receipt verify (via {ts_url}): ok={receipt_ok} errors={receipt_errors}")
    else:
        log("no witnesses on the last checkpoint -- self-checkpointed only, no TS receipt to verify")
        log('honesty note: this checkpoint proves "not rewritten since", NOT "seen by an independent third party"')

    log("")
    log(f"final witness status: {state_b.checkpoint.witness_status()}")

    (LEDGER_DIR / "checkpoint-demo-transcript.txt").write_text("\n".join(transcript_lines) + "\n")

    if not all_ok or not inclusion_result.ok or receipt_ok is False:
        raise SystemExit("CHECKPOINT DEMO FAILED: see transcript above")
    print(f"\nDemo complete. Ledger + transcript written under {LEDGER_DIR.relative_to(ROOT)}/.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hermetic, single-process rehearsal of the 2-role LIVE adversarial harness.

The LIVE version of this flow (real mesh-llm host, real admission-policy
plugin, two real Macs) is `_work/mesh-2role-live-adversarial-runbook.md` --
it needs a real mesh-llm binary and cannot run in CI (same posture as
`host_runtime_e2e.rs`'s `--ignored` tests). This script exercises the SAME
harness code (`send_bilateral_request.py`, `checkpoint_ledger.py`,
`stranger_verify_bundle.py` -- imported, not reimplemented) against
`mock_mesh_node.py` standing in for the real host, so the mechanism is
CI-enforced even though the live two-Mac proof is not.

FLOW (mirrors the runbook 1:1, minus the real host/model):
  1. B (provider): a capsule_sidecar.py in front of a mock backend --
     stands in for the real admission-policy-plugin-loaded host. Serving
     provenance is synthetic here (mock_mesh_node carries none of the real
     x-mesh-poc-v1.serving_provenance block); the runbook is what proves
     that part against real hardware.
  2. A (requester) sends ONE Move-1-attested request via
     send_bilateral_request.send_bilateral_request() -- the same function
     the runbook's CLI wraps.
  3. B's ledger is checkpointed via checkpoint_ledger.checkpoint_ledger()
     (self-checkpointed -- no network in CI, ts_urls=[]).
  4. The ledger dir is COPIED to a separate directory (simulating scp) --
     A/any stranger only ever reads this copy, never B's live state.
  5. Stranger-verify via stranger_verify_bundle: capsule integrity,
     transparent signature, cross_party_rung=full_bilateral derived from
     the copy + A's own Move-4 ack, checkpoint inclusion, and the two
     ADVERSARIAL tamper-a-byte checks (capsule_id, and a .cose byte).

Exit 0 iff every acceptance gate passes.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import mock_mesh_node
from capsule_sidecar import default_state, run_sidecar
from checkpoint_ledger import checkpoint_ledger
from send_bilateral_request import ClientKey, send_bilateral_request, write_ack
from stranger_verify_bundle import run_checkpoint_verify, tamper_check, verify_bundle

ROOT = Path(__file__).parent
MOCK_PORT = 19601
SIDECAR_PORT = 19602
MODEL_ID = mock_mesh_node.MODEL_ID


def _wait_for(url: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5)
            return
        except Exception:
            time.sleep(0.05)
    raise TimeoutError(f"server at {url} did not come up in time")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        b_ledger_dir = tmp_path / "b" / "ledger"
        b_keys_dir = tmp_path / "b" / "keys"
        a_out_dir = tmp_path / "a"
        disclosed_dir = tmp_path / "disclosed" / "ledger"
        disclosed_keys_dir = tmp_path / "disclosed" / "keys"

        print("=" * 72)
        print("2-role LIVE adversarial harness -- hermetic rehearsal (mock backend)")
        print("=" * 72)

        # --- Step 1: B stands up (mock backend + real sidecar/plugin-equivalent logic) ---
        mock_server = mock_mesh_node.ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), mock_mesh_node.Handler)
        threading.Thread(target=mock_server.serve_forever, daemon=True).start()
        _wait_for(f"http://127.0.0.1:{MOCK_PORT}/v1/models")

        state = default_state(
            ledger_dir=b_ledger_dir,
            manifest_path=ROOT / "model-package" / "model-package.json",
            keys_dir=b_keys_dir,
            runtime_label="two-role-demo-fixture",
            runtime_digest="0" * 64,
        )
        sidecar = run_sidecar(
            listen_host="127.0.0.1", listen_port=SIDECAR_PORT, upstream_base=f"http://127.0.0.1:{MOCK_PORT}", state=state
        )
        threading.Thread(target=sidecar.serve_forever, daemon=True).start()
        _wait_for(f"http://127.0.0.1:{SIDECAR_PORT}/v1/models")
        print(f"[B] provider up: node_id={state.node_id}")

        # --- Step 2: A sends a Move-1-attested request ---
        client_key = ClientKey.generate()
        result = send_bilateral_request(
            url=f"http://127.0.0.1:{SIDECAR_PORT}/v1/chat/completions",
            model=MODEL_ID,
            prompt="Explain the 2-role adversarial harness in one sentence.",
            client_key=client_key,
        )
        assert result["status"] == 200, f"exchange failed: status={result['status']} body={result['body']!r}"
        capsule_id = result["capsule_id"]
        assert capsule_id, "no capsule_id returned"
        assert result["ack"] is not None, "no Move-4 ack produced"
        a_out_dir.mkdir(parents=True)
        ack_path = write_ack(result["ack"], a_out_dir)
        print(f"[A] exchange served: capsule_id={capsule_id}")
        print(f"[A] Move-4 ack written: {ack_path.name}")

        sidecar.shutdown()
        mock_server.shutdown()

        # --- Step 3: B checkpoints its own ledger (self-checkpointed, no network) ---
        cp_state, cp = checkpoint_ledger(
            ledger_dir=b_ledger_dir, keys_dir=b_keys_dir, log_id="two-role-demo-provider", ts_urls=[]
        )
        assert cp is not None, "no checkpoint emitted"
        print(f"[B] checkpointed: {cp_state.witness_status()}")

        # --- Step 4: disclose (copy) the bundle to a location A never got live access to ---
        shutil.copytree(b_ledger_dir, disclosed_dir)
        disclosed_keys_dir.mkdir(parents=True)
        shutil.copy(b_keys_dir / "node-key.pub.pem", disclosed_keys_dir / "node-key.pub.pem")
        print(f"[disclosure] copied {b_ledger_dir} -> {disclosed_dir} (stranger reads only this copy)")

        # --- Step 5: stranger-verify from the disclosed copy alone ---
        issuer_key = disclosed_keys_dir / "node-key.pub.pem"
        capsule_ok, any_unverified, capsule_lines = verify_bundle(
            disclosed_dir, {capsule_id: result["ack"]}, issuer_key=issuer_key
        )
        print("\n".join(capsule_lines))
        assert capsule_ok, "stranger-verify of the disclosed bundle failed"
        assert not any_unverified, "a signed statement went unverified in the disclosed bundle"

        rung_line = next(line for line in capsule_lines if line.startswith(f"capsule {capsule_id}"))
        assert "cross_party_rung=full_bilateral" in rung_line, f"expected full_bilateral, got: {rung_line}"
        print("[A/stranger] PROVIDER Q1 (who asked) + REQUESTER-VERIFY Q2 (can I prove it) both answered: full_bilateral")

        checkpoint_ok, checkpoint_report = run_checkpoint_verify(disclosed_dir)
        assert checkpoint_ok, f"checkpoint/inclusion verify failed:\n{checkpoint_report}"
        print("[A/stranger] checkpoint inclusion verify: PASS")

        print("\n--- ADVERSARIAL: tamper-a-byte-fails (on scratch copies of the DISCLOSED bundle) ---")
        tamper_ok = tamper_check(disclosed_dir, issuer_key)
        assert tamper_ok, "tamper was NOT detected -- adversarial claim failed"

        print("\nAll acceptance gates passed:")
        print(f"  - real request served, capsule_id={capsule_id}")
        print("  - stranger-verify (content-hash + chain + transparent signature): PASS")
        print("  - cross_party_rung=full_bilateral, derived from disclosed bytes + A's own ack")
        print("  - checkpoint inclusion + self-checkpoint witness status: PASS")
        print("  - tamper-a-byte (capsule_id AND .cose signature): DETECTED")
        print("\n2-role adversarial harness rehearsal complete. All acceptance gates passed.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

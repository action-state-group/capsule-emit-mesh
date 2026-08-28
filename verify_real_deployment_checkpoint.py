#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline verify + rollback-mutant proof for a real-deployment checkpoint ledger.

Reads ONLY the on-disk ledger dir (capsules.jsonl + checkpoints.jsonl) -- the
posture of a third party holding just those two files, no live sidecar state
involved. Companion to run_real_deployment_checkpoint_demo.sh, which produces
the ledger this script reads.

Usage:
    python3 verify_real_deployment_checkpoint.py <ledger-dir>

Also PRINTS (does not execute) the live-anchor registration command -- see
the "anchor registration" section below for why this run stops short of it.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.checkpoint import DEFAULT_TS_URL, CheckpointRecord, MmrLedger, WitnessRecord, verify_receipt_offline
from checkpointing import JsonlLogSource
from scitt_cose import cll


def cll_checkpoint_from_record(cp: CheckpointRecord) -> cll.Checkpoint:
    """Convert capsule_emit.checkpoint's single-commitment CheckpointRecord
    (v, kind, log_id, mmr_size, root, prev_size, prev_root, key_id, timestamp,
    signature[, witnesses] -- no peaks_digest, per the 2026-08-22 Option-C
    single-commitment ruling) onto scitt_cose.cll.Checkpoint. As of scitt-cose
    0.2.2, Checkpoint.from_dict() reads only known keys and neither requires
    nor reads a `peaks_digest` key, so this is a direct field mapping.
    """
    return cll.Checkpoint.from_dict(cp.to_dict())


def main() -> None:
    ledger_dir = Path(sys.argv[1])
    capsules_path = ledger_dir / "capsules.jsonl"
    checkpoints_path = ledger_dir / "checkpoints.jsonl"

    transcript: list[str] = []

    def log(line: str) -> None:
        print(line)
        transcript.append(line)

    log("=== real-deployment checkpoint offline verify ===")
    log(f"ledger_dir={ledger_dir}")
    log("REAL (this run): mesh-llm-host-runtime inference, capsule_sidecar.py emission, local")
    log("CLL/checkpoint below. STAGED, not executed: live anchor registration -- see the")
    log("'anchor registration' section at the end for the exact command and why.")
    log("")

    log("--- capsule verification ---")
    capsules = [json.loads(line) for line in capsules_path.read_text().splitlines() if line.strip()]
    if not capsules:
        raise SystemExit("NO CAPSULES RECORDED -- real inference exchange did not happen")
    all_ok = True
    prev_id = None
    for idx, capsule in enumerate(capsules, start=1):
        result = verify_capsule(capsule)
        chain_ok = True
        if capsule.get("chain") is not None:
            chain_ok = capsule["chain"]["parent_capsule_id"] == prev_id
        prev_id = capsule["capsule_id"]
        ok = result.ok and chain_ok
        all_ok = all_ok and ok
        log(f"capsule {idx}: capsule_id={capsule['capsule_id']} verify.ok={result.ok} chain_ok={chain_ok}")
    log(f"all {len(capsules)} real capsules verify() ok AND chain-consistent: {all_ok}")
    log("")

    if not checkpoints_path.exists():
        log("NO CHECKPOINT EMITTED -- cadence not reached; nothing further to verify")
        (ledger_dir / "real-deployment-transcript.txt").write_text("\n".join(transcript) + "\n")
        if not all_ok:
            raise SystemExit("CAPSULE VERIFY FAILED")
        return

    checkpoint_lines = [json.loads(line) for line in checkpoints_path.read_text().splitlines() if line.strip()]
    last_checkpoint_dict = checkpoint_lines[-1]
    last_cp = CheckpointRecord.from_dict(last_checkpoint_dict)
    log(f"checkpoints emitted: {len(checkpoint_lines)}; last checkpoint mmr_size={last_cp.mmr_size} root={last_cp.root}")
    log("")

    log("--- offline inclusion verify (scitt_cose.cll, ledger files only) ---")
    fresh_log = JsonlLogSource(capsules_path)
    fresh_mmr = MmrLedger(fresh_log)
    fresh_mmr.sync()

    target_seq = 1
    target_capsule = capsules[target_seq - 1]
    proof = fresh_mmr.inclusion_proof(target_seq, size=last_cp.mmr_size)
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
    cll_checkpoint = cll_checkpoint_from_record(last_cp)
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
    log("")

    log("--- witness status ---")
    receipt_ok = None
    if last_checkpoint_dict.get("witnesses"):
        witness = last_checkpoint_dict["witnesses"][0]
        ts_url = witness["ts_url"]
        receipt_ok, receipt_errors = verify_receipt_offline(WitnessRecord.from_dict(witness), ts_base_url=ts_url)
        log(f"TS receipt verify (via {ts_url}): ok={receipt_ok} errors={receipt_errors}")
    else:
        log("no witnesses on this checkpoint -- self-checkpointed only (ts_urls was empty for this run)")
        log('honesty note: this checkpoint proves "not rewritten since", NOT "seen by an independent third party"')
    log("")

    log("--- rollback mutant (fork/rewrite a COPY of the real log at the SAME size, must go RED) ---")
    baseline_match = fresh_mmr.root_at(last_cp.mmr_size).hex() == last_cp.root
    log(f"baseline (unmutated real log): recomputed root at mmr_size={last_cp.mmr_size} == signed root: {baseline_match}")
    with tempfile.TemporaryDirectory() as tmp:
        mutated_path = Path(tmp) / "capsules-mutated.jsonl"
        shutil.copy(capsules_path, mutated_path)
        lines = mutated_path.read_text().splitlines()
        mutated_line = json.loads(lines[0])
        mutated_line["capsule_id"] = "0" * 64  # same position, same count, different content -- the classic fork/rollback shape
        lines[0] = json.dumps(mutated_line, sort_keys=True)
        mutated_path.write_text("\n".join(lines) + "\n")

        mutated_mmr = MmrLedger(JsonlLogSource(mutated_path))
        mutated_mmr.sync()
        mutated_root = mutated_mmr.root_at(last_cp.mmr_size)
    rollback_detected = mutated_root.hex() != last_cp.root
    log(f"mutated (rewritten entry 1, same mmr_size={last_cp.mmr_size}): recomputed root {mutated_root.hex()}")
    log(f"signed checkpoint root:                                          {last_cp.root}")
    log(f"rollback/rewrite DETECTED (mismatch, expected True): {rollback_detected}")
    log("")

    log("--- anchor registration (STAGED, not executed this run) ---")
    log(f"exact command to register the last real checkpoint at the live public-good witness ({DEFAULT_TS_URL}):")
    log("")
    log("  # register_checkpoint's route is COSE-only (single-host ruling, 2026-08-27) --")
    log("  # a stored checkpoints.jsonl line alone can no longer be re-POSTed as-is (it lacks")
    log("  # the live MMR peak hashes checkpoint_to_cose needs). Force a fresh checkpoint")
    log("  # through the same CheckpointState reconnect() path a real node uses instead:")
    log("  python3 - <<'PY'")
    log("  from pathlib import Path")
    log("  from capsule_emit.checkpoint import CheckpointConfig, DEFAULT_TS_URL")
    log("  from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource")
    log(f"  ledger_dir = Path({str(ledger_dir)!r})")
    log("  log_source = JsonlLogSource(ledger_dir / 'capsules.jsonl')")
    log("  signer = Ed25519Signer(ledger_dir.parent / 'keys' / 'node-key.pem')  # or the node's own keys_dir")
    log("  cfg = CheckpointConfig(ts_urls=[DEFAULT_TS_URL])")
    log("  state = CheckpointState.load(ledger_dir=ledger_dir, log_source=log_source, cfg=cfg, signer=signer, log_id='<this node's log_id>')")
    log("  cp = state.reconnect()  # None if nothing new since the last checkpoint")
    log("  print(state.witness_status())")
    log("  PY")
    log("")
    log("Not run in this session: this task's own gate reserves live-anchor writes for Steven's")
    log("explicit go, separate from the task-level go (neutral/inbox.md constraints). The local")
    log("chain above (real inference -> capsules -> CLL -> checkpoint -> offline verify) is")
    log("complete and real; only this one network POST is deferred.")

    (ledger_dir / "real-deployment-transcript.txt").write_text("\n".join(transcript) + "\n")

    if not all_ok or not inclusion_result.ok or receipt_ok is False or not rollback_detected:
        raise SystemExit("REAL-DEPLOYMENT CHECKPOINT VERIFY FAILED: see transcript above")
    print(f"\nVerify complete. Ledger + transcript under {ledger_dir}/.")


if __name__ == "__main__":
    main()

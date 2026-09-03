#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline verify + mutant proof for a history card, over a real checkpoint
ledger -- companion to `verify_real_deployment_checkpoint.py`, same shape:
reads ONLY the on-disk `checkpoints.jsonl` (the posture of a third party
holding just that file, no live sidecar/MMR state), builds a history card,
verifies it via `history_card.verify_history_card`, then proves the
continuity/consistency mutants flip on a tampered COPY of the same ledger.

Usage:
    python3 verify_history_card.py <ledger-dir> [since_size]
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from history_card import build_history_card, verify_history_card


def main() -> None:
    ledger_dir = Path(sys.argv[1])
    since_size = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    checkpoints_path = ledger_dir / "checkpoints.jsonl"

    transcript: list[str] = []

    def log(line: str) -> None:
        print(line)
        transcript.append(line)

    log("=== history card offline verify ===")
    log(f"ledger_dir={ledger_dir} since_size={since_size}")

    if not checkpoints_path.exists():
        raise SystemExit("NO CHECKPOINTS RECORDED -- nothing to build a history card from")

    lines = [json.loads(line) for line in checkpoints_path.read_text().splitlines() if line.strip()]
    log_id = lines[0]["log_id"]
    node_id = f"node:{lines[0]['key_id'][:16]}"

    log("--- build + self-verify ---")
    card = build_history_card(node_id=node_id, log_id=log_id, checkpoint_lines=lines, since_size=since_size)
    log(f"continuity={card.properties.continuity!r} unforked={card.properties.unforked} "
        f"history_depth={card.properties.history_depth} checkpoint_count={card.checkpoint_count}")
    log(f"card.verify() (core-account recompute+match): {card.verify()}")
    all_ok = card.verify() and card.properties.unforked
    log("")

    log("--- offline verify from the published card + raw checkpoints alone ---")
    published = card.to_value()
    baseline = verify_history_card(published, lines)
    log(f"verify_history_card baseline: ok={baseline.ok} errors={baseline.errors}")
    all_ok = all_ok and baseline.ok
    log("")

    log("--- mutant: tamper a covered checkpoint's root after publish (rewrite) ---")
    tampered_lines = copy.deepcopy(lines)
    mid = len(tampered_lines) // 2
    if len(tampered_lines) > 1:
        tampered_lines[mid]["root"] = "00" * 32
        tampered_result = verify_history_card(published, tampered_lines)
        log(f"verify against a tampered ledger: ok={tampered_result.ok} errors={tampered_result.errors}")
        rewrite_detected = not tampered_result.ok
        log(f"rewrite DETECTED (mismatch, expected True): {rewrite_detected}")
        all_ok = all_ok and rewrite_detected
    else:
        log("only one checkpoint -- rewrite mutant needs >= 2, skipping (not a failure)")
    log("")

    log("--- mutant: drop a covered checkpoint's consistency proof (assert-not-proven) ---")
    if len(lines) > 1:
        dropped_cose = copy.deepcopy(lines)
        victim = len(dropped_cose) - 1
        dropped_cose[victim].pop("checkpoint_cose", None)
        card_over_dropped = build_history_card(
            node_id=node_id, log_id=log_id, checkpoint_lines=dropped_cose, since_size=since_size
        )
        broken = card_over_dropped.properties.continuity.startswith("broken at")
        log(f"continuity over a checkpoint with no consistency proof: {card_over_dropped.properties.continuity!r}")
        log(f"correctly labeled broken, not silently green (expected True): {broken}")
        all_ok = all_ok and broken
    else:
        log("only one checkpoint -- dropped-proof mutant needs >= 2, skipping (not a failure)")
    log("")

    (ledger_dir / "history-card-verify-transcript.txt").write_text("\n".join(transcript) + "\n")

    if not all_ok:
        raise SystemExit("HISTORY CARD VERIFY FAILED: see transcript above")
    print(f"\nVerify complete. Transcript under {ledger_dir}/history-card-verify-transcript.txt.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stranger-verify a DISCLOSED bundle -- a copy of a provider's ledger dir,
read from disk alone, no live access to the provider's process or state.

This is the tool BOTH sides of the 2-role harness run on the SAME kind of
bytes, answering different §6 questions from the identical derivation:

  - the PROVIDER runs this on its OWN ledger_dir to answer "who asked -- a
    verified party, not anonymous?" (cross_party_rung, derived from the
    served capsule + the requester's Move-4 ack, if disclosed back);
  - a REQUESTER (or any third party) runs this on a COPY of the provider's
    disclosed bundle to answer "what did I get, and can I prove it to a
    stranger?" -- the same derivation, over the same bytes, run by someone
    who does not trust the provider.

Composes existing verified primitives rather than reimplementing them:
`agent_action_capsule.verify` / `capsule_emit.signing.verify_store_signed`
for capsule integrity, `derive_cross_party_rung` for the bilateral rung, and
(if `checkpoints.jsonl` is present) shells out to
`verify_real_deployment_checkpoint.py`, which already performs the
inclusion-proof + witness-receipt + rollback-mutant checks generically over
any ledger_dir.

Usage:
    python3 stranger_verify_bundle.py <ledger-dir> [--client-ack PATH ...] \
        [--tamper-check]

--tamper-check proves the negative: copies <ledger-dir> to a scratch temp
dir, flips one byte of the first capsule's capsule_id, and confirms verify
now reports ok=False for that capsule. The real, disclosed <ledger-dir> is
never touched.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from advertisement import Advertisement, reconcile_advertised_vs_served
from agent_action_capsule.verify import verify_store
from bilateral_demo import ClientAck, get_cross_party, verify_client_ack
from capsule_emit.ledger import read_ledger
from capsule_sidecar import derive_cross_party_rung, identity_limitation_for_rung


def _poc_block(capsule: dict) -> dict:
    return (capsule.get("model_attestation", {}).get("compute_attestation", {}).get("x-mesh-poc-v1", {})) or {}


def _load_ack(path: Path) -> ClientAck:
    rec = json.loads(path.read_text())
    import base64

    return ClientAck(
        action_capsule_id=rec["action_capsule_id"],
        request_nonce=rec["request_nonce"],
        timestamp=rec["timestamp"],
        ack_bytes=base64.urlsafe_b64decode(rec["ack_bytes_b64"] + "=="),
        sig=base64.urlsafe_b64decode(rec["sig_b64"] + "=="),
        public_key_pem=base64.urlsafe_b64decode(rec["public_key_pem_b64"] + "=="),
    )


def _issuer_key_for(ledger_dir: Path, issuer_key: Path | None) -> Path | None:
    if issuer_key is not None:
        return issuer_key
    candidate = ledger_dir.parent / "keys" / "node-key.pub.pem"
    return candidate if candidate.exists() else None


def _transparent_check(ledger_dir: Path, capsule_id: str, issuer_key: Path | None) -> str | None:
    """Verify the DETACHED COSE_Sign1 Signed Statement for one capsule
    (`signed-statements/<capsule_id>.cose`, this repo's own producer-
    signature rung -- neither writer embeds a self-attested `signature`/
    `key_id` inline, so `agent_action_capsule.verify()`/`verify_store()`
    alone only prove content-hash + chain integrity, never who signed it;
    this is the separate check that does). Returns a one-line status string,
    or None if there is no statement to check (self-attested rung only)."""
    statement_path = ledger_dir / "signed-statements" / f"{capsule_id}.cose"
    if not statement_path.exists():
        return None
    if issuer_key is None:
        return "signed statement present but no issuer pubkey given (pass --issuer-key or put node-key.pub.pem in a sibling keys/ dir)"
    from agent_action_capsule.transparent import SubstrateInputError, verify_transparent

    try:
        report = verify_transparent(statement_path=str(statement_path), issuer_key_path=str(issuer_key))
    except (OSError, SubstrateInputError) as exc:
        return f"transparent verify error: {exc}"
    return f"transparent verify: signature_verified={report.signature_verified} ok={report.ok}"


def verify_bundle(
    ledger_dir: Path,
    acks_by_capsule_id: dict[str, ClientAck],
    *,
    issuer_key: Path | None = None,
) -> tuple[bool, list[str]]:
    """Capsule-level stranger-verify + cross_party_rung derivation, from
    ledger_dir's bytes alone. Returns (all_ok, report_lines).

    Two independent layers, matching `agent-action-capsule verify --store`
    (content-hash + chain integrity) and `... --transparent --issuer-key`
    (the detached COSE_Sign1 signature) -- see `_transparent_check`'s
    docstring for why this repo's capsules need both rather than the
    single-shot `verify_store_signed` capsule-emit's own `seal()` ledgers
    can use (this repo's writers never embed a `signature`/`key_id`
    producer envelope inline)."""
    lines: list[str] = []
    capsules_path = ledger_dir / "capsules.jsonl"
    if not capsules_path.exists():
        return False, [f"NO capsules.jsonl at {ledger_dir} -- nothing to verify"]

    records = read_ledger(capsules_path)
    if not records:
        return False, ["capsules.jsonl is empty -- no exchange recorded"]

    issuer_key = _issuer_key_for(ledger_dir, issuer_key)
    results = verify_store(records)
    all_ok = True
    for record, result in zip(records, results):
        capsule_id = record.get("capsule_id", "<missing>")
        ok = bool(result.ok)
        all_ok = all_ok and ok
        cross_party = get_cross_party(record)
        ack = acks_by_capsule_id.get(capsule_id)
        ack_ok = False
        if ack is not None:
            correlator = cross_party.get("correlator") if cross_party else None
            ack_ok, ack_reason = verify_client_ack(ack, capsule_id, correlator)
        rung = derive_cross_party_rung(cross_party, has_verified_ack=ack_ok)
        caveat = identity_limitation_for_rung(rung)

        lines.append(f"capsule {capsule_id}: verify.ok={ok} cross_party_rung={rung}")
        if not ok:
            for f in result.findings:
                lines.append(f"    finding: {f.check} -- {f.detail}")
        if caveat:
            lines.append(f"    identity_limitation: {caveat}")
        transparent_line = _transparent_check(ledger_dir, capsule_id, issuer_key)
        if transparent_line:
            lines.append(f"    {transparent_line}")
            if "signature_verified=False" in transparent_line or "error" in transparent_line:
                all_ok = False

        prov = _poc_block(record).get("serving_provenance")
        if prov:
            lines.append(
                "    serving_provenance: model="
                f"{prov.get('model', {}).get('canonical_ref')!r} "
                f"quant={prov.get('quantization')!r} "
                f"gpu={prov.get('hardware', {}).get('gpu')!r} "
                f"served_by={prov.get('served_by_node_id')!r} "
                f"tokens={prov.get('usage', {}).get('total_tokens')!r}"
            )

        # verify-after-advertise (TRUST-MODEL.md §12.3): re-derive the advertised-
        # vs-served reconciliation from THIS record's own bytes (advertisement +
        # serving_provenance), not the producer's co-carried verdict. A mismatch
        # is a first-class, attributable, offline-checkable broken promise.
        poc = _poc_block(record)
        advertisement = poc.get("advertisement")
        ad = Advertisement.from_value(advertisement) if advertisement else None
        recon = reconcile_advertised_vs_served(ad, prov)
        if recon["overall"] == "mismatch":
            lines.append(
                f"    advertised_vs_served: MISMATCH — broken promise on "
                f"{', '.join(recon['mismatches'])} (advertised != served; attributable, offline-checkable)"
            )
        else:
            lines.append(f"    advertised_vs_served: {recon['overall']}")
    return all_ok, lines


def run_checkpoint_verify(ledger_dir: Path) -> tuple[bool, str]:
    """Delegate to verify_real_deployment_checkpoint.py -- already generic
    over any ledger_dir with capsules.jsonl + checkpoints.jsonl, and already
    performs its own inclusion-proof, witness-receipt, and rollback-mutant
    checks. Skipped (ok=True, no-op) if the bundle carries no checkpoint --
    that is a valid, honestly-labeled state (self-checkpointed or Layer 0
    only), not a failure."""
    if not (ledger_dir / "checkpoints.jsonl").exists():
        return True, "no checkpoints.jsonl in this bundle -- Layer 0/1 only, nothing to verify at the checkpoint layer"
    script = Path(__file__).parent / "verify_real_deployment_checkpoint.py"
    proc = subprocess.run([sys.executable, str(script), str(ledger_dir)], capture_output=True, text=True, timeout=60)
    return proc.returncode == 0, proc.stdout + proc.stderr


def tamper_check(ledger_dir: Path, issuer_key: Path | None) -> bool:
    """Two independent tamper probes, each on its own fresh SCRATCH COPY --
    never touches the real, disclosed ledger_dir:

    1. flip one hex digit of the first capsule's capsule_id in capsules.jsonl
       -> content-hash/chain verify (`verify_store`) must go red;
    2. flip one byte inside that capsule's detached `.cose` signed statement
       -> the transparent signature check must go red, proving the tamper
       test also covers the cryptographic layer, not just content-hash
       recomputation (Demo 1/3's "or of a byte in a .cose file" case).

    Returns True iff BOTH tampers were DETECTED (i.e. True is the good
    outcome)."""
    # Resolved from the REAL ledger_dir before any scratch copy is made --
    # a scratch copy under a tempdir has no sibling keys/ dir for
    # _issuer_key_for's default lookup to find.
    issuer_key = _issuer_key_for(ledger_dir, issuer_key)
    capsule_detected = False
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "tampered-capsule-id"
        shutil.copytree(ledger_dir, scratch)
        capsules_path = scratch / "capsules.jsonl"
        lines = capsules_path.read_text().splitlines()
        if not lines:
            return False
        first = json.loads(lines[0])
        original_id = first["capsule_id"]
        flipped = format(int(original_id[0], 16) ^ 0xF, "x") + original_id[1:]
        first["capsule_id"] = flipped
        lines[0] = json.dumps(first, sort_keys=True)
        capsules_path.write_text("\n".join(lines) + "\n")

        tampered_ok, report = verify_bundle(scratch, {}, issuer_key=issuer_key)
        capsule_detected = not tampered_ok
        print(f"tamper-check 1/2 (capsule_id): flipped {original_id} -> {flipped} in a SCRATCH COPY")
        print("\n".join(report))
        print(f"tamper-check 1/2: TAMPER DETECTED = {capsule_detected} (expected True)")

    cose_detected = True  # stays True (vacuously) if there's nothing to tamper
    statements_dir = ledger_dir / "signed-statements"
    cose_files = sorted(statements_dir.glob("*.cose")) if statements_dir.exists() else []
    if cose_files:
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "tampered-cose"
            shutil.copytree(ledger_dir, scratch)
            target = scratch / "signed-statements" / cose_files[0].name
            raw = bytearray(target.read_bytes())
            raw[-1] ^= 0xFF  # flip the last byte -- inside the COSE_Sign1 tag/signature
            target.write_bytes(bytes(raw))
            capsule_id = cose_files[0].stem
            line = _transparent_check(scratch, capsule_id, _issuer_key_for(scratch, issuer_key))
            print(f"tamper-check 2/2 (.cose byte): flipped last byte of {cose_files[0].name} in a SCRATCH COPY")
            print(f"    {line}")
            cose_detected = line is not None and ("signature_verified=False" in line or "error" in line)
            print(f"tamper-check 2/2: TAMPER DETECTED = {cose_detected} (expected True)")
    else:
        print("tamper-check 2/2 (.cose byte): no signed-statements/*.cose in this bundle -- skipped")

    return capsule_detected and cose_detected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ledger_dir")
    parser.add_argument("--client-ack", action="append", default=[], dest="client_acks", help="a Move-4 client-ack-*.json file (repeatable)")
    parser.add_argument("--issuer-key", default=None, help="PEM pubkey for the .cose signed statements; defaults to <ledger_dir>/../keys/node-key.pub.pem")
    parser.add_argument("--tamper-check", action="store_true", help="also prove a corrupted COPY fails verify")
    args = parser.parse_args(argv)

    ledger_dir = Path(args.ledger_dir)
    issuer_key = Path(args.issuer_key) if args.issuer_key else None
    acks_by_capsule_id = {}
    for p in args.client_acks:
        ack = _load_ack(Path(p))
        acks_by_capsule_id[ack.action_capsule_id] = ack

    print(f"=== stranger-verify: {ledger_dir} ===")
    capsule_ok, capsule_lines = verify_bundle(ledger_dir, acks_by_capsule_id, issuer_key=issuer_key)
    print("\n".join(capsule_lines))
    print(f"\nall capsules verify.ok: {capsule_ok}")

    print("\n=== checkpoint / witness verify ===")
    checkpoint_ok, checkpoint_report = run_checkpoint_verify(ledger_dir)
    print(checkpoint_report)

    tamper_ok = True
    if args.tamper_check:
        print("\n=== adversarial: tamper-a-byte-fails ===")
        tamper_ok = tamper_check(ledger_dir, issuer_key)

    overall = capsule_ok and checkpoint_ok and tamper_ok
    print(f"\nOVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())

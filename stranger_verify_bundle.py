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
    """Resolve the issuer pubkey for the detached .cose signed statements.

    Explicit --issuer-key always wins. Otherwise auto-discover, broadened
    (2026-08-29) so the DEFAULT invocation actually verifies a self-contained
    disclosed bundle: a disclosed bundle commonly carries its pubkey INSIDE the
    ledger dir (there is no sibling `keys/` once it has been copied out), so a
    verifier that only looked at `<ledger>/../keys/node-key.pub.pem` would skip
    signature verification and still print PASS. Search, in order:
      1. `<ledger>/../keys/node-key.pub.pem`  (original sibling-keys layout)
      2. `<ledger>/node-key.pub.pem`          (pubkey shipped in the bundle)
      3. `<ledger>/*.pub.pem`                  (any in-bundle pubkey, sorted)
    """
    if issuer_key is not None:
        return issuer_key
    sibling = ledger_dir.parent / "keys" / "node-key.pub.pem"
    if sibling.exists():
        return sibling
    in_bundle = ledger_dir / "node-key.pub.pem"
    if in_bundle.exists():
        return in_bundle
    for candidate in sorted(ledger_dir.glob("*.pub.pem")):
        return candidate
    return None


def _authenticated_capsule_id(report) -> str | None:
    """The capsule_id actually AUTHENTICATED by the COSE_Sign1 signature --
    either the bare-digest `CAPSULE_ID_MEDIA_TYPE` subject, or (this repo's
    own scheme: `sign_capsule()` signs the full capsule JSON) the content-hash
    `agent_action_capsule.verify()` recomputes from the signed payload's own
    bytes (`report.payload.capsule_id`). Mirrors
    `capsule_mesh_view.py::_authenticated_capsule_id`. Never trust a
    `subject`/filename claim the signature itself doesn't cover."""
    if report.authenticated_capsule_id is not None:
        return report.authenticated_capsule_id
    if report.payload is not None:
        return report.payload.capsule_id
    return None


def _transparent_check(ledger_dir: Path, capsule_id: str, issuer_key: Path | None) -> str | None:
    """Verify the DETACHED COSE_Sign1 Signed Statement for one capsule
    (`signed-statements/<capsule_id>.cose`, this repo's own producer-
    signature rung -- neither writer embeds a self-attested `signature`/
    `key_id` inline, so `agent_action_capsule.verify()`/`verify_store()`
    alone only prove content-hash + chain integrity, never who signed it;
    this is the separate check that does). Returns a one-line status string.

    [mesh-verify-bind-statement-to-capsuleid] Two adversarial-review findings
    (ADV-1/ADV-2, `_work/mesh-adversarial-review-2026-09-05.md`) against the
    prior version of this function, both re-verified by execution and both
    fixed here:

    - ADV-2: a MISSING statement used to return None, and the caller left
      `ok` at whatever the content-hash-only check gave it -- so a wholly
      fabricated, never-signed capsule (a self-consistent capsule_id over
      arbitrary claims, no `signed-statements/` at all) read `OVERALL: PASS`.
      Absence is not evidence: this now returns a "NO SIGNATURE:" line the
      caller treats as a hard, named failure -- never a silent pass-through.
    - ADV-1: a validly-signed statement was accepted for ANY capsule_id
      requested, because `report.ok`/`signature_verified` alone only prove
      SOME statement signed by the issuer key exists -- not that it was
      signed over *this* capsule's bytes. A keyless relay can tamper a
      record, recompute its own public unkeyed capsule_id, and rename the
      original (still honestly signed) `.cose` to the new filename -- no key
      material required. The authenticated subject is now bound back to
      `capsule_id` (`_authenticated_capsule_id`); a mismatch is a
      "SUBJECT MISMATCH:" hard failure, distinct from an unverified or
      absent signature so a human reading it knows which attack was caught.
    """
    statement_path = ledger_dir / "signed-statements" / f"{capsule_id}.cose"
    if not statement_path.exists():
        return (
            "NO SIGNATURE: no signed-statements/"
            f"{capsule_id}.cose found for this capsule -- absence of a "
            "signed statement is not evidence of anything; a capsule with "
            "no signature at all can never read PASS"
        )
    if issuer_key is None:
        # A signed statement is present but NO key was found to check it. This
        # is NOT a pass: the caller degrades verify.ok for this capsule and the
        # top line becomes UNVERIFIED. The "UNVERIFIED:" prefix is the signal
        # the caller keys on (kept distinct from a hard "error"/"False").
        return "UNVERIFIED: signed statement present but no issuer pubkey found (pass --issuer-key, or put node-key.pub.pem in the bundle or a sibling keys/ dir) — signature NOT checked"
    from agent_action_capsule.transparent import SubstrateInputError, verify_transparent

    try:
        report = verify_transparent(statement_path=str(statement_path), issuer_key_path=str(issuer_key))
    except (OSError, SubstrateInputError) as exc:
        return f"transparent verify error: {exc}"
    if report.signature_verified:
        authenticated_id = _authenticated_capsule_id(report)
        if authenticated_id is not None and authenticated_id != capsule_id:
            return (
                f"SUBJECT MISMATCH: statement at signed-statements/{capsule_id}.cose "
                f"is validly signed, but authenticates capsule_id={authenticated_id} "
                f"-- NOT {capsule_id}. Signed over a different capsule's bytes, "
                "filed under (or renamed to) this one's filename."
            )
    return f"transparent verify: signature_verified={report.signature_verified} ok={report.ok}"


def verify_bundle(
    ledger_dir: Path,
    acks_by_capsule_id: dict[str, ClientAck],
    *,
    issuer_key: Path | None = None,
) -> tuple[bool, bool, list[str]]:
    """Capsule-level stranger-verify + cross_party_rung derivation, from
    ledger_dir's bytes alone. Returns (all_ok, any_unverified, report_lines).

    `any_unverified` is True iff at least one capsule carried a signed
    statement that was NOT cryptographically checked because no issuer key was
    found. A bundle that CARRIES signatures must never read PASS without those
    signatures being verified: such a capsule's own `verify.ok` is degraded to
    False here, and the caller renders the top line as UNVERIFIED (not PASS,
    not a hard FAIL) so a human reading it is not misled.

    Two independent layers, matching `agent-action-capsule verify --store`
    (content-hash + chain integrity) and `... --transparent --issuer-key`
    (the detached COSE_Sign1 signature) -- see `_transparent_check`'s
    docstring for why this repo's capsules need both rather than the
    single-shot `verify_store_signed` capsule-emit's own `seal()` ledgers
    can use (this repo's writers never embed a `signature`/`key_id`
    producer envelope inline)."""
    lines: list[str] = []
    any_unverified = False
    capsules_path = ledger_dir / "capsules.jsonl"
    if not capsules_path.exists():
        return False, False, [f"NO capsules.jsonl at {ledger_dir} -- nothing to verify"]

    records = read_ledger(capsules_path)
    if not records:
        return False, False, ["capsules.jsonl is empty -- no exchange recorded"]

    issuer_key = _issuer_key_for(ledger_dir, issuer_key)
    results = verify_store(records)
    all_ok = True
    for record, result in zip(records, results):
        capsule_id = record.get("capsule_id", "<missing>")
        ok = bool(result.ok)
        cross_party = get_cross_party(record)
        ack = acks_by_capsule_id.get(capsule_id)
        ack_ok = False
        if ack is not None:
            correlator = cross_party.get("correlator") if cross_party else None
            ack_ok, ack_reason = verify_client_ack(ack, capsule_id, correlator)
        rung = derive_cross_party_rung(cross_party, has_verified_ack=ack_ok)
        caveat = identity_limitation_for_rung(rung)

        # The transparent (detached .cose signature) layer is computed BEFORE
        # we finalize this capsule's reported verify.ok, because a signed
        # statement that was NOT checked (no key) degrades this capsule's ok:
        # a capsule that carries a signature can never read verify.ok=True
        # while that signature is unchecked.
        transparent_line = _transparent_check(ledger_dir, capsule_id, issuer_key)
        capsule_unverified = False
        if transparent_line is not None:
            if transparent_line.startswith("UNVERIFIED:"):
                capsule_unverified = True
                any_unverified = True
                ok = False  # signature present but not checked -> not ok
            elif (
                transparent_line.startswith("NO SIGNATURE:")
                or transparent_line.startswith("SUBJECT MISMATCH:")
                or "signature_verified=False" in transparent_line
                or "error" in transparent_line
            ):
                # Named, hard failures (ADV-1/ADV-2) -- never UNVERIFIED (that
                # state is reserved for "couldn't check", not "checked and it's
                # wrong" or "there's nothing to check at all").
                ok = False

        all_ok = all_ok and ok

        lines.append(f"capsule {capsule_id}: verify.ok={ok} cross_party_rung={rung}")
        if not ok and not capsule_unverified:
            for f in result.findings:
                lines.append(f"    finding: {f.check} -- {f.detail}")
        if caveat:
            lines.append(f"    identity_limitation: {caveat}")
        if transparent_line:
            lines.append(f"    {transparent_line}")

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
    return all_ok, any_unverified, lines


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

        tampered_ok, _tampered_unverified, report = verify_bundle(scratch, {}, issuer_key=issuer_key)
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
    parser.add_argument("--issuer-key", default=None, help="PEM pubkey for the .cose signed statements; auto-discovers <ledger_dir>/../keys/node-key.pub.pem, then <ledger_dir>/node-key.pub.pem, then <ledger_dir>/*.pub.pem")
    parser.add_argument("--tamper-check", action="store_true", help="also prove a corrupted COPY fails verify")
    args = parser.parse_args(argv)

    ledger_dir = Path(args.ledger_dir)
    issuer_key = Path(args.issuer_key) if args.issuer_key else None
    acks_by_capsule_id = {}
    for p in args.client_acks:
        ack = _load_ack(Path(p))
        acks_by_capsule_id[ack.action_capsule_id] = ack

    print(f"=== stranger-verify: {ledger_dir} ===")
    capsule_ok, any_unverified, capsule_lines = verify_bundle(
        ledger_dir, acks_by_capsule_id, issuer_key=issuer_key
    )
    print("\n".join(capsule_lines))
    print(f"\nall capsules verify.ok: {capsule_ok}")
    if any_unverified:
        print(
            "NOTE: at least one capsule carries a signed statement that was NOT checked "
            "(no issuer key found). A bundle carrying signatures cannot read PASS while "
            "those signatures are unverified."
        )

    print("\n=== checkpoint / witness verify ===")
    checkpoint_ok, checkpoint_report = run_checkpoint_verify(ledger_dir)
    print(checkpoint_report)

    tamper_ok = True
    if args.tamper_check:
        print("\n=== adversarial: tamper-a-byte-fails ===")
        tamper_ok = tamper_check(ledger_dir, issuer_key)

    # Three-state top line: PASS only when everything verified; UNVERIFIED when
    # a signed statement was present but unchecked (never silently PASS); FAIL
    # for a hard failure. any_unverified already forced capsule_ok False, but we
    # render UNVERIFIED distinctly so a human is not misled into reading a hard
    # cryptographic failure where there was merely a missing key.
    if any_unverified and checkpoint_ok and tamper_ok:
        print("\nOVERALL: UNVERIFIED")
        return 2
    overall = capsule_ok and checkpoint_ok and tamper_ok
    print(f"\nOVERALL: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())

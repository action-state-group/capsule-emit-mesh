#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pretty-print, labeled, EVERY field that fed one sealed AAC capsule.

Companion to `run_capsule_data_inspector.sh` (the one-command real-host run):
this module takes the JSON the admission-policy plugin returned for ONE
`/v1/chat/completions` exchange (`.admission_policy` from the HTTP response)
plus the checkpoint status line `checkpoint_ledger.py` printed, and renders a
single labeled report answering "on whose hardware, which model, over which
bytes" -- the exact field list `[mesh-capsule-data-inspector-onemac]` asks
for: model_id, quantization, hardware{gpu,vram_bytes,is_soc}, hostname,
served_by_node_id, token counts, agent_input_digest, agent_output_digest,
client_nonce+source, effect_type, gate verdict, capsule_id, chain parent,
checkpoint/witness status.

Also carries the FAIL-LOUD check the task requires: if the host doesn't carry
`feat/serving-provenance`, the plugin's own honest defaults kick in and
`hardware.gpu`/`hardware.vram_bytes`/`hostname` stay `null` forever (proven
against a real host built off `mesh1331-lifecycle-hooks` without the
serving-provenance patch -- see the runbook). `check_hardware_provenance`
raises `ProvenanceMissing` in that case instead of letting the report render
a silent wall of nulls.
"""
from __future__ import annotations

import json
import sys
from typing import Any


class ProvenanceMissing(RuntimeError):
    """Raised when the sealed capsule carries no real host hardware facts."""


def check_hardware_provenance(capsule: dict[str, Any]) -> None:
    """Fail loudly if the host never reported real serving-provenance.

    A host running `feat/serving-provenance` always populates
    `hardware.gpu`/`vram_bytes`/`hostname` from its own Node hardware survey
    -- true for EVERY model, including the synthetic `allowed-test-model`
    (only `quantization`/`model.*` stay null for a model with no loaded
    GGUF). A host on `main` (or any branch predating the patch) never emits
    a `serving_provenance` block at all, so the plugin's honest defaults
    (`None`) flow straight through and `served_by_node_id` falls back to the
    plugin's own literal id ("admission-policy"), never a real iroh node id.
    Verified directly (2026-08-29): a real host built from
    `mesh1331-lifecycle-hooks` (pre-`feat/serving-provenance`) reproduces
    exactly this all-null pattern even after a warm-up request.
    """
    poc = capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
    sp = poc["serving_provenance"]
    hw = sp["hardware"]
    if hw["gpu"] is None and hw["vram_bytes"] is None and sp["hostname"] is None:
        raise ProvenanceMissing(
            "hardware fields are ALL null (hardware.gpu, hardware.vram_bytes, "
            "hostname) -- this host is not reporting real serving provenance.\n"
            "  Most likely cause: the running `mesh-llm serve` host is NOT built "
            "from the `feat/serving-provenance` branch (stacked on "
            "`mesh1331-lifecycle-hooks`) -- it is on `main` or a branch "
            "predating the patch, so it never publishes a `serving_provenance` "
            "block on its `openai.exchange.v1` terminal event.\n"
            "  Second possible cause (ruled out by this script's own warm-up "
            "request, but stated here for a hand run): the VERY FIRST exchange "
            "for a model always races the host's async terminal-event "
            "broadcast (correlation is by MODEL, not exchange id -- see "
            "capsule.rs's ServingProvenance doc comment) -- send one throwaway "
            "request to the same model first, THEN the request you want to "
            "inspect.\n"
            "  Refusing to print a report that would silently show all-null "
            "hardware fields as if that were normal."
        )


def _fmt(value: Any) -> str:
    if value is None:
        return "null"
    return str(value)


def render_report(
    *,
    capsule: dict[str, Any],
    gate_verdict: str,
    checkpoint_status: str,
) -> str:
    """Render the labeled field report. Does NOT run `check_hardware_provenance`
    -- call that first; this function only formats whatever it is given, so a
    caller inspecting an intentionally-unenriched capsule (e.g. while
    debugging) can still get a report if it explicitly skips the check.
    """
    poc = capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
    sp = poc["serving_provenance"]
    hw = sp["hardware"]
    usage = sp["usage"] or {}
    chain = capsule.get("chain")
    disposition = capsule["disposition"]

    lines = [
        "=" * 72,
        "CAPSULE DATA INSPECTOR -- every field that fed this capsule",
        "=" * 72,
        "",
        "-- what ran, on whose hardware --",
        f"  model_id                 : {_fmt(capsule['model_attestation']['model_id'])}",
        f"  quantization              : {_fmt(sp['quantization'])}",
        f"  hardware.gpu              : {_fmt(hw['gpu'])}",
        f"  hardware.vram_bytes       : {_fmt(hw['vram_bytes'])}"
        + (f"  (~{hw['vram_bytes'] / (1024**3):.1f} GiB)" if hw["vram_bytes"] else ""),
        f"  hardware.is_soc           : {_fmt(hw['is_soc'])}",
        f"  hostname                  : {_fmt(sp['hostname'])}",
        f"  served_by_node_id         : {_fmt(sp['served_by_node_id'])}",
        "",
        "-- over which bytes --",
        f"  token usage (prompt/completion/total): "
        f"{_fmt(usage.get('prompt_tokens'))}/{_fmt(usage.get('completion_tokens'))}/{_fmt(usage.get('total_tokens'))}",
        f"  agent_input_digest        : {_fmt(capsule['model_attestation']['compute_attestation']['agent_input_digest'])}",
        f"  agent_output_digest       : {_fmt(capsule['model_attestation']['compute_attestation']['agent_output_digest'])}",
        f"  client_nonce              : {_fmt(poc['client_nonce'])}",
        f"  client_nonce_source       : {_fmt(poc['client_nonce_source'])}",
        "",
        "-- gate + provenance chain --",
        f"  effect.type                : {_fmt(capsule['effect']['type'])}",
        f"  gate verdict (HTTP)        : {_fmt(gate_verdict)}",
        f"  disposition.decision       : {_fmt(disposition['decision'])}",
        f"  disposition.verdict_class  : {_fmt(disposition['verdict_class'])}",
        f"  capsule_id                 : {_fmt(capsule.get('capsule_id'))}",
        f"  chain.parent_capsule_id    : {_fmt(chain['parent_capsule_id']) if chain else 'none -- first capsule in this ledger'}",
        f"  checkpoint/witness status  : {checkpoint_status.strip()}",
        "",
        "-- exchange identity (secondary) --",
        f"  exchange_id                : {_fmt(sp['exchange_id'])}",
        f"  requesting_party           : {_fmt(sp['requesting_party'])}",
        "",
        "-- model identity (honest absence unless a real GGUF-backed model was served) --",
        f"  model.architecture         : {_fmt(sp['model']['architecture'])}",
        f"  model.context_length       : {_fmt(sp['model']['context_length'])}",
        f"  model.parameter_size       : {_fmt(sp['model']['parameter_size'])}",
        f"  model.layer_count          : {_fmt(sp['model']['layer_count'])}",
        f"  model.identity_hash        : {_fmt(sp['model']['identity_hash'])}",
        f"  model.canonical_ref        : {_fmt(sp['model']['canonical_ref'])}",
        f"  model.revision             : {_fmt(sp['model']['revision'])}",
        "=" * 72,
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI: read the HTTP response's `.admission_policy` object from a file
    (or stdin), plus a checkpoint-status line from a second file (or a literal
    string), print the report, and exit non-zero (loudly) on missing hardware
    provenance.

    Usage:
        python3 capsule_field_inspector.py <admission_policy.json> \
            [--checkpoint-status-file <path> | --checkpoint-status <text>]
    """
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "admission_policy_json",
        help="path to a JSON file holding the response's `.admission_policy` "
        "object (capsule_id + capsule + decision), or '-' for stdin",
    )
    parser.add_argument("--checkpoint-status", default="(not checkpointed)")
    parser.add_argument("--checkpoint-status-file")
    parser.add_argument(
        "--skip-provenance-check",
        action="store_true",
        help="print the report even if hardware fields are all null "
        "(debugging only -- the one-command script never passes this)",
    )
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if args.admission_policy_json == "-" else open(args.admission_policy_json).read()
    admission_policy = json.loads(raw)
    capsule = admission_policy["capsule"]
    gate_verdict = admission_policy["decision"]

    checkpoint_status = args.checkpoint_status
    if args.checkpoint_status_file:
        checkpoint_status = open(args.checkpoint_status_file).read()

    if not args.skip_provenance_check:
        try:
            check_hardware_provenance(capsule)
        except ProvenanceMissing as exc:
            print("FAIL: " + str(exc), file=sys.stderr)
            return 2

    print(render_report(capsule=capsule, gate_verdict=gate_verdict, checkpoint_status=checkpoint_status))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

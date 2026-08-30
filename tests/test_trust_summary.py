# SPDX-License-Identifier: Apache-2.0
"""TrustSummary (whole-history) tests -- the summary renders chips + the earned
gradient, and a FORGED co-carried trust value is re-derived (mirrors the mesh
viewer's forged-value discipline: never trust a co-carried value, recompute it).

Two layers, same split as the viewer tests:
  * Python shape assertions -- always run: the model shape (exchanges + chips +
    gradient + honest gaps), the gradient level logic, the meter-not-price
    neutrality of the settings/tokens, and the self-contained-embed invariant.
  * A node-driven forged-value check -- skips cleanly without node: a capsule
    whose stored capsule_id is TAMPERED must be caught by the SAME
    mesh_verify.js recompute the permalink calls, so a forged "verified" chip
    cannot survive in-browser.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from agent_action_capsule import compute_capsule_id
from trust_summary import (
    GRADIENT_ANCHORED,
    GRADIENT_EARNED,
    GRADIENT_UNKNOWN,
    build_trust_summary,
    compute_gradient,
    exchange_chip,
    render_trust_summary_html,
)
from capsule_mesh_viewer import encode_fragment

REPO = Path(__file__).resolve().parent.parent
JS = REPO / "mesh_viewer_static" / "mesh_verify.js"


def _real_capsule(cid_ok: bool = True, tokens=(52, 339, 391)) -> dict:
    """A real-shape mesh capsule (capsule-producer/0.2.0 nested serving_provenance).
    When ``cid_ok`` the stored capsule_id is the REAL recomputed id."""
    pt, ct, tt = tokens
    cap = {
        "spec_version": "draft-mih-scitt-agent-action-capsule-02",
        "format_version": "2",
        "operator": "capsule-emit-mesh-poc-rust",
        "timestamp": "2026-08-30T07:03:55.335Z",
        "model_attestation": {
            "model_id": "local-gguf/sha256-887fbdc66ab91eb5",
            "provider": "mesh-llm",
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "client_nonce_source": "host_served_observed",
                    "serving_provenance": {
                        "served_by_node_id": "740897029e7f72a51a2f4b2a98fd10ace586efdf0ca028b89026f5f9992d4d2e",
                        "requesting_party": "unknown",
                        "hostname": "swim-googles.local",
                        "quantization": "Q4_K_M",
                        "model": {"canonical_ref": "local-gguf/sha256-887fbdc66ab91eb5", "architecture": "llama", "parameter_size": "3B"},
                        "hardware": {"gpu": "Apple M3", "vram_bytes": 11453251584, "is_soc": True},
                        "usage": {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt},
                    },
                    "generation_parameters": {"temperature": "0.0"},
                }
            },
        },
        "effect": {"request_digest": "1" * 64, "response_digest": "2" * 64},
    }
    cap["capsule_id"] = compute_capsule_id(cap) if cid_ok else ("f" * 64)
    return cap


# ---- chip + gradient logic (always runs) ---------------------------------


def test_chip_kinds_cover_the_three_levels():
    assert exchange_chip(verify_ok=True, has_witness_checkpoint=True)["mark"] == "◷"
    assert exchange_chip(verify_ok=True, has_witness_checkpoint=True)["kind"] == "witnessed"
    assert exchange_chip(verify_ok=True, has_witness_checkpoint=False)["kind"] == "verified"
    assert exchange_chip(verify_ok=None, has_witness_checkpoint=False)["kind"] == "self_attested"
    # An anchor over a record that does NOT verify is never a green witnessed chip.
    assert exchange_chip(verify_ok=False, has_witness_checkpoint=True)["kind"] == "failed"


def _mk_exchanges(kinds):
    return [{"chip": {"kind": k}, "counterparty": "unknown"} for k in kinds]


def test_gradient_levels():
    # nothing offline-verifiable -> unknown
    g = compute_gradient(_mk_exchanges(["self_attested", "self_attested"]), anchored=False)
    assert g["level"] == GRADIENT_UNKNOWN and g["n_verifiable"] == 0
    # some verified, no witness -> earned-over-N
    g = compute_gradient(_mk_exchanges(["verified", "verified", "self_attested"]), anchored=False)
    assert g["level"] == GRADIENT_EARNED and g["n_verifiable"] == 2 and g["anchored"] is False
    # witnessed + anchored -> anchored (top rung)
    g = compute_gradient(_mk_exchanges(["witnessed", "verified"]), anchored=True)
    assert g["level"] == GRADIENT_ANCHORED and g["anchored"] is True and g["n_witnessed"] == 1


# ---- whole-history summary shape over real records (always runs) ----------


def test_summary_renders_chips_and_gradient():
    caps = [_real_capsule(tokens=(52, 339, 391)), _real_capsule(tokens=(59, 405, 464))]
    # Give the two distinct capsule_ids so they are separate exchanges.
    caps[1]["capsule_id"] = compute_capsule_id({**caps[1], "timestamp": "2026-08-30T07:02:00.000Z", "capsule_id": None} | {"timestamp": "2026-08-30T07:02:00.000Z"})
    caps[1]["timestamp"] = "2026-08-30T07:02:00.000Z"
    caps[1]["capsule_id"] = compute_capsule_id(caps[1])

    summary = build_trust_summary(caps, source_log="plugin")
    assert summary["view_version"] == "trust-summary-1"
    assert len(summary["exchanges"]) == 2
    # newest-first ordering
    assert summary["exchanges"][0]["timestamp"] >= summary["exchanges"][1]["timestamp"]

    ex = summary["exchanges"][0]
    # Each exchange carries a chip, a direction, a friendly (non-hash) model,
    # counterparty, and in/out tokens.
    assert ex["chip"]["mark"] in {"✓", "◷", "⚠", "✗"}
    assert ex["direction"] in {"served", "sent", "unknown"}
    assert "sha256" not in ex["friendly_model"] and "3B" in ex["friendly_model"]
    assert ex["counterparty"] == "unknown"
    assert ex["tokens_in"] is not None and ex["tokens_out"] is not None

    # The gradient headline is present with the earned-trust counts.
    g = summary["gradient"]
    assert g["level"] in {GRADIENT_UNKNOWN, GRADIENT_EARNED, GRADIENT_ANCHORED}
    assert g["n_exchanges"] == 2

    # honest gaps are never empty (never a fake all-green), and stay neutral.
    assert summary["honest_gaps"], "honest gaps must never be empty"
    assert any("metered" in gap and "priced" in gap for gap in summary["honest_gaps"])


def test_summary_is_neutral_meter_not_price():
    """Neutrality: the whole rendered summary carries no currency/price/rate."""
    caps = [_real_capsule()]
    summary = build_trust_summary(caps, source_log="plugin")
    blob = json.dumps(summary).lower()
    # "price"/"rate" appear ONLY inside the honest-gaps meter-not-price sentence
    # ("...not a priced one — it carries no currency or rate by design."), which
    # is the neutrality STATEMENT, not a leak. Everything else is banned outright.
    assert "not a priced one" in blob and "no currency or rate by design" in blob
    for banned in ("$", "usd", "cost", "€", "£", "invoice"):
        assert banned not in blob, f"neutral summary leaked a pricing token: {banned!r}"


def test_self_contained_embed_invariant():
    caps = [_real_capsule()]
    summary = build_trust_summary(caps, source_log="plugin")
    frag = encode_fragment(summary)
    html = render_trust_summary_html(frag)
    assert html.count(frag) == 1, "fragment must appear ONLY in the placeholder"
    assert f'window.__MESH_FRAGMENT_B64U__="{frag}";' in html
    # The forged-value guard JS + the mesh_verify.js recompute core are inlined.
    assert "__mesh_recomputeCapsuleId" in html
    assert "id MISMATCH" in html, "the in-browser forged-value downgrade path must be present"


# ---- node-driven forged-value re-derivation (skips without node) ----------


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available; forged-value recompute is a local/CI-with-node check")
def test_forged_capsule_id_is_recomputed_and_caught(tmp_path):
    """A capsule whose stored capsule_id is TAMPERED must be caught by the SAME
    mesh_verify.js recompute the permalink calls -- so a forged co-carried
    'verified' chip cannot survive. Drive the real mesh_verify.js under node:
    the honest record's id recomputes to its stored id; the forged one does NOT.
    """
    honest = _real_capsule(cid_ok=True)
    forged = _real_capsule(cid_ok=False)  # stored id = "f"*64, a lie

    harness = tmp_path / "forge.mjs"
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
            const honest = {json.dumps(honest)};
            const forged = {json.dumps(forged)};
            const hId = await sandbox.window.__mesh_recomputeCapsuleId(honest);
            const fId = await sandbox.window.__mesh_recomputeCapsuleId(forged);
            process.stdout.write(JSON.stringify({{
              honest_matches: hId === honest.capsule_id,
              forged_matches: fId === forged.capsule_id,
              forged_recomputed: fId,
            }}));
            """
        ),
        encoding="utf-8",
    )
    result = subprocess.run(["node", str(harness)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["honest_matches"] is True, "the honest record's id must recompute to its stored id"
    assert out["forged_matches"] is False, "the forged (tampered) id must NOT match its recompute"
    # And the re-derived id is the honest one -- the browser learns the truth.
    assert out["forged_recomputed"] == honest["capsule_id"]

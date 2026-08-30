# SPDX-License-Identifier: Apache-2.0
"""capsule-mesh view --html -- a words-first, role-organized mesh capsule VIEWER.

This is a thin PLUG-IN over the neutral fragment-carried viewer *mechanism*,
never a fork of it. The neutral property it reuses -- the load-bearing one --
is the offline, fragment-carried permalink: the capsule data lives ONLY in
the URL fragment (after ``#``), a browser never sends the fragment over the
wire, and the page re-derives every ``capsule_id`` browser-side from that
fragment (no server, no fetch). That is exactly the mechanism
``capsule_ledger.bundle_viewer.viewer`` and ``capsule_ledger.report.render``
ship; this module implements the same contract for the mesh role/question
view rather than importing a DAG-shaped template that answers different
questions. (capsule-ledger is not a dependency of capsule-emit-mesh and this
module adds none.)

What this module ADDS over the neutral base is a mesh *label layer*, composed
from the existing ``capsule_mesh_view`` role/counterparty labelling (imported,
not duplicated) plus a role -> question -> answer projection over the mesh
capsule's ``model_attestation.compute_attestation["x-mesh-poc-v1"].
serving_provenance`` block. The view is organised around the 4 roles x 3
questions of the mesh accountability build plan (§6): Requester, Provider,
Coordinator, Third party. Each question is answered FROM the record where the
record can answer it, and marked "not yet in the record" honestly where it
cannot (e.g. the coordinator receipt is not yet built).

Words-first / hide-the-merkle: every answer leads with a plain-language line
("Served: Llama-3.2-3B (Q4_K_M) on Apple M4 Max, 43 tokens -- verified");
digests, node ids and hashes are carried in the fragment but tucked behind an
expand in the page, GitHub-hides-the-DAG style. Selective disclosure is
honoured per-field: a field the operator chose to disclose (e.g. an
adversarial "why should I trust you" refusal) is carried in full; every other
disclosable field is carried digest-only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from importlib import resources
from typing import Any

# Reuse the neutral mesh label layer -- role/counterparty labelling and the
# best-effort per-log verify -- rather than re-deriving any of it here.
from capsule_mesh_view import (
    SOURCE_PLUGIN,
    SOURCE_SIDECAR,
    _poc_block,
    label_counterparty,
    label_role,
    verify_results_for,
    _verify_ok_map,
)

try:  # read_ledger is the same reader capsule_mesh_view uses for its CLI.
    from capsule_emit.ledger import read_ledger
except Exception:  # pragma: no cover - only when capsule-emit isn't installed
    read_ledger = None  # type: ignore[assignment]

# The canonical JSON-DIGEST (RFC 8785 JCS + float-stringify, spec §5.1) used by
# the Rust admission-policy plugin's `canonical_body_digest` AND its
# host-served `emit_for_observed_host_exchange` output-facts digest. Reused
# verbatim (never reforked) so the viewer's server-facts verification is the
# SAME digest the capsule sealed. `digest_json` = json_digest(stringify_floats).
try:
    from capsule_sidecar import digest_json as _digest_json
except Exception:  # pragma: no cover - only when scitt-cose/aac isn't installed
    _digest_json = None  # type: ignore[assignment]

__all__ = [
    "serving_provenance",
    "plain_model_line",
    "friendly_model_name",
    "build_verdict",
    "build_role_questions",
    "served_facts_digest",
    "build_conversation",
    "to_fragment_payload",
    "encode_fragment",
    "decode_fragment",
    "render_mesh_viewer_html",
    "ROLE_KEYS",
    "DEFAULT_ROLE",
]

# Which role(s) the viewer renders inline, and which is the default. The user's
# feedback: "just the requester only". So the requester's questions are the
# DEFAULT inline view and the other three roles go behind a collapsed "other
# roles" toggle -- still carried in the payload, never deleted. `--role all`
# restores the original 4-roles-x-3-questions layout inline.
ROLE_KEYS = ("requester", "provider", "coordinator", "third_party")
DEFAULT_ROLE = "requester"


# ---------------------------------------------------------------------------
# Field extraction -- tolerant of both mesh capsule shapes seen in real
# captures: the nested x-mesh-poc-v1.serving_provenance{model,hardware,usage}
# block (capsule-producer/0.2.0, mesh-real-model-capture) and the older flat
# serving_provenance (ledger-live). Missing fields stay None; nothing is
# invented.
# ---------------------------------------------------------------------------


def serving_provenance(record: dict[str, Any]) -> dict[str, Any]:
    """Normalise the serving-provenance block to one flat shape.

    Returns keys: model, quantization, architecture, parameter_size,
    context_length, layer_count, model_identity_hash, model_canonical_ref,
    gpu, vram_bytes, is_soc, device, hostname, served_by_node_id,
    requesting_party, exchange_id, prompt_tokens, completion_tokens,
    total_tokens. Every value is either the real field or None.
    """
    poc = _poc_block(record)
    sp = poc.get("serving_provenance") or {}
    model = sp.get("model") or {}
    hw = sp.get("hardware") or {}
    usage = sp.get("usage") or {}

    def pick(*names: str) -> Any:
        for src in (sp, model, hw):
            for n in names:
                if n in src and src[n] is not None:
                    return src[n]
        return None

    return {
        "model": sp.get("model_canonical_ref")
        or model.get("canonical_ref")
        or record.get("model_attestation", {}).get("model_id"),
        "quantization": sp.get("quantization"),
        "architecture": pick("architecture"),
        "parameter_size": pick("parameter_size"),
        "context_length": pick("context_length"),
        "layer_count": pick("layer_count"),
        "model_identity_hash": model.get("identity_hash") or sp.get("model_identity_hash"),
        "model_canonical_ref": sp.get("model_canonical_ref") or model.get("canonical_ref"),
        "model_name_digest": poc.get("model_name_digest"),
        "gpu": hw.get("gpu") or sp.get("gpu"),
        "vram_bytes": hw.get("vram_bytes") if hw.get("vram_bytes") is not None else sp.get("vram_bytes"),
        "is_soc": hw.get("is_soc") if hw.get("is_soc") is not None else sp.get("is_soc"),
        "device": hw.get("device"),
        "hostname": sp.get("hostname"),
        "served_by_node_id": sp.get("served_by_node_id"),
        "requesting_party": sp.get("requesting_party"),
        "exchange_id": sp.get("exchange_id"),
        "client_nonce_source": poc.get("client_nonce_source"),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "total_tokens": usage.get("total_tokens"),
    }


def _fmt_vram(vram_bytes: Any) -> str | None:
    try:
        gb = int(vram_bytes) / (1024**3)
    except (TypeError, ValueError):
        return None
    return f"{gb:.0f} GB VRAM"


def plain_model_line(sp: dict[str, Any]) -> str:
    """One plain-language sentence naming the model/quant/hardware served.

    Words first; no digests. Used verbatim as Requester Q1's headline.
    """
    model = sp.get("model") or "(model not named in record)"
    bits: list[str] = [str(model)]
    if sp.get("quantization") and sp["quantization"] != "unknown":
        bits.append(f"({sp['quantization']})")
    hw_bits: list[str] = []
    if sp.get("gpu"):
        hw_bits.append(str(sp["gpu"]))
    if sp.get("is_soc"):
        hw_bits.append("SoC")
    vram = _fmt_vram(sp.get("vram_bytes"))
    if vram:
        hw_bits.append(vram)
    line = " ".join(bits)
    if hw_bits:
        line += " on " + ", ".join(hw_bits)
    total = sp.get("total_tokens")
    if total:
        line += f", {total} tokens"
    return line


# ---------------------------------------------------------------------------
# Friendly model name + plain-language verdict -- the single biggest
# readability win (Steven's feedback: "the model name is a raw hash").
# ---------------------------------------------------------------------------

# Map a raw GGUF architecture string to a human family name, when we can say it
# truthfully. `llama` + parameter_size `3B` -> "Llama-3.2-3B" is NOT safe to
# assert (the record does not carry the minor version), so we build the honest
# form from what the record actually holds: architecture family + parameter
# size, refined by the canonical_ref when it names a real HF-style model.
_ARCH_FAMILY = {"llama": "Llama", "mistral": "Mistral", "qwen": "Qwen", "gemma": "Gemma", "phi": "Phi"}


def friendly_model_name(sp: dict[str, Any]) -> str:
    """A human model name derived from architecture + parameter_size (+ quant),
    e.g. ``Llama-3.2-3B · Q4_K_M`` -- NEVER the raw ``local-gguf/sha256-…`` id
    or the model_identity_hash. Falls back honestly when the record doesn't
    carry enough to name a family (``model (Q4_K_M)`` / just the raw ref as a
    last resort, since that is still the only identity present).

    The raw hash/canonical_ref still travels in the payload (behind the details
    toggle) -- this function only decides what the DEFAULT view shows.
    """
    ref = sp.get("model_canonical_ref") or sp.get("model") or ""
    quant = sp.get("quantization")
    quant = str(quant) if quant and quant != "unknown" else None

    # 1) A real HF-style ref like "meta-llama/Llama-3.2-3B-Instruct" names
    #    itself -- prefer its human tail over re-deriving.
    if ref and not str(ref).startswith("local-gguf/") and "/" in str(ref):
        human = str(ref).split("/")[-1]
        return f"{human} · {quant}" if quant else human

    # 2) Derive from architecture family + parameter size (the honest default
    #    for a raw local GGUF whose only id is a content hash).
    arch = (sp.get("architecture") or "").lower()
    family = _ARCH_FAMILY.get(arch)
    size = sp.get("parameter_size")
    if family and size:
        base = f"{family}-{size}"
        return f"{base} · {quant}" if quant else base
    if family:
        return f"{family} · {quant}" if quant else family

    # 3) Last resort: we could not derive a family. Do not invent one; show a
    #    neutral placeholder + quant, never the raw sha256 in the default view.
    return f"local model · {quant}" if quant else "local model"


def build_verdict(
    sp: dict[str, Any],
    *,
    verify_ok: bool | None,
    has_witness_checkpoint: bool,
    counterparty: str,
) -> list[dict[str, str]]:
    """Three plain-language lines that are the DEFAULT per-card read, replacing
    the three dense role-questions. Each line is {mark, text} where mark is
    "ok" (✓) or "warn" (⚠) -- never a fake green.

    Line 1 — what really ran (green when the model+hardware facts recompute).
    Line 2 — signed + anchored (green only if witness receipt is carried;
             honest amber "witness receipt not in this bundle" otherwise).
    Line 3 — the honest open gap: who asked + this node's history.
    """
    name = friendly_model_name(sp)
    gpu = sp.get("gpu")
    hw = f" on an {gpu}" if gpu else ""
    if sp.get("is_soc") and gpu:
        hw = f" on an {gpu} (Apple silicon)"

    # Line 1 — really ran. Green when this record's own facts verify here.
    if sp.get("model") and verify_ok is not False:
        line1 = {
            "mark": "ok",
            "text": f"Really ran on {name}{hw} — and you can recompute the proof in your browser.",
        }
    elif sp.get("model") and verify_ok is False:
        line1 = {
            "mark": "warn",
            "text": f"Claims to have run on {name}{hw}, but this record FAILED verification here.",
        }
    else:
        line1 = {"mark": "warn", "text": "No serving-provenance in this record — can't say what ran."}

    # Line 2 — signed + anchored. Honest amber unless a witness receipt rides along.
    if has_witness_checkpoint:
        line2 = {
            "mark": "ok",
            "text": "Signed by the provider and anchored to a public witness, so it can't be quietly changed.",
        }
    else:
        line2 = {
            "mark": "warn",
            "text": "Provider-signed (the signature verifies here) — but the witness receipt isn't in this "
            "bundle, so anchoring isn't shown in this view.",
        }

    # Line 3 — the open gap, stated plainly. Green only if a real counterparty
    #          identity is present; otherwise the honest "not yet proven".
    if counterparty and counterparty != "unknown":
        line3 = {"mark": "ok", "text": f"Who asked is attested ({counterparty})."}
    else:
        line3 = {
            "mark": "warn",
            "text": "Not yet proven: who asked (the requester is self-attested, not named) — "
            "and this node's track record isn't carried in a single record.",
        }

    return [line1, line2, line3]


# ---------------------------------------------------------------------------
# The role x question projection (build plan §6).
#
# answerable states:
#   "answered"     -- the record answers it; ``value`` is the plain answer.
#   "partial"      -- the record answers it, but only self-attested / a weaker
#                     rung than the full mechanism (e.g. no counterparty
#                     countersign yet), stated honestly.
#   "not_in_record"-- the mechanism that would answer it is not yet built for
#                     this record (e.g. the coordinator receipt). Said so
#                     out loud, never faked.
# ---------------------------------------------------------------------------

ANSWERED = "answered"
PARTIAL = "partial"
NOT_IN_RECORD = "not_in_record"


def _q(question: str, state: str, value: str, *, evidence: list[str] | None = None) -> dict[str, Any]:
    return {"question": question, "state": state, "answer": value, "evidence": evidence or []}


def build_role_questions(
    record: dict[str, Any],
    *,
    source_log: str,
    verify_ok: bool | None,
    has_witness_checkpoint: bool,
) -> dict[str, Any]:
    """Answer the 4 roles x 3 questions from one mesh capsule + context.

    ``verify_ok`` is this record's own best-effort store-verify result (from
    capsule_mesh_view's verifier). ``has_witness_checkpoint`` is True when a
    COSE checkpoint receipt covering this log was supplied -- it is what turns
    the third-party "is the record complete / anchored" answer from
    self-attested into witnessed.
    """
    sp = serving_provenance(record)
    role = label_role(record, source_log)
    counterparty = label_counterparty(record)
    effect = record.get("effect", {}) or {}
    disposition = record.get("disposition", {}) or {}
    verified_word = {True: "verified", False: "FAILED verify", None: "not verified here"}[verify_ok]

    # ---- Requester -----------------------------------------------------
    req_q1 = _q(
        "Did I get the model / quant / hardware I asked for?",
        ANSWERED if sp.get("model") else NOT_IN_RECORD,
        f"Served: {plain_model_line(sp)} — {verified_word}."
        if sp.get("model")
        else "No serving-provenance block in this record.",
        evidence=["serving_provenance.model", "serving_provenance.quantization", "serving_provenance.hardware"],
    )
    req_q2 = _q(
        "Can I prove to a stranger what this provider did?",
        PARTIAL,
        (
            "Yes, from this signed record"
            + (" anchored to a witness checkpoint" if has_witness_checkpoint else "")
            + " — self-attested today; a counterparty countersign (Move 4) is not yet in this record, "
            "so it is the provider's signed claim, offline-verifiable, not yet a mutual one."
        ),
        evidence=["capsule_id (recomputed in-browser)", "signed statement", "witness checkpoint receipt"],
    )
    req_q3 = _q(
        "Have I had good exchanges with this node before?",
        NOT_IN_RECORD,
        "A per-node reputation predicate is computed by the relying party over its OWN history — "
        "not carried in a single capsule. This viewer shows one exchange, not a history.",
        evidence=["served_by_node_id"],
    )

    # ---- Provider ------------------------------------------------------
    prov_q1_answered = counterparty != "unknown"
    prov_q1 = _q(
        "Who asked — a verified party, not anonymous?",
        ANSWERED if prov_q1_answered else PARTIAL,
        (f"Counterparty: {counterparty} (bilateral request attestation present)."
         if prov_q1_answered
         else "Requesting party is not identified in this record (counterparty: unknown) — "
              "the honest self-attested rung. A bilateral request attestation would raise it."),
        evidence=["cross_party.initiator_ref", "serving_provenance.requesting_party"],
    )
    prov_q2 = _q(
        "Can I prove I served honestly and wasn't liable for what they asked?",
        ANSWERED if effect else PARTIAL,
        (f"Gate verdict: {disposition.get('decision', 'n/a')} / {disposition.get('verdict_class', 'n/a')}; "
         f"effect: {effect.get('effect_attestation', 'n/a')}; request/response carried as digests only "
         f"(non-retention) — {verified_word}."),
        evidence=["disposition.decision", "effect.effect_attestation", "request_digest", "response_digest"],
    )
    prov_q3 = _q(
        "Should I keep serving this requester?",
        NOT_IN_RECORD,
        "An edge-computed predicate over the provider's own history — not a field in any single capsule.",
        evidence=["requesting_party", "served_by_node_id"],
    )

    # ---- Coordinator ---------------------------------------------------
    coord_q1 = _q(
        "Which nodes held which slices, in what order?",
        NOT_IN_RECORD,
        "The coordinator stage-order receipt (the graph) is NOT YET BUILT (build plan §3, B6). "
        "This is a single-node exchange; no split-inference topology is recorded here.",
        evidence=["coordinator receipt (not built)"],
    )
    coord_q2 = _q(
        "Can I bound what I learn (seeing everything = liability)?",
        NOT_IN_RECORD,
        "A bounded-knowledge marker on the coordinator record is NOT YET IN THE RECORD (B6). "
        "The relay-never-sees-a-token property is a design invariant, not yet an attested field here.",
        evidence=["bounded-knowledge marker (not built)"],
    )
    coord_q3 = _q(
        "Can I prove I routed honestly?",
        NOT_IN_RECORD,
        "The coordinator receipt over per-stage receipts is NOT YET BUILT (B6). "
        "Per-record observation_point exists; the coordinator-level honest-routing proof does not yet.",
        evidence=["coordinator receipt (not built)", "observation_point"],
    )

    # ---- Third party (auditor / court) --------------------------------
    tp_q1_state = ANSWERED if (verify_ok is True and sp.get("model")) else PARTIAL
    tp_q1 = _q(
        "Did this exchange happen as claimed — right model / hardware / both parties?",
        tp_q1_state,
        (f"Model + hardware attested and this record's capsule_id recomputes ({verified_word}); "
         + ("both parties present." if prov_q1_answered
            else "the counterparty half is self-attested only (no bilateral countersign yet).")),
        evidence=["offline verify --store", "serving_provenance", "cross_party.initiator_ref"],
    )
    tp_q2 = _q(
        "Is the record complete / not equivocated?",
        ANSWERED if has_witness_checkpoint else NOT_IN_RECORD,
        ("Anchored: a COSE checkpoint receipt covering this log was supplied — inclusion + consistency "
         "against the public witness checkpoint bound this record into a non-equivocable log."
         if has_witness_checkpoint
         else "No witness checkpoint receipt was supplied with this view, so inclusion/consistency against "
              "the public witness is NOT shown here — the record is self-attested, not yet anchored in THIS view."),
        evidence=["witness checkpoint (COSE_Sign1 cll-checkpoint)", "inclusion proof", "consistency proof"],
    )
    tp_q3 = _q(
        "Can I evaluate a claim I didn't witness?",
        PARTIAL,
        "Yes — this bundle is offline-verifiable from the fragment alone (no access to any party's live "
        "log), and the relying party applies its OWN predicate. Evidence is presented; policy decides; "
        "nobody here is the authority.",
        evidence=["disclosed bundle (this permalink)", "relying-party predicate"],
    )

    return {
        "role_label": role,
        "counterparty": counterparty,
        "roles": {
            "requester": {"title": "Requester", "questions": [req_q1, req_q2, req_q3]},
            "provider": {"title": "Provider", "questions": [prov_q1, prov_q2, prov_q3]},
            "coordinator": {"title": "Coordinator", "questions": [coord_q1, coord_q2, coord_q3]},
            "third_party": {"title": "Third party (auditor / court)", "questions": [tp_q1, tp_q2, tp_q3]},
        },
    }


# ---------------------------------------------------------------------------
# Inference-forward conversation block -- lead with the exchange, disclosed +
# verified against exactly the digest the capsule actually sealed.
#
# The honest crypto boundary (documented in the seal path,
# admission-policy/src/capsule_emit.rs::emit_for_observed_host_exchange, and in
# this demo's b-tool_calls.json artifact): on the host-served observe path the
# plugin NEVER sees the streamed response BODY. It seals:
#   - `request_digest`  = canonical JSON-DIGEST of the REAL request body
#                         (host-forwarded, byte-identical to canonical_body_digest).
#   - `response_digest` = canonical JSON-DIGEST of the observed TERMINAL FACTS
#                         `{model, usage:{prompt,completion,total}}` -- NOT the
#                         response text.
# So a disclosed response TEXT is requester-held and CANNOT be checked against
# `response_digest`; what CAN be checked, and is, is that the `{model, usage}`
# the viewer shows recomputes to the sealed `response_digest`. A disclosed
# request BODY (when the requester supplies the exact bytes) DOES verify against
# `request_digest`. We show each check for what it is and never claim a match we
# can't prove.
# ---------------------------------------------------------------------------


def served_facts_digest(sp: dict[str, Any]) -> str | None:
    """Recompute the host-served ``response_digest`` from the observed terminal
    facts ``{model, usage:{prompt,completion,total}}``.

    Mirrors ``emit_for_observed_host_exchange``'s ``output_facts`` digest
    exactly (same key set, same canonical JSON-DIGEST). Returns None when the
    JCS reference isn't importable or the facts are incomplete -- never a
    fabricated value.
    """
    if _digest_json is None:
        return None
    model = sp.get("model")
    pt, ct, tt = sp.get("prompt_tokens"), sp.get("completion_tokens"), sp.get("total_tokens")
    if model is None or pt is None or ct is None or tt is None:
        return None
    facts = {"model": model, "usage": {"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": tt}}
    try:
        return _digest_json(facts)
    except Exception:  # pragma: no cover - defensive; never fabricate a digest
        return None


def _request_body_digest(request_body: dict[str, Any] | None) -> str | None:
    """Canonical digest of a disclosed request BODY, comparable to the sealed
    ``request_digest``. Returns None when no body was supplied or the reference
    isn't importable."""
    if _digest_json is None or request_body is None:
        return None
    try:
        return _digest_json(request_body)
    except Exception:  # pragma: no cover
        return None


def build_conversation(
    record: dict[str, Any],
    sp: dict[str, Any],
    disclosed: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the words-first Prompt -> Response block for one capsule.

    ``disclosed`` (per capsule_id) may carry:
      - ``request``       : the requester's plain prompt text (shown, not
                            digest-checkable on its own -- the request BODY is
                            what ``request_digest`` seals).
      - ``request_body``  : the exact request JSON body, if the requester holds
                            it; when present it is digest-verified against
                            ``request_digest``.
      - ``response``      : the response text (shown; the served FACTS are what
                            verify against ``response_digest``).
      - ``tool_calls_note``: a short note (e.g. "a web_search tool_call was
                            made") carried verbatim.

    Every ``verify`` sub-object states which sealed digest it checks and the
    outcome, so the reader sees BOTH the words and the proof-or-honest-gap.
    """
    disclosed = disclosed or {}
    effect = record.get("effect", {}) or {}
    request_digest = effect.get("request_digest")
    response_digest = effect.get("response_digest")

    # ---- prompt side ---------------------------------------------------
    prompt_text = disclosed.get("request")
    request_body = disclosed.get("request_body")
    body_digest = _request_body_digest(request_body)
    if request_body is not None:
        # The requester holds the exact request bytes -> a real digest check.
        prompt_verify = {
            "kind": "request_body",
            "sealed_digest": request_digest,
            "computed_digest": body_digest,
            "matches": (body_digest is not None and body_digest == request_digest),
            "label": "request body vs sealed request_digest",
        }
    else:
        # Only the human-readable prompt is held; the request BODY (system
        # prompt + tools + params, prompt_tokens worth) is not in this bundle,
        # so request_digest stays sealed -- stated, never faked as a match.
        prompt_verify = {
            "kind": "request_sealed",
            "sealed_digest": request_digest,
            "computed_digest": None,
            "matches": None,
            "label": "request body not held in this bundle — request_digest sealed",
        }

    # ---- response side -------------------------------------------------
    response_text = disclosed.get("response")
    computed_facts = served_facts_digest(sp)
    response_verify = {
        "kind": "served_facts",
        "sealed_digest": response_digest,
        "computed_digest": computed_facts,
        "matches": (computed_facts is not None and computed_facts == response_digest),
        "label": "served model + usage vs sealed response_digest",
        # A small muted secondary line (styled tiny/grey), not a big paragraph:
        # the honest boundary that response_digest seals the served facts, and
        # the text is the requester's held copy.
        "note": (
            "response_digest seals the served facts (model + token usage); the "
            "text is the requester's held copy."
        ),
    }

    return {
        "served_by": {
            "node_id": sp.get("served_by_node_id"),
            "model": sp.get("model"),
            "quantization": sp.get("quantization"),
            "gpu": sp.get("gpu"),
            "is_soc": sp.get("is_soc"),
        },
        "prompt": {
            "text": prompt_text,
            # For the inline header tag: green "shown by operator" when the
            # operator disclosed this field, grey "sealed — digest only" otherwise.
            "disclosed": prompt_text is not None,
            "verify": prompt_verify,
        },
        "response": {
            "text": response_text,
            "disclosed": response_text is not None,
            "tool_calls_note": disclosed.get("tool_calls_note"),
            "verify": response_verify,
        },
    }


# ---------------------------------------------------------------------------
# Selective disclosure -- per-field shown vs digest-only.
# ---------------------------------------------------------------------------

# The prompt/response content lives behind digests in the capsule
# (request_digest / response_digest) and is disclosable per-field. Absent an
# explicit disclosure map, EVERYTHING content-bearing stays digest-only (the
# closed default the bundle already has). A caller passes disclose={key: text}
# to open a specific field -- e.g. an adversarial refusal the provider chose
# to show -- and the rest stay sealed.
def _disclosure_view(record: dict[str, Any], disclose: dict[str, str] | None) -> dict[str, Any]:
    effect = record.get("effect", {}) or {}
    fields = []
    for label, digest_key in (("request", "request_digest"), ("response", "response_digest")):
        digest = effect.get(digest_key)
        opened = (disclose or {}).get(label)
        fields.append(
            {
                "label": label,
                "digest": digest,
                "disclosed": opened is not None,
                "content": opened,  # None => digest-only (sealed); str => operator disclosed it
            }
        )
    return {"fields": fields}


# ---------------------------------------------------------------------------
# Fragment payload -- the single JSON that travels in the URL after '#'.
# ---------------------------------------------------------------------------


def _witness_summary(witness_checkpoint: dict[str, Any] | None) -> dict[str, Any] | None:
    if not witness_checkpoint:
        return None
    return {
        "kind": witness_checkpoint.get("kind"),
        "log_id": witness_checkpoint.get("log_id"),
        "root": witness_checkpoint.get("root"),
        "size": witness_checkpoint.get("mmr_size") or witness_checkpoint.get("log_size"),
        "issued_at": witness_checkpoint.get("timestamp") or witness_checkpoint.get("issued_at"),
        "cose_present": bool(witness_checkpoint.get("checkpoint_cose")),
    }


def to_fragment_payload(
    records: list[dict[str, Any]],
    *,
    source_log: str = SOURCE_SIDECAR,
    witness_checkpoint: dict[str, Any] | None = None,
    disclose: dict[str, dict[str, Any]] | None = None,
    operator: str | None = None,
    ledger_dir: Any = None,
    default_role: str = DEFAULT_ROLE,
) -> dict[str, Any]:
    """Build the fragment payload for a list of mesh capsules.

    ``disclose`` maps ``capsule_id -> {"request"|"response": revealed_text}``;
    any field not named there stays digest-only. ``witness_checkpoint`` is the
    optional COSE checkpoint receipt covering ``source_log``. ``ledger_dir``,
    when given, lets ``verify_results_for`` reach the DETACHED
    ``signed-statements/<capsule_id>.cose`` producer signatures next to the
    log -- turning ``verify_ok`` green for records that carry no inline
    envelope (the mesh capsules' usual shape).
    """
    try:
        verify_results = verify_results_for(records, ledger_dir=ledger_dir)
    except TypeError:
        # Older capsule_mesh_view without the ledger_dir kwarg.
        verify_results = verify_results_for(records)
    vmap = _verify_ok_map(records, verify_results)
    has_witness = witness_checkpoint is not None

    entries = []
    for rec in records:
        cid = rec.get("capsule_id", "")
        verify_ok = vmap.get(cid)
        sp = serving_provenance(rec)
        cap_disclose = (disclose or {}).get(cid)
        entries.append(
            {
                "capsule_id": cid,
                "timestamp": rec.get("timestamp"),
                "operator": rec.get("operator"),
                "verify_ok": verify_ok,
                # Friendly display name for the DEFAULT view (never the raw
                # local-gguf/sha256 hash -- that stays in serving_provenance,
                # surfaced only behind the security-checks toggle).
                "friendly_model": friendly_model_name(sp),
                # Three plain-language lines that ARE the default per-card read.
                "verdict": build_verdict(
                    sp,
                    verify_ok=verify_ok,
                    has_witness_checkpoint=has_witness,
                    counterparty=label_counterparty(rec),
                ),
                "serving_provenance": sp,
                # Inference-forward: the words-first Prompt -> Response block,
                # disclosed + digest-verified, rendered ABOVE the questions.
                "conversation": build_conversation(rec, sp, cap_disclose),
                "role_questions": build_role_questions(
                    rec, source_log=source_log, verify_ok=verify_ok, has_witness_checkpoint=has_witness
                ),
                # The full record travels so the browser can recompute capsule_id
                # (hide-the-merkle, but the merkle is CHECKABLE, not just hidden).
                "record": rec,
            }
        )
    if default_role not in ROLE_KEYS and default_role != "all":
        default_role = DEFAULT_ROLE
    return {
        "view_version": "mesh-role-2",
        "operator": operator or (records[0].get("operator") if records else None),
        "source_log": source_log,
        # Which role renders inline by default; the rest fold behind a toggle.
        # "all" renders every role inline (the original layout).
        "default_role": default_role,
        "witness": _witness_summary(witness_checkpoint),
        "entries": entries,
    }


def encode_fragment(payload: dict[str, Any]) -> str:
    """base64url(JSON), no padding -- URL-transportable, not encrypted. Same
    encoding the neutral report/bundle viewers use."""
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_fragment(token: str) -> dict[str, Any]:
    token = token.lstrip("#")
    padding = "=" * (-len(token) % 4)
    return json.loads(base64.urlsafe_b64decode(token + padding).decode("utf-8"))


# ---------------------------------------------------------------------------
# The self-contained HTML shell + inline verify.js. Carries NO capsule data;
# everything renders from the fragment at load time, offline.
# ---------------------------------------------------------------------------


def _load_verify_js() -> str:
    return (
        resources.files("mesh_viewer_static")
        .joinpath("mesh_verify.js")
        .read_text(encoding="utf-8")
    )


def render_mesh_viewer_html(fragment: str) -> str:
    """Return the self-contained mesh viewer HTML for *fragment*.

    Open it as ``<file>#<fragment>``. No external references, no server, no
    network -- the page reads ``location.hash`` (or the embedded fragment),
    decodes it, recomputes each ``capsule_id`` in-browser, and renders the
    4 roles x 3 questions words-first.
    """
    verify_js = _load_verify_js()
    # The self-contained embed: the base64url fragment must land ONLY in the
    # `window.__MESH_FRAGMENT_B64U__` placeholder -- NEVER anywhere else. The
    # verify.js boot guard tests `embedded !== "@@FRAGMENT_SENTINEL@@"` (a
    # DISTINCT token that is not the placeholder), so it is never overwritten by
    # the fragment. The earlier bug replaced a shared token in BOTH the
    # placeholder and the guard condition, jamming the base64 into
    # `if (embedded && embedded !== "...")` -> a JS syntax error that blanked the
    # page (see mesh-live-demo-permalink.html.bak). Order matters: inline the JS
    # first, THEN substitute the single placeholder, and assert the fragment
    # appears exactly once in the output.
    embed = json.dumps(fragment)  # a JSON string literal: "<base64url>"
    shell = _HTML_SHELL.replace("@@VERIFY_JS@@", verify_js)
    if "@@FRAGMENT@@" not in shell or shell.count("@@FRAGMENT@@") != 1:
        raise RuntimeError(
            "embed invariant broken: exactly one @@FRAGMENT@@ placeholder must "
            f"exist in the shell, found {shell.count('@@FRAGMENT@@')}"
        )
    html = shell.replace("@@FRAGMENT@@", embed)
    # Belt-and-suspenders: the base64 must appear ONLY in the placeholder
    # assignment, never in the boot guard.
    if fragment and (f'!== "{fragment}"' in html or f"!=='{fragment}'" in html):
        raise RuntimeError(
            "embed invariant broken: fragment leaked into the boot guard condition"
        )
    return html


# The shell is data-free chrome + templates; mesh_verify.js fills it in.
_HTML_SHELL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mesh capsule viewer — what my capsules look like</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background:#F4F4F0; color:#161B25; font-family:system-ui,-apple-system,sans-serif; -webkit-font-smoothing:antialiased; }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .wrap { max-width:960px; margin:0 auto; padding:40px 28px 90px; }
  .share { display:flex; justify-content:space-between; align-items:center; gap:12px; font-size:11px; color:#5C6573; margin-bottom:10px; flex-wrap:wrap; }
  .share button { font:inherit; font-size:11px; background:none; border:none; color:#3A5BD9; cursor:pointer; padding:0; font-family:ui-monospace,monospace; }
  .disclosure { font-size:12px; color:#5C6573; line-height:1.6; border-left:2px solid #3A5BD9; padding-left:12px; margin-bottom:22px; }
  h1 { font-size:30px; letter-spacing:-1px; color:#0B0E14; margin-bottom:6px; }
  h1 em { color:#3A5BD9; font-style:normal; }
  .sub { font-size:14px; color:#5C6573; margin-bottom:8px; }
  .meta { font-size:11px; color:#5C6573; margin-bottom:26px; }
  .empty { background:#FCFCFA; border:1px solid #E3E3DC; border-radius:16px; padding:60px 30px; text-align:center; color:#5C6573; }
  .entry { background:#FCFCFA; border:1px solid #E3E3DC; border-radius:16px; margin-bottom:24px; overflow:hidden; }
  .entry-head { padding:20px 24px; border-bottom:1px solid #E3E3DC; display:flex; justify-content:space-between; align-items:baseline; gap:12px; flex-wrap:wrap; }
  .entry-title { font-size:17px; color:#0B0E14; font-weight:600; }
  .badge { display:inline-flex; align-items:center; gap:6px; font-size:11px; border:1px solid #E3E3DC; border-radius:100px; padding:3px 11px; color:#5C6573; }
  .badge.ok { color:#127A52; border-color:#B8DCC9; background:#E6F2EC; }
  .badge.fail { color:#B3261E; border-color:#F0C4C0; background:#FBEAE8; }
  .state { font-size:10px; text-transform:uppercase; letter-spacing:1px; padding:2px 8px; border-radius:100px; margin-left:8px; vertical-align:middle; }
  .state.answered { background:#E6F2EC; color:#127A52; }
  .state.partial { background:#FBF3E2; color:#9A6B12; }
  .state.not_in_record { background:#F1F1EC; color:#7A6355; }
  details.merkle { margin-top:8px; font-size:11px; }
  details.merkle summary { cursor:pointer; color:#3A5BD9; font-family:ui-monospace,monospace; }
  .kv { display:grid; grid-template-columns:180px 1fr; gap:4px 12px; margin-top:8px; font-size:11px; color:#5C6573; word-break:break-all; }
  .kv b { color:#161B25; font-weight:500; }
  .foot { font-size:11px; color:#5C6573; margin-top:20px; line-height:1.6; }
  /* Plain-language verdict -- the DEFAULT read per card (3 human lines). */
  .verdict { padding:16px 24px 18px; border-bottom:1px solid #E3E3DC; }
  .vline { display:flex; align-items:flex-start; gap:10px; font-size:14.5px; line-height:1.5; color:#161B25; margin-bottom:9px; }
  .vline:last-child { margin-bottom:0; }
  .vline .vmark { flex:0 0 auto; font-size:15px; line-height:1.4; }
  .vline.ok   .vmark { color:#127A52; }
  .vline.warn .vmark { color:#9A6B12; }
  .vline.warn { color:#5B4A2A; }
  /* Inference-forward conversation block -- lead with the exchange. */
  .conv { padding:18px 24px 6px; border-bottom:1px solid #E3E3DC; }
  .conv-served { font-size:11px; color:#5C6573; margin-bottom:12px; font-family:ui-monospace,monospace; }
  .conv-turn { margin-bottom:14px; }
  .conv-label { font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#3A5BD9; font-weight:600; margin-bottom:4px; display:flex; align-items:center; gap:8px; }
  .conv-tag { font-size:9.5px; letter-spacing:0.6px; text-transform:uppercase; border-radius:100px; padding:2px 8px; font-weight:600; }
  .conv-tag.shown  { color:#127A52; background:#E6F2EC; border:1px solid #B8DCC9; }
  .conv-tag.sealed { color:#7A6355; background:#F1F1EC; border:1px solid #E3DDD4; }
  .conv-text { font-size:14.5px; line-height:1.6; color:#161B25; white-space:pre-wrap; background:#FBFBF9; border:1px solid #ECECE6; border-radius:10px; padding:12px 14px; }
  .conv-verify { margin-top:6px; }
  .conv-toolcall { display:block; margin-top:6px; font-size:12px; color:#9A6B12; background:#FBF3E2; border-radius:8px; padding:6px 10px; }
  .conv-note { display:block; margin-top:5px; font-size:10.5px; color:#8A8A80; line-height:1.45; }
  .vchip { display:inline-flex; align-items:center; font-size:11px; border-radius:100px; padding:2px 10px; border:1px solid #E3E3DC; }
  .vchip.ok { color:#127A52; border-color:#B8DCC9; background:#E6F2EC; }
  .vchip.fail { color:#B3261E; border-color:#F0C4C0; background:#FBEAE8; }
  .vchip.sealed { color:#7A6355; border-color:#E3DDD4; background:#F5F1EA; font-family:ui-monospace,monospace; }
  /* The ONE "Show the security checks" toggle -- collapsed by default. */
  details.checks { border-top:1px solid #E3E3DC; }
  details.checks > summary { cursor:pointer; list-style:none; padding:12px 24px; font-size:12.5px; color:#3A5BD9; font-weight:600; display:flex; align-items:center; gap:8px; user-select:none; }
  details.checks > summary::-webkit-details-marker { display:none; }
  details.checks > summary::before { content:"▸"; font-size:11px; }
  details.checks[open] > summary::before { content:"▾"; }
  details.checks > summary .hint { font-weight:400; color:#8A8A80; font-size:11px; }
  .checks-body { padding:4px 24px 18px; }
  .checks-body .id-line { font-size:11px; color:#5C6573; font-family:ui-monospace,monospace; word-break:break-all; white-space:pre-wrap; line-height:1.7; margin-bottom:12px; }
  .checks-body .id-line b { color:#161B25; font-weight:500; }
  .roles { margin-top:6px; }
  .role { margin-top:16px; }
  .role-title { font-size:13px; text-transform:uppercase; letter-spacing:1.2px; color:#3A5BD9; font-weight:600; margin-bottom:8px; }
  .qa { border:1px solid #ECECE6; border-radius:12px; padding:12px 16px; margin-bottom:8px; }
  .q { font-size:12.5px; color:#5C6573; margin-bottom:4px; }
  .a { font-size:14px; color:#161B25; line-height:1.55; }
  details.other-roles { margin-top:16px; border-top:1px dashed #E3E3DC; padding-top:10px; }
  details.other-roles > summary { cursor:pointer; font-size:12px; color:#5C6573; font-family:ui-monospace,monospace; }
  [hidden] { display:none !important; }
</style>
</head>
<body>
<div class="wrap">
  <div class="share">
    <span class="mono" data-permalink>(open the full shared link to load capsules)</span>
    <span><button type="button" data-copy>copy permalink</button></span>
  </div>
  <div class="disclosure">
    This page reads its capsules from the link fragment (after <span class="mono">#</span>) — a browser
    never sends that part over the wire, so even a hosted copy of this page never receives your capsules.
    Every <span class="mono">capsule_id</span> is recomputed in your browser from the record; the merkle is
    hidden by default but stays checkable. Disclosable content is per-field: sealed to a digest unless the
    operator chose to show it.
  </div>

  <h1>What my capsules <em>look like</em></h1>
  <p class="sub">Each card leads with a plain-language verdict — what really ran, whether it's signed, and what's still open — then shows the exchange. The security details fold behind one toggle.</p>
  <div class="meta mono" data-meta></div>

  <div class="empty" data-empty>
    No capsule data in this URL. Open the full shared link (the part after <span class="mono">#</span>) to
    load the view — this page never fetches from a server.
  </div>

  <div data-entries></div>

  <div class="foot" data-foot hidden></div>
</div>

<template id="entry-template">
  <div class="entry">
    <div class="entry-head">
      <span class="entry-title" data-entry-title></span>
      <span class="badge" data-verify-badge></span>
    </div>
    <div class="verdict" data-verdict></div>
    <div data-conv-slot></div>
    <details class="checks">
      <summary>Show the security checks <span class="hint">— the auditor view: recomputed id, signature, roles, raw model hash</span></summary>
      <div class="checks-body">
        <div class="id-line" data-id-line></div>
        <div class="roles" data-roles></div>
      </div>
    </details>
  </div>
</template>

<template id="conv-template">
  <div class="conv">
    <div class="conv-served" data-conv-served></div>
    <div class="conv-turn">
      <div class="conv-label">Prompt (sent) <span class="conv-tag" data-conv-prompt-tag></span></div>
      <div class="conv-text" data-conv-prompt></div>
      <div class="conv-verify" data-conv-prompt-verify></div>
    </div>
    <div class="conv-turn">
      <div class="conv-label">Response (came back) <span class="conv-tag" data-conv-response-tag></span></div>
      <div class="conv-text" data-conv-response></div>
      <span class="conv-toolcall" data-conv-toolcall hidden></span>
      <div class="conv-verify" data-conv-response-verify></div>
      <span class="conv-note" data-conv-response-note hidden></span>
    </div>
  </div>
</template>

<template id="verdict-line-template">
  <div class="vline"><span class="vmark" data-vmark></span><span data-vtext></span></div>
</template>

<template id="role-template">
  <div class="role">
    <div class="role-title" data-role-title></div>
    <div data-role-qs></div>
  </div>
</template>

<template id="qa-template">
  <div class="qa">
    <div class="q"><span data-q></span><span class="state" data-state></span></div>
    <div class="a" data-a></div>
    <details class="merkle" data-evidence hidden>
      <summary>evidence / fields</summary>
      <div class="kv" data-evidence-kv></div>
    </details>
  </div>
</template>

<script>window.__MESH_FRAGMENT_B64U__=@@FRAGMENT@@;</script>
<script>
@@VERIFY_JS@@
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI -- `capsule-mesh-viewer` / composed under capsule-mesh view --html.
# ---------------------------------------------------------------------------


def _read_records(path: str) -> list[dict[str, Any]]:
    if read_ledger is not None:
        try:
            return read_ledger(path)
        except Exception:
            pass
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _read_first_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read().strip()
    # a .jsonl checkpoints file: take the first line; else a plain .json object
    first = text.splitlines()[0] if "\n" in text else text
    return json.loads(first)


def _cmd_html(args: argparse.Namespace) -> int:
    records = _read_records(args.ledger)
    if not records:
        print(f"capsule-mesh view --html: no records in {args.ledger}", file=sys.stderr)
        return 1
    witness = _read_first_json(args.witness) if args.witness else None
    disclose: dict[str, dict[str, Any]] = {}
    if args.disclose:
        # --disclose CAPSULE_ID:FIELD=TEXT  (FIELD is request|response|
        # tool_calls_note). Everything not named here stays digest-only.
        for spec in args.disclose:
            head, _, text = spec.partition("=")
            cid, _, field = head.partition(":")
            disclose.setdefault(cid, {})[field] = text
    if args.disclose_file:
        # --disclose-file CAPSULE_ID:FIELD=PATH  -- for multi-line content
        # (a full response body/refusal) that a shell arg can't carry cleanly.
        for spec in args.disclose_file:
            head, _, path = spec.partition("=")
            cid, _, field = head.partition(":")
            with open(path, encoding="utf-8") as fh:
                disclose.setdefault(cid, {})[field] = fh.read()

    import os

    payload = to_fragment_payload(
        records,
        source_log=args.source_log,
        witness_checkpoint=witness,
        disclose=disclose or None,
        operator=args.operator,
        ledger_dir=os.path.dirname(os.path.abspath(args.ledger)),
        default_role=args.role,
    )
    fragment = encode_fragment(payload)
    html = render_mesh_viewer_html(fragment)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    permalink = f"file://{args.out}#{fragment}"
    if args.permalink_out:
        with open(args.permalink_out, "w", encoding="utf-8") as fh:
            fh.write(permalink + "\n")
    n_witness = "with witness checkpoint" if witness else "no witness checkpoint"
    print(f"mesh viewer: {len(records)} capsule(s), {n_witness} -> {args.out}")
    print(f"permalink ({len(fragment)} b64u chars): open the HTML then append #<fragment>")
    print(f"  {permalink}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capsule-mesh-viewer",
        description="Render mesh capsules as a words-first, role-organised, offline, "
        "fragment-carried HTML viewer (4 roles x 3 questions).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    html = sub.add_parser("html", help="emit the role-organised offline HTML viewer + permalink")
    html.add_argument("--ledger", required=True, metavar="PATH", help="mesh capsule JSONL ledger")
    html.add_argument("--out", required=True, metavar="PATH", help="output HTML path")
    html.add_argument("--witness", metavar="PATH", default=None, help="optional COSE checkpoint receipt (json/jsonl)")
    html.add_argument(
        "--source-log",
        default=SOURCE_SIDECAR,
        choices=[SOURCE_PLUGIN, SOURCE_SIDECAR],
        help="which single-writer log these records came from (drives the role label)",
    )
    html.add_argument("--operator", default=None, help="operator label for the view header")
    html.add_argument("--permalink-out", metavar="PATH", default=None, help="write the file:// permalink here")
    html.add_argument(
        "--role",
        default=DEFAULT_ROLE,
        choices=list(ROLE_KEYS) + ["all"],
        help="which role's questions render inline by default (default: requester); "
        "the other roles fold behind a collapsed 'other roles' toggle. 'all' shows "
        "every role inline (the original layout).",
    )
    html.add_argument(
        "--disclose",
        action="append",
        metavar="CID:FIELD=TEXT",
        help="open one disclosable field (FIELD is request|response|tool_calls_note); "
        "repeatable. Everything else stays digest-only.",
    )
    html.add_argument(
        "--disclose-file",
        action="append",
        metavar="CID:FIELD=PATH",
        help="like --disclose but reads the content from a file (for multi-line "
        "response bodies); repeatable.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "html":
        return _cmd_html(args)
    _build_parser().error(f"unknown command {args.command!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

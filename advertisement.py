# SPDX-License-Identifier: Apache-2.0
"""verify-after-advertise: a neutral advertisement artifact and its reconciliation
against the serving-provenance record (TRUST-MODEL.md §12.3, §10 Rule 3).

A mesh node ADVERTISES what it can serve -- model id/name, quantization, a
hardware class (GPU string, VRAM, SoC flag). That advertisement is a
self-attested CLAIM, never evidence: §10 Rule 3 -- "an advertised model name
... is a claim. The record says which it holds." The ``serving_provenance``
block on a sealed capsule (``plugins/capsule-producer/src/capsule.rs`` /
``capsule_sidecar.build_capsule``) proves what ACTUALLY ran.

Reconciling the two is the "after" half of C1 (§2.4): given (advertisement,
serving_provenance), emit a PER-FIELD verdict -- a kept promise is a ``match``;
a broken one is a first-class, attributable ``mismatch`` (evidence, not a
score). The reconciliation is deliberately OFFLINE and SELF-CONTAINED: it reads
only the two artifacts, so a third party who witnessed neither the advertisement
nor the exchange can run it from a disclosed bundle alone.

THREE-STATE DISCIPLINE (§10 Rule 1, "three states, never two"): a field is
never silently green. Each field's verdict is exactly one of:

    match          -- advertised value and served value are both present and
                      equal (a kept promise).
    mismatch       -- both present and NOT equal (a broken promise; the §2.6
                      "advertises one model, serves another" adversary, caught).
    not_advertised -- the served record carries the fact but the advertisement
                      made no claim about it -- so there is nothing to keep or
                      break. NOT a pass.
    absent         -- the served record does not carry the fact at all, so no
                      reconciliation is possible. NOT a pass either.

A missing advertisement as a WHOLE is ``advertisement_absent`` -- never a
silent green over the record (§1 consequence 3: "absence of evidence must never
render as a pass").

HONEST GAP (stated, not hidden): an advertisement is signed by the SAME node
that serves. It is therefore a self-attested claim reconciled against another
self-attested claim -- both from one party. That still buys a great deal: a
node that advertises Llama-3.2-3B-Q4 and serves something else now leaves an
attributable, portable ``mismatch`` in one offline artifact, which it could not
before (the record proved what ran but did not co-carry what was promised). The
STRONG version needs the counterparty's independently-held advertisement /
discovery note (the membership-gated "member-signed discovery note" posture,
TRUST-MODEL.md §9.1) so the two claims come from two parties; that is a
deployment progression, not a change to this mechanism, and is called out in
``reconcile_advertised_vs_served``'s ``advertisement_self_signed`` note.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

ADVERTISEMENT_SCHEMA = "capsule-emit-mesh/advertisement/v1"

#: Per-field verdict values -- the three-state discipline, made a closed set so
#: a caller can never invent a fourth "silent green" state.
VERDICT_MATCH = "match"
VERDICT_MISMATCH = "mismatch"
VERDICT_NOT_ADVERTISED = "not_advertised"
VERDICT_ABSENT = "absent"

#: The honest self-signing caveat -- see this module's docstring "HONEST GAP".
#: Attached to every reconciliation result so a reader is never solely
#: dependent on the producer having chosen to disclose it (same discipline as
#: capsule_sidecar.identity_limitation_for_rung()).
ADVERTISEMENT_SELF_SIGNED_NOTE = (
    "advertisement-self-signed: the advertisement is signed by the same node "
    "that served; a match reconciles two self-attested claims from one party, "
    "not one party's claim against an independently-held counterparty note. "
    "A mismatch is still attributable and portable; a match is not proof of a "
    "second, independent party. TRUST-MODEL.md §9.1 (membership-gated "
    "member-signed discovery note) is the deployment that closes this."
)


@dataclass
class Advertisement:
    """A node's self-attested claim of what it can serve (a CLAIM, not evidence).

    Deliberately minimal and honest -- only the facts a served exchange can be
    reconciled against: model identity, quantization, and a hardware class.
    ``None`` on any field means "did not advertise this", which reconciles to
    ``not_advertised`` -- distinct from advertising a value that then does not
    match (``mismatch``).
    """

    #: The node advertising -- carried so the advertisement is attributable to
    #: an identity, matching the served record's ``served_by_node_id``.
    node_id: str
    #: Advertised model identity. ``model_id`` is the human name/ref the node
    #: claims to serve; ``model_canonical_ref`` an optional canonical ref.
    model_id: str | None = None
    model_canonical_ref: str | None = None
    #: Advertised quantization (e.g. "Q4_K_M"). ``None`` = not advertised.
    quantization: str | None = None
    #: Advertised hardware class. A claim about capability, not a live reading.
    hardware_gpu: str | None = None
    hardware_vram_bytes: int | None = None
    hardware_is_soc: bool | None = None
    #: Free-form, non-load-bearing extras (never reconciled) -- kept so a node
    #: can advertise context length etc. without those becoming silent passes.
    extra: dict[str, Any] = field(default_factory=dict)

    def to_value(self) -> dict[str, Any]:
        """The canonical dict form (co-carried into the bundle / capsule)."""
        return {
            "schema": ADVERTISEMENT_SCHEMA,
            "node_id": self.node_id,
            "model_id": self.model_id,
            "model_canonical_ref": self.model_canonical_ref,
            "quantization": self.quantization,
            "hardware": {
                "gpu": self.hardware_gpu,
                "vram_bytes": self.hardware_vram_bytes,
                "is_soc": self.hardware_is_soc,
            },
            "extra": self.extra,
        }

    @classmethod
    def from_value(cls, value: dict[str, Any]) -> "Advertisement":
        hw = value.get("hardware") or {}
        return cls(
            node_id=value.get("node_id", ""),
            model_id=value.get("model_id"),
            model_canonical_ref=value.get("model_canonical_ref"),
            quantization=value.get("quantization"),
            hardware_gpu=hw.get("gpu"),
            hardware_vram_bytes=hw.get("vram_bytes"),
            hardware_is_soc=hw.get("is_soc"),
            extra=value.get("extra") or {},
        )

    def digest(self) -> str:
        """A stable content address over the advertisement's canonical bytes.

        Deterministic (sorted keys, compact separators) so an independently
        held copy of the same advertisement digests identically -- the hook a
        stronger deployment uses to bind a discovery note to a served record.
        """
        raw = json.dumps(self.to_value(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


def _served_facts(serving_provenance: dict[str, Any] | None) -> dict[str, Any]:
    """Flatten the served facts we reconcile from a ``serving_provenance`` block.

    Tolerant of BOTH real capsule shapes (same tolerance as
    ``capsule_mesh_viewer.serving_provenance``): the nested
    ``{model{...}, hardware{...}}`` block the Rust producer emits, and any older
    flat form. A fact genuinely not carried stays ``None`` -> ``absent``; the
    honest ``"unknown"`` sentinel the producer writes for a fact the host never
    told it likewise reconciles as ``absent`` (nothing to keep or break),
    never as a value that could spuriously match or mismatch.
    """
    sp = serving_provenance or {}
    model = sp.get("model") or {}
    hw = sp.get("hardware") or {}

    def clean(v: Any) -> Any:
        # The producer writes the literal "unknown" for a fact the host did not
        # expose -- treat it as absent, not as a real served value.
        if isinstance(v, str) and v.strip().lower() == "unknown":
            return None
        return v

    return {
        "model_id": clean(sp.get("model_id") or model.get("model_id")),
        "model_canonical_ref": clean(sp.get("model_canonical_ref") or model.get("canonical_ref")),
        "quantization": clean(sp.get("quantization")),
        "hardware_gpu": clean(hw.get("gpu") or sp.get("gpu")),
        "hardware_vram_bytes": clean(
            hw.get("vram_bytes") if hw.get("vram_bytes") is not None else sp.get("vram_bytes")
        ),
        "hardware_is_soc": clean(
            hw.get("is_soc") if hw.get("is_soc") is not None else sp.get("is_soc")
        ),
    }


def _reconcile_field(advertised: Any, served: Any) -> str:
    """One field's three-state verdict. NEVER a silent green.

    - served absent (None)              -> ``absent`` (cannot reconcile).
    - served present, not advertised    -> ``not_advertised`` (nothing claimed).
    - both present and equal            -> ``match``.
    - both present and unequal          -> ``mismatch``.
    """
    if served is None:
        return VERDICT_ABSENT
    if advertised is None:
        return VERDICT_NOT_ADVERTISED
    if _values_equal(advertised, served):
        return VERDICT_MATCH
    return VERDICT_MISMATCH


def _values_equal(advertised: Any, served: Any) -> bool:
    """Compare an advertised claim to a served fact.

    Strings are compared case-insensitively and whitespace-trimmed (an
    advertised "q4_k_m" keeps its promise against a served "Q4_K_M"); other
    types compare by equality. Deliberately conservative -- no fuzzy model-name
    normalization or hardware-equivalence classing here, because a loose match
    would silently upgrade a near-miss to a kept promise. A node wanting an
    equivalence class must advertise the exact served string; §12.3 keeps the
    mismatch first-class rather than papering over it.
    """
    if isinstance(advertised, str) and isinstance(served, str):
        return advertised.strip().casefold() == served.strip().casefold()
    return advertised == served


def reconcile_advertised_vs_served(
    advertisement: Advertisement | dict[str, Any] | None,
    serving_provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    """Reconcile a node's advertised CLAIM against what its record proves ran.

    This is the "after" half of C1 (TRUST-MODEL.md §12.3), self-contained and
    offline: it consumes ONLY the advertisement and the serving-provenance
    block, so a third party holding a disclosed bundle can run it without the
    mesh's cooperation.

    Returns a dict::

        {
          "overall": "match" | "mismatch" | "advertisement_absent"
                     | "no_served_facts",
          "advertisement_present": bool,
          "advertised_node_id": <str|None>,
          "served_node_id": <str|None>,
          "node_id_consistent": <bool|None>,   # None when either side absent
          "fields": {
              "model_id":            {"advertised": ..., "served": ..., "verdict": ...},
              "model_canonical_ref": {...},
              "quantization":        {...},
              "hardware_gpu":        {...},
              "hardware_vram_bytes": {...},
              "hardware_is_soc":     {...},
          },
          "mismatches": ["quantization", ...],   # every mismatched field, named
          "advertisement_self_signed": <ADVERTISEMENT_SELF_SIGNED_NOTE>,
        }

    ``overall`` is:
      - ``advertisement_absent`` when no advertisement was supplied -- the
        record is NOT reconciled and this is NOT a pass (§1 consequence 3);
      - ``no_served_facts`` when the record carries no serving-provenance facts
        to check against -- also not a pass;
      - ``mismatch`` when ANY reconcilable field mismatched (loud, first-class);
      - ``match`` only when at least one field was reconcilable and NONE
        mismatched. A ``match`` overall still carries the self-signed caveat and
        may include ``not_advertised``/``absent`` fields -- it is "no broken
        promise found in what was both claimed and served", never "everything
        verified".
    """
    if advertisement is None:
        return {
            "overall": "advertisement_absent",
            "advertisement_present": False,
            "advertised_node_id": None,
            "served_node_id": (serving_provenance or {}).get("served_by_node_id"),
            "node_id_consistent": None,
            "fields": {},
            "mismatches": [],
            "advertisement_self_signed": ADVERTISEMENT_SELF_SIGNED_NOTE,
        }

    ad = advertisement if isinstance(advertisement, Advertisement) else Advertisement.from_value(advertisement)
    served = _served_facts(serving_provenance)
    served_node_id = (serving_provenance or {}).get("served_by_node_id")

    field_specs = (
        ("model_id", ad.model_id, served["model_id"]),
        ("model_canonical_ref", ad.model_canonical_ref, served["model_canonical_ref"]),
        ("quantization", ad.quantization, served["quantization"]),
        ("hardware_gpu", ad.hardware_gpu, served["hardware_gpu"]),
        ("hardware_vram_bytes", ad.hardware_vram_bytes, served["hardware_vram_bytes"]),
        ("hardware_is_soc", ad.hardware_is_soc, served["hardware_is_soc"]),
    )

    fields: dict[str, Any] = {}
    mismatches: list[str] = []
    any_reconcilable = False
    for name, advertised_value, served_value in field_specs:
        verdict = _reconcile_field(advertised_value, served_value)
        fields[name] = {"advertised": advertised_value, "served": served_value, "verdict": verdict}
        if verdict == VERDICT_MISMATCH:
            mismatches.append(name)
        if verdict in (VERDICT_MATCH, VERDICT_MISMATCH):
            any_reconcilable = True

    node_id_consistent: bool | None
    if ad.node_id and served_node_id:
        node_id_consistent = ad.node_id == served_node_id
    else:
        node_id_consistent = None
    # A node advertising as one identity but serving as another is itself a
    # mismatch -- the advertisement doesn't even describe this server.
    if node_id_consistent is False:
        mismatches.append("node_id")

    if not any_reconcilable and not mismatches:
        overall = "no_served_facts"
    elif mismatches:
        overall = VERDICT_MISMATCH
    else:
        overall = VERDICT_MATCH

    return {
        "overall": overall,
        "advertisement_present": True,
        "advertised_node_id": ad.node_id or None,
        "served_node_id": served_node_id,
        "node_id_consistent": node_id_consistent,
        "fields": fields,
        "mismatches": mismatches,
        "advertisement_self_signed": ADVERTISEMENT_SELF_SIGNED_NOTE,
    }


def compute_meter(
    *,
    latency_ms: float | str | None,
    compute_ms: float | str | None = None,
    usage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A NEUTRAL metered-facts block: wall-clock / compute time + token usage.

    Metering, never pricing (TRUST-MODEL.md §12.4, §6): this counts units the
    node spent and served -- wall-clock latency, optional compute (on-device)
    time, and the token ``usage`` already sealed in the record. It carries NO
    currency, rate, invoice, or settlement, by construction: there is no field
    here that could hold one, and none is ever added. Pricing belongs to
    whatever commercial layer a deployment chooses; this record proposes none.

    All time values are milliseconds, carried as exact decimal STRINGS (the
    same §5.1 digest-bearing-float discipline the rest of the record uses).
    Any field the node cannot honestly count stays absent, never zero-filled.
    """
    meter: dict[str, Any] = {"unit": "milliseconds"}
    if latency_ms is not None:
        meter["wall_clock_ms"] = _as_ms_string(latency_ms)
    if compute_ms is not None:
        meter["compute_ms"] = _as_ms_string(compute_ms)
    if usage:
        # Tokens are already sealed end-to-end via serving_provenance.usage;
        # co-carrying the counts here keeps all metered facts in one block.
        meter["tokens"] = {
            k: usage[k]
            for k in ("prompt_tokens", "completion_tokens", "total_tokens")
            if usage.get(k) is not None
        }
    return meter


def _as_ms_string(value: float | str) -> str:
    if isinstance(value, str):
        return value
    return f"{float(value):.3f}"

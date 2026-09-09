# SPDX-License-Identifier: Apache-2.0
"""verify-after-advertise (TRUST-MODEL.md §12.3): reconcile a node's advertised
CLAIM against what its serving_provenance record proves ran.

The three adversarial cases the task fixes, plus the three-state edges:
  - advertise Llama-3.2-3B-Q4, serve a DIFFERENT model/quant -> mismatch, loud.
  - advertise nothing -> advertisement_absent (NOT a false green).
  - advertise matches served -> match.
"""
from __future__ import annotations

from advertisement import (
    ADVERTISEMENT_SELF_SIGNED_NOTE,
    VERDICT_ABSENT,
    VERDICT_MATCH,
    VERDICT_MISMATCH,
    VERDICT_NOT_ADVERTISED,
    VERDICT_PARTIAL_MATCH,
    VERDICT_SELF_REPORTED_ABSENT,
    Advertisement,
    compute_meter,
    reconcile_advertised_vs_served,
)


def _served(**overrides):
    """A nested serving_provenance block, the Rust-producer shape."""
    sp = {
        "served_by_node_id": "mesh-node-demo-1",
        "quantization": "Q4_K_M",
        "model": {"canonical_ref": "meta/Llama-3.2-3B", "architecture": "llama"},
        "hardware": {"gpu": "Apple M4 Max", "vram_bytes": 42_949_672_960, "is_soc": True},
        "usage": {"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33},
    }
    sp.update(overrides)
    return sp


def _llama_q4_ad(**overrides) -> Advertisement:
    kwargs = dict(
        node_id="mesh-node-demo-1",
        model_canonical_ref="meta/Llama-3.2-3B",
        quantization="Q4_K_M",
        hardware_gpu="Apple M4 Max",
        hardware_vram_bytes=42_949_672_960,
        hardware_is_soc=True,
    )
    kwargs.update(overrides)
    return Advertisement(**kwargs)


# ---------------------------------------------------------------------------
# The three headline adversarial cases (task acceptance).
# ---------------------------------------------------------------------------

def test_advertise_llama_q4_but_serve_a_different_model_is_a_loud_mismatch():
    ad = _llama_q4_ad()
    # Node advertised Llama-3.2-3B / Q4_K_M but served a different model at a
    # different quant -- the §2.6 "advertises one model, serves another" node.
    served = _served(
        quantization="Q8_0",
        model={"canonical_ref": "mistralai/Mistral-7B", "architecture": "mistral"},
    )
    result = reconcile_advertised_vs_served(ad, served)

    assert result["overall"] == VERDICT_MISMATCH
    # Both broken fields are named, first-class -- never a silent green.
    assert set(result["mismatches"]) == {"model_canonical_ref", "quantization"}
    assert result["fields"]["quantization"]["verdict"] == VERDICT_MISMATCH
    assert result["fields"]["quantization"]["advertised"] == "Q4_K_M"
    assert result["fields"]["quantization"]["served"] == "Q8_0"
    assert result["fields"]["model_canonical_ref"]["verdict"] == VERDICT_MISMATCH
    # The mismatch is attributable and portable, and still carries the honest
    # self-signed caveat.
    assert result["advertisement_self_signed"] == ADVERTISEMENT_SELF_SIGNED_NOTE


def test_advertise_nothing_is_advertisement_absent_not_a_false_green():
    result = reconcile_advertised_vs_served(None, _served())
    assert result["overall"] == "advertisement_absent"
    assert result["advertisement_present"] is False
    # Crucially: NOT "match", NOT any per-field green.
    assert result["overall"] != VERDICT_MATCH
    assert result["fields"] == {}
    assert result["mismatches"] == []


def test_advertise_matching_served_is_a_match():
    result = reconcile_advertised_vs_served(_llama_q4_ad(), _served())
    assert result["overall"] == VERDICT_MATCH
    assert result["mismatches"] == []
    assert result["fields"]["quantization"]["verdict"] == VERDICT_MATCH
    assert result["fields"]["model_canonical_ref"]["verdict"] == VERDICT_MATCH
    assert result["fields"]["hardware_gpu"]["verdict"] == VERDICT_MATCH
    # A match is never disclosed alone -- the self-signed caveat rides with it.
    assert result["advertisement_self_signed"] == ADVERTISEMENT_SELF_SIGNED_NOTE


# ---------------------------------------------------------------------------
# Three-state discipline (§10 Rule 1): every non-pass is distinct.
# ---------------------------------------------------------------------------

def test_field_advertised_but_absent_from_record_is_absent_not_a_pass():
    # Advertise a GPU; serve a record whose hardware carries no gpu.
    ad = _llama_q4_ad()
    served = _served(hardware={"gpu": None, "vram_bytes": None, "is_soc": None})
    result = reconcile_advertised_vs_served(ad, served)
    assert result["fields"]["hardware_gpu"]["verdict"] == VERDICT_ABSENT
    # An absent field is not a mismatch and not a match.
    assert "hardware_gpu" not in result["mismatches"]


def test_served_fact_not_advertised_is_not_advertised_not_a_pass():
    # Advertise ONLY the model; serve a record that also carries a quantization.
    ad = Advertisement(node_id="mesh-node-demo-1", model_canonical_ref="meta/Llama-3.2-3B")
    result = reconcile_advertised_vs_served(ad, _served())
    assert result["fields"]["quantization"]["verdict"] == VERDICT_NOT_ADVERTISED
    assert result["fields"]["model_canonical_ref"]["verdict"] == VERDICT_MATCH
    # not_advertised is not a mismatch, but the overall is partial_match --
    # keeping one promise while leaving quantization, hardware etc. un-promised
    # does NOT earn a full VERDICT_MATCH (which requires coverage of all served facts).
    assert result["overall"] == "partial_match"  # kept the one promise but left quant un-promised


def test_unknown_sentinel_in_record_reconciles_as_absent_not_a_spurious_value():
    # The producer writes literal "unknown" for a fact the host never exposed;
    # an advertised quant must reconcile to `self_reported_absent`, never mismatch
    # against the sentinel string, and never as plain `absent` (which would be
    # indistinguishable from the fact simply not being in the record).
    ad = _llama_q4_ad()
    served = _served(quantization="unknown")
    result = reconcile_advertised_vs_served(ad, served)
    assert result["fields"]["quantization"]["verdict"] == VERDICT_SELF_REPORTED_ABSENT


def test_no_served_facts_at_all_is_not_a_pass():
    result = reconcile_advertised_vs_served(_llama_q4_ad(), {"served_by_node_id": "mesh-node-demo-1"})
    assert result["overall"] == "no_served_facts"
    assert result["overall"] != VERDICT_MATCH


def test_node_id_mismatch_is_flagged():
    # Advertisement claims one node identity; the record served under another.
    ad = _llama_q4_ad(node_id="node-A")
    served = _served(served_by_node_id="node-B")
    result = reconcile_advertised_vs_served(ad, served)
    assert result["node_id_consistent"] is False
    assert "node_id" in result["mismatches"]
    assert result["overall"] == VERDICT_MISMATCH


# ---------------------------------------------------------------------------
# String comparison + dict round-trip.
# ---------------------------------------------------------------------------

def test_quantization_match_is_case_and_whitespace_insensitive():
    ad = _llama_q4_ad(quantization="  q4_k_m ")
    result = reconcile_advertised_vs_served(ad, _served(quantization="Q4_K_M"))
    assert result["fields"]["quantization"]["verdict"] == VERDICT_MATCH


def test_advertisement_dict_form_reconciles_identically_to_dataclass():
    ad = _llama_q4_ad()
    from_dataclass = reconcile_advertised_vs_served(ad, _served())
    from_dict = reconcile_advertised_vs_served(ad.to_value(), _served())
    assert from_dataclass["overall"] == from_dict["overall"] == VERDICT_MATCH


def test_advertisement_round_trips_through_its_value_form():
    ad = _llama_q4_ad()
    assert Advertisement.from_value(ad.to_value()) == ad


def test_advertisement_digest_is_stable_and_order_independent():
    ad1 = _llama_q4_ad()
    ad2 = _llama_q4_ad()
    assert ad1.digest() == ad2.digest()
    assert len(ad1.digest()) == 64


# ---------------------------------------------------------------------------
# compute_meter: metered facts, NEVER pricing (§12.4).
# ---------------------------------------------------------------------------

def test_compute_meter_carries_time_and_tokens_but_no_price():
    meter = compute_meter(
        latency_ms=1234.5,
        compute_ms=987.0,
        usage={"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33},
    )
    assert meter["unit"] == "milliseconds"
    assert meter["wall_clock_ms"] == "1234.500"
    assert meter["compute_ms"] == "987.000"
    assert meter["tokens"] == {"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33}
    # Non-negotiable: no currency / rate / price / invoice field, ever.
    forbidden = {"price", "currency", "rate", "cost", "amount", "invoice", "usd", "settlement"}
    assert forbidden.isdisjoint(_all_keys(meter))


def test_compute_meter_omits_facts_it_cannot_count_rather_than_zero_filling():
    meter = compute_meter(latency_ms=None)
    assert "wall_clock_ms" not in meter
    assert "compute_ms" not in meter
    assert "tokens" not in meter


def _all_keys(obj) -> set:
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k).lower())
            keys |= _all_keys(v)
    return keys


# ---- [mesh-promise-reconciliation-grading] adversarial tests ----

def test_promising_nothing_does_not_outgrade_promising_something_and_missing_one():
    """Node A promises 1 trivial field (model_id), Node B promises 6 fields
    and misses quantization.  A must NOT get a higher overall grade than B;
    specifically, promising nothing gets 'partial_match' or 'advertisement_absent',
    never 'match'.  'match' is reserved for keeping ALL the served facts you
    promised (with nothing left un-promised)."""
    # Node A: advertises only model_id -- one tiny promise kept
    ad_a = Advertisement(node_id="mesh-node-demo-1", model_id="Llama-3.2-3B")
    result_a = reconcile_advertised_vs_served(ad_a, _served())
    # Node B: advertises everything, misses quantization
    ad_b = _llama_q4_ad()
    served_b = _served(quantization="Q8_0")  # quant mismatch
    result_b = reconcile_advertised_vs_served(ad_b, served_b)

    # A kept its one tiny promise -- but that is NOT a full match; it left
    # hardware, quant etc. un-promised.  Overall must be partial_match.
    assert result_a["overall"] == "partial_match", (
        f"A node promising only model_id must get 'partial_match', not {result_a['overall']!r}"
    )
    # B broke a promise -- still mismatch.
    assert result_b["overall"] == VERDICT_MISMATCH
    # Core invariant: partial_match must never be rendered as 'kept'
    assert result_a["overall"] != VERDICT_MATCH


def test_full_coverage_match_requires_no_not_advertised_fields():
    """'match' overall is reserved for when every served fact that could be
    reconciled WAS promised and matched -- no not_advertised fields left over."""
    # Full coverage: all 5 served facts were advertised and matched
    result = reconcile_advertised_vs_served(_llama_q4_ad(), _served())
    assert result["overall"] == VERDICT_MATCH
    # No not_advertised fields
    not_adv = [k for k, v in result["fields"].items() if v["verdict"] == VERDICT_NOT_ADVERTISED]
    assert not_adv == []


def test_self_reported_unknown_is_self_reported_absent_not_honest_absent():
    """The serving node writes 'unknown' in serving_provenance for fields it
    doesn't want reconciled.  This self-selected absence must produce
    VERDICT_SELF_REPORTED_ABSENT, not VERDICT_ABSENT -- byte-identical to
    honest absence is the [mesh-promise-reconciliation-grading] defect 2."""
    ad = _llama_q4_ad()
    # The serving node self-reports quantization as "unknown"
    served = _served(quantization="unknown")
    result = reconcile_advertised_vs_served(ad, served)
    assert result["fields"]["quantization"]["verdict"] == VERDICT_SELF_REPORTED_ABSENT, (
        "self-reported 'unknown' must be VERDICT_SELF_REPORTED_ABSENT, "
        f"got {result['fields']['quantization']['verdict']!r}"
    )
    # Self-reported-absent is NOT the same as honest absent
    assert result["fields"]["quantization"]["verdict"] != VERDICT_ABSENT
    # It IS still not a mismatch (nothing to break if the node didn't serve a real value)
    assert "quantization" not in result["mismatches"]


def test_advertisement_digest_is_bound_into_reconciliation_result():
    """reconcile_advertised_vs_served() must include 'advertisement_digest' in
    its output so a relying party can independently verify the advertisement
    was prior to the exchange -- the [mesh-promise-reconciliation-grading] defect 3."""
    ad = _llama_q4_ad()
    result = reconcile_advertised_vs_served(ad, _served())
    assert "advertisement_digest" in result, "advertisement_digest must be in reconciliation output"
    assert result["advertisement_digest"] == ad.digest()


def test_advertisement_issued_at_is_carried_through_reconciliation():
    """An advertisement with an issued_at must surface it in the reconciliation
    result so a relying party can check the advertisement predates the exchange."""
    ad = _llama_q4_ad()
    ad_with_time = Advertisement(
        node_id=ad.node_id,
        model_id=ad.model_id,
        model_canonical_ref=ad.model_canonical_ref,
        quantization=ad.quantization,
        hardware_gpu=ad.hardware_gpu,
        hardware_vram_bytes=ad.hardware_vram_bytes,
        hardware_is_soc=ad.hardware_is_soc,
        issued_at="2026-09-08T00:00:00Z",
    )
    result = reconcile_advertised_vs_served(ad_with_time, _served())
    assert result["advertisement_issued_at"] == "2026-09-08T00:00:00Z"


def test_advertisement_absent_result_includes_digest_and_issued_at_as_none():
    """When no advertisement is supplied, advertisement_digest and
    advertisement_issued_at must be present but None -- never omitted,
    so a consumer doesn't have to handle a missing key."""
    result = reconcile_advertised_vs_served(None, _served())
    assert result["overall"] == "advertisement_absent"
    assert result["advertisement_digest"] is None
    assert result["advertisement_issued_at"] is None

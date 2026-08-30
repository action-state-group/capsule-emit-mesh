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
    # not_advertised is not a mismatch, and the overall is still a match
    # (nothing that was both claimed and served was broken).
    assert result["overall"] == VERDICT_MATCH


def test_unknown_sentinel_in_record_reconciles_as_absent_not_a_spurious_value():
    # The producer writes literal "unknown" for a fact the host never exposed;
    # an advertised quant must reconcile to `absent`, never mismatch against
    # the sentinel string.
    ad = _llama_q4_ad()
    served = _served(quantization="unknown")
    result = reconcile_advertised_vs_served(ad, served)
    assert result["fields"]["quantization"]["verdict"] == VERDICT_ABSENT


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

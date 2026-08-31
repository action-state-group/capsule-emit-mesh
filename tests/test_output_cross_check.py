# SPDX-License-Identifier: Apache-2.0
"""Tests for the prototype_cross_check seam and its trivial baseline.

Three things are under test:
  1. the typed SEAM (check_output_against_config + the OutputCrossChecker
     Protocol drop-in point),
  2. the TRIVIAL baseline (token-rate / output-shape sanity),
  3. the HONESTY labeling -- every result is prototype_cross_check, no verdict.
"""
from __future__ import annotations

from advertisement import Advertisement
from output_cross_check import (
    CROSS_CHECK_SCHEMA,
    DIRECTION_INCONCLUSIVE,
    DIRECTION_LOWERS,
    DIRECTION_RAISES,
    PROTOTYPE_CROSS_CHECK,
    PROTOTYPE_CROSS_CHECK_NOTE,
    ConfigClaim,
    CrossCheckResult,
    Observation,
    baseline_cross_check,
    check_output_against_config,
)


def _soc_claim() -> ConfigClaim:
    return ConfigClaim(
        model_canonical_ref="meta/Llama-3.2-3B",
        quantization="Q4_K_M",
        hardware_gpu="Apple M4 Max",
        hardware_vram_bytes=42_949_672_960,
        hardware_is_soc=True,
    )


def _response(completion=22, wall_clock_ms="300.000", **usage_over):
    usage = {"prompt_tokens": 11, "completion_tokens": completion, "total_tokens": 11 + completion}
    usage.update(usage_over)
    return {"usage": usage, "compute_meter": {"unit": "milliseconds", "wall_clock_ms": wall_clock_ms}}


# ---------------------------------------------------------------------------
# 1. The SEAM
# ---------------------------------------------------------------------------

def test_seam_accepts_advertisement_as_config_claim():
    ad = Advertisement(node_id="n1", quantization="Q4_K_M", hardware_is_soc=True)
    result = check_output_against_config(ad, {"max_tokens": 64}, _response())
    assert isinstance(result, CrossCheckResult)


def test_seam_accepts_advertisement_dict_and_none():
    r1 = check_output_against_config({"quantization": "Q4_K_M", "hardware": {"is_soc": True}}, {}, _response())
    r2 = check_output_against_config(None, {}, _response())
    assert isinstance(r1, CrossCheckResult)
    assert isinstance(r2, CrossCheckResult)


def test_seam_uses_a_pluggable_checker_the_real_model_would_drop_into():
    sentinel = CrossCheckResult(checker_id="future-statistical-model/v9", confidence_direction=DIRECTION_RAISES)

    def fake_real_model(config_claim, request, response):
        assert isinstance(config_claim, ConfigClaim)  # seam lifted it for the impl
        return sentinel

    out = check_output_against_config(_soc_claim(), {}, _response(), checker=fake_real_model)
    assert out is sentinel  # no caller change needed to swap the implementation


def test_config_claim_from_serving_provenance_treats_unknown_as_absent():
    claim = ConfigClaim.from_serving_provenance({"quantization": "unknown", "model": {"canonical_ref": "meta/Llama-3.2-3B"}})
    assert claim.quantization is None
    assert claim.model_canonical_ref == "meta/Llama-3.2-3B"


# ---------------------------------------------------------------------------
# 2. The TRIVIAL baseline
# ---------------------------------------------------------------------------

def test_baseline_plausible_output_raises_confidence():
    # 22 tokens in 300ms => ~73 tok/s, inside the SoC band; length within cap.
    result = baseline_cross_check(_soc_claim(), {"max_tokens": 64}, _response())
    assert result.confidence_direction == DIRECTION_RAISES
    assert result.lowers() is False


def test_baseline_empty_completion_under_a_cap_lowers():
    result = baseline_cross_check(_soc_claim(), {"max_tokens": 64}, _response(completion=0))
    assert result.confidence_direction == DIRECTION_LOWERS
    assert result.lowers() is True
    assert any(o.name == "completion_length_shape" and o.direction == DIRECTION_LOWERS for o in result.observations)


def test_baseline_completion_over_cap_lowers():
    result = baseline_cross_check(_soc_claim(), {"max_tokens": 5}, _response(completion=200))
    assert result.confidence_direction == DIRECTION_LOWERS


def test_baseline_impossible_token_rate_for_soc_lowers():
    # 5000 tokens in 1ms => 5,000,000 tok/s -- absurd for an on-device SoC.
    result = baseline_cross_check(_soc_claim(), {"max_tokens": 8192}, _response(completion=5000, wall_clock_ms="1.000"))
    assert result.confidence_direction == DIRECTION_LOWERS
    assert any(o.name == "tokens_per_sec_band" and o.direction == DIRECTION_LOWERS for o in result.observations)


def test_baseline_missing_meter_is_inconclusive_not_a_pass():
    resp = {"usage": {"completion_tokens": 22}}  # no compute_meter
    result = baseline_cross_check(_soc_claim(), {}, resp)
    rate_obs = [o for o in result.observations if o.name == "tokens_per_sec_band"]
    assert rate_obs and rate_obs[0].direction == DIRECTION_INCONCLUSIVE


def test_baseline_no_facts_at_all_is_inconclusive():
    result = baseline_cross_check(ConfigClaim(), {}, {})
    assert result.confidence_direction == DIRECTION_INCONCLUSIVE


def test_unknown_hardware_widens_the_band_toward_uselessness():
    # No hardware claimed -> 'unknown' kind -> near-useless wide rail; a rate
    # that would be flagged on SoC passes the wide rail. Documents the honest
    # weakness rather than hiding it.
    claim = ConfigClaim(quantization="Q4_K_M")  # no hardware
    result = baseline_cross_check(claim, {"max_tokens": 64}, _response(completion=300, wall_clock_ms="1000.000"))
    rate_obs = [o for o in result.observations if o.name == "tokens_per_sec_band"][0]
    assert rate_obs.direction == DIRECTION_RAISES


# ---------------------------------------------------------------------------
# 3. The HONESTY labeling -- probabilistic, prototype, never a verdict.
# ---------------------------------------------------------------------------

def test_every_result_is_labelled_prototype_cross_check():
    result = check_output_against_config(_soc_claim(), {"max_tokens": 64}, _response())
    assert result.label == PROTOTYPE_CROSS_CHECK
    assert result.note == PROTOTYPE_CROSS_CHECK_NOTE
    assert "PROBABILISTIC" in result.note
    assert "NOT a verification" in result.note or "not a verification" in result.note.lower()


def test_result_has_no_pass_fail_verdict_field():
    result = check_output_against_config(_soc_claim(), {"max_tokens": 64}, _response())
    for banned in ("passed", "pass", "fail", "failed", "ok", "verified", "verdict"):
        assert not hasattr(result, banned), f"result must carry no {banned!r} verdict field"


def test_to_value_carries_the_label_and_no_verdict():
    value = check_output_against_config(_soc_claim(), {"max_tokens": 64}, _response()).to_value()
    assert value["schema"] == CROSS_CHECK_SCHEMA
    assert value["label"] == PROTOTYPE_CROSS_CHECK
    assert PROTOTYPE_CROSS_CHECK in value["note"]
    assert "confidence_direction" in value
    for banned in ("passed", "pass", "fail", "failed", "ok", "verified", "verdict"):
        assert banned not in value


def test_lowers_is_not_a_fail_verdict_only_a_reason_to_look():
    # The convenience .lowers() must map to the 'lowers' direction, and the
    # note must still forbid reading it as a catch/verdict.
    result = baseline_cross_check(_soc_claim(), {"max_tokens": 64}, _response(completion=0))
    assert result.lowers()
    assert "not a verdict" in result.note.lower() or "not a pass/fail" in result.note.lower()
    assert "does NOT 'catch'" in result.note or "not 'catch'" in result.note.lower()


def test_observations_never_claim_pass_or_caught():
    result = baseline_cross_check(_soc_claim(), {"max_tokens": 5}, _response(completion=200))
    for obs in result.observations:
        assert isinstance(obs, Observation)
        low = obs.detail.lower()
        assert "caught" not in low
        assert "pass/fail" not in low or "not a verdict" in low or "reason to look" in low

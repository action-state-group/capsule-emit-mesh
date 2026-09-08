# SPDX-License-Identifier: Apache-2.0
"""Tests for independence-first twin/referee selection (`twin_selection.py`).

Negative-check mandate (QUEUE_PROTOCOL §7): every check must fail its
mutant. Each acceptance mutant from the inbox item gets its own test:

  - mismatched weights_digest -> excluded from the candidate pool
  - empty/no-comparable pool -> REASON_NO_COMPARABLE_TWIN, no crash
  - a low-RTT/direct/same-owner (co-located) candidate ranks BELOW a
    relay/distinct-owner candidate
  - the tie-break is a RANDOM draw within the top band, never the single
    nearest and never uniform over the whole pool
  - select_referee HARD-excludes a candidate sharing an owner with either
    twin (not merely scored down), and requires both twins to already
    share one weights_digest
  - select_referee falls back to "distinct node key" (owner_diversity_limited)
    when the hard owner-exclusion would otherwise leave zero candidates
  - an injected history_check that fails drops the candidate and the next
    band is drawn from what remains; all candidates failing -> a distinct,
    labeled reason
"""
from __future__ import annotations

import random

from twin_selection import (
    DEFAULT_POLICY,
    NOTE_OWNER_DIVERSITY_LIMITED,
    REASON_NO_CANDIDATE_PASSED_HISTORY_CHECK,
    REASON_NO_COMPARABLE_TWIN,
    HistorySanityResult,
    PeerInfo,
    SelectionPolicy,
    select_referee,
    select_twin,
    selection_rationale_block,
)

WEIGHTS_A = "sha256-" + "a" * 64
WEIGHTS_B = "sha256-" + "b" * 64


def _peer(peer_id: str, **overrides) -> PeerInfo:
    kwargs: dict = {"peer_id": peer_id, "state": "serving", "weights_digest": WEIGHTS_A}
    kwargs.update(overrides)
    return PeerInfo(**kwargs)


def test_mismatched_weights_digest_excluded():
    peers = [
        _peer("other-model", weights_digest=WEIGHTS_B, owner_id="owner-x", latency_source="relay"),
        _peer("same-model", weights_digest=WEIGHTS_A, owner_id="owner-y", latency_source="relay"),
    ]
    result = select_twin(WEIGHTS_A, "requester-1", peers)
    assert result.chosen_peer_id == "same-model"
    assert "other-model" not in result.breakdown


def test_no_comparable_twin_on_empty_pool():
    result = select_twin(WEIGHTS_A, "requester-1", [])
    assert result.chosen_peer_id is None
    assert result.reason == REASON_NO_COMPARABLE_TWIN
    assert result.breakdown == {}


def test_no_comparable_twin_when_no_peer_matches_model():
    peers = [_peer("p1", weights_digest=WEIGHTS_B)]
    result = select_twin(WEIGHTS_A, "requester-1", peers)
    assert result.chosen_peer_id is None
    assert result.reason == REASON_NO_COMPARABLE_TWIN


def test_requester_excluded_from_its_own_candidate_pool():
    peers = [_peer("requester-1", owner_id="owner-r"), _peer("p2", owner_id="owner-other")]
    result = select_twin(WEIGHTS_A, "requester-1", peers)
    assert result.chosen_peer_id == "p2"
    assert "requester-1" not in result.breakdown


def test_colocated_pair_ranks_below_distant_distinct_owner_pair():
    """A low-RTT/direct/same-owner peer must independence-rank BELOW a
    relay/distinct-owner peer -- the exact mutant the inbox item names."""
    requester_info = _peer("requester-1", hostname="requester-box", owner_id="owner-r", owner_verified=True)
    colocated = _peer(
        "colocated",
        rtt_ms=1.0,
        latency_source="direct",
        hostname="requester-box",  # same box as the requester
        owner_id="owner-r",  # same owner as the requester
        owner_verified=True,
    )
    distant = _peer(
        "distant",
        latency_source="relay",
        hostname="far-box",
        owner_id="owner-far",
        owner_verified=True,
    )
    result = select_twin(WEIGHTS_A, "requester-1", [colocated, distant], requester_info=requester_info)

    assert result.breakdown["colocated"].independence < result.breakdown["distant"].independence
    assert result.chosen_peer_id == "distant"


def test_unknown_owner_and_fleet_signals_degrade_to_neutral_not_fabricated():
    peer = _peer("p1", latency_source="relay")  # no owner/hostname/gpus/tenure disclosed
    result = select_twin(WEIGHTS_A, "requester-1", [peer])
    breakdown = result.breakdown["p1"]
    assert breakdown.owner_diversity == 0.5
    assert breakdown.fleet_diversity == 0.5
    assert breakdown.tenure == 0.5
    assert "owner_unknown" in breakdown.notes
    assert "fleet_signal_unknown" in breakdown.notes


def test_tie_break_is_random_within_top_band_not_always_first_or_nearest():
    """Two candidates with equal independence: across many seeds, both get
    picked (random draw), and the draw is confined to the tie band."""
    peers = [
        _peer("p1", latency_source="relay", owner_id="owner-1", owner_verified=True),
        _peer("p2", latency_source="relay", owner_id="owner-2", owner_verified=True),
    ]
    picks = set()
    for seed in range(30):
        result = select_twin(WEIGHTS_A, "requester-1", peers, rng=random.Random(seed))
        assert set(result.tie_band_peer_ids) == {"p1", "p2"}
        picks.add(result.chosen_peer_id)
    assert picks == {"p1", "p2"}


def test_tie_break_never_reaches_outside_the_top_band():
    close = _peer("close", rtt_ms=1.0, latency_source="direct")
    far = _peer("far", latency_source="relay")
    result = select_twin(WEIGHTS_A, "requester-1", [close, far], rng=random.Random(0))
    assert "close" not in result.tie_band_peer_ids
    assert result.chosen_peer_id == "far"


def test_select_referee_requires_matching_weights_digest_on_both_twins():
    twin_a = _peer("twin-a", weights_digest=WEIGHTS_A)
    twin_b = _peer("twin-b", weights_digest=WEIGHTS_B)
    result = select_referee(twin_a, twin_b, [_peer("candidate")])
    assert result.chosen_peer_id is None
    assert result.reason == REASON_NO_COMPARABLE_TWIN


def test_select_referee_hard_excludes_candidate_sharing_owner_with_either_twin():
    """[mesh-referee-live-e17c] Owner independence is a HARD gate for
    select_referee, not just a scoring penalty: a same-owner candidate is
    excluded from the pool entirely -- it must not even appear in
    `breakdown`, and the pick must be the independent candidate with
    `owner_diversity_limited=False`."""
    twin_a = _peer("twin-a", owner_id="owner-a", owner_verified=True)
    twin_b = _peer("twin-b", owner_id="owner-b", owner_verified=True)
    same_as_a = _peer("same-as-a", owner_id="owner-a", owner_verified=True, latency_source="relay")
    independent = _peer("independent", owner_id="owner-c", owner_verified=True, latency_source="relay")

    result = select_referee(twin_a, twin_b, [same_as_a, independent], rng=random.Random(1))

    assert "same-as-a" not in result.breakdown
    assert result.chosen_peer_id == "independent"
    assert result.owner_diversity_limited is False


def test_select_referee_falls_back_to_distinct_node_key_when_no_owner_independent_candidate():
    """[mesh-referee-live-e17c] When the hard owner-exclusion would leave
    zero candidates -- every same-model peer shares an owner with a twin --
    select_referee falls back to the full comparable pool ("distinct node
    key" instead of distinct owner) rather than refusing outright, and
    records the narrowing via `owner_diversity_limited=True` so it is
    never silent."""
    twin_a = _peer("twin-a", owner_id="owner-a", owner_verified=True)
    twin_b = _peer("twin-b", owner_id="owner-b", owner_verified=True)
    only_candidate = _peer("only-candidate", owner_id="owner-a", owner_verified=True, latency_source="relay")

    result = select_referee(twin_a, twin_b, [only_candidate], rng=random.Random(1))

    assert result.chosen_peer_id == "only-candidate"
    assert result.owner_diversity_limited is True
    assert "only-candidate" in result.breakdown
    block = selection_rationale_block(result)
    assert block["owner_diversity_limited"] is True
    assert block["owner_diversity_limited_note"] == NOTE_OWNER_DIVERSITY_LIMITED


def test_select_referee_unknown_owner_candidate_is_never_hard_excluded():
    """An unknown `owner_id` on a candidate is never treated as a match --
    that would fabricate independence from absence in the wrong direction
    (excluding on a guess). It stays in the pool, scored by the existing
    soft owner_diversity component."""
    twin_a = _peer("twin-a", owner_id="owner-a", owner_verified=True)
    twin_b = _peer("twin-b", owner_id="owner-b", owner_verified=True)
    unknown_owner = _peer("unknown-owner", owner_id=None, latency_source="relay")

    result = select_referee(twin_a, twin_b, [unknown_owner], rng=random.Random(1))

    assert result.chosen_peer_id == "unknown-owner"
    assert result.owner_diversity_limited is False


def test_select_referee_excludes_the_twins_themselves_from_the_pool():
    twin_a = _peer("twin-a")
    twin_b = _peer("twin-b")
    result = select_referee(twin_a, twin_b, [twin_a, twin_b])
    assert result.chosen_peer_id is None
    assert result.reason == REASON_NO_COMPARABLE_TWIN
    assert result.breakdown == {}


def test_history_check_drops_a_failing_candidate_and_retries():
    good = _peer("good", latency_source="relay", owner_id="owner-good")
    bad = _peer("bad", latency_source="relay", owner_id="owner-bad")

    def history_check(peer: PeerInfo) -> HistorySanityResult:
        if peer.peer_id == "bad":
            return HistorySanityResult(ok=False, reason="continuity broken at size 3")
        return HistorySanityResult(ok=True, reason="clean")

    # Force "bad" to be drawn first regardless of independence ties by
    # giving it a slightly higher independence, then confirm the sanity
    # check still routes the pick to "good".
    bad = _peer("bad", latency_source="relay", owner_id="owner-bad", owner_verified=True)
    result = select_twin(WEIGHTS_A, "requester-1", [good, bad], history_check=history_check, rng=random.Random(2))
    assert result.chosen_peer_id == "good"


def test_history_check_failing_for_every_candidate_is_a_distinct_reason():
    peers = [_peer("p1", latency_source="relay"), _peer("p2", latency_source="relay")]

    def always_fails(peer: PeerInfo) -> HistorySanityResult:
        return HistorySanityResult(ok=False, reason="empty log")

    result = select_twin(WEIGHTS_A, "requester-1", peers, history_check=always_fails)
    assert result.chosen_peer_id is None
    assert result.reason == REASON_NO_CANDIDATE_PASSED_HISTORY_CHECK
    # The full pool considered is still recorded, even though nothing was picked.
    assert set(result.breakdown) == {"p1", "p2"}


def test_older_tenure_gets_a_bonus_over_a_freshly_joined_peer():
    older = _peer("older", latency_source="relay", first_joined_mesh_ts=1_000.0)
    newer = _peer("newer", latency_source="relay", first_joined_mesh_ts=1_000_000.0)
    result = select_twin(WEIGHTS_A, "requester-1", [older, newer])
    assert result.breakdown["older"].tenure > result.breakdown["newer"].tenure


def test_selection_rationale_block_is_json_safe_and_carries_the_caveat():
    peers = [_peer("p1", latency_source="relay", owner_id="owner-1")]
    result = select_twin(WEIGHTS_A, "requester-1", peers)
    block = selection_rationale_block(result)

    assert block["schema"] == "capsule-emit-mesh/twin-selection/v1"
    assert block["chosen_peer_id"] == "p1"
    assert block["independence_caveat"]
    assert isinstance(block["policy"]["weight_owner_diversity"], str)  # digest-bearing-float discipline
    assert block["candidates"][0]["peer_id"] == "p1"


def test_default_policy_weights_start_equal():
    assert (
        DEFAULT_POLICY.weight_network_distance
        == DEFAULT_POLICY.weight_owner_diversity
        == DEFAULT_POLICY.weight_fleet_diversity
        == DEFAULT_POLICY.weight_tenure
    )


def test_custom_policy_can_reweight_without_touching_selection_logic():
    owner_heavy = SelectionPolicy(
        weight_network_distance=0.1,
        weight_owner_diversity=0.7,
        weight_fleet_diversity=0.1,
        weight_tenure=0.1,
    )
    requester_info = _peer("requester-1", owner_id="owner-r")
    same_owner_but_far = _peer("same-owner-far", latency_source="relay", owner_id="owner-r")
    distinct_owner_but_close = _peer(
        "distinct-owner-close", rtt_ms=1.0, latency_source="direct", owner_id="owner-other", owner_verified=True
    )
    result = select_twin(
        WEIGHTS_A,
        "requester-1",
        [same_owner_but_far, distinct_owner_but_close],
        owner_heavy,
        requester_info=requester_info,
    )
    assert result.chosen_peer_id == "distinct-owner-close"

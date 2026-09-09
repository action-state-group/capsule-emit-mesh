# SPDX-License-Identifier: Apache-2.0
"""Tests for mesh_expectation_comparison — denominators, not scores.

These tests enforce the core boundary: no score/rating/ranking/aggregate/grade/
trust field exists anywhere in any output, every rate is "N of M" (never a bare
float or percentage), and the boundary marker is always present.

The canonical adversarial test (test_evading_node_anomaly) verifies that a node
that is inconclusive 100 of 100 times is VISIBLE as anomalous against the peer
median purely from the "N of M" figures — without any aggregate rating being
produced.
"""
from __future__ import annotations

import pytest

from mesh_expectation_comparison import (
    NodeExpectationRecord,
    PopulationExpectationSummary,
    build_node_expectation_record,
    build_population_summary,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Keys whose names contain these substrings are forbidden — EXCEPT the explicit
# sentinel key "not_a_score" which is REQUIRED by the spec and whose name
# negates the very concept.  The check below excludes that key by name before
# testing substrings.
_FORBIDDEN_KEY_SUBSTRINGS = ("score", "rating", "ranking", "aggregate", "grade", "trust")
# Keys explicitly allowed even though they contain a forbidden substring (they
# are the sentinel markers, not aggregate-score fields).
_ALLOWED_KEYS = frozenset({"not_a_score"})


def _all_keys_recursive(obj: object) -> list[str]:
    """Return every dict key reachable from obj, recursively."""
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(k)
            keys.extend(_all_keys_recursive(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            keys.extend(_all_keys_recursive(item))
    return keys


def _all_values_recursive(obj: object) -> list[object]:
    """Return every leaf value reachable from obj, recursively."""
    values: list[object] = []
    if isinstance(obj, dict):
        for v in obj.values():
            values.extend(_all_values_recursive(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            values.extend(_all_values_recursive(item))
    else:
        values.append(obj)
    return values


def _make_node(
    node_id: str = "node:abc123",
    *,
    inconclusive: int = 5,
    total_adj: int = 100,
    refusals: int = 2,
    total_requests: int = 50,
    coverage_unsatisfiable: int = 1,
    total_refusals: int = 2,
    reconciled_peer_count: int = 8,
) -> NodeExpectationRecord:
    return build_node_expectation_record(
        node_id,
        adjudications={"corroborated": total_adj - inconclusive, "contradicted": 0, "inconclusive": inconclusive},
        total_adjudications=total_adj,
        refusals=refusals,
        total_requests=total_requests,
        coverage_unsatisfiable=coverage_unsatisfiable,
        total_refusals=total_refusals,
        reconciled_peer_count=reconciled_peer_count,
    )


# ---------------------------------------------------------------------------
# 1. test_no_score_field_in_output
# ---------------------------------------------------------------------------

class TestNoScoreFieldInOutput:
    """No key containing score/rating/ranking/aggregate/grade/trust may appear."""

    def test_node_record_has_no_forbidden_key(self) -> None:
        record = _make_node()
        all_keys = _all_keys_recursive(record.to_value())
        for key in all_keys:
            if key in _ALLOWED_KEYS:
                continue
            for forbidden in _FORBIDDEN_KEY_SUBSTRINGS:
                assert forbidden not in key.lower(), (
                    f"Forbidden key substring {forbidden!r} found in key {key!r} "
                    f"in NodeExpectationRecord.to_value()"
                )

    def test_population_summary_has_no_forbidden_key(self) -> None:
        records = [_make_node(f"node:{i:03d}") for i in range(5)]
        summary = build_population_summary(records)
        all_keys = _all_keys_recursive(summary.to_value())
        for key in all_keys:
            if key in _ALLOWED_KEYS:
                continue
            for forbidden in _FORBIDDEN_KEY_SUBSTRINGS:
                assert forbidden not in key.lower(), (
                    f"Forbidden key substring {forbidden!r} found in key {key!r} "
                    f"in PopulationExpectationSummary.to_value()"
                )

    def test_empty_population_has_no_forbidden_key(self) -> None:
        summary = build_population_summary([])
        all_keys = _all_keys_recursive(summary.to_value())
        for key in all_keys:
            if key in _ALLOWED_KEYS:
                continue
            for forbidden in _FORBIDDEN_KEY_SUBSTRINGS:
                assert forbidden not in key.lower(), (
                    f"Forbidden key substring {forbidden!r} found in key {key!r} "
                    f"in empty PopulationExpectationSummary.to_value()"
                )


# ---------------------------------------------------------------------------
# 2. test_every_rate_has_denominator
# ---------------------------------------------------------------------------

class TestEveryRateHasDenominator:
    """Every rate dict must have both 'n' and 'of' keys — never a bare float."""

    def _check_no_bare_float(self, obj: object, path: str = "root") -> None:
        if isinstance(obj, dict):
            # If this dict looks like a rate (has 'n' or 'of'), both must be present
            has_n = "n" in obj
            has_of = "of" in obj
            if has_n or has_of:
                assert has_n and has_of, (
                    f"Rate dict at {path!r} is missing 'n' or 'of': {obj!r}"
                )
                assert isinstance(obj["n"], int), f"'n' at {path!r} must be int, got {type(obj['n'])}"
                assert isinstance(obj["of"], int), f"'of' at {path!r} must be int, got {type(obj['of'])}"
            for k, v in obj.items():
                self._check_no_bare_float(v, f"{path}.{k}")
        elif isinstance(obj, (list, tuple)):
            for i, item in enumerate(obj):
                self._check_no_bare_float(item, f"{path}[{i}]")
        elif isinstance(obj, float):
            raise AssertionError(
                f"Bare float {obj!r} found at {path!r} — rates must be 'N of M' dicts"
            )

    def test_node_record_no_bare_float(self) -> None:
        record = _make_node()
        self._check_no_bare_float(record.to_value())

    def test_population_summary_no_bare_float(self) -> None:
        records = [_make_node(f"node:{i:03d}") for i in range(5)]
        summary = build_population_summary(records)
        self._check_no_bare_float(summary.to_value())

    def test_rate_keys_present_on_node(self) -> None:
        record = _make_node()
        v = record.to_value()
        for rate_key in ("inconclusive_rate", "refusal_rate", "coverage_unsatisfiable_rate"):
            assert rate_key in v, f"Expected rate key {rate_key!r} in NodeExpectationRecord.to_value()"
            assert "n" in v[rate_key] and "of" in v[rate_key], (
                f"Rate {rate_key!r} must be a dict with 'n' and 'of', got {v[rate_key]!r}"
            )


# ---------------------------------------------------------------------------
# 3. test_boundary_present
# ---------------------------------------------------------------------------

class TestBoundaryPresent:
    """boundary == "denominators_only" must always appear."""

    def test_node_record_has_boundary(self) -> None:
        record = _make_node()
        v = record.to_value()
        assert "boundary" in v, "NodeExpectationRecord.to_value() missing 'boundary'"
        assert v["boundary"] == "denominators_only", (
            f"Expected boundary='denominators_only', got {v['boundary']!r}"
        )

    def test_population_summary_has_boundary(self) -> None:
        summary = build_population_summary([_make_node()])
        v = summary.to_value()
        assert "boundary" in v, "PopulationExpectationSummary.to_value() missing 'boundary'"
        assert v["boundary"] == "denominators_only", (
            f"Expected boundary='denominators_only', got {v['boundary']!r}"
        )

    def test_empty_population_has_boundary(self) -> None:
        summary = build_population_summary([])
        v = summary.to_value()
        assert v.get("boundary") == "denominators_only", (
            f"Empty summary must still have boundary='denominators_only'"
        )


# ---------------------------------------------------------------------------
# 4. test_evading_node_anomaly — the canonical adversarial test
# ---------------------------------------------------------------------------

class TestEvadingNodeAnomaly:
    """An evading node (inconclusive 100/100) must be visible as an anomaly
    against the peer median purely from "N of M" counts — no aggregate rating
    produced anywhere."""

    def _build_population(self) -> tuple[NodeExpectationRecord, PopulationExpectationSummary]:
        # Evading node: inconclusive 100 of 100
        evading = build_node_expectation_record(
            "node:evader",
            adjudications={"corroborated": 0, "contradicted": 0, "inconclusive": 100},
            total_adjudications=100,
            refusals=0,
            total_requests=100,
            coverage_unsatisfiable=0,
            total_refusals=0,
            reconciled_peer_count=3,
        )
        # 9 typical peers with inconclusive 1..9 of 100
        typical = [
            build_node_expectation_record(
                f"node:peer{i:02d}",
                adjudications={"corroborated": 100 - i, "contradicted": 0, "inconclusive": i},
                total_adjudications=100,
                refusals=0,
                total_requests=100,
                coverage_unsatisfiable=0,
                total_refusals=0,
                reconciled_peer_count=10,
            )
            for i in range(1, 10)
        ]
        all_records = [evading] + typical
        summary = build_population_summary(all_records)
        return evading, summary

    def test_evading_node_inconclusive_count_visible(self) -> None:
        evading, summary = self._build_population()
        ev = evading.to_value()
        # The evading node's inconclusive count is present as "N of M"
        assert ev["inconclusive_rate"]["n"] == 100
        assert ev["inconclusive_rate"]["of"] == 100

    def test_peer_median_visible_for_comparison(self) -> None:
        _evading, summary = self._build_population()
        sv = summary.to_value()
        # The peer median inconclusive numerator is present and much lower (1..9)
        median_n = sv["peer_medians"]["inconclusive_rate"]["median_of"]
        # median of [100, 1, 2, 3, 4, 5, 6, 7, 8, 9] = 5 (middle of sorted list)
        assert median_n < 100, (
            f"Peer median inconclusive count {median_n} should be well below the evading node's 100"
        )
        # The denominator is also present
        assert "denominator" in sv["peer_medians"]["inconclusive_rate"]

    def test_no_aggregate_rating_in_anomaly_output(self) -> None:
        _evading, summary = self._build_population()
        all_keys = _all_keys_recursive(summary.to_value())
        for key in all_keys:
            if key in _ALLOWED_KEYS:
                continue
            for forbidden in _FORBIDDEN_KEY_SUBSTRINGS:
                assert forbidden not in key.lower(), (
                    f"Forbidden aggregate key {forbidden!r} found in evading-node anomaly output"
                )

    def test_relying_party_can_observe_anomaly_from_n_of_m(self) -> None:
        """A relying party can detect the evading node by comparing N-of-M counts.

        Specifically: if evading_node.inconclusive_rate["n"] > peer_median["median_of"],
        the anomaly is visible without any score or rating being computed.
        """
        evading, summary = self._build_population()
        ev = evading.to_value()
        sv = summary.to_value()
        evading_inconclusive = ev["inconclusive_rate"]["n"]
        peer_median_inconclusive = sv["peer_medians"]["inconclusive_rate"]["median_of"]
        # Relying party predicate (computed here, NOT by the module):
        is_anomalous = evading_inconclusive > peer_median_inconclusive
        assert is_anomalous, (
            f"Relying party should be able to observe anomaly: "
            f"evading_inconclusive={evading_inconclusive} vs peer_median={peer_median_inconclusive}"
        )


# ---------------------------------------------------------------------------
# 5. test_not_a_score
# ---------------------------------------------------------------------------

class TestNotAScore:
    """not_a_score must equal "relying_party_computes_predicate" on both types."""

    def test_node_record_not_a_score(self) -> None:
        record = _make_node()
        v = record.to_value()
        assert "not_a_score" in v, "NodeExpectationRecord.to_value() missing 'not_a_score'"
        assert v["not_a_score"] == "relying_party_computes_predicate", (
            f"Expected not_a_score='relying_party_computes_predicate', got {v['not_a_score']!r}"
        )

    def test_population_summary_not_a_score(self) -> None:
        summary = build_population_summary([_make_node()])
        v = summary.to_value()
        assert "not_a_score" in v, "PopulationExpectationSummary.to_value() missing 'not_a_score'"
        assert v["not_a_score"] == "relying_party_computes_predicate", (
            f"Expected not_a_score='relying_party_computes_predicate', got {v['not_a_score']!r}"
        )


# ---------------------------------------------------------------------------
# 6. test_zero_denominator_safe
# ---------------------------------------------------------------------------

class TestZeroDenominatorSafe:
    """Building a record with total_adjudications=0 must not crash and must
    carry the denominator (0) explicitly in the output."""

    def test_zero_total_adjudications_does_not_crash(self) -> None:
        record = build_node_expectation_record(
            "node:empty",
            adjudications={"corroborated": 0, "contradicted": 0, "inconclusive": 0},
            total_adjudications=0,
            refusals=0,
            total_requests=0,
            coverage_unsatisfiable=0,
            total_refusals=0,
            reconciled_peer_count=0,
        )
        v = record.to_value()
        assert v["inconclusive_rate"] == {"n": 0, "of": 0}, (
            f"Zero-adjudications node must output {{n:0, of:0}}, got {v['inconclusive_rate']!r}"
        )
        assert v["refusal_rate"] == {"n": 0, "of": 0}
        assert v["coverage_unsatisfiable_rate"] == {"n": 0, "of": 0}

    def test_zero_denominator_still_has_boundary(self) -> None:
        record = build_node_expectation_record(
            "node:empty",
            adjudications={"corroborated": 0, "contradicted": 0, "inconclusive": 0},
            total_adjudications=0,
            refusals=0,
            total_requests=0,
            coverage_unsatisfiable=0,
            total_refusals=0,
            reconciled_peer_count=0,
        )
        v = record.to_value()
        assert v.get("boundary") == "denominators_only"
        assert v.get("not_a_score") == "relying_party_computes_predicate"


# ---------------------------------------------------------------------------
# 7. test_population_median_has_denominator
# ---------------------------------------------------------------------------

class TestPopulationMedianHasDenominator:
    """The median for each rate in peer_medians must be {"median_of": N, "denominator": M}."""

    def test_median_keys_present(self) -> None:
        records = [_make_node(f"node:{i:03d}", inconclusive=i * 3, total_adj=100) for i in range(1, 6)]
        summary = build_population_summary(records)
        v = summary.to_value()
        for rate_name in ("inconclusive_rate", "refusal_rate", "coverage_unsatisfiable_rate"):
            assert rate_name in v["peer_medians"], (
                f"peer_medians missing key {rate_name!r}"
            )
            median_entry = v["peer_medians"][rate_name]
            assert "median_of" in median_entry, (
                f"peer_medians[{rate_name!r}] missing 'median_of', got {median_entry!r}"
            )
            assert "denominator" in median_entry, (
                f"peer_medians[{rate_name!r}] missing 'denominator', got {median_entry!r}"
            )
            assert isinstance(median_entry["median_of"], int), (
                f"peer_medians[{rate_name!r}]['median_of'] must be int"
            )
            assert isinstance(median_entry["denominator"], int), (
                f"peer_medians[{rate_name!r}]['denominator'] must be int"
            )

    def test_median_is_not_bare_float(self) -> None:
        records = [_make_node(f"node:{i:03d}") for i in range(4)]
        summary = build_population_summary(records)
        v = summary.to_value()
        all_values = _all_values_recursive(v["peer_medians"])
        for val in all_values:
            assert not isinstance(val, float), (
                f"Bare float {val!r} found in peer_medians — must be int"
            )

    def test_single_node_median_equals_that_node(self) -> None:
        record = _make_node("node:solo", inconclusive=7, total_adj=30)
        summary = build_population_summary([record])
        v = summary.to_value()
        med = v["peer_medians"]["inconclusive_rate"]
        assert med["median_of"] == 7
        assert med["denominator"] == 30

    def test_empty_population_medians_are_empty(self) -> None:
        summary = build_population_summary([])
        v = summary.to_value()
        assert v["peer_medians"] == {}, (
            f"Empty population should have empty peer_medians, got {v['peer_medians']!r}"
        )

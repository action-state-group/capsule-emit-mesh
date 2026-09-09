# SPDX-License-Identifier: Apache-2.0
"""Per-node and per-population DENOMINATORS for mesh corroboration rates.

**This module publishes denominators, not scores.**

The adversarial council's largest finding is that an evading node can force
``inconclusive`` at zero cost, and that evasion is invisible without a
denominator comparison.  A node that is ``inconclusive`` 100 of 100 times is
structurally different from one that is ``inconclusive`` 1 of 100, but any
aggregate that collapses both into a percentage or rating makes them look
similar.  This module prevents that collapse by always publishing both the
numerator and the denominator and never computing an aggregate itself.

**Boundary (enforced in both the data shape and the tests):**
- No ``rating``, ``ranking``, ``aggregate``, ``score``, ``grade``, or ``trust``
  field exists anywhere in the output.
- Every rate is rendered as ``{"n": N, "of": M}`` — denominator always present
  and always named.
- The relying party receives raw counts and computes whatever predicate they
  need.  This module never does.
- Every figure ships with its denominator, boundary marker
  (``"denominators_only"``), and audience.

**How to consume it:**
  1. Call :func:`build_node_expectation_record` for each node using the
     adjudications dict that ``ask_history.py``'s
     ``ReferencesResult.adjudications_about_x`` already produces
     (``{"corroborated": N, "contradicted": N, "inconclusive": N}``), plus the
     per-node refusal counts.
  2. Collect the records into a list and call
     :func:`build_population_summary` to get the peer-median comparison.
  3. In the returned ``to_value()`` output, compare a specific node's
     ``inconclusive_of`` / ``inconclusive_denominator`` against
     ``peer_medians["inconclusive_rate"]`` to observe anomalies — purely as
     "N of M" counts, with no aggregate rating produced anywhere.

**Coordination with mesh-adjudicator-margin-tau:**
The ``[mesh-adjudicator-margin-tau]`` workstream owns the per-exchange
``inconclusive`` verdict logic (the margin/tau thresholds that make a single
adjudication resolve as ``inconclusive``).  This module consumes the
ACCUMULATED RATE of those verdicts — the ``inconclusive`` count from the
adjudications dict — and does not redefine what ``inconclusive`` means or
duplicate any threshold logic.
"""
from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Any


__all__ = [
    "NodeExpectationRecord",
    "PopulationExpectationSummary",
    "build_node_expectation_record",
    "build_population_summary",
]

_BOUNDARY = "denominators_only"
_NOT_A_SCORE = "relying_party_computes_predicate"


def _n_of(n: int, of: int) -> dict[str, int]:
    """Canonical "N of M" shape — denominator always present."""
    return {"n": n, "of": of}


@dataclass(frozen=True)
class NodeExpectationRecord:
    """Denominators for a single node's adjudication and refusal rates.

    All rate fields are stored as raw integers; ``to_value()`` renders them as
    ``{"n": N, "of": M}`` so the relying party always sees both the numerator
    and the denominator.

    No field here is a score, rating, or aggregate.
    """

    node_id: str

    # Inconclusive adjudications: N of M
    inconclusive_of: int
    inconclusive_denominator: int

    # Signed refusals: N of M evidence requests
    refusal_of: int
    refusal_denominator: int

    # coverage_unsatisfiable refusals: N of M total refusals
    coverage_unsatisfiable_of: int
    coverage_unsatisfiable_denominator: int

    # Raw peer-reconciliation count — a count, not a rate; no denominator needed
    reconciled_peer_count: int

    # Boundary and audience markers — always present, never omitted
    boundary: str = _BOUNDARY
    audience: str = "relying_party"
    not_a_score: str = _NOT_A_SCORE

    def to_value(self) -> dict[str, Any]:
        """Return a dict with every rate as ``{"n": N, "of": M}`` and no
        score, rating, ranking, aggregate, grade, or trust field."""
        return {
            "node_id": self.node_id,
            "inconclusive_rate": _n_of(self.inconclusive_of, self.inconclusive_denominator),
            "refusal_rate": _n_of(self.refusal_of, self.refusal_denominator),
            "coverage_unsatisfiable_rate": _n_of(
                self.coverage_unsatisfiable_of,
                self.coverage_unsatisfiable_denominator,
            ),
            "reconciled_peer_count": self.reconciled_peer_count,
            "boundary": self.boundary,
            "audience": self.audience,
            "not_a_score": self.not_a_score,
        }


@dataclass(frozen=True)
class PopulationExpectationSummary:
    """Denominators for a population of nodes, with peer medians.

    ``peer_medians`` maps each rate name to a ``{"median_of": N, "denominator": M}``
    dict so the median is also "N of M" — never a bare float or percentage.

    No field here is a score, rating, or aggregate.
    """

    node_count: int
    nodes: tuple[NodeExpectationRecord, ...]

    # peer_medians: each value is {"median_of": int, "denominator": int}
    peer_medians: dict[str, dict[str, int]]

    boundary: str = _BOUNDARY
    not_a_score: str = _NOT_A_SCORE

    def to_value(self) -> dict[str, Any]:
        """Return a dict with every rate as ``{"n": N, "of": M}`` and no
        score, rating, ranking, aggregate, grade, or trust field."""
        return {
            "node_count": self.node_count,
            "nodes": [n.to_value() for n in self.nodes],
            "peer_medians": {k: dict(v) for k, v in self.peer_medians.items()},
            "boundary": self.boundary,
            "not_a_score": self.not_a_score,
        }


def build_node_expectation_record(
    node_id: str,
    *,
    adjudications: dict[str, int],
    total_adjudications: int,
    refusals: int,
    total_requests: int,
    coverage_unsatisfiable: int,
    total_refusals: int,
    reconciled_peer_count: int,
    audience: str = "relying_party",
) -> NodeExpectationRecord:
    """Build a :class:`NodeExpectationRecord` from adjudication tallies.

    Parameters
    ----------
    node_id:
        Stable identifier for the node (e.g. the ``node_id`` from a
        ``HistoryCard``).
    adjudications:
        Dict in the shape ``ask_history.py``'s
        ``ReferencesResult.adjudications_about_x`` already produces:
        ``{"corroborated": N, "contradicted": N, "inconclusive": N}``.
        Only the ``"inconclusive"`` key is consumed here; the others are
        available to the caller for their own predicate.
    total_adjudications:
        The denominator for inconclusive rate (total adjudications from all
        peers that asked about this node).
    refusals:
        Number of signed refusals from this node.
    total_requests:
        Total evidence requests made to this node (denominator for refusal
        rate).
    coverage_unsatisfiable:
        Number of ``coverage_unsatisfiable`` refusals from this node.
    total_refusals:
        Total refusals from this node (denominator for
        ``coverage_unsatisfiable`` rate).
    reconciled_peer_count:
        Raw count of peers this node has reconciled checkpoint roots with.
    audience:
        Who this record is for.  Defaults to ``"relying_party"``.
    """
    inconclusive = adjudications.get("inconclusive", 0)
    return NodeExpectationRecord(
        node_id=node_id,
        inconclusive_of=inconclusive,
        inconclusive_denominator=total_adjudications,
        refusal_of=refusals,
        refusal_denominator=total_requests,
        coverage_unsatisfiable_of=coverage_unsatisfiable,
        coverage_unsatisfiable_denominator=total_refusals,
        reconciled_peer_count=reconciled_peer_count,
        audience=audience,
    )


def _median_n_of(
    numerators: list[int],
    denominators: list[int],
) -> dict[str, int]:
    """Return ``{"median_of": N, "denominator": M}`` for a population.

    When the population is empty, returns zeros.  When it has one element, the
    median is that element's value.  ``statistics.median`` returns the middle
    value for odd-length lists and the mean of the two middle values for even-
    length lists — for integer counts we floor-divide so the result stays an
    integer, preserving the "N of M" shape.
    """
    if not numerators:
        return {"median_of": 0, "denominator": 0}
    median_num = int(median(numerators))
    median_den = int(median(denominators))
    return {"median_of": median_num, "denominator": median_den}


def build_population_summary(
    records: list[NodeExpectationRecord],
) -> PopulationExpectationSummary:
    """Build a :class:`PopulationExpectationSummary` from a list of node records.

    The peer medians for each rate are computed as the median numerator paired
    with the median denominator, each expressed as an integer.  When the
    population has 0 nodes, medians are empty dicts.  When it has 1 node, the
    median is that node's value.

    No score, rating, or aggregate is computed.  The relying party receives the
    raw counts and computes whatever predicate they need.
    """
    if not records:
        return PopulationExpectationSummary(
            node_count=0,
            nodes=(),
            peer_medians={},
        )

    inconclusive_nums = [r.inconclusive_of for r in records]
    inconclusive_dens = [r.inconclusive_denominator for r in records]

    refusal_nums = [r.refusal_of for r in records]
    refusal_dens = [r.refusal_denominator for r in records]

    cu_nums = [r.coverage_unsatisfiable_of for r in records]
    cu_dens = [r.coverage_unsatisfiable_denominator for r in records]

    peer_medians: dict[str, dict[str, int]] = {
        "inconclusive_rate": _median_n_of(inconclusive_nums, inconclusive_dens),
        "refusal_rate": _median_n_of(refusal_nums, refusal_dens),
        "coverage_unsatisfiable_rate": _median_n_of(cu_nums, cu_dens),
    }

    return PopulationExpectationSummary(
        node_count=len(records),
        nodes=tuple(records),
        peer_medians=peer_medians,
    )

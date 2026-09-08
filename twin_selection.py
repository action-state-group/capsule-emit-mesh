# SPDX-License-Identifier: Apache-2.0
"""Independence-first twin/referee selection over observable peer attributes.

Today the twin (a second provider asked the same prompt, for corroboration)
and the referee (a third-node adjudicator, E17c) are hand-picked via
``x-mesh-target`` -- there is no selection logic. For the corroboration/
adjudication this repo already builds (``twin_adjudicator.py``) to *mean*
anything, WHO gets asked has to be chosen so that two co-located or
colluding machines corroborating each other cannot pass as independent
agreement. Two problems, in order:

  1. **Comparability.** A twin running a different model is not evidence of
     anything -- it is "different model, different answer." Same-model is a
     hard gate, using ``weights_digest`` (identical across nodes running the
     SAME weights file) -- never the per-node ``local-gguf/sha256-...`` load
     id, which differs node to node even for the same weights.
  2. **Independence.** Among same-model peers, prefer the one LEAST likely
     to be the same operator / same box / same rack as whoever it is being
     compared against -- using only what a peer already discloses in its
     own status (``rtt_ms``/``latency_source``, ``owner``, ``hostname``/
     ``gpus``/``is_soc``, ``first_joined_mesh_ts``).

WHAT THIS IS NOT -- read before extending
------------------------------------------
  - NOT a public ranking. `select_twin`/`select_referee` are a REQUESTER-
    SIDE, per-request "who do I ask" policy. Nothing here is gossiped,
    published, or attached to a peer's identity as a standing rating -- the
    independence breakdown is recorded ALONGSIDE one twin comparison as
    evidence for why that pairing was chosen, not as a score a node carries
    around (same discipline as `twin_adjudicator.py`'s own "NOT a scorer").
  - NOT proof of independence. Every component below is a heuristic over
    what a peer discloses about ITSELF -- see `INDEPENDENCE_CAVEAT`.
    Selection improves the odds a twin/referee is independent; it never
    proves it, and callers must not present a choice made here as a
    verified-distinct-party guarantee.
  - NOT a network call. Like `twin_adjudicator.adjudicate()`, this module
    is pure: it scores and picks over a `peers` sequence the caller already
    holds. The one place a network round trip could enter -- Step 4's
    optional history sanity-check -- is an INJECTED callable
    (`HistoryCheck`), never something this module dials itself.
  - `select_referee`'s owner-independence gate is HARD, not just a scoring
    penalty (added [mesh-referee-live-e17c], 2026-09-08): a candidate
    sharing an `owner_id` with either twin is excluded from the candidate
    pool entirely, not merely scored `0.0` on the owner-diversity
    component. When that hard exclusion would leave zero candidates --
    every same-model peer shares an owner with a twin -- it falls back to
    the full (twin-excluded-only) comparable pool, "distinct node key"
    instead of distinct owner, and `SelectionResult.owner_diversity_limited`
    is set so this narrowing is never silent.

The selection algorithm
------------------------
1. **Comparability filter (hard gate).** Candidates = peers with
   ``state == "serving"`` and ``weights_digest`` equal to the target (and,
   for `select_referee`, not equal to either twin's own peer id). Empty
   candidate pool -> `REASON_NO_COMPARABLE_TWIN`, never a substituted model.
2. **Independence.** Each candidate gets four 0-1 components -- network
   distance, operator diversity, fleet diversity, tenure -- combined by
   `SelectionPolicy`'s (documented, tunable, equal-by-default) weights into
   one 0-1 value. See each `_*_component` function for exactly what each
   component reads and how it degrades on absent data.
3. **Pick.** The highest-independence candidates within `tie_band_width` of
   the top form a band; the pick is a RANDOM draw from that band (never the
   single nearest -- nearest is *likely* co-located; never uniformly random
   over the whole pool -- that can draw a co-located candidate half the
   time). Randomness inside the top band only stops a target from gaming
   which twin/referee it faces.
4. **Optional history sanity-check.** If `history_check` is supplied, a
   picked candidate whose check fails is dropped and the next band is
   drawn from what remains, so a twin with a broken or suspiciously empty
   history never gets picked silently.
"""
from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from capsule_emit.numbers import float_to_str

__all__ = [
    "DEFAULT_POLICY",
    "INDEPENDENCE_CAVEAT",
    "NOTE_OWNER_DIVERSITY_LIMITED",
    "REASON_NO_CANDIDATE_PASSED_HISTORY_CHECK",
    "REASON_NO_COMPARABLE_TWIN",
    "TWIN_SELECTION_SCHEMA",
    "HistoryCheck",
    "HistorySanityResult",
    "IndependenceBreakdown",
    "PeerInfo",
    "SelectionPolicy",
    "SelectionResult",
    "select_referee",
    "select_twin",
    "selection_rationale_block",
]

TWIN_SELECTION_SCHEMA = "capsule-emit-mesh/twin-selection/v1"

#: Closed set of "nothing to select" reasons -- distinct from an exception:
#: the inputs are fine, there is simply no eligible candidate. Mirrors
#: twin_adjudicator.py's NO_VERDICT_* discipline.
REASON_NO_COMPARABLE_TWIN = "no_comparable_twin"
REASON_NO_CANDIDATE_PASSED_HISTORY_CHECK = "no_twin_passed_history_check"

#: HONESTY GRADE -- carried into every SelectionResult/rationale block, same
#: discipline as node_ownership.IDENTITY_LIMITATION_CAVEAT and
#: advertisement.ADVERTISEMENT_SELF_SIGNED_NOTE: a reader must never see an
#: independence figure without the caveat attached.
INDEPENDENCE_CAVEAT = (
    "selection-improves-odds-not-proof: this independence figure is a "
    "requester-side heuristic over what each peer discloses about itself "
    "(network distance, self-reported/opt-in owner identity, hardware/"
    "hostname hints, join tenure) -- it is NOT a verified-distinct-party "
    "guarantee. Two distant IPs can still be one operator; an unsigned "
    "owner id can be anything. The one signal that would actually prove "
    "distinct operators is a signed join-card binding (node_ownership.py), "
    "which is opt-in and not universal today. rtt/relay is a network-"
    "distance heuristic, not geography. Nothing here is a public ranking or "
    "a standing figure attached to any peer -- it is recorded once, "
    "alongside the one twin/referee comparison it informed, as evidence a "
    "verifier can inspect."
)


@dataclass(frozen=True)
class PeerInfo:
    """One peer as observable from ``/api/status`` ``peers[]`` today.

    Every field defaults to ``None`` -- "not disclosed" -- and every
    component function below treats absence as a neutral, honestly-labeled
    unknown, never a fabricated value (same discipline as
    `node_ownership.owner_provenance_block`'s owner-absent default).
    """

    peer_id: str
    #: ``state == "serving"`` is the liveness half of the comparability
    #: gate; a peer that isn't currently serving is never a candidate.
    state: str = "serving"
    #: The real same-model key (identical across nodes running the same
    #: weights file). NOT the per-node ``local-gguf/sha256-...`` load id.
    weights_digest: str | None = None
    #: Network-distance proxy, from the requester's own vantage point.
    rtt_ms: float | None = None
    latency_source: str | None = None  # "direct" | "relay"
    #: Operator identity. Weak today (owner identity is opt-in and
    #: self-asserted -- see node_ownership.py); `owner_verified` distinguishes
    #: a re-checked signed cert from a bare claim.
    owner_id: str | None = None
    owner_verified: bool = False
    #: Fleet / co-location hints.
    hostname: str | None = None
    gpus: tuple[str, ...] | None = None
    is_soc: bool | None = None
    #: Tenure -- when this peer was first observed on the mesh. Any
    #: consistent unit works (unix ms is the natural one); only used for
    #: pool-relative ordering, never compared to wall-clock "now".
    first_joined_mesh_ts: float | None = None


@dataclass(frozen=True)
class SelectionPolicy:
    """Tunable, documented weights for `select_twin`/`select_referee`.

    Defaults: the four independence components start EQUALLY weighted (the
    design note's own instruction -- "weights are the tunable policy, start
    equal"). A deployment that has reason to trust one signal more (e.g. it
    has enough owner-cert adoption that `owner_verified` is common) can
    raise that weight without touching this module's logic.

    Cadence (how often a twin fires at all) is a CALLER-level decision,
    orthogonal to which peer gets picked once a request is made -- it is
    not a field here. See ``docs/TWIN-REFEREE-SELECTION.md`` "Cadence" for
    the recommended default.
    """

    weight_network_distance: float = 0.25
    weight_owner_diversity: float = 0.25
    weight_fleet_diversity: float = 0.25
    weight_tenure: float = 0.25
    #: A candidate within this fraction of the top independence value is in
    #: the tie-break band eligible for the random pick (Step 3).
    tie_band_width: float = 0.10
    #: rtt_ms at/above this saturates the network-distance component to 1.0
    #: when `latency_source` isn't `"relay"`. A heuristic threshold, not a
    #: geography claim -- see INDEPENDENCE_CAVEAT.
    rtt_saturation_ms: float = 250.0


DEFAULT_POLICY = SelectionPolicy()


@dataclass(frozen=True)
class HistorySanityResult:
    """Result of an injected Step-4 history sanity-check. Never raises --
    a verdict the caller's carrier reports back, same shape discipline as
    `node_ownership.OwnershipRecheck`."""

    ok: bool
    reason: str


#: A caller-supplied Step-4 check: given the candidate under consideration,
#: report whether its history card looks sane enough to proceed (no broken
#: continuity, not suspiciously empty/just-created). This module never
#: calls out over the network itself -- see the module docstring.
HistoryCheck = Callable[[PeerInfo], HistorySanityResult]


@dataclass(frozen=True)
class IndependenceBreakdown:
    """The four 0-1 components for one candidate plus their weighted
    combination -- the "why" a verifier inspects (design note item 3:
    "selection is itself evidence")."""

    peer_id: str
    network_distance: float
    owner_diversity: float
    fleet_diversity: float
    tenure: float
    independence: float
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_value(self) -> dict[str, Any]:
        return {
            "peer_id": self.peer_id,
            "network_distance": float_to_str(self.network_distance, field="network_distance"),
            "owner_diversity": float_to_str(self.owner_diversity, field="owner_diversity"),
            "fleet_diversity": float_to_str(self.fleet_diversity, field="fleet_diversity"),
            "tenure": float_to_str(self.tenure, field="tenure"),
            "independence": float_to_str(self.independence, field="independence"),
            "notes": list(self.notes),
        }


#: [mesh-referee-live-e17c] Recorded on `SelectionResult` (and echoed into
#: `selection_rationale_block`) whenever `select_referee`'s hard
#: owner-exclusion left zero candidates and it fell back to the full
#: (twin-excluded-only) comparable pool -- "distinct node key" instead of
#: distinct owner. Never silent: a verifier must be able to see the
#: independence guarantee was narrowed, not just infer it from a low
#: `owner_diversity` score buried in the breakdown.
NOTE_OWNER_DIVERSITY_LIMITED = "owner_diversity_limited_single_owner_pool"


@dataclass(frozen=True)
class SelectionResult:
    """Outcome of `select_twin`/`select_referee` -- either a chosen peer id
    or a first-class "nothing eligible" reason, never both, plus the full
    breakdown for every candidate considered so the pick is auditable."""

    chosen_peer_id: str | None
    reason: str | None
    target_weights_digest: str | None
    breakdown: dict[str, IndependenceBreakdown]
    tie_band_peer_ids: tuple[str, ...]
    policy: SelectionPolicy
    #: True only for `select_referee`, and only when the hard
    #: owner-exclusion candidate pool was empty and it fell back to
    #: "distinct node key" (see `NOTE_OWNER_DIVERSITY_LIMITED`). Always
    #: `False` for `select_twin`, which does not run this hard gate.
    owner_diversity_limited: bool = False

    def has_selection(self) -> bool:
        return self.chosen_peer_id is not None


def _network_distance_component(candidate: PeerInfo, policy: SelectionPolicy) -> tuple[float, str | None]:
    if candidate.latency_source == "relay":
        return 1.0, None
    if candidate.rtt_ms is not None:
        component = max(0.0, min(candidate.rtt_ms / policy.rtt_saturation_ms, 1.0))
        return component, None
    return 0.5, "network_distance_unknown"


def _owner_diversity_component(candidate: PeerInfo, others: Sequence[PeerInfo]) -> tuple[float, str | None]:
    if not others:
        # No second party to compare against -- unknown, never assumed independent.
        return 0.5, "owner_unknown"
    worst = 1.0
    worst_note: str | None = None
    for other in others:
        if candidate.owner_id is None or other.owner_id is None:
            component, note = 0.5, "owner_unknown"
        elif candidate.owner_id == other.owner_id:
            component, note = 0.0, f"same_owner_as:{other.peer_id}"
        else:
            component = 1.0 if candidate.owner_verified else 0.7
            note = None if candidate.owner_verified else "owner_claim_unverified"
        if component < worst:
            worst, worst_note = component, note
    return worst, worst_note


def _fleet_diversity_component(candidate: PeerInfo, others: Sequence[PeerInfo]) -> tuple[float, str | None]:
    if not others:
        return 0.5, "fleet_signal_unknown"
    worst = 1.0
    worst_note: str | None = None
    for other in others:
        if candidate.hostname is not None and other.hostname is not None:
            if candidate.hostname == other.hostname:
                component, note = 0.0, f"same_hostname_as:{other.peer_id}"
            else:
                component, note = 1.0, None
        elif candidate.gpus is not None and other.gpus is not None and candidate.is_soc is not None and other.is_soc is not None:
            same_gpus = candidate.gpus == other.gpus
            same_soc = candidate.is_soc == other.is_soc
            if same_gpus and same_soc:
                component, note = 0.3, f"same_hardware_class_as:{other.peer_id}"
            elif same_gpus or same_soc:
                component, note = 0.6, f"similar_hardware_class_as:{other.peer_id}"
            else:
                component, note = 1.0, None
        else:
            component, note = 0.5, "fleet_signal_unknown"
        if component < worst:
            worst, worst_note = component, note
    return worst, worst_note


def _tenure_components(candidates: Sequence[PeerInfo]) -> dict[str, tuple[float, str | None]]:
    known = [c.first_joined_mesh_ts for c in candidates if c.first_joined_mesh_ts is not None]
    if len(known) < 2 or max(known) == min(known):
        return {c.peer_id: (0.5, "tenure_unknown" if c.first_joined_mesh_ts is None else "tenure_indistinguishable") for c in candidates}
    ts_min, ts_max = min(known), max(known)
    span = ts_max - ts_min
    out: dict[str, tuple[float, str | None]] = {}
    for c in candidates:
        if c.first_joined_mesh_ts is None:
            out[c.peer_id] = (0.5, "tenure_unknown")
        else:
            # Older (smaller timestamp) -> closer to 1.0 -- "small bonus" for
            # tenure, pool-relative so no wall-clock "now" is ever read here.
            out[c.peer_id] = ((ts_max - c.first_joined_mesh_ts) / span, None)
    return out


def _breakdown_for(candidate: PeerInfo, others: Sequence[PeerInfo], policy: SelectionPolicy, tenure: tuple[float, str | None]) -> IndependenceBreakdown:
    network, network_note = _network_distance_component(candidate, policy)
    owner, owner_note = _owner_diversity_component(candidate, others)
    fleet, fleet_note = _fleet_diversity_component(candidate, others)
    tenure_value, tenure_note = tenure

    weights = (
        policy.weight_network_distance,
        policy.weight_owner_diversity,
        policy.weight_fleet_diversity,
        policy.weight_tenure,
    )
    total_weight = sum(weights) or 1.0
    independence = (
        policy.weight_network_distance * network
        + policy.weight_owner_diversity * owner
        + policy.weight_fleet_diversity * fleet
        + policy.weight_tenure * tenure_value
    ) / total_weight

    notes = tuple(n for n in (network_note, owner_note, fleet_note, tenure_note) if n is not None)
    return IndependenceBreakdown(
        peer_id=candidate.peer_id,
        network_distance=network,
        owner_diversity=owner,
        fleet_diversity=fleet,
        tenure=tenure_value,
        independence=independence,
        notes=notes,
    )


def _comparable_candidates(
    peers: Sequence[PeerInfo],
    *,
    target_weights_digest: str,
    exclude_peer_ids: frozenset[str],
) -> list[PeerInfo]:
    return [
        p
        for p in peers
        if p.state == "serving" and p.weights_digest == target_weights_digest and p.peer_id not in exclude_peer_ids
    ]


def _pick(
    candidates: list[PeerInfo],
    others: Sequence[PeerInfo],
    policy: SelectionPolicy,
    *,
    rng: random.Random,
    history_check: HistoryCheck | None,
) -> tuple[str | None, str | None, tuple[str, ...], dict[str, IndependenceBreakdown]]:
    """Shared Step 2/3/4 pick, given an already-comparability-filtered pool.

    Returns (chosen_peer_id, reason, tie_band_peer_ids, breakdown-by-id).
    `breakdown` always covers every candidate PASSED IN (even ones later
    dropped by the history check), so a verifier can see the full pool this
    pick was drawn from.
    """
    tenure_by_id = _tenure_components(candidates)
    breakdown = {c.peer_id: _breakdown_for(c, others, policy, tenure_by_id[c.peer_id]) for c in candidates}

    if not candidates:
        return None, REASON_NO_COMPARABLE_TWIN, (), breakdown

    remaining = list(candidates)
    while remaining:
        top = max(breakdown[c.peer_id].independence for c in remaining)
        band = [c for c in remaining if breakdown[c.peer_id].independence >= top - policy.tie_band_width]
        pick = rng.choice(band)

        if history_check is None:
            return pick.peer_id, None, tuple(c.peer_id for c in band), breakdown

        check = history_check(pick)
        if check.ok:
            return pick.peer_id, None, tuple(c.peer_id for c in band), breakdown

        remaining = [c for c in remaining if c.peer_id != pick.peer_id]

    return None, REASON_NO_CANDIDATE_PASSED_HISTORY_CHECK, (), breakdown


def _owner_independent_candidates(
    candidates: list[PeerInfo],
    twin_a: PeerInfo,
    twin_b: PeerInfo,
) -> list[PeerInfo]:
    """Hard owner-exclusion for `select_referee`: a candidate whose
    `owner_id` is known and equals either twin's KNOWN `owner_id` is
    excluded outright -- never merely penalized. An unknown owner_id on
    either side is never treated as a match (that would be fabricating
    independence from absence); it stays in the pool here and is still
    scored by the existing soft `owner_diversity` component in `_pick`.
    """
    excluded_owner_ids = {
        owner_id for owner_id in (twin_a.owner_id, twin_b.owner_id) if owner_id is not None
    }
    if not excluded_owner_ids:
        return list(candidates)
    return [c for c in candidates if c.owner_id is None or c.owner_id not in excluded_owner_ids]


def select_twin(
    target_weights_digest: str,
    requester_id: str,
    peers: Sequence[PeerInfo],
    policy: SelectionPolicy = DEFAULT_POLICY,
    *,
    requester_info: PeerInfo | None = None,
    rng: random.Random | None = None,
    history_check: HistoryCheck | None = None,
) -> SelectionResult:
    """Pick a same-model twin, biased toward independence from the requester.

    `requester_info` is optional self-description (hostname/gpus/is_soc/
    owner_id -- attributes the requester knows about ITSELF, not something
    read off `peers[]`) used for the owner/fleet diversity components.
    Omitted, those two components degrade to their honest "unknown" value
    for every candidate -- never fabricated, never silently treated as
    independent.

    Never raises. `rng` defaults to a fresh `random.Random()` -- pass a
    seeded one for deterministic tests.
    """
    others = [requester_info] if requester_info is not None else []
    candidates = _comparable_candidates(
        peers,
        target_weights_digest=target_weights_digest,
        exclude_peer_ids=frozenset({requester_id}),
    )
    chosen, reason, tie_band, breakdown = _pick(
        candidates, others, policy, rng=rng or random.Random(), history_check=history_check
    )
    return SelectionResult(
        chosen_peer_id=chosen,
        reason=reason,
        target_weights_digest=target_weights_digest,
        breakdown=breakdown,
        tie_band_peer_ids=tie_band,
        policy=policy,
    )


def select_referee(
    twin_a: PeerInfo,
    twin_b: PeerInfo,
    peers: Sequence[PeerInfo],
    policy: SelectionPolicy = DEFAULT_POLICY,
    *,
    rng: random.Random | None = None,
    history_check: HistoryCheck | None = None,
) -> SelectionResult:
    """Pick a referee independent of BOTH twins, same-model as both.

    Wired to the live E17c third-node call (`live_referee.py`) as of
    [mesh-referee-live-e17c]. `twin_a`/`twin_b` must already share one
    `weights_digest` (the same comparability gate `twin_adjudicator
    .adjudicate()` runs); if they disagree, neither is trusted as the target
    and the candidate pool is empty (`REASON_NO_COMPARABLE_TWIN`).

    Owner independence is a HARD gate here (unlike `select_twin`): a
    candidate whose `owner_id` is known to equal either twin's is excluded
    from the pool outright, not merely scored down. If that leaves zero
    candidates -- every same-model peer shares an owner with a twin -- this
    falls back to the full comparable pool ("distinct node key" instead of
    distinct owner) and sets `owner_diversity_limited=True` so the
    narrowing is recorded, never silent.
    """
    target_weights_digest = twin_a.weights_digest
    if target_weights_digest is None or target_weights_digest != twin_b.weights_digest:
        return SelectionResult(
            chosen_peer_id=None,
            reason=REASON_NO_COMPARABLE_TWIN,
            target_weights_digest=None,
            breakdown={},
            tie_band_peer_ids=(),
            policy=policy,
        )

    candidates = _comparable_candidates(
        peers,
        target_weights_digest=target_weights_digest,
        exclude_peer_ids=frozenset({twin_a.peer_id, twin_b.peer_id}),
    )
    independent_candidates = _owner_independent_candidates(candidates, twin_a, twin_b)
    owner_diversity_limited = bool(candidates) and not independent_candidates
    pick_pool = candidates if owner_diversity_limited else independent_candidates

    chosen, reason, tie_band, breakdown = _pick(
        pick_pool, [twin_a, twin_b], policy, rng=rng or random.Random(), history_check=history_check
    )
    return SelectionResult(
        chosen_peer_id=chosen,
        reason=reason,
        target_weights_digest=target_weights_digest,
        breakdown=breakdown,
        tie_band_peer_ids=tie_band,
        policy=policy,
        owner_diversity_limited=owner_diversity_limited,
    )


def selection_rationale_block(result: SelectionResult) -> dict[str, Any]:
    """The selection's rationale as a JSON-safe block, ready to be recorded
    alongside the resulting twin capsule (design note item 3: "selection is
    itself evidence a verifier can inspect").

    This never mutates or re-seals the twin's own already-sealed capsule --
    same discipline as `mesh-b2-cite-and-ack-wire`'s provider-ack item: a
    caller attaches this block to ITS OWN record (e.g. the requester's
    `compute_attestation`), never to the twin's.
    """
    return {
        "schema": TWIN_SELECTION_SCHEMA,
        "chosen_peer_id": result.chosen_peer_id,
        "reason": result.reason,
        "target_weights_digest": result.target_weights_digest,
        "owner_diversity_limited": result.owner_diversity_limited,
        "owner_diversity_limited_note": NOTE_OWNER_DIVERSITY_LIMITED if result.owner_diversity_limited else None,
        "tie_band_peer_ids": list(result.tie_band_peer_ids),
        "policy": {
            "weight_network_distance": float_to_str(result.policy.weight_network_distance, field="policy.weight_network_distance"),
            "weight_owner_diversity": float_to_str(result.policy.weight_owner_diversity, field="policy.weight_owner_diversity"),
            "weight_fleet_diversity": float_to_str(result.policy.weight_fleet_diversity, field="policy.weight_fleet_diversity"),
            "weight_tenure": float_to_str(result.policy.weight_tenure, field="policy.weight_tenure"),
            "tie_band_width": float_to_str(result.policy.tie_band_width, field="policy.tie_band_width"),
            "rtt_saturation_ms": float_to_str(result.policy.rtt_saturation_ms, field="policy.rtt_saturation_ms"),
        },
        "candidates": [result.breakdown[peer_id].to_value() for peer_id in sorted(result.breakdown)],
        "independence_caveat": INDEPENDENCE_CAVEAT,
    }

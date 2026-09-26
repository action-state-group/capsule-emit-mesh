#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The "one correlator, no second join
key" CI gate -- the structural mirror of the CLOSED gate's "no second
predicate" rule (one code path, no second key).

WHY THIS GATE EXISTS
--------------------
The two halves of one mesh exchange share ``effect.request_digest`` /
``effect.response_digest`` but each carries its OWN host-minted
``serving_provenance.exchange_id`` -- so ANY code that groups/correlates the
two halves by ``exchange_id`` silently never correlates a real cross-node
(pushed) sibling. Three separate sites were found doing exactly that; two were
patched piecemeal and a third (``peer_accountability_tab.pair_cell`` ->
``records_for_exchange`` -> ``exchange_id_for``) was missed. Piecemeal patching
does not hold -- the next new grouping site would reintroduce the bug.

THE ONE CORRELATOR
------------------
``capsule_exchange_tab.exchange_correlator`` is the SINGLE function that maps a
record to its exchange grouping key (order: ``exchange_id`` ->
``request_digest`` -> ``twin_bracket_id``, identical to
``served_request_join``'s pairwise-mint CORRELATION FALLBACK). Every grouping
site routes through it.

WHAT THIS GATE FORBIDS
----------------------
Deriving an exchange GROUPING key from ``exchange_id`` anywhere other than
inside ``exchange_correlator``. Concretely, in any first-party ``.py`` source
file (tests and vendored packages excluded), these idioms are banned OUTSIDE
the body of ``exchange_correlator``:

  * calling ``exchange_id_for(...)`` -- the raw-field reader is allowed ONLY
    for the explicitly-allowlisted field-read sites below (a single-record id
    lookup / header render / role identity), never to build a grouping key;
  * reading ``.get("exchange_id")`` to build a grouping key.

``exchange_id_for`` (the raw-field reader) and ``exchange_correlator`` (the
grouping key) both legitimately touch ``exchange_id`` -- their definitions are
allowlisted by function name, not by forbidding the substring.

This gate runs in the normal test suite (``pytest``), no extra harness.
"""
from __future__ import annotations

import ast
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The ONE correlator + the raw-field reader -- the only two functions allowed
#: to derive anything from ``exchange_id``. Any grouping key MUST come from the
#: first; the second only reads the bare field (never groups by it).
_CORRELATOR_MODULE = "capsule_exchange_tab.py"
_ALLOWED_EXCHANGE_ID_FUNCTIONS = frozenset({"exchange_correlator", "exchange_id_for", "exchange_key_for"})

#: Legitimate NON-grouping reads of ``exchange_id`` outside the correlator.
#: Each entry is (relative_path, enclosing_function): a field read / a
#: DIFFERENT-domain correlator, never the accountability-pane half-grouping
#: this gate governs. Adding a line here is the deliberate, reviewable act of
#: asserting "this exchange_id use does not group exchange HALVES the pane
#: way" -- keep it tiny, and give each a reason inline.
_FIELD_READ_ALLOWLIST = {
    # The serving-provenance NORMALIZER -- the one place the raw exchange_id
    # field is surfaced for every downstream reader/display. Not a grouping.
    ("capsule_mesh_viewer.py", "serving_provenance"),
    # build_exchange_view reads the raw exchange_id ONLY to render the card
    # header ("exchange_id: ..."); the SAME function groups via
    # exchange_correlator() on the adjacent line. Header display, not grouping.
    ("capsule_exchange_tab.py", "build_exchange_view"),
    # ledger_finder: single-record id-query match ("does THIS record carry the
    # exchange_id the user typed"), not a grouping of halves.
    ("ledger_finder.py", "_record_matches"),
    ("ledger_finder.py", "exchange_id_for"),
    # served_request_join is the PAIRWISE-MINT authority whose CORRELATION
    # FALLBACK order (exchange_id -> request_digest -> twin_bracket_id)
    # exchange_correlator mirrors. It reads exchange_id to CHOOSE the join key
    # for exactly two named capsules (provider/requester) -- it does not group
    # an arbitrary record set by exchange_id, and it already refuses to join
    # on an agreeing exchange_id when request_digest disagrees. The single
    # Python pairwise-correlation point, by design.
    ("served_request_join.py", "join_served_request"),
    # DIFFERENT DOMAIN -- the x-mesh-lifecycle-v1 / coordinator single-node hop
    # trace. Its exchange_id lives in the lifecycle block (not
    # serving_provenance) and correlates a node's OWN hops/commitment, never
    # two cross-node halves. Out of scope for the half-grouping gate.
    ("mesh_coordinator_bundle_flow.py", "_inner_record_identity"),
    ("mesh_record_verifier.py", "verify_record_bytes"),
    ("requester_commitment.py", "verify_requester_commitment"),
}

#: Directories whose Python is not first-party (vendored libs, build output).
_EXCLUDED_DIR_PARTS = frozenset(
    {"tests", "node_modules", ".git", "__pycache__", "target", "build", "dist", "site-packages",
     "plugins", "examples", "canonicalization", "conformance", "replay", "fixtures"}
)


def _first_party_sources() -> list[pathlib.Path]:
    """Every first-party ``.py`` at the repo root (the sidecar's own Python
    modules). Vendored packages / build dirs / tests excluded -- this gate
    governs the code WE write here, not libraries we depend on."""
    out: list[pathlib.Path] = []
    for path in sorted(REPO_ROOT.glob("*.py")):
        if path.name.startswith("test_"):
            continue
        out.append(path)
    return out


class _ExchangeIdGroupingVisitor(ast.NodeVisitor):
    """Flags ``exchange_id``-as-grouping-key idioms, tracking the enclosing
    function so ``exchange_correlator``/``exchange_id_for`` (allowlisted by
    name) are exempt."""

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.func_stack: list[str] = []
        self.violations: list[tuple[int, str]] = []

    def _enclosing(self) -> str | None:
        return self.func_stack[-1] if self.func_stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.func_stack.append(node.name)
        self.generic_visit(node)
        self.func_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def _allowed_here(self) -> bool:
        enclosing = self._enclosing()
        if enclosing in _ALLOWED_EXCHANGE_ID_FUNCTIONS:
            return True
        return (self.rel_path, enclosing) in _FIELD_READ_ALLOWLIST

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func
        # exchange_id_for(...) -- bare name or attribute (module.exchange_id_for)
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name == "exchange_id_for" and not self._allowed_here():
            self.violations.append(
                (node.lineno, "calls exchange_id_for() outside exchange_correlator -- use exchange_correlator() as the grouping key")
            )
        # X.get("exchange_id") -- reading the raw field to build a key
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "exchange_id"
            and not self._allowed_here()
        ):
            self.violations.append(
                (node.lineno, 'reads .get("exchange_id") outside exchange_correlator -- route grouping through exchange_correlator()')
            )
        self.generic_visit(node)


def _scan(path: pathlib.Path) -> list[tuple[int, str]]:
    rel = path.name  # first-party sources are flat at repo root
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    visitor = _ExchangeIdGroupingVisitor(rel)
    visitor.visit(tree)
    return visitor.violations


def test_exchange_correlator_is_the_single_grouping_key():
    """No first-party module derives an exchange GROUPING key from
    ``exchange_id`` outside ``exchange_correlator`` (with the tiny field-read
    allowlist). Mirrors the CLOSED gate's "no second predicate" rule."""
    offenders: list[str] = []
    for path in _first_party_sources():
        for lineno, why in _scan(path):
            offenders.append(f"{path.name}:{lineno}: {why}")
    assert not offenders, (
        "exchange_id used as a grouping/correlation key outside exchange_correlator "
        "(the ONE correlator -- see capsule_exchange_tab.exchange_correlator):\n  "
        + "\n  ".join(offenders)
    )


def test_correlator_module_and_symbol_exist():
    """The correlator this gate is named after must actually exist and be the
    real single grouping function -- so a rename can't silently defang the
    gate (a renamed correlator would leave every call site flagged)."""
    import capsule_exchange_tab

    assert hasattr(capsule_exchange_tab, "exchange_correlator")
    assert (REPO_ROOT / _CORRELATOR_MODULE).exists()


def test_gate_would_fire_on_a_reintroduced_grouping_by_exchange_id():
    """MUTANT: a synthetic module that groups halves by exchange_id must be
    caught by the same visitor the gate uses -- proving the gate has teeth,
    not that it merely passes because the tree happens to be clean today."""
    bad_source = (
        "def group_two_halves(records):\n"
        "    keys = {r.get('exchange_id') for r in records}\n"
        "    return keys\n"
    )
    tree = ast.parse(bad_source)
    visitor = _ExchangeIdGroupingVisitor("synthetic_offender.py")
    visitor.visit(tree)
    assert visitor.violations, "gate visitor failed to flag a .get('exchange_id') grouping key"

    bad_source_2 = (
        "def group_two_halves(records):\n"
        "    return sorted({exchange_id_for(r) for r in records})\n"
    )
    tree_2 = ast.parse(bad_source_2)
    visitor_2 = _ExchangeIdGroupingVisitor("synthetic_offender.py")
    visitor_2.visit(tree_2)
    assert visitor_2.violations, "gate visitor failed to flag an exchange_id_for() grouping key"


def test_gate_does_not_flag_the_correlator_itself():
    """The correlator's OWN body reads exchange_id -- that is the one place it
    is allowed. The gate must not flag it (else it could never pass)."""
    correlator_src = (REPO_ROOT / _CORRELATOR_MODULE).read_text(encoding="utf-8")
    tree = ast.parse(correlator_src)
    visitor = _ExchangeIdGroupingVisitor(_CORRELATOR_MODULE)
    visitor.visit(tree)
    assert not visitor.violations, (
        "the correlator module itself tripped the gate -- exchange_correlator/"
        f"exchange_id_for must be allowlisted by name: {visitor.violations}"
    )

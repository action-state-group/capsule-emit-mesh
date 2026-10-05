"""No module writes an unregistered ``chain.relation``.

The AAC registry (REGISTRY section 6) registers five chain relations: ``follows``,
``confirms``, ``supersedes``, ``epoch_opens`` and ``duplicates``. It lists ``adjudicates``
and ``assesses`` as legacy aliases of ``confirms`` and ``resolves``/``escalates`` of
``supersedes``: older records carrying them are still read, but nothing writes them.
capsule-emit carries the same list as ``capsule_emit.relations.REGISTERED_RELATIONS``;
import it here once a released capsule-emit has it.

The static check reads every ``chain_relation=`` argument in this repository's modules and
resolves it (a literal, a module constant, a constant imported from another module here,
or either branch of a conditional), so a new writer of an unregistered relation fails here.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from twin_adjudicator import (
    EPISTEMIC_TYPE_ADJUDICATION,
    LEGACY_RELATION_ADJUDICATES,
    RELATION_ADJUDICATES,
    is_adjudication,
)

REGISTERED = {"follows", "confirms", "supersedes", "epoch_opens", "duplicates"}
ROOT = Path(__file__).resolve().parent.parent


def _modules() -> list[Path]:
    return sorted(p for p in ROOT.glob("*.py") if p.name != "conftest.py")


def _module_constants(tree: ast.Module) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = node.value.value
    return out


def _constants_by_module() -> dict[str, dict[str, str]]:
    return {p.stem: _module_constants(ast.parse(p.read_text())) for p in _modules()}


def _resolve(node: ast.expr, local: dict[str, str], imported: dict[str, str]) -> list[str | None]:
    if isinstance(node, ast.Constant):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return _resolve(node.body, local, imported) + _resolve(node.orelse, local, imported)
    if isinstance(node, ast.Name):
        if node.id in local:
            return [local[node.id]]
        if node.id in imported:
            return [imported[node.id]]
    raise AssertionError(f"cannot resolve chain_relation={ast.unparse(node)}")


def _written_relations() -> list[tuple[str, int, str | None]]:
    constants = _constants_by_module()
    found: list[tuple[str, int, str | None]] = []
    for path in _modules():
        tree = ast.parse(path.read_text())
        imported: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module in constants:
                for alias in node.names:
                    if alias.name in constants[node.module]:
                        imported[alias.asname or alias.name] = constants[node.module][alias.name]
        local = constants[path.stem]
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "chain_relation":
                for value in _resolve(node.value, local, imported):
                    found.append((path.name, node.value.lineno, value))
    return found


def test_every_written_chain_relation_is_registered():
    written = _written_relations()
    assert written, "the scan found no chain_relation= argument at all"
    unregistered = [(f, line, v) for f, line, v in written if v is not None and v not in REGISTERED]
    assert unregistered == []


def test_adjudications_write_confirms():
    assert RELATION_ADJUDICATES == "confirms"


def _record(relation: str | None, *, adjudication: bool) -> dict:
    ca = {"epistemic_type": EPISTEMIC_TYPE_ADJUDICATION, "adjudication": {"verdict": "corroborated"}} if adjudication else {}
    return {"chain": {"relation": relation} if relation else {}, "model_attestation": {"compute_attestation": ca}}


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (_record("confirms", adjudication=True), True),  # written now
        (_record(LEGACY_RELATION_ADJUDICATES, adjudication=True), True),  # an older record
        (_record(LEGACY_RELATION_ADJUDICATES, adjudication=False), True),  # older, by relation alone
        (_record("confirms", adjudication=False), False),  # a plain confirms record
        (_record(None, adjudication=False), False),
        ("not a record", False),
    ],
)
def test_is_adjudication_reads_new_and_legacy_records(record, expected):
    assert is_adjudication(record) is expected

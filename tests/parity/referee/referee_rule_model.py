# SPDX-License-Identifier: Apache-2.0
"""The corpus's own check of the rule-stated answers.

Three paths have no Python reference that follows the rules: choosing a
referee (``select``), when a referee is asked (``request``), and the counts
with the opt-in stop-routing rule (``counts``). Their expected answers are
written by hand next to each case in ``build_referee_corpus.py``. This module
works the same answers out from the case input, so every hand-written answer
is stated twice and the two must agree (``test_referee_parity.py``).

It is a checker for this corpus, not a reference implementation: the rules
are the ones in ``README.md``, and where this file and the README differ the
README is right.

Each function takes an optional ``mutant``: a named, deliberate fault
(``mutants.json``). The harness uses them to show which cases catch an
implementation that has that fault.
"""
from __future__ import annotations

from datetime import datetime, timedelta

DEFAULT_BAR_DAYS = 30
DEFAULT_WINDOW_DAYS = 30
BUCKETS = ("corroborated", "contradicted", "inconclusive", "not_comparable")
CONTRADICTED_PREFIX = "contradicted:"

MUTANT_SKIPS_BAR_WINDOW = "select-skips-bar-window"
MUTANT_MIXES_TIERS = "select-mixes-tiers"
MUTANT_ASKS_TWICE = "request-asks-twice-per-pair"
MUTANT_SKIPS_ASKED_GATE = "counts-skip-asked-gate"


def _time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# --- select: who is eligible, which tier, which node --------------------------


def select(case: dict, mutant: str | None = None) -> list[dict]:
    now = _time(case["now"])
    days = case["referee_bar_days"] if case["referee_bar_days"] is not None else DEFAULT_BAR_DAYS
    since = now - timedelta(days=days)
    model = case["model_hash"]
    about = [v for v in case["verdicts"] if v["model_hash"] == model]

    def barred(node: str) -> bool:
        if mutant == MUTANT_SKIPS_BAR_WINDOW:
            return False
        return any(
            v["node_id"] == node and v["bucket"] == "contradicted" and since <= _time(v["recorded_at"]) <= now
            for v in about
        )

    eligible = [
        p["node_id"]
        for p in case["peers"]
        if p["model_hash"] == model
        and p["weights_digest"] == case["weights_digest"]
        and p["node_id"] not in case["twins"]
        and p["announced_key"]
        and not p["blocked"]
        and not barred(p["node_id"])
    ]
    tier1 = sorted(n for n in eligible if any(v["node_id"] == n and v["bucket"] == "corroborated" for v in about))
    tier2 = sorted(n for n in eligible if n not in tier1)
    if mutant == MUTANT_MIXES_TIERS:
        tier, pool = (1 if tier1 else 2), sorted(tier1 + tier2)
    elif tier1:
        tier, pool = 1, tier1
    else:
        tier, pool = 2, tier2
    if not pool:
        return [{"tier": None, "pool": [], "asked": [], "not_adjudicated": "no_eligible_referee"}]
    return [{"tier": tier, "pool": pool, "asked": [pool[d] for d in case["draws"]], "not_adjudicated": None}]


# --- request: when a referee is asked, and at most once -----------------------


def _first_difference(a: list[str], b: list[str]) -> int | None:
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return None if len(a) == len(b) else min(len(a), len(b))


def _verdict(halves: list[dict], reanswer: str) -> str:
    """The ruling a re-answer gives: it must repeat the twins' agreed words,
    and its next word names the twin it agrees with."""
    a, b = (h["text"].split() for h in halves)
    at = _first_difference(a, b)
    words = reanswer.split()
    word = words[at] if words[:at] == a[:at] and at < len(words) else None
    matches_a = word is not None and at < len(a) and word == a[at]
    matches_b = word is not None and at < len(b) and word == b[at]
    if matches_a and not matches_b:
        return CONTRADICTED_PREFIX + halves[1]["node_id"]
    if matches_b and not matches_a:
        return CONTRADICTED_PREFIX + halves[0]["node_id"]
    return "inconclusive"


def _not_adjudicated(reason: str, because: str | None = None) -> dict:
    row = {"state": "not_adjudicated", "reason": reason}
    if because:
        row["because"] = because
    return row


def _decide(setting, attempt: dict) -> tuple[int, dict]:
    """``(referee calls made, the pair's row)`` for a pair not asked before."""
    pair = attempt["pair"]
    halves = pair["halves"]
    if setting is False:
        return 0, _not_adjudicated("off")
    if not pair["twin_bracket_id"]:
        return 0, _not_adjudicated("host_does_not_mark_twins")
    if any(h["temperature"] > 0 for h in halves):
        return 0, _not_adjudicated("not_comparable", "sampled")
    digests = [h["weights_digest"] for h in halves]
    if not all(digests):
        return 0, _not_adjudicated("not_comparable", "weights_unknown")
    if digests[0] != digests[1]:
        return 0, _not_adjudicated("not_comparable", "weights_differ")
    if _first_difference(halves[0]["text"].split(), halves[1]["text"].split()) is None:
        return 0, _not_adjudicated("twins_agree")
    selection = attempt["selection"]
    if selection.get("not_adjudicated"):
        return 0, _not_adjudicated(selection["not_adjudicated"])
    referee = attempt["referee"]
    if referee["reanswer"] is None:
        return 1, _not_adjudicated("referee_unreachable")
    if not referee["signs"]:
        return 1, _not_adjudicated("referee_cannot_sign")
    return 1, {
        "state": "adjudicated",
        "verdict": _verdict(halves, referee["reanswer"]),
        "referee": selection["asked"],
        "tier": selection["tier"],
    }


def _counts_against(row: dict) -> str | None:
    verdict = row.get("verdict", "")
    return verdict[len(CONTRADICTED_PREFIX):] if verdict.startswith(CONTRADICTED_PREFIX) else None


def request(case: dict, mutant: str | None = None) -> list[dict]:
    asked: dict[tuple, dict] = {}
    answers = []
    for attempt in case["attempts"]:
        pair = attempt["pair"]
        key = (pair["twin_bracket_id"], pair["request_digest"], tuple(sorted(h["node_id"] for h in pair["halves"])))
        if key in asked and mutant != MUTANT_ASKS_TWICE:
            calls, row = 0, asked[key]
        else:
            calls, row = _decide(case["adjudicate_differing_twins"], attempt)
            if calls:
                asked[key] = row
        answers.append({"referee_calls": calls, "row": row, "counts_against": _counts_against(row)})
    return answers


# --- counts: the counts, and the opt-in stop-routing rule --------------------


def _text(block: dict, key: str) -> str | None:
    value = block.get(key)
    return value if isinstance(value, str) and value else None


def _pair(block: dict, key: str) -> list[str] | None:
    value = block.get(key)
    if isinstance(value, list) and len(value) == 2 and all(isinstance(v, str) for v in value):
        return value
    return None


def _ruling_about(verdict: str, nodes: list[str], node: str) -> str | None:
    if verdict.startswith(CONTRADICTED_PREFIX):
        named = verdict[len(CONTRADICTED_PREFIX):]
        if named == node:
            return "contradicted"
        return "corroborated" if named in nodes else None
    return verdict if verdict in ("corroborated", "inconclusive", "not_comparable") else None


def _fold(records: list[dict], requested: list[dict], mutant: str | None) -> dict[str, list[dict]]:
    """Every counted verdict, per judged node, in chain order."""
    asked = {(line["referee"], tuple(sorted(line["halves"]))) for line in requested}
    seen: set[tuple] = set()
    by_peer: dict[str, list[dict]] = {}
    for record in records:
        attestation = (record.get("model_attestation") or {}).get("compute_attestation") or {}
        if "adjudication_received" in attestation:
            block, at_key, issued = attestation["adjudication_received"], "received_at", False
        elif "adjudication_issued" in attestation:
            block, at_key, issued = attestation["adjudication_issued"], "issued_at", True
        else:
            continue
        verdict, verdict_id, referee = (_text(block, k) for k in ("verdict", "verdict_capsule_id", "referee_node_id"))
        nodes, halves = _pair(block, "half_node_ids"), _pair(block, "halves")
        if not (verdict and verdict_id and referee and nodes and halves):
            continue
        if nodes[0] == nodes[1] or halves[0] == halves[1] or referee in nodes:
            continue
        key = (referee, tuple(sorted(halves)))
        if not issued and key not in asked and mutant != MUTANT_SKIPS_ASKED_GATE:
            continue
        if key in seen:
            continue
        seen.add(key)
        for node in nodes:
            bucket = _ruling_about(verdict, nodes, node)
            if bucket is not None:
                by_peer.setdefault(node, []).append(
                    {
                        "verdict_capsule_id": verdict_id,
                        "referee_node_id": referee,
                        "bucket": bucket,
                        "model_hash": block.get("model_hash"),
                        "recorded_at": _text(block, at_key),
                    }
                )
    return by_peer


def _counts(by_peer: dict[str, list[dict]]) -> dict:
    out: dict = {}
    for peer, verdicts in by_peer.items():
        for model in sorted({v["model_hash"] for v in verdicts}):
            out.setdefault(peer, {})[model] = {
                bucket: {
                    "count": sum(1 for v in verdicts if v["model_hash"] == model and v["bucket"] == bucket),
                    "verdict_capsule_ids": [
                        v["verdict_capsule_id"] for v in verdicts if v["model_hash"] == model and v["bucket"] == bucket
                    ],
                }
                for bucket in BUCKETS
            }
    return out


def _positive(raw: str) -> int | None:
    raw = raw.strip()
    return int(raw) if raw.isascii() and raw.isdigit() and int(raw) > 0 else None


def _rule(settings: dict) -> dict | None:
    after, window = settings["stop_routing_after_contradictions"], settings["stop_routing_window_days"]
    if after is None or _positive(after) is None:
        return None
    if window is None:
        return {"after": _positive(after), "window_days": DEFAULT_WINDOW_DAYS}
    if _positive(window) is None:
        return None
    return {"after": _positive(after), "window_days": _positive(window)}


def _due(rule: dict, by_peer: dict[str, list[dict]], cited: set[str], now: datetime) -> list[tuple[str, list[str]]]:
    since = now - timedelta(days=rule["window_days"])
    cap = max(rule["after"] - 1, 1)
    firings = []
    for peer in sorted(by_peer):
        per_referee: dict[str, int] = {}
        ids = []
        for v in by_peer[peer]:
            if v["bucket"] != "contradicted" or v["verdict_capsule_id"] in cited:
                continue
            if v["recorded_at"] is None or not since <= _time(v["recorded_at"]) <= now:
                continue
            per_referee[v["referee_node_id"]] = per_referee.get(v["referee_node_id"], 0) + 1
            if per_referee[v["referee_node_id"]] <= cap:
                ids.append(v["verdict_capsule_id"])
        if len(ids) >= rule["after"]:
            firings.append((peer, ids))
    return firings


def counts_and_rule(case: dict, mutant: str | None = None) -> list[dict]:
    records: list[dict] = []
    requested: list[dict] = []
    cited: set[str] = set(case["cited"])
    blocked: set[str] = set(case["host"]["blocked"])
    rule = _rule(case["settings"])
    answers = []
    for step in case["steps"]:
        records += step["add_records"]
        requested += step["add_requested"]
        blocked -= set(step["unblock"])
        by_peer = _fold(records, requested, mutant)
        outcomes: list[dict] = []
        firings = _due(rule, by_peer, cited, _time(step["now"])) if rule else []
        if firings and not case["host"]["peer_blocks"]:
            outcomes.append({"outcome": "no_host_hook"})
        else:
            for peer, ids in firings:
                if peer in blocked:
                    outcomes.append({"outcome": "already_blocked", "peer_id": peer})
                else:
                    blocked.add(peer)
                    outcomes.append({"outcome": "blocked", "peer_id": peer, "verdict_capsule_ids": ids})
                cited |= set(ids)
        answers.append({"counts": _counts(by_peer), "rule": rule, "outcomes": outcomes, "cited": sorted(cited)})
    return answers


MODELS = {"select": select, "request": request, "counts": counts_and_rule}

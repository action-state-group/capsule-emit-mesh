#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""C2a replay spot-check harness — temperature-0, fixed-seed re-run comparison.

Implements ONLY the mechanism `docs/TRUST-MODEL.md` §3 Class C calls C2a:

    "A receipt already commits the request digest, generation parameters,
    execution-bundle identity and runtime. Anyone holding the weights ...
    has everything needed to re-run the request and compare. At temperature
    0 with a pinned seed that comparison is *exact* rather than statistical."

Comparison domain (read from the declaration, not assumed): the sidecar's
own committed comparison bytes are `response_digest` — `digest_json()` (jcs-n
over the float-stringified raw upstream response), the exact function
`capsule_sidecar.py` uses to build a capsule. This harness imports that
function rather than reimplementing it, so there is one definition of
"match," not two that can drift apart.

`response_digest` itself is run-unique on the supported port — see
`capsule_sidecar.forwarded_copy_record`'s docstring: backend-minted `id`/
`created` carry a wall clock and differ across runs even for byte-identical
model output. Two genuine replay firings would therefore mismatch on content
they agree on. `REPLAY_VOLATILE_FIELDS`, below, is declared and excluded
before digesting so replay-match scope is self-documenting, never implied —
in-family with the Rust capsule-producer crate's `CHAIN_LINKAGE_FIELDS`
exclusion from `capsule_id` (`jcs.rs`).

WHAT THIS IS NOT (standing constraint — read before extending this file):
  - Not a scorer. `SpotCheckResult` has no confidence, trust, or reputation
    field, and never will — that logic is Authority-tier and explicitly out
    of bounds for this neutral, public-repo lane.
  - Not a verdict. TRUST-MODEL.md is explicit that a mismatch is "grounds to
    investigate, never a verdict" even within one hardware class, because
    sampling non-determinism is a known, expected confound. The advisory
    text returned alongside every result says this; it is a fixed constant,
    not a judgment this tool computes.
  - Not a cross-hardware-class comparator. C2a's precondition is byte-
    identical weights / hardware class (GPU reduction order is not
    deterministic across silicon); this harness does not know or check the
    caller's hardware class and says so.

Two ways to drive it:
  - `compare(response_a, response_b)` / `compare` CLI subcommand — offline,
    given two already-captured response bodies (e.g. two capsule
    `agent_output`s, or two files on disk). This is what the test suite
    exercises directly.
  - `run_replay(upstream_base, request_body)` / `live` CLI subcommand — the
    end-to-end path: pins the request to temperature 0 + a fixed seed,
    fires it twice against an OpenAI-compatible `/v1/chat/completions`
    endpoint, and compares. Requires a real upstream; not exercised by CI
    (no model weights in the test environment) but covered against a local
    stub server in `tests/test_replay_spot_check.py`.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capsule_sidecar import digest_json  # noqa: E402  (path setup above)

# Any fixed integer pins sampling; this one is arbitrary and only needs to
# stay constant across the two calls of a given spot-check, not globally.
DEFAULT_SEED = 20260821

# Backend-minted-fresh top-level response fields, excluded from the replay
# digest. `id`/`created` carry a wall clock and are expected to differ
# between two firings of an otherwise byte-identical request (see
# `capsule_sidecar.forwarded_copy_record`'s docstring on why `response_digest`
# is run-unique) -- including them would make this harness report a false
# mismatch on deterministic output. In-family with the Rust capsule-producer
# crate's `CHAIN_LINKAGE_FIELDS` (`jcs.rs`): a declared exclusion, not an
# implied one.
REPLAY_VOLATILE_FIELDS = frozenset({"id", "created"})

DOMAIN = (
    "response_digest (jcs-n over float-stringified raw upstream response; "
    "capsule_sidecar.digest_json), excluding REPLAY_VOLATILE_FIELDS "
    f"({sorted(REPLAY_VOLATILE_FIELDS)})"
)

# Fixed advisory text — see module docstring "WHAT THIS IS NOT." Never
# computed from the comparison outcome; the same string ships on match and
# on mismatch so nothing about severity is implied by its presence.
ADVISORY = (
    "C2a replay spot-check (docs/TRUST-MODEL.md Class C). A mismatch is grounds to "
    "investigate, never a verdict: model sampling non-determinism and cross-hardware-class "
    "execution are known, expected confounds, not evidence of dishonesty on their own. "
    "This harness draws no conclusion beyond match/mismatch on the declared domain."
)


@dataclass(frozen=True)
class SpotCheckResult:
    domain: str
    digest_a: str
    digest_b: str
    match: bool
    advisory: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _exclude_replay_volatile_fields(response: dict[str, Any]) -> dict[str, Any]:
    """Drop `REPLAY_VOLATILE_FIELDS` from a response's top level before digesting."""
    return {k: v for k, v in response.items() if k not in REPLAY_VOLATILE_FIELDS}


def compare(response_a: dict[str, Any], response_b: dict[str, Any]) -> SpotCheckResult:
    """Compare two response bodies on the declared C2a domain.

    Pure function: does not know whether the two responses came from a live
    re-run, two capsules, or two files on disk. Firing the requests is a
    separate concern (`run_replay`, below).
    """
    digest_a = digest_json(_exclude_replay_volatile_fields(response_a))
    digest_b = digest_json(_exclude_replay_volatile_fields(response_b))
    return SpotCheckResult(
        domain=DOMAIN,
        digest_a=digest_a,
        digest_b=digest_b,
        match=digest_a == digest_b,
        advisory=ADVISORY,
    )


def build_pinned_request(base_request: dict[str, Any], *, seed: int = DEFAULT_SEED) -> dict[str, Any]:
    """Return a copy of `base_request` pinned to C2a's reproducible domain.

    Raises if the caller already set a non-zero temperature: silently
    overriding it would let a request that was never in the reproducible
    domain masquerade as one, which is exactly the kind of unmeasured claim
    TRUST-MODEL.md's "Measured precondition" section warns against.
    """
    temperature = base_request.get("temperature")
    if temperature is not None and temperature != 0:
        raise ValueError(
            f"refusing to pin request with explicit temperature={temperature!r}: "
            "C2a only applies to the temperature-0, fixed-seed domain"
        )
    pinned = copy.deepcopy(base_request)
    pinned["temperature"] = 0
    pinned["seed"] = seed
    return pinned


def fire_request(upstream_base: str, request_body: dict[str, Any], *, timeout: float = 60) -> dict[str, Any]:
    """POST one OpenAI-shaped chat-completions request, return the parsed JSON body.

    Mirrors the plain POST `capsule_sidecar.handle_chat_completion` makes to
    upstream — deliberately does not import that function, since this tool
    never builds or emits a capsule; it only compares two responses.
    """
    data = json.dumps(request_body).encode("utf-8")
    req = urllib.request.Request(
        url=f"{upstream_base}/v1/chat/completions",
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
    return json.loads(body.decode("utf-8"))


def run_replay(upstream_base: str, request_body: dict[str, Any], *, seed: int = DEFAULT_SEED) -> SpotCheckResult:
    """Fire the same pinned request twice against `upstream_base` and compare."""
    pinned = build_pinned_request(request_body, seed=seed)
    response_a = fire_request(upstream_base, pinned)
    response_b = fire_request(upstream_base, pinned)
    return compare(response_a, response_b)


def _cmd_compare(args: argparse.Namespace) -> int:
    response_a = json.loads(Path(args.response_a).read_text())
    response_b = json.loads(Path(args.response_b).read_text())
    result = compare(response_a, response_b)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.match else 1


def _cmd_live(args: argparse.Namespace) -> int:
    request_body = json.loads(Path(args.request).read_text())
    result = run_replay(args.upstream, request_body, seed=args.seed)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.match else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_compare = sub.add_parser("compare", help="Compare two already-captured response JSON files")
    p_compare.add_argument("response_a", help="Path to first response JSON")
    p_compare.add_argument("response_b", help="Path to second response JSON")
    p_compare.set_defaults(func=_cmd_compare)

    p_live = sub.add_parser("live", help="Fire a request twice against a live upstream and compare")
    p_live.add_argument("--upstream", required=True, help="Base URL, e.g. http://127.0.0.1:9337")
    p_live.add_argument("--request", required=True, help="Path to an OpenAI-shaped chat-completions request JSON")
    p_live.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p_live.set_defaults(func=_cmd_live)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""``ask_history.py`` -- the requester side of E15's HTTP evidence door.

Posts an E14 request map to a peer's ``POST /evidence-request``
(``evidence_server.py``), then verifies whatever comes back OFFLINE, from
the response bytes alone -- no further trust in the peer, no second round
trip:

  * an Artifact -> reconstruct each ``capsule_emit.bundle.Bundle`` from its
    own ``.to_dict()`` shape (``Bundle.from_dict``) and run
    ``capsule_emit.bundle.verify_bundle()`` -- the PURE, offline, per-bundle
    verifier this artifact shape actually calls for. This is deliberately
    NOT ``stranger_verify_bundle.py``'s ledger-DIR ``verify_bundle`` (same
    function name, different signature and purpose): that one needs a full
    COPY of a ledger directory on disk, which this route never hands out --
    it returns digests-only ``Bundle`` objects, the bundle tier's own
    standalone-verifiable shape (see ``evidence_server.py``'s module
    docstring for the exact scope split, including the known limit that a
    bundle never carries a Rust-producer capsule's own detached
    ``signed-statements/<capsule_id>.cose``);
  * a Refusal -> ``capsule_emit.evidence_request.verify_refusal_offline`` --
    a signed decline or a signed "recorded absence", either way citable
    offline against the peer's own key, never a bare unsigned 404.

Also renders a small "history card" -- ``continuity``/``history_depth``/
``unforked`` -- folded from the returned bundle's OWN ``checkpoint``/
``prior_checkpoint``/``checkpoint_cose`` fields via ``history_card.
build_history_card`` (reused unchanged, never re-derived): every bundle in
one Artifact answers under the SAME covering checkpoint (``answer()``'s
``expected_pin`` check enforces that whenever a pin was supplied), so the
first bundle alone already carries the (at most two-checkpoint) segment
this response proves.

Usage:
    python3 ask_history.py <peer-base-url> --subject range --selector <sel> \\
        [--expected-pin-root <hex> --expected-pin-mmr-size <int>] \\
        [--capsule-id <cid>] [--node-id <label>] [--tamper-check]

``--subject record --capsule-id <cid>`` asks for one record instead of a
range. ``--tamper-check`` proves the negative end to end: flips one byte of
the FIRST returned bundle's receipt in memory (never touching the peer) and
confirms ``verify_bundle`` now reports not-ok -- raises if it doesn't.

``--via mesh <peer-id>`` -- for a peer with no reachable ``evidence_server.py``
HTTP door (e.g. relay-only mesh peers): the first positional argument becomes
a hex mesh peer id instead of a base URL, and the request rides THIS node's
own admission-policy plugin's plugin-mesh-stream carrier
(``mesh_evidence_bridge``, channel ``evidence-request/1``) instead of a
direct HTTP POST -- reached locally via ``--local-host-api`` (the mesh-llm
host's own API port, default ``http://127.0.0.1:8080``). Verification is
IDENTICAL either way: this module never trusts the carrier, only the
response bytes.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

from capsule_emit.bundle import Bundle, verify_bundle
from capsule_emit.evidence_request import Refusal, verify_refusal_offline

from history_card import build_history_card

__all__ = [
    "main",
    "post_evidence_request",
    "post_mesh_evidence_request",
    "render_artifact",
    "render_refusal",
]


def _build_request_map(
    *,
    subject_kind: str,
    capsule_id: str | None,
    selector: str | None,
    expected_pin_root: str | None,
    expected_pin_mmr_size: int | None,
    nonce: str | None,
) -> dict[str, Any]:
    if subject_kind == "record":
        subject: dict[str, Any] = {"kind": "record", "capsule_id": capsule_id}
    else:
        subject = {"kind": "range", "selector": selector}
    coverage: dict[str, Any] = {}
    if expected_pin_root is not None and expected_pin_mmr_size is not None:
        coverage["expected_pin"] = {"root": expected_pin_root, "mmr_size": expected_pin_mmr_size}
    request: dict[str, Any] = {"subject": subject, "coverage": coverage}
    if nonce is not None:
        request["nonce"] = nonce
    return request


def post_evidence_request(peer_base_url: str, request_map: dict[str, Any]) -> dict[str, Any]:
    """POST ``request_map`` to ``<peer_base_url>/evidence-request``; return
    the parsed JSON response -- the raw Artifact-or-Refusal dict,
    unmodified."""
    body = json.dumps(request_map).encode("utf-8")
    url = peer_base_url.rstrip("/") + "/evidence-request"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def post_mesh_evidence_request(
    local_host_api: str, plugin_name: str, peer_id: str, request_map: dict[str, Any]
) -> dict[str, Any]:
    """The mesh carrier for a peer with no reachable ``evidence_server.py``
    HTTP door (e.g. relay-only): ask THIS node's own admission-policy plugin
    to carry ``request_map`` to ``peer_id`` over the plugin mesh stream
    (``mesh_evidence_bridge::handle_mesh_evidence_request``, channel
    ``evidence-request/1``), via the plugin's ``mesh_evidence_request`` tool,
    reached locally through mesh-llm's own
    ``POST /api/plugins/<name>/tools/<tool>`` tool-call route -- never a new
    host route, never new host code. Returns the peer's own Artifact-or-
    Refusal dict unmodified, same as ``post_evidence_request``; a peer that
    never declared the channel surfaces as a non-2xx ``urllib.error.HTTPError``
    (the plugin's bounded wait timed out), never a hang.
    """
    body = json.dumps({"peer_id": peer_id, "request": request_map}).encode("utf-8")
    url = f"{local_host_api.rstrip('/')}/api/plugins/{plugin_name}/tools/mesh_evidence_request"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def render_refusal(payload: dict[str, Any]) -> str:
    refusal = Refusal(
        request_digest=payload["request_digest"],
        reason=payload["reason"],
        issued_at=payload["issued_at"],
        key_id=payload["key_id"],
        sig=payload["sig"],
    )
    verified = verify_refusal_offline(refusal)
    return "\n".join(
        [
            f"REFUSAL reason={refusal.reason} issued_at={refusal.issued_at} key_id={refusal.key_id}",
            f"signature verifies offline: {verified}",
        ]
    )


def _history_card_lines(bundles: list[Bundle], *, node_id: str) -> list[str]:
    if not bundles:
        return []
    b = bundles[0]
    checkpoint_lines: list[dict[str, Any]] = []
    since_size = 0
    if b.prior_checkpoint is not None:
        checkpoint_lines.append(b.prior_checkpoint.to_dict())
        since_size = b.prior_checkpoint.mmr_size
    current = b.checkpoint.to_dict()
    if b.checkpoint_cose is not None:
        current["checkpoint_cose"] = b.checkpoint_cose.hex()
    checkpoint_lines.append(current)

    card = build_history_card(
        node_id=node_id,
        log_id=b.checkpoint.log_id,
        checkpoint_lines=checkpoint_lines,
        since_size=since_size,
    )
    props = card.properties
    return [
        "history card (folded from this response's own checkpoint fields):",
        f"    continuity={props.continuity!r} history_depth={props.history_depth} unforked={props.unforked}",
        f"    checkpoint_count={card.checkpoint_count} witnessed={card.witnessed}",
    ]


def render_artifact(payload: dict[str, Any], *, node_id: str, tamper_check: bool = False) -> str:
    bundles = [Bundle.from_dict(bd) for bd in payload["bundles"]]
    lines = [f"ARTIFACT subject_kind={payload['subject_kind']} bundles={len(bundles)}"]
    for b in bundles:
        ok, errors = verify_bundle(b)
        lines.append(f"  bundle {b.capsule_id}: log-integrity verify_bundle.ok={ok}")
        lines.extend(f"      {e}" for e in errors)
        lines.append(
            "      NOTE: bundle-tier evidence proves LOG integrity (inclusion, checkpoint "
            "signature/consistency), never a Rust-producer capsule's own detached "
            "signed-statement (signed-statements/<capsule_id>.cose is not carried in this "
            "artifact shape) -- see evidence_server.py's module docstring."
        )

    lines.extend(_history_card_lines(bundles, node_id=node_id))

    if tamper_check and bundles:
        tampered = json.loads(json.dumps(payload["bundles"][0]))
        tampered["receipt"] = {**tampered["receipt"], "capsule_id": "0" * 64}
        tampered_ok, _tampered_errors = verify_bundle(Bundle.from_dict(tampered))
        lines.append(f"tamper-check (flipped receipt.capsule_id in memory): verify.ok={tampered_ok} (expected False)")
        if tampered_ok:
            raise AssertionError("tamper-check FAILED to be detected -- verify_bundle did not flip")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "peer",
        help="peer's evidence_server.py base URL (default) or, with --via mesh, the peer's hex mesh peer id",
    )
    parser.add_argument("--subject", choices=["record", "range"], default="range")
    parser.add_argument("--capsule-id", default=None, help="required for --subject record")
    parser.add_argument("--selector", default=None, help="required for --subject range, e.g. id1..id2")
    parser.add_argument("--expected-pin-root", default=None)
    parser.add_argument("--expected-pin-mmr-size", type=int, default=None)
    parser.add_argument("--nonce", default=None)
    parser.add_argument("--node-id", default="requester", help="label only, for the rendered history card")
    parser.add_argument(
        "--tamper-check", action="store_true", help="prove a corrupted COPY of the response fails verify"
    )
    parser.add_argument(
        "--via",
        choices=["http", "mesh"],
        default="http",
        help="http (default): POST peer directly. mesh: carry the request over THIS node's own "
        "admission-policy plugin's plugin-mesh-stream (for peers with no reachable HTTP door).",
    )
    parser.add_argument(
        "--local-host-api",
        default="http://127.0.0.1:8080",
        help="--via mesh only: this node's own mesh-llm host API base URL",
    )
    parser.add_argument(
        "--local-plugin-name",
        default="admission-policy",
        help="--via mesh only: the plugin name carrying the request (its /tools/mesh_evidence_request route)",
    )
    args = parser.parse_args(argv)

    if args.subject == "record" and not args.capsule_id:
        parser.error("--subject record requires --capsule-id")
    if args.subject == "range" and not args.selector:
        parser.error("--subject range requires --selector")

    request_map = _build_request_map(
        subject_kind=args.subject,
        capsule_id=args.capsule_id,
        selector=args.selector,
        expected_pin_root=args.expected_pin_root,
        expected_pin_mmr_size=args.expected_pin_mmr_size,
        nonce=args.nonce,
    )
    try:
        if args.via == "mesh":
            payload = post_mesh_evidence_request(args.local_host_api, args.local_plugin_name, args.peer, request_map)
        else:
            payload = post_evidence_request(args.peer, request_map)
    except urllib.error.URLError as exc:
        print(f"request to {args.peer} (via {args.via}) failed: {exc}", file=sys.stderr)
        return 1

    if "reason" in payload:
        print(render_refusal(payload))
        return 0
    print(render_artifact(payload, node_id=args.node_id, tamper_check=args.tamper_check))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

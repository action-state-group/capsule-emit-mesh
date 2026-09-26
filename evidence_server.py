#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""E15 -- an HTTP door on the E14 evidence responder.

``evidence_responder.handle_evidence_request`` reaches ``capsule_emit.
evidence_request.answer()`` against one node's ledger + node key (E14,
capsule-emit#148; wired to a real ``NodeState`` in #83) -- but nothing can
REACH it from another node yet. This module is entirely ours: it puts
``POST /evidence-request`` in front of the SAME responder, unchanged, so a
peer can ask for a ``record``/``range`` and get back exactly what
``answer()`` returns -- an ``Artifact`` or a signed ``Refusal`` -- never a
new artifact shape, never beyond the bundle tier (never ``disclose()``).

STANDALONE by design ([mesh-e15-evidence-http-route], Lane B): its own
module importing ``evidence_responder``, never wired into
``capsule_sidecar.py``'s own request handling -- every Batch-1 item touches
that file, so this stays out of the merge-order queue and runs against
whichever ledger + node key a node names on the command line, sidecar
running or not.

State this module needs from a node is exactly what
``evidence_responder.handle_evidence_request`` reads off its ``state``
argument -- ``ledger_path`` and ``signing_key_path`` -- and nothing else
(no manifest, no runtime label, no advertisement). See
``EvidenceServerState``, deliberately lighter than
``capsule_sidecar.NodeState`` for that reason: this server answers evidence
requests, it never seals a capsule.

**The plugin-ledger bridge (Step 0 finding).** The live serving path on a
mesh node is the Rust plugin, which owns ``<data_dir>/ledger/capsules.jsonl``
+ ``signed-statements/`` -- ``capsule_sidecar.py``'s ``NodeState.
plugin_checkpoint`` wiring ([mesh-plugin-cll-consume] A2/A3) then
checkpoints that log READ-ONLY, into a SIBLING ``checkpoints.jsonl``
(``checkpointing.CheckpointState`` never becomes a second writer into a
ledger it does not own). ``capsule_emit.bundle.bundle()`` (what ``answer()``
dispatches to) only ever recognizes a checkpoint that arrives as an IN-BAND
``checkpoint_stamp``-kind leaf inside the SAME file it is bundling from
(``capsule_emit.witness.push()``'s convention, for a self-checkpointed
ledger) -- so pointed straight at the plugin's ``capsules.jsonl``, every
request refuses ``coverage_unsatisfiable``/``no_such_record``, even for a
record long since checkpointed, because ``bundle()`` can never see a
checkpoint that lives in a sibling file.

``_merged_evidence_view`` closes that gap, in-repo, without touching
``capsule-emit`` or the Rust plugin: given a ledger dir carrying a sibling
``checkpoints.jsonl``, it materializes a scratch JSONL file = the ledger's
own lines, unchanged, plus one synthesized ``checkpoint_stamp`` entry per
persisted checkpoint line, in the EXACT shape ``capsule_emit.witness.
_persist_checkpoint_stamp`` writes for a self-checkpointed ledger --
appended in checkpoint order, after the leaves each covers (never
interleaved before them, which would shift every later leaf's ``seq`` and
invalidate inclusion proofs the checkpoint never covered). An append-only
history tree's root at size S is a pure function of its first
``leaf_count(S)`` leaves, independent of anything appended after -- so a
trailing synthesized stamp reproduces the SAME root ``bundle()`` re-derives,
and the checkpoint's own signature/COSE-wire proof (computed once, for
real, by ``checkpointing.CheckpointState`` against the plugin's actual
bytes) verifies unchanged. Regenerated fresh on every request (never
cached, matching ``bundle()``'s own "re-derive from the ledger every call"
discipline) into a fresh ``tempfile`` -- never written back into the
plugin's own directory, preserving the "two single-writer logs" invariant.

**Known, honest scope limit this bridge does NOT close** (documented, not
hidden): ``capsule_emit.bundle.verify_bundle()``'s step-1 check expects a
capsule's OWN self-attested ``signature``/``key_id`` embedded inline --
that is this repo's PYTHON producer's convention (``capsule_emit.seal()``).
The Rust plugin instead signs a DETACHED COSE_Sign1 Signed Statement per
capsule (``signed-statements/<capsule_id>.cose``, verified today by
``stranger_verify_bundle.py``'s ``_transparent_check`` against a COPY of
the ledger dir) -- and a bundle-tier ``Artifact`` never carries that
detached statement (only the COVERING CHECKPOINT's own COSE wire form,
``Bundle.checkpoint_cose``). So for a Rust-produced capsule, a bundle-tier
answer proves LOG integrity (inclusion, non-tamper-since-checkpoint, the
checkpoint's own signature) but does NOT prove the individual capsule's OWN
producer signature -- that provenance question is out of the bundle tier's
reach entirely, not a bug in this bridge. ``ask_history.py`` reports this
distinction rather than rounding a log-integrity pass up to a full verify.

Route:
    POST /evidence-request
        body = the E14 request map (JSON: ``{subject, coverage?,
               derivation?, deadline?, nonce?}``).
        200 + the ``Artifact``/``Refusal`` JSON exactly as
            ``answer()``/``.to_dict()`` returns it -- a refusal is a SIGNED
            answer, not an HTTP-level decline, so it is 200 too;
            distinguish by the presence of ``bundles`` (Artifact) vs
            ``reason`` (Refusal). A missing/empty ledger resolves to a
            signed ``no_such_record`` refusal INSIDE ``answer()`` itself --
            never a 500.
    POST /evidence/deliver
        [mesh-adjudication-delivery-ack] -- body = a sealed twin-adjudication
        capsule's own canonical JSON bytes (opaque at this layer; see
        ``adjudication_delivery.py`` for the full contract). 200 +
        ``{"status": "received"}`` or a signed ``Refusal``
        (``request_malformed`` / ``policy_decline``) -- same
        signed-answer-always discipline as ``/evidence-request``, and the
        SAME ledger + node key ``EvidenceServerState`` already names; this
        route never opens a second ledger.
    POST /evidence/record-push
        the sharing-policy -- body = a counterparty's own sealed
        exchange record, pushed at completion (see ``record_push.py`` for
        the full contract). 200 + ``{"status": "received"}`` or a signed
        ``Refusal`` (``request_malformed`` / ``policy_decline``, the latter
        only when this node's own ``share_policy.record_at_completion`` is
        ``off`` -- the symmetry rule).
    GET /
        200 + a one-line human status. Carries no evidence -- in
        particular, never this node's own ledger filesystem path (that is
        local operational detail, not evidence, and telling a stranger
        where a file lives on this host is a gratuitous disclosure a
        neutral witness has no reason to make).
    anything else -> 404.

**the sharing-policy the relationship gate + "Asked of you" log.**
``EvidenceServerState.share_policy`` (``share_policy.SharePolicy | None``,
resolved once at server start from ``share_policy.share_policy_from_env()``
-- ``None`` when this node has never touched any of the four env vars,
same "unaffected byte for byte" default as every other caller of
``handle_evidence_request``) is threaded into both ``/evidence-request``
(as ``policy``, gating ``record``/``correlation``/``chain_segment`` by
``classify_relationship`` -- see ``evidence_responder.py``) and
``/evidence/record-push`` (gating accept-or-decline by
``record_at_completion``, symmetric with the send side -- see
``record_push.py``). The caller's self-declared identity for the gate rides
the ``X-Mesh-Requester-Id`` header, exactly as self-attested as every other
claim this vocabulary already trusts (see ``evidence_responder.
classify_relationship``'s own docstring) -- never verified against a
signature the wire does not carry.

Every inbound decision this door makes -- ``evidence-request`` answered or
refused, ``record-push`` received or refused -- is appended to
``received_log.jsonl`` in ``EvidenceServerState.received_log_dir`` (opt-in,
``None``/off by default; best-effort when set, mirrors
``peer_evidence_client.py``'s own ``send_log.jsonl`` for the OUTBOUND side):
this is the provider's own half of the double entry, the data an "Asked of
you" view reads to show inbound requests with their outcome and reason --
absent entirely before this module logged it. Deliberately never
``ledger_dir`` itself -- see ``EvidenceServerState.received_log_dir``'s own
docstring for why (the plugin-ledger bridge's "never a second writer"
invariant).
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, TypedDict

from adjudication_delivery import handle_delivery
from evidence_responder import augment_evidence_answer_dict, handle_evidence_request
from record_push import handle_record_push
from share_policy import SharePolicy, share_policy_from_env

__all__ = [
    "EvidenceServerState",
    "main",
    "make_evidence_handler",
    "run_evidence_server",
]


@dataclass(frozen=True)
class EvidenceServerState:
    """What ``handle_evidence_request``/``handle_delivery`` actually read
    off a node's state -- ``ledger_dir`` (the ledger DIRECTORY -- a
    ``cll.ledger.store.LedgerStore`` if migrated, else the legacy flat
    ``capsules.jsonl`` layout; see ``ledger_store_backend``), ``ledger_path``
    (kept for backward-compatible display/logging only -- never read for
    content, computed the same way ``capsule_sidecar.NodeState`` computes
    it) and ``signing_key_path`` (the node's own persisted Ed25519 key).
    Duck-type compatible with ``capsule_sidecar.NodeState`` (same three
    attribute names) without requiring everything else that dataclass needs
    to construct (a model manifest, a runtime label/digest, ...).

    ``share_policy`` the sharing-policy -- ``None`` (the default) when
    this node has never configured any of the four ``ADMISSION_POLICY_SHARE_*``
    / ``ADMISSION_POLICY_WITNESS`` env vars; see the module docstring's
    "relationship gate" note for how it's threaded into each route.

    ``received_log_dir`` the sharing-policy -- ``None`` (the default,
    no logging at all) or a directory to append ``received_log.jsonl`` into.
    Deliberately NEVER ``ledger_dir`` itself, and never defaulted to one --
    ``ledger_dir`` may be the Rust plugin's OWNED directory
    (``<data_dir>/ledger``), and this module never becomes a second writer
    into a ledger it does not own (module docstring, "two single-writer
    logs"; ``TestPluginLedgerBridge.test_bridge_never_writes_into_the_
    plugin_ledger_dir`` pins this for ``/evidence-request`` already -- this
    field keeps record-push logging from reopening that gap). An operator
    who wants the "Asked of you" log points this at a directory it actually
    owns, e.g. beside (never inside) the plugin's ledger dir.
    """

    ledger_dir: Path
    ledger_path: Path
    signing_key_path: Path
    share_policy: SharePolicy | None = None
    received_log_dir: Path | None = None


def _merged_evidence_view(ledger_dir: Path) -> Path:
    """Return the path ``answer()``/``bundle()`` should actually read for
    ``ledger_dir`` -- delegates entirely to ``ledger_store_backend.
    materialize_flat_view``, which is store-aware (this sidecar's own
    ledger may now be a ``cll.ledger.store.LedgerStore``) and folds in the
    same synthesized in-band ``checkpoint_stamp`` entries this function used
    to build by hand for the plugin-ledger read-only-checkpointed shape (see
    module docstring) -- one bridging implementation for both cases now.
    Never mutates ``ledger_dir``.
    """
    from ledger_store_backend import materialize_flat_view

    return materialize_flat_view(ledger_dir)


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _outcome_and_reason(result: dict[str, Any]) -> tuple[str, str | None]:
    """Classify one route's already-built response dict for
    ``received_log.jsonl`` -- ``"refused"`` (a signed ``Refusal``, ``reason``
    carried alongside), ``"received"`` (``/evidence/deliver``,
    ``/evidence/record-push`` success), or ``"answered"`` (an
    ``/evidence-request`` ``Artifact``/``served_summary`` success)."""
    if "reason" in result:
        return "refused", result["reason"]
    if result.get("status") == "received":
        return "received", None
    return "answered", None


class ReceivedLogEntry(TypedDict):
    """the sharing-policy the ``received_log.jsonl`` line shape -- a
    shape this module OWNS (unlike the capsule/Refusal wire dicts elsewhere
    in this file, which stay ``dict[str, Any]`` because their keys are
    producer-defined per the AAC spec, not a fixed internal shape)."""

    ts: str
    path: str
    requester_id: str | None
    subject_kind: str | None
    status: str
    reason: str | None


def _append_received_log(received_log_dir: Path | None, entry: ReceivedLogEntry) -> None:
    """the sharing-policy best-effort append to ``received_log.jsonl``
    in ``received_log_dir`` -- the provider's own half of the double entry
    (module docstring's "Asked of you" note), symmetric with
    ``peer_evidence_client.py``'s own ``send_log.jsonl`` for the OUTBOUND
    side. A no-op when ``received_log_dir`` is ``None`` (the default --
    logging is opt-in, see ``EvidenceServerState.received_log_dir``'s own
    docstring for why this is never ``ledger_dir``). Best-effort like that
    module's own ``_append_send_log``: a logging failure must never turn an
    already-decided answer/refusal into a 500."""
    if received_log_dir is None:
        return
    try:
        path = received_log_dir / "received_log.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        # Best-effort, same discipline as peer_evidence_client._append_send_log:
        # a logging failure must never turn an already-decided answer/refusal
        # into a 500 -- the caller already has its real response either way.
        pass


def make_evidence_handler(state: EvidenceServerState):
    """Build a BaseHTTPRequestHandler class closing over one node's state."""

    class EvidenceHandler(BaseHTTPRequestHandler):
        server_version = "capsule-evidence-server/0.1"

        def _write_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # BaseHTTPRequestHandler API names this do_POST
            path = self.path.strip("/")
            length = int(self.headers.get("Content-Length", "0") or "0")
            request_bytes = self.rfile.read(length) if length else b""

            if path == "evidence-request":
                # the sharing-policy the caller's self-declared
                # identity for the relationship gate -- see module
                # docstring's "relationship gate" note. `None` when absent,
                # reproducing pre-the sharing-policy behavior exactly
                # (`policy` gates on it only when BOTH are supplied).
                requester_id = self.headers.get("X-Mesh-Requester-Id") or None
                # [mesh-ledger-store-migration] handle_evidence_request's
                # own generic path now does this bridging itself (see
                # evidence_responder.py), so this door hands it state
                # unchanged rather than pre-building a merged view.
                result = handle_evidence_request(
                    state, request_bytes, requester_id=requester_id, policy=state.share_policy
                )
                # [mesh-served-summary-derivation] a served_summary/1 success
                # is already a plain dict (no .to_dict()); an Artifact/Refusal
                # is not. augment_evidence_answer_dict is additive-only either
                # way (a no-op on a shape it does not recognize).
                result_dict = result.to_dict() if hasattr(result, "to_dict") else result
                outcome, reason = _outcome_and_reason(result_dict)
                try:
                    subject_kind = json.loads(request_bytes).get("subject", {}).get("kind")
                except Exception:
                    subject_kind = None
                _append_received_log(
                    state.received_log_dir,
                    {
                        "ts": _now_iso(),
                        "path": "evidence-request",
                        "requester_id": requester_id,
                        "subject_kind": subject_kind,
                        "status": outcome,
                        "reason": reason,
                    },
                )
                self._write_json(200, augment_evidence_answer_dict(result_dict))
                return

            if path == "evidence/deliver":
                # Delivery targets THIS node's own ledger directly (never
                # the plugin-ledger bridge's scratch view) -- a delivered
                # verdict is a NEW record this node holds, not a read
                # against an existing one.
                result = handle_delivery(state, request_bytes)
                self._write_json(200, result)
                return

            if path == "evidence/record-push":
                # the sharing-policy see record_push.py for the full
                # contract -- gated by this node's own share_policy,
                # symmetric with the send side.
                result = handle_record_push(state, request_bytes, policy=state.share_policy)
                outcome, reason = _outcome_and_reason(result)
                _append_received_log(
                    state.received_log_dir,
                    {
                        "ts": _now_iso(),
                        "path": "evidence/record-push",
                        "requester_id": None,
                        "subject_kind": "record_push",
                        "status": outcome,
                        "reason": reason,
                    },
                )
                self._write_json(200, result)
                return

            self._write_json(404, {"error": "not_found", "path": self.path})

        def do_GET(self) -> None:
            body = b"capsule-evidence-server: ready\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

    return EvidenceHandler


def run_evidence_server(
    *, host: str = "127.0.0.1", port: int = 8091, state: EvidenceServerState
) -> ThreadingHTTPServer:
    handler = make_evidence_handler(state)
    return ThreadingHTTPServer((host, port), handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--ledger-dir",
        required=True,
        help="this node's ledger directory -- a cll.ledger.store.LedgerStore if migrated "
        "([mesh-ledger-store-migration]), else a legacy flat capsules.jsonl -- e.g. this "
        "sidecar's own ledger_dir, or the Rust plugin's <data_dir>/ledger for the live serving "
        "path (auto-bridged if a sibling checkpoints.jsonl is present)",
    )
    parser.add_argument(
        "--node-key",
        required=True,
        help="path to this node's persisted Ed25519 signing key (node-key.pem) -- the SAME key "
        "every capsule on this ledger is already signed with",
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8091)
    parser.add_argument(
        "--received-log-dir",
        default=None,
        help="the sharing-policy opt-in: append received_log.jsonl (the 'Asked of you' "
        "data -- every inbound evidence-request/record-push decision, with outcome and reason) "
        "into this directory. Off (no logging) unless set. Deliberately NEVER --ledger-dir -- "
        "point this at a directory this process actually owns, e.g. beside (never inside) the "
        "Rust plugin's ledger dir.",
    )
    args = parser.parse_args(argv)

    state = EvidenceServerState(
        ledger_dir=Path(args.ledger_dir),
        ledger_path=Path(args.ledger_dir) / "capsules.jsonl",
        signing_key_path=Path(args.node_key),
        # the sharing-policy None when this node has never touched
        # any of the four env vars -- see share_policy.py's own
        # "backward-compatible by construction" note.
        share_policy=share_policy_from_env(),
        received_log_dir=Path(args.received_log_dir) if args.received_log_dir else None,
    )
    server = run_evidence_server(host=args.listen_host, port=args.listen_port, state=state)
    print(
        f"capsule evidence server listening on http://{args.listen_host}:{args.listen_port} "
        f"ledger={state.ledger_dir}"
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

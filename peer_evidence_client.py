#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-peers-live-fetch] Peer evidence client.

Sends evidence-request messages to a peer's HTTP door (POST /evidence-request),
verifies responses OFFLINE, and fills Pane B cells with LIVE verified data.

Transport: direct HTTP POST to the peer's evidence door base URL.

HONESTY BAR (non-negotiable):
  - A cell only shows "verified" when the peer's response was fetched AND
    verified offline against the response bytes alone.
  - Unreachable / timed-out -> honest "no_answer" with transport/timeout.
  - Signed refusal -> "refused" with the peer's own reason, never inferred.
  - Verification failure -> "failed" with reason, never rounded to "present".
  - NEVER fabricate a count or status.

Send-log: each outgoing request is appended to send_log.jsonl in
ledger_dir (when supplied). The Pane B "Asked" cell reads this log to
show what THIS node sent each peer and whether they answered.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "PEER_FETCH_ENABLED",
    "PeerFetchResult",
    "SendLog",
    "fetch_all_peer_cells",
    "fetch_peer_history",
    "fetch_served_summary",
    "fetch_verdicts_about_peer",
]

#: Module-level default -- peer-fetch is opt-in.
PEER_FETCH_ENABLED = False

_SERVED_SUMMARY_SCHEMA = "mesh-served-summary/1"
_SERVED_SUMMARY_DERIVATION = "served_summary/1"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ask(peer_base_url: str, request_map: dict[str, Any], *, timeout: int) -> Any:
    """Send ``request_map`` to the peer's door and check the reply offline
    (``ask_history.read_reply``): signature, request binding, digests."""
    from ask_history import post_evidence_request, read_reply

    return read_reply(post_evidence_request(peer_base_url, request_map, timeout=timeout))


def _append_send_log(ledger_dir: Path | None, entry: dict[str, Any]) -> None:
    if ledger_dir is None:
        return
    try:
        path = ledger_dir / "send_log.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def fetch_served_summary(
    peer_base_url: str,
    *,
    timeout_seconds: int = 10,
    ledger_dir: Path | None = None,
    peer_id: str = "unknown",
) -> dict[str, Any]:
    """Fetch and verify a peer's served_summary/1 artifact.

    Returns one of:
      {"status": "verified", "served_summary": {...}, ...}
      {"status": "refused", "reason": "...", "signed": bool}
      {"status": "no_answer", "transport": "http", "timeout_seconds": N, "reason": "..."}
      {"status": "failed", "reason": "..."}
    NEVER fabricates a count or status.
    """
    from agent_action_capsule.evidence_request import Subject

    from ask_history import build_request

    # served_summary/1 is a static export: a mesh door serves it only under
    # an expected_pin naming its latest anchor, and refuses this
    # min_freshness request policy_declined. That refusal is reported as
    # such, never as an absence.
    request_map = build_request(Subject("full_history"), derivation=_SERVED_SUMMARY_DERIVATION)
    log_entry: dict[str, Any] = {
        "ts": _now_iso(),
        "peer_id": peer_id,
        "derivation": _SERVED_SUMMARY_DERIVATION,
        "transport": "http",
        "timeout_seconds": timeout_seconds,
    }
    try:
        reply = _ask(peer_base_url, request_map, timeout=timeout_seconds)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = f"unreachable: {type(exc).__name__}"
        log_entry["status"] = "no_answer"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {
            "status": "no_answer",
            "transport": "http",
            "timeout_seconds": timeout_seconds,
            "reason": reason,
        }

    if reply.refusal is not None:
        reason = reply.refusal.reason
        log_entry["status"] = "refused"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {"status": "refused", "reason": reason, "signed": reply.ok}

    if not reply.ok:
        reason = f"reply does not verify: {'; '.join(reply.errors)}"
        log_entry["status"] = "failed"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {"status": "failed", "reason": reason}

    served_summary = reply.body.get("served_summary") if isinstance(reply.body, dict) else None
    if not isinstance(served_summary, dict):
        log_entry["status"] = "failed"
        log_entry["reason"] = "no served_summary in response"
        _append_send_log(ledger_dir, log_entry)
        return {"status": "failed", "reason": "no served_summary in response"}

    schema = served_summary.get("schema")
    if schema != _SERVED_SUMMARY_SCHEMA:
        log_entry["status"] = "failed"
        log_entry["reason"] = f"schema mismatch: got {schema!r}"
        _append_send_log(ledger_dir, log_entry)
        return {"status": "failed", "reason": f"schema mismatch: got {schema!r}"}

    required_keys = {"n_served", "n_completed", "n_failed", "witness_bounded"}
    missing = required_keys - set(served_summary.keys())
    if missing:
        log_entry["status"] = "failed"
        log_entry["reason"] = f"served_summary missing required keys: {sorted(missing)}"
        _append_send_log(ledger_dir, log_entry)
        return {
            "status": "failed",
            "reason": f"served_summary missing required keys: {sorted(missing)}",
        }

    log_entry["status"] = "verified"
    _append_send_log(ledger_dir, log_entry)
    return {
        "status": "verified",
        "served_summary": served_summary,
        "schema": schema,
        "timeout_seconds": timeout_seconds,
        "verification_note": (
            "signed envelope verified; structural shape verified (schema tag + required "
            "fields present); recompute+match requires peer raw capsule records (out-of-scope)"
        ),
    }


def fetch_peer_history(
    peer_base_url: str,
    *,
    timeout_seconds: int = 10,
    ledger_dir: Path | None = None,
    peer_id: str = "unknown",
) -> dict[str, Any]:
    """Fetch and verify a peer's checkpoint history via their evidence door.

    Asks for the peer's ``checkpoints`` (served whatever the log's length),
    verifies the signed reply, checks that every checkpoint statement is the
    peer's own, that the list starts the stream, that each extends the one
    before it and that the last is the envelope's anchor (``ask_history
    .answer_checkpoints``), and folds them into a history card
    (``history_card.build_history_card``), which re-verifies every link.

    Returns one of:
      {"status": "verified", "history_summary": {...}, ...}
      {"status": "refused", "reason": "...", "signed": bool}
      {"status": "no_answer", "transport": "http", "timeout_seconds": N, ...}
      {"status": "failed", "reason": "...", ...}
    """
    from agent_action_capsule.evidence_request import Subject

    from ask_history import answer_checkpoints, build_request
    from history_card import build_history_card

    request_map = build_request(Subject("checkpoints"))
    derivation_label = "checkpoints"
    log_entry: dict[str, Any] = {
        "ts": _now_iso(),
        "peer_id": peer_id,
        "derivation": derivation_label,
        "transport": "http",
        "timeout_seconds": timeout_seconds,
    }

    def failed(reason: str) -> dict[str, Any]:
        log_entry["status"] = "failed"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {"status": "failed", "reason": reason}

    try:
        reply = _ask(peer_base_url, request_map, timeout=timeout_seconds)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = f"unreachable: {type(exc).__name__}"
        log_entry["status"] = "no_answer"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {
            "status": "no_answer",
            "transport": "http",
            "timeout_seconds": timeout_seconds,
            "reason": reason,
        }

    if reply.refusal is not None:
        reason = reply.refusal.reason
        log_entry["status"] = "refused"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {"status": "refused", "reason": reason, "signed": reply.ok}

    if not reply.ok:
        return failed(f"reply does not verify: {'; '.join(reply.errors)}")

    body = reply.body if isinstance(reply.body, dict) else {}
    lines, problems = answer_checkpoints(reply)
    if problems:
        return failed("; ".join(problems))
    try:
        card = build_history_card(node_id=peer_id, log_id=str(body.get("evidence_stream", "")), checkpoint_lines=lines)
    except (KeyError, TypeError, ValueError) as exc:
        return failed(f"the checkpoint lines do not fold into a history card: {exc}")

    props = card.properties
    if props.continuity != "unbroken" or not props.unforked:
        # build_history_card reports a link that fails its proof in the card,
        # not by raising: such a chain is not verified history.
        return failed(f"the peer's checkpoint chain does not verify: {props.continuity}")
    history_summary: dict[str, Any] = {
        "checkpoint_count": card.checkpoint_count,
        "witnessed": card.witnessed,
        "continuity": props.continuity,
        "unforked": props.unforked,
        "latest_checkpoint": lines[-1],
        "anchor": reply.envelope.anchor_digest,
    }
    log_entry["status"] = "verified"
    _append_send_log(ledger_dir, log_entry)
    return {
        "status": "verified",
        "history_summary": history_summary,
        "timeout_seconds": timeout_seconds,
    }


def fetch_verdicts_about_peer(
    peer_base_url: str,
    peer_node_id: str,
    *,
    peer_map: dict[str, str] | None = None,
    k: int = 3,
    timeout_seconds: int = 10,
    ledger_dir: Path | None = None,
) -> dict[str, Any]:
    """Ask the peer's counterparties for adjudications about this peer.

    Uses ask_history.run_references. Refusals are COUNTED, never inferred from.

    Returns one of:
      {"status": "verified", "tally": {...}, "ack_refusals": N, ...}
      {"status": "no_answer", "reason": "...", ...}
      {"status": "failed", "reason": "...", ...}
    """
    derivation_label = "references"
    log_entry: dict[str, Any] = {
        "ts": _now_iso(),
        "peer_id": peer_node_id,
        "derivation": derivation_label,
        "transport": "http",
        "timeout_seconds": timeout_seconds,
    }
    try:
        from ask_history import run_references
        result = run_references(
            peer_base_url,
            x_node_id=peer_node_id,
            peer_map=peer_map or {},
            k=k,
        )
    except ImportError:
        log_entry["status"] = "no_answer"
        log_entry["reason"] = "ask_history not available"
        _append_send_log(ledger_dir, log_entry)
        return {"status": "no_answer", "reason": "ask_history not available"}
    except RuntimeError as exc:
        reason = str(exc)
        log_entry["status"] = "failed"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {"status": "failed", "reason": reason}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = f"unreachable: {type(exc).__name__}"
        log_entry["status"] = "no_answer"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {
            "status": "no_answer",
            "reason": reason,
            "transport": "http",
            "timeout_seconds": timeout_seconds,
        }
    except Exception as exc:
        reason = f"unexpected error: {type(exc).__name__}: {exc}"
        log_entry["status"] = "failed"
        log_entry["reason"] = reason
        _append_send_log(ledger_dir, log_entry)
        return {"status": "failed", "reason": reason}

    log_entry["status"] = "verified"
    _append_send_log(ledger_dir, log_entry)
    return {
        "status": "verified",
        "tally": getattr(result, "adjudications_about_x", {}),
        "ack_refusals": getattr(result, "ack_refusals_about_x", 0),
        "references_asked": getattr(result, "references_asked", 0),
        "references_answered": getattr(result, "references_answered", 0),
        "candidates_discovered": getattr(result, "candidates_discovered", 0),
        "unreachable_references": getattr(result, "unreachable_references", 0),
        "selection": getattr(result, "selection", {}),
    }


@dataclass
class PeerFetchResult:
    """Combined result of all three peer-cell fetches for one peer.

    Each field is a status dict from the corresponding fetch function.
    None means the fetch was not attempted (peer-fetch disabled or no URL).
    """

    served: dict[str, Any] | None = None
    history: dict[str, Any] | None = None
    verdicts: dict[str, Any] | None = None


class SendLog:
    """In-memory per-peer send-log. Written to send_log.jsonl in
    ledger_dir by each fetch function; this class reads it back for
    the asked_cell builder."""

    def __init__(self, ledger_dir: Path | None = None) -> None:
        self._ledger_dir = ledger_dir
        self._lock = threading.Lock()
        self._in_memory: list[dict[str, Any]] = []

    def record_send(
        self, peer_id: str, derivation: str, response_status: str, **kwargs: Any
    ) -> None:
        entry: dict[str, Any] = {
            "ts": _now_iso(),
            "peer_id": peer_id,
            "derivation": derivation,
            "status": response_status,
            **kwargs,
        }
        with self._lock:
            self._in_memory.append(entry)
        _append_send_log(self._ledger_dir, entry)

    def get_log(self, peer_id: str) -> list[dict[str, Any]]:
        with self._lock:
            mem = [e for e in self._in_memory if e.get("peer_id") == peer_id]
        disk: list[dict[str, Any]] = []
        if self._ledger_dir is not None:
            path = self._ledger_dir / "send_log.jsonl"
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("peer_id") == peer_id:
                            disk.append(entry)
                    except Exception:
                        pass
        seen: set[tuple[str, str]] = set()
        merged: list[dict[str, Any]] = []
        for e in disk + mem:
            key = (e.get("ts", ""), e.get("derivation", ""))
            if key not in seen:
                seen.add(key)
                merged.append(e)
        return sorted(merged, key=lambda e: e.get("ts", ""))


def fetch_all_peer_cells(
    peer_id: str,
    peer_base_url: str,
    *,
    enabled: bool = True,
    timeout_seconds: int = 10,
    peer_map: dict[str, str] | None = None,
    ledger_dir: Path | None = None,
    fetch_verdicts: bool = True,
) -> PeerFetchResult:
    """Fetch all three peer-cell types for one peer.

    When enabled=False, returns honest no_answer for all cells.
    Never raises -- degrades gracefully to honest-pending on transport failure.
    """
    if not enabled:
        disabled = {"status": "no_answer", "reason": "peer_fetch_disabled"}
        return PeerFetchResult(served=disabled, history=disabled, verdicts=disabled)

    served = fetch_served_summary(
        peer_base_url,
        timeout_seconds=timeout_seconds,
        ledger_dir=ledger_dir,
        peer_id=peer_id,
    )
    history = fetch_peer_history(
        peer_base_url,
        timeout_seconds=timeout_seconds,
        ledger_dir=ledger_dir,
        peer_id=peer_id,
    )
    verdicts: dict[str, Any] | None = None
    if fetch_verdicts and peer_id != "unknown":
        verdicts = fetch_verdicts_about_peer(
            peer_base_url,
            peer_id,
            peer_map=peer_map,
            timeout_seconds=timeout_seconds,
            ledger_dir=ledger_dir,
        )
    return PeerFetchResult(served=served, history=history, verdicts=verdicts)

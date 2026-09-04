# SPDX-License-Identifier: Apache-2.0
"""A REAL NIP-01 Nostr relay client over a WebSocket connection.

This exists for exactly two uses in this repo:

  1. The **local test-relay round trip** (`run_b7_nostr_demo.py`): publish an
     account-capsule event to a relay running on ``localhost`` (e.g. `nak
     serve`), fetch it back over the wire, and verify the Nostr signature +
     the account. This is a genuine client/server round trip over a real
     socket — not the in-process `nostr_account.MockRelay` — against a relay
     that never leaves the machine.

  2. The **staged, HELD live-publish path** in `nostr_live_publish.py`, which
     wraps this client behind an explicit gate that refuses to run without
     Steven's one-line nod. See that module's docstring — nothing in this
     repo calls this client against a public relay.

This module carries **no default relay URL** anywhere: every call site names
one explicitly, so a `WebsocketRelayClient("wss://relay.damus.io")` is
something a caller has to type out on purpose, never something that falls out
of a missing argument.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from websockets.sync.client import connect

from nostr_account import NostrEvent

__all__ = ["WebsocketRelayClient"]


@dataclass
class WebsocketRelayClient:
    """A minimal synchronous NIP-01 relay client: `send_event` satisfies the
    same `nostr_account.RelayClient` protocol `MockRelay` does, so this class
    is a drop-in real-relay counterpart to it. `fetch_replaceable` pulls a
    parameterized-replaceable event back by (pubkey, kind, d-tag) — the read
    half of the round trip a mock relay cannot exercise (it never leaves the
    process)."""

    url: str
    timeout: float = 5.0

    def send_event(self, event: NostrEvent) -> dict[str, Any]:
        """Send ``["EVENT", <event>]`` and wait for the relay's NIP-01 OK
        response: ``["OK", <id>, <accepted?>, <message>]``."""
        with connect(self.url, open_timeout=self.timeout) as ws:
            ws.send(json.dumps(["EVENT", event.to_value()]))
            while True:
                msg = json.loads(ws.recv(timeout=self.timeout))
                if msg[0] == "OK" and msg[1] == event.id:
                    return {
                        "ok": bool(msg[2]),
                        "id": msg[1],
                        "message": msg[3] if len(msg) > 3 else "",
                    }

    def fetch_replaceable(self, pubkey: str, kind: int, d_tag: str) -> dict[str, Any] | None:
        """Open a ``REQ`` subscription filtered to (pubkey, kind, ``d`` tag),
        collect the newest matching event up to ``EOSE``, then ``CLOSE`` the
        subscription. Returns the raw event dict (as the relay sent it) or
        ``None`` if nothing matched — the caller verifies it with
        `nostr_account.NostrEvent.verify_value`."""
        sub_id = uuid.uuid4().hex[:16]
        filt = {"authors": [pubkey], "kinds": [kind], "#d": [d_tag]}
        found: dict[str, Any] | None = None
        with connect(self.url, open_timeout=self.timeout) as ws:
            ws.send(json.dumps(["REQ", sub_id, filt]))
            while True:
                msg = json.loads(ws.recv(timeout=self.timeout))
                if msg[0] == "EVENT" and msg[1] == sub_id:
                    found = msg[2]
                elif msg[0] == "EOSE" and msg[1] == sub_id:
                    ws.send(json.dumps(["CLOSE", sub_id]))
                    break
        return found

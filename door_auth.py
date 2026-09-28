# SPDX-License-Identifier: Apache-2.0
"""Mutual authentication between the Rust plugin and its local evidence door.

The plugin forwards peers' pushed records and record requests to
``evidence_server.py`` over loopback HTTP. Without this, any local process
that binds the door's port first receives that traffic and can answer in the
door's name. With it, both ends hold one shared token and prove it on every
exchange, without ever sending the token itself:

- the token is ``<plugin data dir>/evidence-door.token``: 64 lowercase hex
  characters (32 random bytes), no newline, mode 0600, created by the plugin
  on first start and never overwritten. The HMAC key is those 64 ASCII
  characters as bytes.
- every plugin request carries ``X-Evidence-Door-Nonce`` (32 lowercase hex
  characters, fresh per request) and ``X-Evidence-Door-Auth`` =
  ``hex(HMAC-SHA256(key, "plugin\\n" + METHOD + "\\n" + PATH + "\\n" + NONCE))``.
  A missing or wrong MAC, or a nonce already seen, gets 401 and nothing is
  processed.
- every reply to an authenticated request carries ``X-Evidence-Door-Proof`` =
  ``hex(HMAC-SHA256(key, "door\\n" + NONCE + "\\n" + STATUS + "\\n" +
  hex(sha256(body))))``, so the plugin can refuse a reply that did not come
  from the door.

Opt-in on the door: a door started without ``--token-file`` behaves as before,
so the Python callers that reach a door directly keep working. The packaged
launcher always passes the token file.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from collections import deque
from pathlib import Path

__all__ = [
    "AUTH_HEADER",
    "NONCE_HEADER",
    "PROOF_HEADER",
    "TOKEN_FILENAME",
    "DoorAuth",
    "DoorTokenError",
]

TOKEN_FILENAME = "evidence-door.token"
NONCE_HEADER = "X-Evidence-Door-Nonce"
AUTH_HEADER = "X-Evidence-Door-Auth"
PROOF_HEADER = "X-Evidence-Door-Proof"

_TOKEN = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_MAC = re.compile(r"[0-9a-f]{64}")
_SEEN_NONCES = 4096


class DoorTokenError(Exception):
    """The token file is missing, unreadable, or not 64 lowercase hex chars."""


class DoorAuth:
    """One door's side of the protocol: checks requests, proves replies."""

    def __init__(self, token: str) -> None:
        if not _TOKEN.fullmatch(token):
            raise DoorTokenError("door token must be 64 lowercase hex characters")
        self._key = token.encode("ascii")
        self._lock = threading.Lock()
        self._seen: set[str] = set()
        self._order: deque[str] = deque()

    @classmethod
    def from_file(cls, path: Path) -> DoorAuth:
        try:
            token = path.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as error:
            raise DoorTokenError(f"cannot read door token {path}: {error}") from error
        return cls(token)

    def _mac(self, message: str) -> str:
        return hmac.new(self._key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def request_mac(self, method: str, path: str, nonce: str) -> str:
        return self._mac(f"plugin\n{method}\n{path}\n{nonce}")

    def check_request(
        self, method: str, path: str, nonce: str | None, mac: str | None
    ) -> bool:
        """True only for a well-formed, correct MAC over a nonce not seen
        before; the nonce is then remembered so a replay fails."""
        if nonce is None or mac is None:
            return False
        if not _NONCE.fullmatch(nonce) or not _MAC.fullmatch(mac):
            return False
        if not hmac.compare_digest(self.request_mac(method, path, nonce), mac):
            return False
        with self._lock:
            if nonce in self._seen:
                return False
            self._seen.add(nonce)
            self._order.append(nonce)
            if len(self._order) > _SEEN_NONCES:
                self._seen.discard(self._order.popleft())
        return True

    def reply_proof(self, nonce: str, status: int, body: bytes) -> str:
        return self._mac(f"door\n{nonce}\n{status}\n{hashlib.sha256(body).hexdigest()}")

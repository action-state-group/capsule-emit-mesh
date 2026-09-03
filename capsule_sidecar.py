#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""capsule-emit-mesh-poc sidecar.

A reverse-proxy sidecar that sits in front of a mesh-llm node's OpenAI-
compatible `/v1` HTTP surface. For every `/v1/chat/completions` call it:

  1. reads the raw request, computes a canonicalized, privacy-preserving
     digest of it (the prompt itself is never stored in the capsule);
  2. forwards the request unmodified to the real upstream node;
  3. captures the real response (success or error) and digests it too;
  4. emits + signs an Agent Action Capsule recording the exchange, hash-
     chained to the previous capsule this sidecar emitted for this node.

WHY A SIDECAR AND NOT A MESH-LLM PLUGIN -- see poc/README.md
"Architecture decision" for the full writeup. Short version: neither of
mesh-llm's two plugin surfaces gives a plugin clean access to the raw
request/response JSON at the /v1 boundary --
  - the native serving plugin ABI (crates/mesh-native-serving-plugin-api)
    only sees token-level GenerationStart/Commit/Finish events, never the
    OpenAI JSON request or response bodies;
  - the external capability-plugin system (crates/mesh-llm-plugin, the
    architecture documented in docs/plugins/) is for capability PROVIDERS
    (model backends like openai-endpoint, or add-ons like metrics/
    blackboard/agents) that mesh-llm's core calls INTO -- there is no
    documented capability for observing mesh-llm's own /v1 frontend traffic
    from outside core.
  - there IS an in-process Rust hook, `OpenAiHookPolicy` +
    `HookedOpenAiBackend` (crates/openai-frontend/src/hooks.rs), that can see
    the full request before forwarding and (by wrapping the backend) the
    full response after -- but using it means compiling a custom mesh-llm
    binary that wires the wrapper in, which is a fork of their source, not
    an installable plugin, and this sandbox has no Rust toolchain to build
    or verify one anyway.
A sidecar needs zero changes to mesh-llm's code, runs against any release
build or local `cargo run`, and is honestly what it is: an external
observer at the wire, not a first-party integration.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent_action_capsule.canonical import json_digest
from agent_action_capsule.contracts import Disposition, EffectRecord
from agent_action_capsule.emit import emit
from agent_action_capsule.verify import verify as verify_capsule

import scitt_cose

from advertisement import Advertisement, compute_meter, reconcile_advertised_vs_served
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource, load_checkpoint_config
from model_identity import load_manifest, model_package_digest
from node_ownership import (
    SignedNodeOwnership,
    load_signed_node_ownership,
    owner_provenance_block,
    recheck_ownership_validity,
    seal_identity_capsule,
)

# Generation parameters we carry verbatim (not digested -- these are policy
# knobs, not prompt content, and are useful for audit as legible values).
# These are the settings the CLIENT requested (requested, not proven-effective)
# and are kept byte-identical to the Rust plugin's GENERATION_PARAM_KEYS
# (plugins/admission-policy/src/capsule_emit.rs) so both capture paths seal the
# SAME param set. Honest-by-absence is enforced at the call site: only keys
# actually present in the request are carried (see build_capsule below).
GENERATION_PARAM_KEYS = (
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "seed",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "repeat_penalty",
    "stop",
)

CLIENT_NONCE_HEADER = "X-Capsule-Client-Nonce"
#: Set by mesh-llm's own local ingress (never by a real client) only when IT
#: minted the nonce -- lets the sidecar tell "harness sent it" from "ingress
#: minted it one hop upstream" even though both arrive as a present header.
CLIENT_NONCE_ORIGIN_HEADER = "x-capsule-nonce-origin"
CLIENT_NONCE_ORIGIN_LOCAL_INGRESS = "local_ingress"
SIG_ALG = "EdDSA"

# [b6a-requester-seal] The two half-of-exchange roles a sidecar can seal.
# provider = the sharer's sidecar (attests what it SERVED); requester = the
# requestor's own outbound sidecar (attests its OWN half — what it requested +
# the response it received). Both halves of ONE exchange are lined up by a
# third party via the shared exchange_id (see EXCHANGE_ID_SOURCE below).
ROLE_PROVIDER = "provider"
ROLE_REQUESTER = "requester"
ROLES = (ROLE_PROVIDER, ROLE_REQUESTER)

#: How exchange_id is derived, recorded honestly in the capsule so a reader
#: knows it is the wire-observed response id, not a host-minted correlator this
#: proxy cannot see. Both the provider and requester sidecars observe the SAME
#: response object at the wire, so both record the SAME exchange_id — that is
#: what makes the two halves joinable. Matches the Rust admission-policy
#: plugin's serving_provenance.exchange_id lineage ("the host's exchange_id /
#: response `id` / x-request-id"), so a single verifier joins across both
#: capture paths uniformly.
EXCHANGE_ID_SOURCE = "response_id"


def exchange_id_from_response(response_json: dict[str, Any]) -> tuple[str, str]:
    """Derive the per-exchange correlator both halves share, from the response.

    Returns ``(exchange_id, source)``. The correlator is the OpenAI response
    ``id`` (e.g. ``chatcmpl-...``) — the field the serving host mints once per
    exchange and returns verbatim to the requester, so provider-side and
    requester-side sidecars observing the same exchange record the SAME value.

    When the upstream returns no ``id`` (an error object, or a truncated
    stream), the correlator is ``"unknown"`` and the source is
    ``"unavailable"`` — never fabricated, so a verifier can tell "not
    correlatable" apart from a real id. This mirrors the Rust plugin's
    ``exchange_id.unwrap_or("unknown")`` discipline.
    """
    resp_id = response_json.get("id")
    if isinstance(resp_id, str) and resp_id:
        return resp_id, EXCHANGE_ID_SOURCE
    return "unknown", "unavailable"

# Bilateral request attestation headers (Move 1 of draft-mih-agent-bilateral-attestation-01).
# Lowercased — HTTP/1.1 headers are case-insensitive; the handler normalises them before lookup.
BILATERAL_RA_HEADER = "x-capsule-request-attestation"
BILATERAL_RA_SIG_HEADER = "x-capsule-request-attestation-sig"
BILATERAL_PUBKEY_HEADER = "x-capsule-client-pubkey"

# Non-conformant identity label — REQUIRED per the #1233 receipt tuple's own
# task acceptance, and referenced from build_capsule() below. Factored out to
# a module constant so identity_limitation_for_rung() (D1's honest-labeling
# fix, see its docstring) can reuse the exact same text rather than a second
# hand-copied string drifting from this one.
IDENTITY_LIMITATION_CAVEAT = (
    "non-conformant-demo-key: self-generated Ed25519 key; not bound to "
    "any third-party-issued credential or trusted root; "
    "draft-mih-agent-bilateral-attestation-01 §4.1 states first-use "
    "acceptance MUST NOT be treated as conformant bilateral attestation"
)

#: Node signing key, generated on first run into --keys-dir. Never committed:
#: keys/ is gitignored.
NODE_KEY_FILENAME = "node-key.pem"


@dataclass
class BilateralEvalResult:
    """Result of evaluating a bilateral request attestation (Move 2)."""

    present: bool
    valid: bool
    initiator_ref: str | None
    correlator: str | None
    fail_reason: str | None



def load_or_create_signing_key(keys_dir: Path) -> bytes:
    """Return the node's Ed25519 signing key PEM, generating one on first run.

    Rules, in order:

    1. ``<keys_dir>/node-key.pem`` exists -> use it.
    2. It does not exist -> generate a fresh Ed25519 key, write it 0600, write the
       public half beside it, and say so on stdout.

    No private key is ever committed to this repository. A generated key is
    still self-attested and still not bound to any real node
    identity or hardware root -- see README. It is merely not *published*.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    keys_dir.mkdir(parents=True, exist_ok=True)
    node_key = keys_dir / NODE_KEY_FILENAME
    if node_key.exists():
        return node_key.read_bytes()

    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    node_key.write_bytes(pem)
    os.chmod(node_key, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    (keys_dir / "node-key.pub.pem").write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"generated a new node signing key at {node_key} (0600); keys/ is gitignored")
    return pem


def evaluate_bilateral_attestation(
    headers: dict[str, str],
    raw_body: bytes,
    request_json: dict[str, Any],
) -> BilateralEvalResult:
    """Move 2: evaluate the client's request attestation before dispatch.

    Returns ``present=False`` when no attestation headers are sent (degraded
    path); ``present=True, valid=False`` with ``fail_reason`` when the
    attestation is malformed, expired, or doesn't match the request; and
    ``present=True, valid=True`` on a clean bilateral exchange.

    ⚠ Non-conformant identity: the client's public key is accepted at
    face-value here. draft-mih-agent-bilateral-attestation-01 §4.1 requires
    a credential chaining to a root the relying party accepts; first-use
    acceptance of a bare public key MUST NOT be treated as conformant.
    This PoC demonstrates the mechanism only.
    """
    import base64
    from datetime import datetime, timezone

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    ra_b64 = headers.get(BILATERAL_RA_HEADER)
    sig_b64 = headers.get(BILATERAL_RA_SIG_HEADER)
    pubkey_b64 = headers.get(BILATERAL_PUBKEY_HEADER)

    if not ra_b64:
        return BilateralEvalResult(
            present=False, valid=False, initiator_ref=None, correlator=None, fail_reason=None
        )

    if not sig_b64 or not pubkey_b64:
        return BilateralEvalResult(
            present=True, valid=False, initiator_ref=None, correlator=None,
            fail_reason="missing sig or pubkey header alongside request attestation",
        )

    try:
        ra_bytes = base64.urlsafe_b64decode(ra_b64 + "==")
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
        pubkey_pem = base64.urlsafe_b64decode(pubkey_b64 + "==")
    except Exception as exc:
        return BilateralEvalResult(
            present=True, valid=False, initiator_ref=None, correlator=None,
            fail_reason=f"base64 decode error: {exc}",
        )

    try:
        ra = json.loads(ra_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return BilateralEvalResult(
            present=True, valid=False, initiator_ref=None, correlator=None,
            fail_reason=f"RA JSON parse error: {exc}",
        )

    nonce = ra.get("nonce")

    # Verify Ed25519 signature over the raw RA bytes.
    try:
        pubkey = serialization.load_pem_public_key(pubkey_pem)
        pubkey.verify(sig_bytes, ra_bytes)
    except InvalidSignature:
        return BilateralEvalResult(
            present=True, valid=False, initiator_ref=None, correlator=nonce,
            fail_reason="signature verification failed",
        )
    except Exception as exc:
        return BilateralEvalResult(
            present=True, valid=False, initiator_ref=None, correlator=nonce,
            fail_reason=f"signature error: {exc}",
        )

    initiator_ref = hashlib.sha256(ra_bytes).hexdigest()

    # Check validity window.
    valid_until_str = ra.get("valid_until")
    if valid_until_str:
        try:
            valid_until = datetime.fromisoformat(valid_until_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > valid_until:
                return BilateralEvalResult(
                    present=True, valid=False, initiator_ref=initiator_ref, correlator=nonce,
                    fail_reason="request attestation expired (valid_until in the past)",
                )
        except ValueError:
            pass  # malformed timestamp: log but don't hard-fail in the demo

    # Check request_digest: RA must commit to THIS request body.
    actual_request_digest = hashlib.sha256(raw_body).hexdigest()
    if ra.get("request_digest") != actual_request_digest:
        return BilateralEvalResult(
            present=True, valid=False, initiator_ref=initiator_ref, correlator=nonce,
            fail_reason=(
                f"request_digest mismatch: RA attests {ra.get('request_digest')!r}, "
                f"actual body digest {actual_request_digest!r}"
            ),
        )

    # Check authorization bound: request must not exceed the token ceiling the client authorized.
    ra_max_tokens = ra.get("max_tokens")
    req_max_tokens = request_json.get("max_tokens") or request_json.get("max_completion_tokens")
    if ra_max_tokens is not None and req_max_tokens is not None:
        if int(req_max_tokens) > int(ra_max_tokens):
            return BilateralEvalResult(
                present=True, valid=False, initiator_ref=initiator_ref, correlator=nonce,
                fail_reason=(
                    f"max_tokens bound exceeded: request wants {req_max_tokens}, "
                    f"RA authorized {ra_max_tokens}"
                ),
            )

    return BilateralEvalResult(
        present=True, valid=True, initiator_ref=initiator_ref, correlator=nonce, fail_reason=None
    )


def derive_cross_party_rung(cross_party: dict[str, Any] | None, has_verified_ack: bool = False) -> str:
    """Derive the cross_party_rung from the evidence block's own bytes.

    This function IS the rung derivation described in the forthcoming capsule
    format revision. The producer NEVER asserts a rung; the verifier derives it.

    Ordering: unilateral_fallback < acknowledged_receipt < full_bilateral

    unilateral_fallback
        No ``cross_party`` block in the record, or ``initiator_ref`` is absent.
        The node's record is a unilateral account of the exchange.

    acknowledged_receipt
        ``initiator_ref`` is present and verified — the node has cryptographic
        evidence of the initiator's prior commitment — but no verified client
        acknowledgment of the action capsule has been received.

    full_bilateral
        Both: ``initiator_ref`` present (node verified initiator's commitment)
        AND a verified client ack referencing this action capsule's
        ``capsule_id`` has been produced, establishing that both parties signed
        over the same exchange.

    ⚠ [mesh-rung12-adversarial-review] D1 — WHAT THIS FUNCTION DOES NOT AND
    CANNOT CHECK, stated precisely because "checks presence" is easy to
    misread as "checks validity":

    - ``initiator_ref`` is checked for PRESENCE (truthy) only. It is never
      re-derived or verified against a real request attestation — this
      function has no access to the raw request-attestation bytes/signature,
      only whatever string the capsule (potentially forged) claims. A node
      that fabricates the capsule directly (bypassing build_capsule()) can
      put any truthy string here.
    - ``has_verified_ack`` is a bool the CALLER computed (normally via
      bilateral_demo.verify_client_ack()) — this function is stateless and
      trusts it as given. Passing an uncomputed ``True`` reaches
      full_bilateral with zero evidence; that is a caller contract violation,
      not a property this function verifies or can verify.
    - Even when the caller's ack verification is done correctly,
      verify_client_ack() only confirms the ack's signature is
      self-consistent under its OWN embedded public key — it does not pin
      that key to a real, independent requester. One attacker controlling
      both the emitting node and a throwaway client keypair can satisfy
      every check this function and verify_client_ack() perform.

    None of the above is closable without an external identity anchor (out
    of scope here — see TRUST-MODEL.md §4.1). The honest response is
    disclosure: call identity_limitation_for_rung() on this function's return
    value and surface the result alongside the rung. Every caller in this
    repo that reports a rung does so (verify_exchange() below; the offline
    verification section of bilateral_demo.py's demo runner).
    """
    if not cross_party or not cross_party.get("initiator_ref"):
        return "unilateral_fallback"
    if has_verified_ack:
        return "full_bilateral"
    return "acknowledged_receipt"


def identity_limitation_for_rung(rung: str) -> str | None:
    """Return the identity-limitation caveat for a derived cross_party_rung.

    [mesh-rung12-adversarial-review] D1 — derive_cross_party_rung() cannot
    confirm ``initiator_ref`` or the client ack's key belong to a party
    independent of the node (see its docstring). ``full_bilateral`` is
    therefore never disclosed alone: every caller that surfaces a rung MUST
    also surface this caveat when it is not None, so "the claim matches what
    the crypto proves" — the rung says a commitment and an ack were present
    and self-consistent; this text says that alone does not prove a second,
    independent party produced them.

    Returns None for unilateral_fallback and acknowledged_receipt — those
    rungs make no independent-party claim in the first place.
    """
    return IDENTITY_LIMITATION_CAVEAT if rung == "full_bilateral" else None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stringify_floats(value: Any) -> Any:
    """Recursively replace JSON floats with their exact decimal-string form.

    agent_action_capsule's JSON-DIGEST (spec §5.1) refuses any float in a
    digest-bearing value -- JSON float serialization isn't cross-
    implementation deterministic, so the spec requires exact decimal
    strings instead. OpenAI-shaped chat requests/responses are full of
    floats (temperature, top_p, penalties, ...), so request/response
    canonicalization for digesting must stringify them first. `repr()` is
    used because it round-trips a Python float exactly (shortest string
    that reparses to the same float64) -- deterministic for this sidecar's
    own digest, not a claim of byte-parity with mesh-llm's Rust
    serialization.
    """
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, dict):
        return {k: _stringify_floats(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stringify_floats(v) for v in value]
    return value


def digest_json(value: Any) -> str:
    return json_digest(_stringify_floats(value))


@dataclass
class NodeState:
    """Chain + identity state the sidecar holds for one node/run."""

    node_id: str
    operator: str
    developer: str
    signing_key_pem: bytes
    signing_key_path: Path
    manifest_path: Path
    runtime_label: str
    runtime_digest: str
    ledger_dir: Path
    #: [b6a-requester-seal] Which half of an exchange this sidecar seals.
    #: ``"provider"`` (default) — the sharer's sidecar, in front of its own
    #: serving node; the capsule attests what it SERVED. ``"requester"`` — the
    #: requestor's own outbound sidecar; the capsule attests what it REQUESTED
    #: and the response it RECEIVED (its own half). A single node runs one
    #: sidecar per role and is thus both requestor and sharer; the two halves of
    #: one exchange are lined up by a third party via the shared ``exchange_id``
    #: (the response ``id`` lineage — see build_capsule). This is rung-1/2
    #: mechanics only: the requester seals its OWN half. It is NOT the Move-4
    #: acknowledgment leg / ``full_bilateral`` upgrade (spec-gated, out of
    #: scope here) — the requester never signs an ack of the provider's
    #: capsule_id, it only seals its own-half record independently.
    role: str = "provider"
    #: The node's self-attested advertisement -- what it CLAIMS it can serve
    #: (verify-after-advertise, TRUST-MODEL.md §12.3). Co-carried into every
    #: capsule alongside serving_provenance so a third party has BOTH the claim
    #: and the served fact from one offline artifact and can run
    #: reconcile_advertised_vs_served() from the bundle alone. ``None`` when the
    #: node advertised nothing -- reconciliation then reports
    #: ``advertisement_absent`` (never a silent green; §10 Rule 1).
    advertisement: Advertisement | None = None
    last_capsule_id: str | None = None
    emitted: list[dict[str, Any]] = field(default_factory=list)
    #: [mesh-rung12-adversarial-review] D3 — client-supplied nonces this node
    #: has already seen, in-memory, this process's lifetime. rung-1's claim
    #: is equivocation resistance: the node cannot have precomputed a record
    #: before seeing the client's nonce. A captured genuine nonce replayed
    #: verbatim on a later, unrelated exchange defeats exactly that property,
    #: and nothing tracked it before this set. Scope, stated honestly: this
    #: is per-node, in-memory, and does not persist across a restart or
    #: correlate across independently-operated nodes — see
    #: _resolve_client_nonce()'s docstring.
    seen_client_nonces: set[str] = field(default_factory=set)
    checkpoint_config_path: Path | None = None
    #: [mesh-plugin-cll-consume] A3 — the Rust plugin's OWN, separately-owned
    #: `<plugin_ledger_dir>/capsules.jsonl` (two single-writer logs, one
    #: machine view; §4 A2/A3 rev 3). When set, this sidecar process ALSO
    #: checkpoints that log (read-only: it is never written here — see
    #: checkpointing.py's module docstring for why direct capsule_emit.push()
    #: can't be pointed at a ledger this process doesn't own).
    plugin_ledger_dir: Path | None = None
    #: The Rust plugin's keys_dir (`<plugin_keys_dir>/node-key.pem`).
    #: Defaults to this node's own keys_dir -- the documented shared-identity
    #: deployment (`plugins/capsule-producer/src/keys.rs`'s module docstring:
    #: a keypair generated by either language loads cleanly in the other) --
    #: override when the plugin is provisioned with its own key.
    plugin_keys_dir: Path | None = None
    #: Falls back to `checkpoint_config_path` when omitted (same cadence
    #: policy for both logs); give a dedicated file for the "independent
    #: checkpoint cadence (serving runs hotter)" case rev 3 calls out.
    plugin_checkpoint_config_path: Path | None = None
    #: [b4-who-did] WHO+DID binding. mesh-llm's OPT-IN owner-identity cert
    #: (``SignedNodeOwnership``), loaded from ``~/.mesh-llm/node-ownership.json``
    #: or an override path. ``None`` (the DEFAULT) means owner identity is off —
    #: serving capsules then seal ``served_by_node_id`` only and mark the owner
    #: ABSENT (never fabricated). See node_ownership.py.
    node_ownership: SignedNodeOwnership | None = None
    #: The 32-byte-hex node endpoint id the cert binds to (the cert's
    #: ``node_endpoint_id``, distinct from the human ``node_id`` on the wire).
    #: The first-serve re-check confirms the cert binds THIS endpoint. Defaults
    #: to the cert's own claim when a cert is loaded, so a matching cert
    #: re-checks green out of the box.
    owner_node_endpoint_id: str | None = None
    #: capsule_id of the sealed identity capsule (the "who"), cited by every
    #: serving capsule whose owner re-check passes (the "did" cites the "who").
    identity_capsule_id: str | None = None

    def __post_init__(self) -> None:
        self.manifest = load_manifest(self.manifest_path)
        self.model_package_digest = model_package_digest(self.manifest)
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.ledger_dir / "capsules.jsonl"
        self.statements_dir = self.ledger_dir / "signed-statements"
        self.statements_dir.mkdir(parents=True, exist_ok=True)

        # [b4-who-did] Default the expected endpoint id from the loaded cert, so
        # a matching cert re-checks green without extra config. When no cert is
        # loaded this stays None and the owner block is simply ABSENT.
        if self.owner_node_endpoint_id is None and self.node_ownership is not None:
            self.owner_node_endpoint_id = self.node_ownership.claim.node_endpoint_id

        self.log_source = JsonlLogSource(self.ledger_path)
        self.checkpoint: CheckpointState | None = None
        if self.checkpoint_config_path is not None:
            loaded = load_checkpoint_config(self.checkpoint_config_path)
            if loaded is not None:
                cfg, log_id_override = loaded
                log_id = log_id_override or self.node_id
                signer = Ed25519Signer(self.signing_key_path)
                self.checkpoint = CheckpointState.load(
                    ledger_dir=self.ledger_dir,
                    log_source=self.log_source,
                    cfg=cfg,
                    signer=signer,
                    log_id=log_id,
                )

        self.plugin_checkpoint: CheckpointState | None = None
        if self.plugin_ledger_dir is not None:
            # Only ensures the directory exists (matching Rust's own
            # Ledger::open() -- idempotent either way); never creates or
            # touches capsules.jsonl itself, which stays the plugin's alone.
            self.plugin_ledger_dir.mkdir(parents=True, exist_ok=True)
            plugin_cfg_path = self.plugin_checkpoint_config_path or self.checkpoint_config_path
            if plugin_cfg_path is not None:
                loaded = load_checkpoint_config(plugin_cfg_path)
                if loaded is not None:
                    cfg, log_id_override = loaded
                    # A log_id override from a config file SHARED with the
                    # sidecar's own log (no dedicated --plugin-checkpoint-config)
                    # must never be reused verbatim -- two independently
                    # checkpointed logs colliding on the wire log_id would be
                    # indistinguishable to a verifier holding both streams.
                    if self.plugin_checkpoint_config_path is not None and log_id_override:
                        log_id = log_id_override
                    else:
                        log_id = f"{self.node_id}-plugin"
                    plugin_keys_dir = self.plugin_keys_dir or self.signing_key_path.parent
                    plugin_signer = Ed25519Signer(plugin_keys_dir / NODE_KEY_FILENAME)
                    # Read-only use: .append() is never called on this source --
                    # the Rust plugin is this ledger's sole writer.
                    plugin_log_source = JsonlLogSource(self.plugin_ledger_dir / "capsules.jsonl")
                    self.plugin_checkpoint = CheckpointState.load(
                        ledger_dir=self.plugin_ledger_dir,
                        log_source=plugin_log_source,
                        cfg=cfg,
                        signer=plugin_signer,
                        log_id=log_id,
                    )


def build_capsule(
    state: NodeState,
    *,
    client_nonce: str,
    client_nonce_source: str,
    request_json: dict[str, Any],
    request_digest: str,
    status: str,  # "confirmed" | "failed"
    response_digest: str,
    verdict_class: str,
    disposition_decision: str,
    latency_ms: float,
    exchange_id: str = "unknown",
    exchange_id_source: str = "unavailable",
    forwarded_copy: dict[str, Any] | None = None,
    bilateral_eval: "BilateralEvalResult | None" = None,
) -> dict[str, Any]:
    # Stringified for the same reason as digest_json() above: this dict is
    # committed into compute_attestation, which is itself committed into
    # capsule_id -- so any float here hits the same §5.1 digest-bearing-
    # float ban. The values are still exact and legible, just decimal
    # strings instead of JSON numbers.
    generation_parameters = _stringify_floats(
        {key: request_json[key] for key in GENERATION_PARAM_KEYS if key in request_json and request_json[key] is not None}
    )

    # verify-after-advertise (TRUST-MODEL.md §12.3): what THIS record can attest
    # about what ran, in the serving_provenance shape reconcile_advertised_vs_served
    # reads. The sidecar observes at the wire, so it honestly carries only the
    # model identity it can see (the served model name from the manifest) plus
    # served_by_node_id; quantization/hardware are facts the /v1 wire does not
    # expose to a proxy, so they stay ABSENT here (never fabricated) and any
    # advertised quant/hardware reconciles to `absent`, not a false green. The
    # Rust producer, which sees the host serving-provenance event, fills the
    # richer block; the reconcile function is identical over either shape.
    #
    # [b6a-requester-seal] serving_provenance is now EMITTED into the capsule
    # (previously it was a local reconcile-only var and never sealed on the
    # Python path). It carries the shared exchange_id + the role of this half,
    # so a third party can line up the requester's own-half capsule and the
    # provider's served-half capsule for ONE exchange. served_by_node_id and
    # requesting_party name the two ends honestly per role:
    #   provider  — served_by_node_id = this node; requesting_party = the
    #               counterparty (from the bilateral request attestation when
    #               present, else "unknown" — a proxy cannot name a caller it
    #               was given no attested identity for).
    #   requester — requesting_party = this node (it IS the requester);
    #               served_by_node_id = "unknown" (the requester's outbound
    #               sidecar sees the served MODEL but not the serving node's
    #               id at the /v1 wire — never fabricated).
    if state.role == ROLE_REQUESTER:
        served_by_node_id: str | None = "unknown"
        requesting_party = state.node_id
    else:
        served_by_node_id = state.node_id
        requesting_party = (
            bilateral_eval.initiator_ref
            if bilateral_eval and bilateral_eval.valid and bilateral_eval.initiator_ref
            else "unknown"
        )
    serving_provenance = {
        "served_by_node_id": served_by_node_id,
        "requesting_party": requesting_party,
        # The per-exchange correlator BOTH halves record identically (the wire
        # response id). exchange_id_source names how it was derived so a reader
        # never mistakes an "unknown" for a fabricated correlator (§10 Rule 1).
        "exchange_id": exchange_id,
        "exchange_id_source": exchange_id_source,
        # Which half of the exchange this record is — provider (served) or
        # requester (own half). A verifier reads this to know which side it is
        # holding before joining on exchange_id.
        "role": state.role,
        "model_canonical_ref": state.manifest.get("model_id"),
        "quantization": "unknown",
    }
    reconciliation = reconcile_advertised_vs_served(state.advertisement, serving_provenance)

    compute_attestation = {
        # Sanctioned ModelAttestation.compute_attestation keys (per its own
        # docstring): best-effort I/O digests + runtime label.
        "agent_input_digest": request_digest,
        "agent_output_digest": response_digest,
        "runtime": f"{state.runtime_digest}:{state.runtime_label}",
        # Namespaced, PoC-only extension. NOT a registered spec field --
        # riding inside compute_attestation because that block is explicitly
        # documented as a free-form, best-effort dict (contracts.py
        # ModelAttestation docstring), not because we are repurposing a
        # fixed-meaning field. See README "Field mapping" for the rationale
        # and the registration path (§12) this would need before being
        # anything more than illustrative.
        "x-mesh-poc-v1": {
            "client_nonce": client_nonce,
            "client_nonce_source": client_nonce_source,
            "model_package_digest": state.model_package_digest,
            "generation_parameters": generation_parameters,
            "latency_ms": f"{latency_ms:.3f}",
            # [b6a-requester-seal] The observed serving facts for THIS half,
            # including the shared exchange_id both halves record identically
            # and the role of this record. Emitted on the Python path (was
            # reconcile-only before) so the same field the Rust plugin fills is
            # present on both capture paths — capsule_mesh_viewer.serving_
            # provenance() reads exactly this block, and a third party joins the
            # requester's own-half capsule to the provider's served-half capsule
            # on serving_provenance.exchange_id. This is rung-1/2 correlation
            # ONLY: independent half-records sharing a correlator, NOT the
            # Move-4 ack leg (the requester does not sign the provider's
            # capsule_id here — that upgrade is spec-gated and out of scope).
            "serving_provenance": serving_provenance,
            # verify-after-advertise (§12.3): the node's self-attested CLAIM,
            # co-carried so a third party has BOTH the advertisement and the
            # serving fact from ONE offline artifact -- the reconciliation is
            # then self-contained (no discovery-note side channel needed to
            # check it). `null` when the node advertised nothing; the derived
            # `advertisement_reconciliation.overall` is then `advertisement_absent`,
            # never a silent pass (§10 Rule 1).
            "advertisement": state.advertisement.to_value() if state.advertisement else None,
            # DERIVED per-field verdict (match / mismatch / not_advertised /
            # absent). Carried so a reader that trusts neither party sees the
            # kept-or-broken promise without re-deriving it, AND re-derivable
            # from `advertisement` + `serving_provenance` by any verifier that
            # would rather not trust this producer's own copy.
            "advertisement_reconciliation": reconciliation,
            # NEUTRAL metered facts (§12.4, §6): wall-clock time as an
            # additional metered fact. Token usage stays sealed end-to-end via
            # the Rust producer's serving_provenance.usage (prompt/completion/
            # total_tokens) -- the sidecar proxies at the wire and does not
            # re-count tokens, so it does NOT co-carry a token count it did not
            # measure. Metering, never pricing -- no currency/rate/invoice field
            # exists here and none is ever added (§12.4).
            "compute_meter": compute_meter(latency_ms=latency_ms),
            # What the CALLING AGENT actually received, which is not always
            # byte-identical to what response_digest attests. response_digest
            # commits to the raw upstream object; a client-compatibility copy
            # may differ (see build_forwarded_copy). Reporting both, with the
            # transform list, is what lets a verifier reason about the seam
            # between this record stream and the agent's own downstream
            # capsules -- exactly where the bytes changed.
            "forwarded_copy": forwarded_copy,
            # Typed reference fields, present-but-empty (issue #1233: "a
            # fingerprint result or TEE quote rides as a typed reference
            # (digest + declared context) inside the same record"). Empty
            # here because this PoC implements #1233 step 3 only (receipts);
            # steps 4/5 (statistical fingerprint, TEE evidence) are future
            # work that upgrades these slots without changing the record
            # shape.
            "evidence_refs": {
                "statistical_fingerprint": {"type": "statistical_fingerprint", "digest": None, "context": None},
                "tee_attestation": {"type": "tee_attestation", "digest": None, "context": None},
            },
            # Bilateral attestation evidence block (Move 3 of
            # draft-mih-agent-bilateral-attestation-01). Populated from the
            # node's evaluation of the client's request attestation (Move 2).
            # ``cross_party_rung`` is NOT stored here — it is DERIVED by the
            # verifier from these bytes using derive_cross_party_rung().
            # ``counterparty_ref`` is null in the action capsule: the node's
            # own signed capsule IS the counterparty evidence; a verifier
            # evaluating the full exchange checks whether the initiator
            # acknowledged the returned capsule_id (the client ack, Move 4).
            "cross_party": {
                "initiator_ref": bilateral_eval.initiator_ref if bilateral_eval and bilateral_eval.valid else None,
                "counterparty_ref": None,
                "correlator": bilateral_eval.correlator if bilateral_eval and bilateral_eval.present else None,
                "substantive": bool(bilateral_eval and bilateral_eval.valid),
            } if bilateral_eval and bilateral_eval.present else None,
            # Non-conformant identity label — REQUIRED per task acceptance.
            # This demo uses a self-held Ed25519 key; §4.1 of the draft
            # requires a credential chaining to a root the relying party
            # accepts and states that first-use acceptance MUST NOT be
            # treated as conformant bilateral attestation.
            "identity_limitation": (
                IDENTITY_LIMITATION_CAVEAT
            ) if bilateral_eval and bilateral_eval.present else None,
            # [b4-who-did] WHO+DID binding. served_by_node_id (in
            # serving_provenance above) is the "did" — this endpoint served this
            # exchange. This block binds the "who" — the node OWNER's identity —
            # into that same record, and (when a valid cert is present) cites the
            # sealed identity capsule (identity_capsule_id) as the signed "who"
            # record, AND [mesh-e6-identity-owner-cert] carries the owner cert
            # itself as a CPB typed digest reference (owner_cert_ref — see
            # node_ownership.owner_cert_reference()), computed directly from the
            # cert's own bytes so the binding doesn't depend on identity-capsule
            # sealing order. Reuses the existing citation/caveat seam
            # (requester_commitment.py's cross_party block); no new machinery.
            # Owner identity is OPT-IN and self-asserted: node_ownership is None
            # by default, in which case owner_status="absent" and no owner is
            # ever fabricated. owner_provenance_block() runs the cheap
            # first-serve validity re-check and carries the identity_limitation
            # honesty grade whenever a cert is present. See node_ownership.py.
            "owner": owner_provenance_block(
                state.node_ownership,
                expected_node_endpoint_id=state.owner_node_endpoint_id or "",
                identity_capsule_id=state.identity_capsule_id,
            ),
        },
    }

    effect = EffectRecord(
        status=status,
        type="inference_completion",
        request_digest=request_digest,
        response_digest=response_digest,
        effect_attestation="gate_executed",
    )

    disposition = Disposition(
        decision=disposition_decision,
        approver="policy",
        human_disposed=False,
        verdict_class=verdict_class,
    )

    capsule = emit(
        action_id=f"mesh-poc/{state.node_id}/{uuid.uuid4()}",
        action_type="decide",
        operator=state.operator,
        developer=state.developer,
        model_id=state.manifest["model_id"],
        provider="mesh-llm",
        compute_attestation=compute_attestation,
        effect=effect,
        disposition=disposition,
        prior_capsule_id=state.last_capsule_id,
        chain_relation="confirms" if state.last_capsule_id else None,
        domain="action",
        provenance="collector",  # sidecar observes passively at the wire, not at mesh-llm's own gate
    )
    return capsule


def sign_capsule(state: NodeState, capsule: dict[str, Any]) -> bytes:
    payload = json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return scitt_cose.build_signed_statement(
        payload,
        alg=SIG_ALG,
        private_key_pem=state.signing_key_pem,
        issuer=state.node_id,
        subject=capsule["capsule_id"],
        content_type="application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02",
    )


def record_capsule(state: NodeState, capsule: dict[str, Any], signed_statement: bytes) -> None:
    # [adv-run-2-fix-batch] B3: verify BEFORE either disk write -- a capsule
    # that fails its own verify() must never be persisted to the ledger or
    # have a signed .cose statement written for it, even transiently.
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"sidecar emitted a capsule that fails its own verify(): {result.findings}")
    state.log_source.append(capsule)
    (state.statements_dir / f"{capsule['capsule_id']}.cose").write_bytes(signed_statement)
    state.last_capsule_id = capsule["capsule_id"]
    state.emitted.append(capsule)
    if state.checkpoint is not None:
        state.checkpoint.record_appended()
    # Opportunistic: this process has no direct hook into the Rust plugin's
    # own writes (a separate process), so it piggybacks the plugin ledger's
    # cadence check on its own request-handling cadence instead of running a
    # background timer -- record_appended() re-syncs from disk regardless of
    # who appended, so this still catches everything the plugin wrote since
    # the last check.
    if state.plugin_checkpoint is not None:
        try:
            state.plugin_checkpoint.record_appended()
        except Exception as exc:  # noqa: BLE001 -- best-effort, availability-only guard
            # [bounce 2026-08-28] The Rust plugin is a SEPARATE process
            # concurrently writing this ledger: a read here can race a
            # partial (torn) trailing line, or any other transient hiccup
            # capsule_emit's own MMR indexing raises on. Checkpointing this
            # foreign-owned log must never fail the exchange this sidecar is
            # otherwise done recording -- the same "never on the serving
            # path" promise checkpointing.py's own module docstring already
            # makes for the (unreachable-witness) registration leg applies
            # here too. Nothing on the safety side is at risk: capsules.jsonl
            # itself is untouched either way (record_capsule already wrote
            # THIS node's own capsule above); a missed plugin checkpoint just
            # means it's picked up whole on the next successful read.
            print(f"plugin-ledger checkpoint update failed (best-effort, continuing): {exc}")


def maybe_seal_identity_capsule(state: NodeState) -> str | None:
    """[b4-who-did] Seal + record the identity capsule (the "who") for this node.

    Called once at startup when a cert is present. Sets
    ``state.identity_capsule_id`` so serving capsules can cite it. The capsule is
    ALWAYS sealed when a cert exists (it is a faithful record of the cert,
    including an expired one), but serving capsules only CITE it as a live owner
    binding when the first-serve re-check passes — see owner_provenance_block().

    Returns the identity capsule_id, or None if no cert is present.
    """
    if state.node_ownership is None:
        return None
    identity_capsule = seal_identity_capsule(
        state.node_ownership,
        operator=state.operator,
        developer=state.developer,
        signing_node_id=state.node_id,
    )
    signed = sign_capsule(state, identity_capsule)
    record_capsule(state, identity_capsule, signed)
    state.identity_capsule_id = identity_capsule["capsule_id"]
    recheck = recheck_ownership_validity(
        state.node_ownership,
        expected_node_endpoint_id=state.owner_node_endpoint_id or "",
    )
    print(
        f"[b4-who-did] identity capsule sealed: {state.identity_capsule_id} "
        f"owner_id={state.node_ownership.claim.owner_id} recheck_valid={recheck.valid} "
        f"({recheck.reason})"
    )
    return state.identity_capsule_id


def _resolve_client_nonce(state: NodeState, headers: dict[str, str]) -> tuple[str, str]:
    """Resolve the client nonce and label its source honestly.

    [mesh-rung12-adversarial-review] D3 — a captured genuine client nonce
    replayed verbatim on a later, unrelated exchange used to be
    indistinguishable from a fresh one: both returned ``client_supplied``
    with no dedup, no rejection, no warning, weakening the one property
    rung-1 exists to buy (equivocation resistance -- the node can't have
    precomputed a record before seeing THIS exchange's client nonce). A
    nonce already present in ``state.seen_client_nonces`` is now labeled
    ``client_supplied_replayed`` instead of ``client_supplied`` -- named,
    not hidden, same discipline as the sidecar_generated_fallback label
    below.

    Scope, stated honestly rather than assumed: ``seen_client_nonces`` is
    in-memory and per-NodeState. It catches replay within one node's
    running lifetime (exactly what Attack 6a demonstrated) but NOT replay
    across a process restart (the set is not persisted) or across two
    independently-operated nodes (each node's set is its own). Closing
    those needs a shared/persistent store, which is out of scope for a PoC
    sidecar; if replay-across-restart or replay-across-node resistance is
    required, that scope gap must be closed explicitly, not assumed away by
    this fix.
    """
    client_nonce = headers.get(CLIENT_NONCE_HEADER.lower())
    if client_nonce:
        if client_nonce in state.seen_client_nonces:
            return client_nonce, "client_supplied_replayed"
        state.seen_client_nonces.add(client_nonce)
        if headers.get(CLIENT_NONCE_ORIGIN_HEADER) == CLIENT_NONCE_ORIGIN_LOCAL_INGRESS:
            # Present, but minted by mesh-llm's own local ingress one hop
            # upstream, not contributed by the actual client -- same honest-
            # labeling discipline as the sidecar's own fallback below: name
            # the degradation, do not silently upgrade it to "client_supplied".
            return client_nonce, "local_ingress"
        return client_nonce, "client_supplied"
    # Honest PoC compromise: #1233 requires the CLIENT to contribute the
    # nonce (so the node can't fabricate/replay). When no client nonce
    # header is present the sidecar mints one itself so the record still
    # has a nonce field -- but this weakens the anti-replay property and
    # MUST be labeled, not silently upgraded to "client_supplied".
    return uuid.uuid4().hex, "sidecar_generated_fallback"


def _seal_chat_completion(
    state: NodeState,
    *,
    client_nonce: str,
    client_nonce_source: str,
    request_json: dict[str, Any],
    request_digest: str,
    response_json: dict[str, Any],
    status_code: int,
    latency_ms: float,
    forwarded_copy: dict[str, Any] | None = None,
    bilateral_eval: "BilateralEvalResult | None" = None,
) -> dict[str, Any]:
    response_digest = digest_json(response_json)
    # [b6a-requester-seal] The shared per-exchange correlator, off the response
    # id — recorded identically by whichever role's sidecar seals this half.
    exchange_id, exchange_id_source = exchange_id_from_response(response_json)
    if 200 <= status_code < 300:
        capsule = build_capsule(
            state,
            client_nonce=client_nonce,
            client_nonce_source=client_nonce_source,
            request_json=request_json,
            request_digest=request_digest,
            status="confirmed",
            response_digest=response_digest,
            verdict_class="executed",
            disposition_decision="accept",
            latency_ms=latency_ms,
            exchange_id=exchange_id,
            exchange_id_source=exchange_id_source,
            forwarded_copy=forwarded_copy,
            bilateral_eval=bilateral_eval,
        )
    else:
        # "checked and failed", not "absent" -- see #1233 step 7 (full
        # rationale in handle_chat_completion's non-streaming twin below).
        capsule = build_capsule(
            state,
            client_nonce=client_nonce,
            client_nonce_source=client_nonce_source,
            request_json=request_json,
            request_digest=request_digest,
            status="failed",
            response_digest=response_digest,
            verdict_class="errored",
            disposition_decision="reject",
            latency_ms=latency_ms,
            exchange_id=exchange_id,
            exchange_id_source=exchange_id_source,
            forwarded_copy=forwarded_copy,
            bilateral_eval=bilateral_eval,
        )
    signed_statement = sign_capsule(state, capsule)
    record_capsule(state, capsule, signed_statement)
    return capsule


def reassemble_streamed_response(sse_chunks: list[dict[str, Any]]) -> dict[str, Any]:
    """Fold OpenAI-style SSE `chat.completion.chunk` deltas into one committed
    `chat.completion` object -- the same shape a non-streaming call returns.

    Goose (like most OpenAI-compatible clients) requests `stream: true`;
    mesh-llm's real /v1 surface streams token-level deltas, including
    incremental `tool_calls` deltas when the model is making a tool call.
    #1233's `output_digest` is defined over "the response" (a committed I/O
    digest), not over a token stream -- so the sidecar digests this
    reassembled object, identical in shape and content to what a
    non-streaming call would have returned for the same generation.
    """
    role = "assistant"
    content_parts: list[str] = []
    tool_calls: dict[int, dict[str, Any]] = {}
    finish_reason = None
    resp_id = resp_model = resp_created = None
    for chunk in sse_chunks:
        resp_id = resp_id or chunk.get("id")
        resp_model = resp_model or chunk.get("model")
        resp_created = resp_created or chunk.get("created")
        choices = chunk.get("choices") or []
        if not choices:
            continue
        delta = choices[0].get("delta") or {}
        if delta.get("role"):
            role = delta["role"]
        if delta.get("content"):
            content_parts.append(delta["content"])
        for tc in delta.get("tool_calls") or []:
            idx = tc.get("index", 0)
            slot = tool_calls.setdefault(idx, {"id": None, "type": "function", "function": {"name": "", "arguments": ""}})
            if tc.get("id"):
                slot["id"] = tc["id"]
            fn = tc.get("function") or {}
            if fn.get("name"):
                slot["function"]["name"] += fn["name"]
            if fn.get("arguments"):
                slot["function"]["arguments"] += fn["arguments"]
        if choices[0].get("finish_reason"):
            finish_reason = choices[0]["finish_reason"]

    message: dict[str, Any] = {"role": role, "content": "".join(content_parts) or None}
    if tool_calls:
        message["tool_calls"] = [tool_calls[i] for i in sorted(tool_calls)]
    return {
        "id": resp_id,
        "object": "chat.completion",
        "created": resp_created,
        "model": resp_model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }


def build_forwarded_copy(response_json: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    """Build the client-compatibility copy of a reassembled response, and
    return it alongside the list of transforms that were applied to it and
    any tool-call IDs that were already present in the raw upstream response.

    The capsule's ``response_digest`` always attests to the RAW object this
    function receives; it is never recomputed from the return value. The
    transform list exists so the record can *say* that the bytes handed to
    the calling agent differed from the bytes attested, rather than leaving a
    verifier to discover the divergence from the README. Same principle as
    ``client_nonce_source``: name the degradation, do not hide it.

    Transforms (each emitted only when it actually fired):

    ``content_dropped_with_tool_calls``
        A real, live-observed small-model quirk: Hermes-2-Pro-Mistral-7B
        driven by goose's agent system prompt sometimes returns a well-formed
        ``tool_calls`` array AND a spurious ``content`` string; goose's
        client-side parser rejects that combination.

    ``tool_call_id_minted``
        mesh-llm's real ``tool_calls`` entries carry no ``id`` field (on the
        ``--local-model-only`` path, which bypasses the host-runtime OpenAI
        normalizer). When the normalizer IS active (supported port), IDs are
        already present in the raw response and this transform does NOT fire.

    Returns (forwarded_copy, transforms, upstream_tool_call_ids) where
    ``upstream_tool_call_ids`` holds the IDs that came from the upstream
    response as-is (i.e. minted by the normalizer, not by this sidecar).
    An empty list means the normalizer was not active or made no tool calls.
    """
    forwarded = json.loads(json.dumps(response_json))
    transforms: list[str] = []
    upstream_tool_call_ids: list[str] = []
    for choice in forwarded.get("choices", []):
        message = choice.get("message", {})
        tool_calls = message.get("tool_calls")
        if tool_calls and message.get("content"):
            message["content"] = None
            if "content_dropped_with_tool_calls" not in transforms:
                transforms.append("content_dropped_with_tool_calls")
        for tc in tool_calls or []:
            if tc.get("id"):
                # ID came from the upstream normalizer; pass through unchanged.
                upstream_tool_call_ids.append(tc["id"])
            else:
                tc["id"] = f"call_{uuid.uuid4().hex[:24]}"
                if "tool_call_id_minted" not in transforms:
                    transforms.append("tool_call_id_minted")
    return forwarded, transforms, upstream_tool_call_ids


def forwarded_copy_record(forwarded: dict[str, Any], transforms: list[str], upstream_tool_call_ids: list[str] | None = None) -> dict[str, Any]:
    """The in-capsule statement about what the calling agent actually received.

    ``transforms: []`` with ``digest == response_digest`` is the honest
    "nothing was changed on the way out" case, and is emitted explicitly
    rather than omitted, so a verifier can tell "unchanged" apart from
    "this producer does not report it at all".

    ``upstream_tool_call_ids`` (when non-None) lists IDs that the upstream
    normalizer added to the raw response.  When the list is non-empty, the
    ``response_digest`` field attests to bytes that include those IDs; because
    the IDs carry a wall clock they will differ across runs even for identical
    model output, making ``response_digest`` run-unique on the supported port.
    An absent or empty list means either no tool calls or the sidecar had to
    mint them (``--local-model-only`` path).
    """
    result: dict[str, Any] = {"transforms": transforms, "digest": digest_json(forwarded)}
    if upstream_tool_call_ids is not None:
        result["upstream_tool_call_ids"] = upstream_tool_call_ids
    return result


def synthesize_sse(response_json: dict[str, Any]) -> list[bytes]:
    """Turn one committed chat.completion object into an OpenAI-style SSE
    chunk sequence (a role delta, then content or tool_calls deltas, then a
    finish_reason chunk, then [DONE]) -- what a streaming client expects.

    Takes the already-built forwarded copy from build_forwarded_copy();
    every client-compatibility mutation (including tool_call id minting)
    happens there and is reported in the capsule's forwarded_copy.transforms,
    so this function is now pure serialization and mutates nothing.
    """
    choice = (response_json.get("choices") or [{}])[0]
    message = choice.get("message", {})
    base = {"id": response_json.get("id"), "object": "chat.completion.chunk", "created": response_json.get("created"), "model": response_json.get("model")}

    def frame(delta: dict[str, Any], finish_reason: str | None = None) -> bytes:
        chunk = {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}]}
        return f"data: {json.dumps(chunk)}\n\n".encode()

    lines = [frame({"role": message.get("role", "assistant")})]
    if message.get("tool_calls"):
        for i, tc in enumerate(message["tool_calls"]):
            lines.append(
                frame(
                    {
                        "tool_calls": [
                            {
                                "index": i,
                                "id": tc.get("id"),
                                "type": tc.get("type", "function"),
                                "function": tc.get("function", {}),
                            }
                        ]
                    }
                )
            )
    elif message.get("content"):
        lines.append(frame({"content": message["content"]}))
    lines.append(frame({}, finish_reason=choice.get("finish_reason")))
    lines.append(b"data: [DONE]\n\n")
    return lines


def handle_chat_completion(state: NodeState, upstream_base: str, headers: dict[str, str], raw_body: bytes) -> tuple[int, bytes, dict[str, str]]:
    request_json = json.loads(raw_body.decode("utf-8"))
    request_digest = digest_json(request_json)
    client_nonce, client_nonce_source = _resolve_client_nonce(state, headers)
    bilateral_eval = evaluate_bilateral_attestation(headers, raw_body, request_json)

    req = urllib.request.Request(
        url=f"{upstream_base}/v1/chat/completions",
        data=raw_body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            status_code = resp.status
            response_body = resp.read()
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        response_body = exc.read()
    latency_ms = (time.monotonic() - start) * 1000

    response_json = json.loads(response_body.decode("utf-8"))
    response_digest = digest_json(response_json)
    # Non-streaming: response_body is returned to the caller unmodified, so the
    # forwarded copy IS the raw object. Reported explicitly (empty transforms,
    # digest == response_digest) rather than omitted, so "nothing changed" is a
    # positive statement in the record instead of an absence.
    # Still check for upstream-minted IDs so the capsule records whether the
    # normalizer was active (same field as in the streaming path).
    _, _, upstream_ids = build_forwarded_copy(response_json)
    forwarded_copy = forwarded_copy_record(response_json, [], upstream_ids)
    # [b6a-requester-seal] Shared correlator off the response id (see
    # _seal_chat_completion / the streaming twin — same derivation everywhere).
    exchange_id, exchange_id_source = exchange_id_from_response(response_json)

    if 200 <= status_code < 300:
        capsule = build_capsule(
            state,
            client_nonce=client_nonce,
            client_nonce_source=client_nonce_source,
            request_json=request_json,
            request_digest=request_digest,
            status="confirmed",
            response_digest=response_digest,
            verdict_class="executed",
            disposition_decision="accept",
            latency_ms=latency_ms,
            exchange_id=exchange_id,
            exchange_id_source=exchange_id_source,
            forwarded_copy=forwarded_copy,
            bilateral_eval=bilateral_eval,
        )
    else:
        # "checked and failed", not "absent" -- see #1233 step 7. The
        # sidecar directly observed the request AND the real error
        # response; both are digested into the capsule. verdict_class is
        # "errored", not "denied": the spec's own §5.4.2 invariant
        # (NEVER_DISPATCH_VERDICT_CLASSES) rejects "denied" paired with
        # effect.status="failed" -- "denied" means pre-dispatch, and the
        # sidecar cannot claim that from outside the process; all it can
        # honestly say is that a request WAS dispatched (it sent it and got
        # a real response back) and the outcome was a refusal. That is
        # exactly "ran and threw" per the verdict_class registry.
        capsule = build_capsule(
            state,
            client_nonce=client_nonce,
            client_nonce_source=client_nonce_source,
            request_json=request_json,
            request_digest=request_digest,
            status="failed",
            response_digest=response_digest,
            verdict_class="errored",
            disposition_decision="reject",
            latency_ms=latency_ms,
            exchange_id=exchange_id,
            exchange_id_source=exchange_id_source,
            forwarded_copy=forwarded_copy,
            bilateral_eval=bilateral_eval,
        )

    signed_statement = sign_capsule(state, capsule)
    record_capsule(state, capsule, signed_statement)

    out_headers = {"Content-Type": "application/json", "X-Capsule-Id": capsule["capsule_id"]}
    return status_code, response_body, out_headers


def make_handler(state: NodeState, upstream_base: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # noqa: A003
            pass

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            if self.path != "/v1/chat/completions":
                self._proxy_passthrough("POST", raw)
                return
            headers = {k.lower(): v for k, v in self.headers.items()}
            try:
                request_json = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                body = json.dumps({"error": {"message": f"capsule sidecar error: bad request JSON: {exc}", "type": "sidecar_error", "param": None, "code": None}}).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if request_json.get("stream"):
                self._handle_streaming_chat_completion(headers, raw, request_json)
                return
            try:
                status_code, body, out_headers = handle_chat_completion(state, upstream_base, headers, raw)
            except Exception as exc:  # sidecar-internal failure -- never silently swallow
                body = json.dumps({"error": {"message": f"capsule sidecar error: {exc}", "type": "sidecar_error", "param": None, "code": None}}).encode()
                status_code = 500
                out_headers = {"Content-Type": "application/json"}
            self.send_response(status_code)
            for k, v in out_headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle_streaming_chat_completion(self, headers: dict[str, str], raw_body: bytes, request_json: dict[str, Any]) -> None:
            """Buffer the real SSE stream, seal a capsule over the RAW
            reassembled response, then forward a re-synthesized SSE stream
            built from a CLIENT-COMPATIBILITY-NORMALIZED copy of that same
            response to the caller (goose).

            Honest limitation, found live in this session: mesh-llm serving
            a real small local model (Hermes-2-Pro-Mistral-7B) under
            goose's own agent system prompt sometimes returns a message with
            BOTH a populated `tool_calls` array AND a spurious, unrelated
            `content` string (observed: the model echoing a `<turn-budget>`
            tag from goose's prompt back as content alongside a *correct*
            tool call). goose's client-side response parser rejects that
            combination ("does not match the expected peg-native format").
            This is a real small-model output quirk, not a sidecar bug --
            confirmed by capturing the identical raw (non-streamed) response
            directly from mesh-llm outside of goose.

            The capsule's response_digest attests to the RAW response
            exactly as mesh-llm returned it (see reassemble_streamed_response
            call below, computed before normalization) -- the attestation is
            never silently altered. Only the copy forwarded to the calling
            agent is normalized (content dropped when tool_calls is
            present), so the task can actually proceed. This trades true
            token-by-token pass-through streaming for correctness: the
            sidecar buffers the full upstream response before re-emitting a
            synthesized SSE stream, rather than forwarding raw bytes live.
            """
            request_digest = digest_json(request_json)
            client_nonce, client_nonce_source = _resolve_client_nonce(state, headers)
            bilateral_eval = evaluate_bilateral_attestation(headers, raw_body, request_json)
            req = urllib.request.Request(
                url=f"{upstream_base}/v1/chat/completions",
                data=raw_body,
                method="POST",
                headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
            )
            start = time.monotonic()
            sse_chunks: list[dict[str, Any]] = []
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:
                    status_code = resp.status
                    for raw_line in resp:
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line.startswith("data:"):
                            continue
                        data_part = line[len("data:") :].strip()
                        if data_part == "[DONE]" or not data_part:
                            continue
                        try:
                            sse_chunks.append(json.loads(data_part))
                        except json.JSONDecodeError:
                            continue
            except urllib.error.HTTPError as exc:
                status_code = exc.code
                error_body = exc.read()
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(error_body)))
                self.end_headers()
                self.wfile.write(error_body)
                try:
                    response_json = json.loads(error_body.decode("utf-8"))
                except json.JSONDecodeError:
                    response_json = {"error": {"message": error_body.decode("utf-8", errors="replace")}}
                latency_ms = (time.monotonic() - start) * 1000
                _seal_chat_completion(
                    state,
                    client_nonce=client_nonce,
                    client_nonce_source=client_nonce_source,
                    request_json=request_json,
                    request_digest=request_digest,
                    response_json=response_json,
                    status_code=status_code,
                    latency_ms=latency_ms,
                    bilateral_eval=bilateral_eval,
                )
                return

            latency_ms = (time.monotonic() - start) * 1000
            response_json = reassemble_streamed_response(sse_chunks)  # RAW -- what mesh-llm actually returned
            # Build the compat copy BEFORE sealing so the capsule can state what
            # the caller actually got. response_digest still commits to RAW.
            forwarded, transforms, upstream_ids = build_forwarded_copy(response_json)
            _seal_chat_completion(
                state,
                client_nonce=client_nonce,
                client_nonce_source=client_nonce_source,
                request_json=request_json,
                request_digest=request_digest,
                response_json=response_json,
                status_code=status_code,
                latency_ms=latency_ms,
                forwarded_copy=forwarded_copy_record(forwarded, transforms, upstream_ids),
                bilateral_eval=bilateral_eval,
            )

            body = b"".join(synthesize_sse(forwarded))
            self.send_response(status_code)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            self._proxy_passthrough("GET", b"")

        def _proxy_passthrough(self, method: str, raw: bytes) -> None:
            req = urllib.request.Request(url=f"{upstream_base}{self.path}", data=raw or None, method=method)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = resp.read()
                    status = resp.status
            except urllib.error.HTTPError as exc:
                body = exc.read()
                status = exc.code
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def run_sidecar(
    *,
    listen_host: str = "127.0.0.1",
    listen_port: int = 8089,
    upstream_base: str = "http://127.0.0.1:9337",
    state: NodeState,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((listen_host, listen_port), make_handler(state, upstream_base))
    return server


def default_state(
    ledger_dir: Path,
    manifest_path: Path,
    keys_dir: Path,
    runtime_label: str,
    runtime_digest: str,
    checkpoint_config_path: Path | None = None,
    plugin_ledger_dir: Path | None = None,
    plugin_keys_dir: Path | None = None,
    plugin_checkpoint_config_path: Path | None = None,
    advertisement: Advertisement | None = None,
    node_ownership: SignedNodeOwnership | None = None,
    role: str = ROLE_PROVIDER,
    node_id: str = "mesh-node-demo-1",
) -> NodeState:
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}, got {role!r}")
    signing_key_pem = load_or_create_signing_key(keys_dir)
    return NodeState(
        node_id=node_id,
        operator="capsule-emit-mesh-poc-demo",
        developer="capsule-emit-mesh-poc-sidecar/0.1.0",
        signing_key_pem=signing_key_pem,
        signing_key_path=keys_dir / NODE_KEY_FILENAME,
        manifest_path=manifest_path,
        runtime_label=runtime_label,
        runtime_digest=runtime_digest,
        ledger_dir=ledger_dir,
        role=role,
        advertisement=advertisement,
        checkpoint_config_path=checkpoint_config_path,
        plugin_ledger_dir=plugin_ledger_dir,
        plugin_keys_dir=plugin_keys_dir,
        plugin_checkpoint_config_path=plugin_checkpoint_config_path,
        node_ownership=node_ownership,
    )


def main(argv: list[str] | None = None) -> int:
    """Standalone CLI: point this at a REAL mesh-llm node.

      mesh-llm serve --local-model-only --model <path.gguf> --port 9337
      capsule-sidecar --upstream http://127.0.0.1:9337 --listen-port 8089

    (or `python3 capsule_sidecar.py ...` from a checkout, same thing.)
    """
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", default="http://127.0.0.1:9337")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8089)
    parser.add_argument(
        "--role",
        choices=ROLES,
        default=ROLE_PROVIDER,
        help=(
            "which half of an exchange this sidecar seals. 'provider' (default): "
            "the sharer's sidecar, in front of its own serving node — the capsule "
            "attests what it SERVED. 'requester': the requestor's OWN outbound "
            "sidecar — the capsule attests its own half (model requested, "
            "gen-params, its nonce, the response it received). A node that is both "
            "requestor and sharer runs one sidecar per role; a third party lines up "
            "the two halves of one exchange via the shared exchange_id (the response "
            "id lineage). rung-1/2 correlation ONLY — NOT the Move-4 acknowledgment "
            "leg / full_bilateral upgrade (spec-gated, not built here)."
        ),
    )
    parser.add_argument(
        "--node-id",
        default=None,
        help="stable node id for this sidecar (defaults per role: mesh-node-demo-1 "
        "for provider, mesh-requester-demo-1 for requester). On the requester role "
        "this is the requesting_party recorded in serving_provenance.",
    )
    parser.add_argument(
        "--ledger-dir",
        default=str(Path.cwd() / "ledger"),
        help="defaults to ./ledger in the current working directory (not the package install location) "
        "so a pip/pipx install writes into wherever you run it from.",
    )
    parser.add_argument(
        "--manifest",
        default=str(Path.cwd() / "model-package" / "model-package.json"),
        help="path to mesh-llm's own model-package.json for the model currently loaded. Defaults to "
        "./model-package/model-package.json in the current working directory; see QUICKSTART.md for "
        "how to get one (or generate a placeholder fixture with build_model_package.py).",
    )
    parser.add_argument("--runtime-label", default="unspecified-real-node")
    parser.add_argument("--runtime-artifact", help="path to a binary/artifact to hash for runtime_digest (read-only, never executed)")
    parser.add_argument(
        "--checkpoint-config",
        help="path to a TOML file with a [checkpoint] table (Layers 1-2: local MMR + optional witness "
        "registration); omit to stay at Layer 0 (a signed capsule per exchange, no local log). See "
        "checkpoint.example.toml.",
    )
    parser.add_argument(
        "--plugin-ledger-dir",
        help="the Rust plugin's OWN ledger dir (plugins/capsule-producer's <ledger_dir>, containing its "
        "capsules.jsonl) -- when given, this sidecar ALSO checkpoints that log (read-only; two "
        "single-writer logs, one machine view -- see checkpointing.py). Omit to leave the plugin's log "
        "unchecked (Layer 0 only, same as today).",
    )
    parser.add_argument(
        "--plugin-keys-dir",
        help="the Rust plugin's keys_dir (<dir>/node-key.pem). Defaults to this sidecar's own --keys-dir "
        "(the shared-identity deployment plugins/capsule-producer/src/keys.rs documents); only needed "
        "with --plugin-ledger-dir.",
    )
    parser.add_argument(
        "--plugin-checkpoint-config",
        help="a [checkpoint] TOML for the plugin's log specifically (independent cadence -- serving runs "
        "hotter than the sidecar's own request log). Falls back to --checkpoint-config when omitted; "
        "only used with --plugin-ledger-dir.",
    )
    parser.add_argument(
        "--advertisement",
        help="path to a JSON advertisement -- the node's self-attested CLAIM of what it can serve "
        "(model/quantization/hardware; see advertisement.Advertisement.to_value()). Co-carried into "
        "every capsule and reconciled against the served record (verify-after-advertise, §12.3). Omit "
        "to advertise nothing (reconciliation reports advertisement_absent -- never a silent pass).",
    )
    parser.add_argument(
        "--node-ownership",
        help="[b4-who-did] path to mesh-llm's signed owner-identity cert "
        "(node-ownership.json, written by `mesh-llm auth init`). OPT-IN / off by "
        "default: without it, serving capsules seal served_by_node_id only and "
        "mark the owner ABSENT (never fabricated). With it, an identity capsule "
        "(the 'who') is sealed at startup and every serving capsule's provenance "
        "binds owner_id + cites that capsule (the 'did' cites the 'who'), after a "
        "cheap first-serve validity re-check. Owner identity is self-asserted -- "
        "see node_ownership.IDENTITY_LIMITATION_CAVEAT.",
    )
    args = parser.parse_args(argv)

    advertisement = None
    if args.advertisement:
        advertisement = Advertisement.from_value(json.loads(Path(args.advertisement).read_text(encoding="utf-8")))

    if args.runtime_artifact:
        runtime_digest = _sha256_hex(Path(args.runtime_artifact).read_bytes())
    else:
        runtime_digest = "0" * 64
        print("WARNING: no --runtime-artifact given; runtime_digest is a placeholder. See README.")

    # [b4-who-did] Load mesh-llm's opt-in owner cert if a path was given. Absent
    # (the default) degrades gracefully to did-only, owner ABSENT.
    node_ownership = None
    if args.node_ownership:
        node_ownership = load_signed_node_ownership(Path(args.node_ownership))
        if node_ownership is None:
            print(f"WARNING: --node-ownership {args.node_ownership!r} missing or malformed; owner identity ABSENT (did-only).")

    node_id = args.node_id or (
        "mesh-requester-demo-1" if args.role == ROLE_REQUESTER else "mesh-node-demo-1"
    )
    keys_dir = Path.cwd() / "keys"
    state = default_state(
        ledger_dir=Path(args.ledger_dir),
        manifest_path=Path(args.manifest),
        keys_dir=keys_dir,
        runtime_label=args.runtime_label,
        runtime_digest=runtime_digest,
        checkpoint_config_path=Path(args.checkpoint_config) if args.checkpoint_config else None,
        plugin_ledger_dir=Path(args.plugin_ledger_dir) if args.plugin_ledger_dir else None,
        plugin_keys_dir=Path(args.plugin_keys_dir) if args.plugin_keys_dir else None,
        plugin_checkpoint_config_path=(
            Path(args.plugin_checkpoint_config) if args.plugin_checkpoint_config else None
        ),
        advertisement=advertisement,
        node_ownership=node_ownership,
        role=args.role,
        node_id=node_id,
    )

    # [b4-who-did] Seal the identity capsule (the "who") ONCE at startup, if a
    # cert is present. Serving capsules then cite its capsule_id. Only cited when
    # the first-serve re-check passes, so an expired/mismatched cert is sealed as
    # a record but never presented as a live owner binding.
    if state.node_ownership is not None:
        maybe_seal_identity_capsule(state)
    if state.checkpoint is not None:
        # Latest-checkpoint-on-reconnect: catch up on anything this node
        # accrued locally while this process wasn't running, in one shot.
        reconnect_cp = state.checkpoint.reconnect()
        if reconnect_cp is not None:
            print(f"reconnect checkpoint emitted: {state.checkpoint.witness_status()}")
    if state.plugin_checkpoint is not None:
        plugin_reconnect_cp = state.plugin_checkpoint.reconnect()
        if plugin_reconnect_cp is not None:
            print(f"plugin-ledger reconnect checkpoint emitted: {state.plugin_checkpoint.witness_status()}")
    server = run_sidecar(listen_host=args.listen_host, listen_port=args.listen_port, upstream_base=args.upstream, state=state)
    print(f"capsule sidecar listening on http://{args.listen_host}:{args.listen_port} -> upstream {args.upstream}")
    print(f"role={state.role} node_id={state.node_id} model_package_digest={state.model_package_digest}")
    if state.role == ROLE_REQUESTER:
        print(
            "  requester role: sealing this node's OWN-HALF capsule per request "
            "(its request + the response it received). Correlate with the "
            "provider's served-half capsule on serving_provenance.exchange_id."
        )
    if state.checkpoint is not None:
        print(f"checkpointing enabled: log_id={state.checkpoint.log_id} {state.checkpoint.witness_status()}")
    if state.plugin_checkpoint is not None:
        print(f"plugin-ledger checkpointing enabled: log_id={state.plugin_checkpoint.log_id} {state.plugin_checkpoint.witness_status()}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

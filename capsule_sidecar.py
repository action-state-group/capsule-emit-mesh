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

from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource, load_checkpoint_config
from model_identity import load_manifest, model_package_digest

# Generation parameters we carry verbatim (not digested -- these are policy
# knobs, not prompt content, and are useful for audit as legible values).
GENERATION_PARAM_KEYS = (
    "temperature",
    "top_p",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "seed",
    "presence_penalty",
    "frequency_penalty",
    "stop",
)

CLIENT_NONCE_HEADER = "X-Capsule-Client-Nonce"
SIG_ALG = "EdDSA"

# Bilateral request attestation headers (Move 1 of draft-mih-agent-bilateral-attestation-01).
# Lowercased — HTTP/1.1 headers are case-insensitive; the handler normalises them before lookup.
BILATERAL_RA_HEADER = "x-capsule-request-attestation"
BILATERAL_RA_SIG_HEADER = "x-capsule-request-attestation-sig"
BILATERAL_PUBKEY_HEADER = "x-capsule-client-pubkey"

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
    """
    if not cross_party or not cross_party.get("initiator_ref"):
        return "unilateral_fallback"
    if has_verified_ack:
        return "full_bilateral"
    return "acknowledged_receipt"


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
    manifest_path: Path
    runtime_label: str
    runtime_digest: str
    ledger_dir: Path
    last_capsule_id: str | None = None
    emitted: list[dict[str, Any]] = field(default_factory=list)
    checkpoint_config_path: Path | None = None

    def __post_init__(self) -> None:
        self.manifest = load_manifest(self.manifest_path)
        self.model_package_digest = model_package_digest(self.manifest)
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.ledger_dir / "capsules.jsonl"
        self.statements_dir = self.ledger_dir / "signed-statements"
        self.statements_dir.mkdir(parents=True, exist_ok=True)

        self.log_source = JsonlLogSource(self.ledger_path)
        self.checkpoint: CheckpointState | None = None
        if self.checkpoint_config_path is not None:
            loaded = load_checkpoint_config(self.checkpoint_config_path)
            if loaded is not None:
                cfg, log_id_override = loaded
                log_id = log_id_override or self.node_id
                signer = Ed25519Signer(log_id, self.signing_key_pem)
                self.checkpoint = CheckpointState.load(
                    ledger_dir=self.ledger_dir,
                    log_source=self.log_source,
                    cfg=cfg,
                    signer=signer,
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
                "non-conformant-demo-key: self-generated Ed25519 key; not bound to "
                "any third-party-issued credential or trusted root; "
                "draft-mih-agent-bilateral-attestation-01 §4.1 states first-use "
                "acceptance MUST NOT be treated as conformant bilateral attestation"
            ) if bilateral_eval and bilateral_eval.present else None,
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
    state.log_source.append(capsule)
    (state.statements_dir / f"{capsule['capsule_id']}.cose").write_bytes(signed_statement)
    result = verify_capsule(capsule)
    if not result.ok:
        raise RuntimeError(f"sidecar emitted a capsule that fails its own verify(): {result.findings}")
    state.last_capsule_id = capsule["capsule_id"]
    state.emitted.append(capsule)
    if state.checkpoint is not None:
        state.checkpoint.record_appended()


def _resolve_client_nonce(headers: dict[str, str]) -> tuple[str, str]:
    client_nonce = headers.get(CLIENT_NONCE_HEADER.lower())
    if client_nonce:
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
    client_nonce, client_nonce_source = _resolve_client_nonce(headers)
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
            client_nonce, client_nonce_source = _resolve_client_nonce(headers)
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
) -> NodeState:
    signing_key_pem = load_or_create_signing_key(keys_dir)
    return NodeState(
        node_id="mesh-node-demo-1",
        operator="capsule-emit-mesh-poc-demo",
        developer="capsule-emit-mesh-poc-sidecar/0.1.0",
        signing_key_pem=signing_key_pem,
        manifest_path=manifest_path,
        runtime_label=runtime_label,
        runtime_digest=runtime_digest,
        ledger_dir=ledger_dir,
        checkpoint_config_path=checkpoint_config_path,
    )


if __name__ == "__main__":
    # Standalone CLI: point this at a REAL mesh-llm node.
    #   mesh-llm serve --local-model-only --model <path.gguf> --port 9337
    #   python3 capsule_sidecar.py --upstream http://127.0.0.1:9337 --listen-port 8089
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", default="http://127.0.0.1:9337")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8089)
    parser.add_argument("--ledger-dir", default=str(Path(__file__).parent / "ledger"))
    parser.add_argument("--manifest", default=str(Path(__file__).parent / "model-package" / "model-package.json"))
    parser.add_argument("--runtime-label", default="unspecified-real-node")
    parser.add_argument("--runtime-artifact", help="path to a binary/artifact to hash for runtime_digest (read-only, never executed)")
    parser.add_argument(
        "--checkpoint-config",
        help="path to a TOML file with a [checkpoint] table (Layers 1-2: local MMR + optional witness "
        "registration); omit to stay at Layer 0 (a signed capsule per exchange, no local log). See "
        "checkpoint.example.toml.",
    )
    args = parser.parse_args()

    if args.runtime_artifact:
        runtime_digest = _sha256_hex(Path(args.runtime_artifact).read_bytes())
    else:
        runtime_digest = "0" * 64
        print("WARNING: no --runtime-artifact given; runtime_digest is a placeholder. See README.")

    state = default_state(
        ledger_dir=Path(args.ledger_dir),
        manifest_path=Path(args.manifest),
        keys_dir=Path(__file__).parent / "keys",
        runtime_label=args.runtime_label,
        runtime_digest=runtime_digest,
        checkpoint_config_path=Path(args.checkpoint_config) if args.checkpoint_config else None,
    )
    if state.checkpoint is not None:
        # Latest-checkpoint-on-reconnect: catch up on anything this node
        # accrued locally while this process wasn't running, in one shot.
        reconnect_cp = state.checkpoint.reconnect()
        if reconnect_cp is not None:
            print(f"reconnect checkpoint emitted: {state.checkpoint.witness_status()}")
    server = run_sidecar(listen_host=args.listen_host, listen_port=args.listen_port, upstream_base=args.upstream, state=state)
    print(f"capsule sidecar listening on http://{args.listen_host}:{args.listen_port} -> upstream {args.upstream}")
    print(f"node_id={state.node_id} model_package_digest={state.model_package_digest}")
    if state.checkpoint is not None:
        print(f"checkpointing enabled: log_id={state.checkpoint.log_id} {state.checkpoint.witness_status()}")
    server.serve_forever()

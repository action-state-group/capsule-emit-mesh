#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""[mesh-sidecar-provenance-fold-option3] Option 3b -- the sidecar<->plugin
hardware-provenance join.

Two producers on the SAME node observe the SAME real host-served exchange
from two different vantages, and today neither alone seals both facts:

  - The Python sidecar (`capsule_sidecar.py`, a reverse proxy) sees the full
    request/response bytes at the `/v1` wire and seals real I/O digests --
    but its own module comment is explicit that "quantization/hardware are
    facts the /v1 wire does not expose to a proxy", so they stay ABSENT
    there, never fabricated.
  - The Rust admission-policy plugin (`plugins/admission-policy/src/
    lifecycle_channel.rs` + `capsule_emit::emit_for_observed_host_exchange`)
    observes the host's `openai.exchange.v1` terminal event for the SAME
    exchange and seals real hardware (gpu/vram/architecture/model identity)
    -- but only host-forwarded DIGESTS of the I/O, never the full content.

FDE RULING (2026-08-28, `_work/gcp-3rd-node-standup.md` #7b): hardware is
OBSERVED BY THE HOST, only relayed to whichever producer reads the mesh
channel -- presenting it as if the SIDECAR observed it directly would be the
`gate_executed`-vs-`runtime_claimed` overclaim applied to provenance.
PREFERRED = two independently-sealed, single-writer capsules, joined by a
citation ("two single-writer logs, one presentation view") rather than
folding the hardware block directly into the sidecar's own capsule.

CORRELATOR -- CORRECTED BY REAL-HOST VERIFICATION (2026-09-06):

`capsule_sidecar.py`'s `EXCHANGE_ID_SOURCE` comment and `lifecycle_channel.
OpenAiExchangeEnvelope.exchange_id`'s doc comment both assert that the
sidecar's response-`id`-derived `exchange_id` and the host's own minted
`exchange_id` are "the same value" for one real exchange. **This was tested
against a real `mesh-llm serve --gguf` host (0.76.0-rc6,
`feat/serving-provenance-host-served-terminal`) and is FALSE**: the host
mints an internal UUID for its own `openai.exchange.v1` correlator
(`serving_provenance.exchange_id`, e.g. `"5b9a2b06-f929-4fe7-b272-
649681ac9263"`), completely independent of the OpenAI response `id` field it
returns to the client (e.g. `"chatcmpl-1788674397355"`, `EXCHANGE_ID_SOURCE
= "response_id"`). Joining on `exchange_id` would never correlate a single
real exchange across the two producers.

What DOES correlate, verified against the same real host: the canonical
JSON digest of the REQUEST body. The host forwards it on the terminal event
as `request_digest` (sealed into the plugin's capsule as the top-level
`compute_attestation.agent_input_digest`); the sidecar independently
computes the identical canonical digest over the same wire bytes it proxied
(`capsule_sidecar.digest_json`, sealed as its own `agent_input_digest`).
Both are the SAME cross-language-pinned canonical-JSON digest construction
(see `capsule_emit.rs`'s `canonical_body_digest_matches_python_reference_
digest_json` test) -- confirmed byte-identical in the real-host run:
`77c0e133dc7b0a84c6231171efe2d190998b550275dc528ff1a605e40feef4db` on both
sides for one real exchange. This module therefore joins on
`compute_attestation.agent_input_digest`, NOT `exchange_id`.

KNOWN LIMITATION (stated, not hidden): two BYTE-IDENTICAL requests to the
same model produce the same `agent_input_digest` -- verified directly (two
identical requests through the real host both digested to the value above).
`find_host_provenance_capsule()` resolves ambiguity by returning the MOST
RECENTLY sealed match; a caller joining a high-traffic node with frequently
repeated prompts should additionally narrow by timestamp proximity. This is
a real, disclosed correlator weakness -- raised under `## Needs decision`
in the outbox for this task, not silently accepted as sufficient forever.

This module never touches the sidecar's own `serving_provenance` block --
hardware there stays exactly what `capsule_sidecar.py` already honestly
records (absent). It only mints a SEPARATE, later join capsule (same "two
already-sealed capsules, offline" shape as `served_request_join.py`) citing
the plugin's provenance capsule by CPB typed digest reference.

SHAPE NOTE: the plugin's real `x-mesh-poc-v1.serving_provenance` nests
hardware/model facts under `hardware` (`gpu`, `vram_bytes`, `device`,
`is_soc`) and `model` (`architecture`, `identity_hash`, `weights_digest`,
`canonical_ref`, `revision`, `context_length`, `parameter_size`,
`layer_count`) sub-objects -- confirmed against a real captured capsule, not
assumed from the Rust struct's field-literal names (which are flat at the
construction call site; the wire JSON groups them).

WHAT THIS IS NOT
  - NOT a real-time capture path -- the join is a second, later step over two
    ALREADY-SEALED capsules, exactly like `served_request_join.py`.
  - NOT a mutation, and NOT a trust upgrade for either half: `join_hardware_
    provenance()` refuses to mint over a half that does not already verify
    on its own bytes.
  - NOT a substitute for the honest three-state absence: when the plugin has
    not (yet) sealed a matching capsule for this exchange (the §6-#2
    host-restart / delivery-race lag, or simply not-yet-delivered), `find_
    host_provenance_capsule()` returns `None` and `hardware_provenance_
    status()` reports `"absent"` -- never a fabricated `"present"`, and no
    join is minted.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import scitt_cose

from agent_action_capsule.canonical import compute_capsule_id
from agent_action_capsule.verify import verify as verify_capsule
from served_request_join import build_reference

__all__ = [
    "CITATION_PURPOSE_CITES_HOST_PROVENANCE",
    "HARDWARE_PROVENANCE_VANTAGE_CAVEAT",
    "JOIN_CHAIN_RELATION",
    "JOIN_CONTENT_TYPE",
    "JOIN_SCHEMA",
    "SIG_ALG",
    "IoDigestMismatchError",
    "JoinerNotServingNodeError",
    "RoleNotServedError",
    "SignerMismatchError",
    "UnverifiableHalfError",
    "find_host_provenance_capsule",
    "hardware_provenance_status",
    "join_hardware_provenance",
    "sign_hardware_provenance_join",
    "verify_hardware_provenance_join_signature",
]

#: PROVISIONAL, same posture as CPB #70's role/observation_point pair
#: (`capsule_sidecar.py`'s own note): not yet a promoted registry entry, so
#: this module hard-codes the value ahead of promotion, matching the
#: vocabulary a future `scitt-payload-binding` registry entry would use
#: exactly, so promotion is a rename, not a reshape.
CITATION_PURPOSE_CITES_HOST_PROVENANCE = "cites_host_provenance"

#: Same-stream continuation of the SIDECAR's own ledger (never the plugin's
#: -- that citation is exclusively the `references` entry below), mirroring
#: `served_request_join.JOIN_CHAIN_RELATION`'s reasoning.
JOIN_CHAIN_RELATION = "confirms"

JOIN_SCHEMA = "capsule-emit-mesh/provenance-fold-join/v1"

#: EdDSA (Ed25519) -- same alg name every other capsule this node signs uses.
SIG_ALG = "EdDSA"

JOIN_CONTENT_TYPE = f"application/vnd.agent-action-capsule+json; profile={JOIN_SCHEMA}"

#: Sealed INTO the join capsule's own content (`compute_attestation.
#: hardware_provenance_fold.vantage_caveat`) so the honesty grade travels
#: with the bytes -- same discipline as `served_request_join.
#: JOIN_ASSERTION_CAVEAT`. Names exactly what citing the plugin's capsule
#: does and does not mean: the hardware fact remains the PLUGIN's own
#: observation, never re-labeled as the sidecar's.
HARDWARE_PROVENANCE_VANTAGE_CAVEAT = (
    "vantage-honesty: the hardware facts in the CITED capsule were observed and sealed "
    "by the party that mints THAT capsule (the admission-policy plugin, in-host, off the "
    "mesh openai.exchange.v1 terminal event) -- never by the joiner. This join capsule "
    "does not re-assert the cited hardware as its own observation; it only cites the "
    "other producer's already-sealed, independently-verifiable record by digest. "
    "Presenting host-observed-and-relayed hardware as if the joiner observed it directly "
    "is exactly the gate_executed-vs-runtime_claimed overclaim this label exists to "
    "prevent (2026-08-28 FDE ruling, gcp-3rd-node-standup.md #7b). Correlated by "
    "agent_input_digest, NOT exchange_id -- see module docstring for why."
)


class UnverifiableHalfError(RuntimeError):
    """A supplied half fails its own `agent_action_capsule.verify()`.

    The join can only add a citation between two records that were already
    independently sound.
    """


class RoleNotServedError(ValueError):
    """Either half's `x-mesh-poc-v1.role` is not `"served"`.

    Both producers must be attesting the SERVED side of the SAME real
    exchange -- a `"requested"`/`"unknown"` role half names a different
    relationship and must never be folded in as if it were this node's own
    served-side hardware.
    """


class IoDigestMismatchError(ValueError):
    """The two halves do not share one `compute_attestation.agent_input_digest`.

    Joining two capsules for DIFFERENT requests would fabricate a
    same-exchange relationship that never happened at the wire -- refused
    rather than minted. (NOT `exchange_id`: verified false correlator across
    these two producers -- see module docstring.)
    """


class JoinerNotServingNodeError(ValueError):
    """*joiner_node_id* is not the node the sidecar half names as the server.

    Mirrors `served_request_join.JoinerNotRequesterError`'s discipline: only
    the node that actually served the exchange (named in its own
    sidecar-sealed `serving_provenance.served_by_node_id`) may mint a join
    citing the plugin's hardware observation for it.
    """


class SignerMismatchError(ValueError):
    """*signing_node_id* does not match this join's own `asserted_by_node_id`."""


def _compute_attestation(capsule: dict[str, Any]) -> dict[str, Any]:
    return (capsule.get("model_attestation") or {}).get("compute_attestation") or {}


def _poc(capsule: dict[str, Any]) -> dict[str, Any]:
    return _compute_attestation(capsule).get("x-mesh-poc-v1") or {}


def _serving_provenance(capsule: dict[str, Any]) -> dict[str, Any]:
    return _poc(capsule).get("serving_provenance") or {}


def _role(capsule: dict[str, Any]) -> str | None:
    return _poc(capsule).get("role")


def _agent_input_digest(capsule: dict[str, Any]) -> str | None:
    return _compute_attestation(capsule).get("agent_input_digest")


def hardware_provenance_status(plugin_capsule: dict[str, Any] | None) -> str:
    """Three-state honesty check for the hardware-provenance fold: returns
    `"present"` or `"absent"` -- NEVER `None`-as-if-present, and never
    fabricated. `"absent"` covers both "no matching plugin capsule exists yet"
    (the §6-#2 host-restart / delivery-race lag -- pass `None`) and "a
    matching capsule exists but its own hardware fields are honestly empty".
    """
    if plugin_capsule is None:
        return "absent"
    sp = _serving_provenance(plugin_capsule)
    hardware = sp.get("hardware") or {}
    model = sp.get("model") or {}
    if hardware.get("gpu") or model.get("architecture") or model.get("identity_hash"):
        return "present"
    return "absent"


def find_host_provenance_capsule(ledger_dir: Path, agent_input_digest: str) -> dict[str, Any] | None:
    """Scan a Rust admission-policy plugin's `capsules.jsonl` ledger for the
    host-served-observed capsule sharing *agent_input_digest* (the canonical
    digest of the real request body -- NOT `exchange_id`, which does not
    correlate across producers; see module docstring).

    Returns `None` -- never raises, never fabricates a match -- when no
    capsule in the ledger carries this digest (yet): the honest §6-#2 case
    where the host's terminal-event broadcast for this exchange has not been
    observed/sealed by the plugin, e.g. immediately after a host restart, or
    a fire-and-forget delivery race. Scans newest-first, so on the disclosed
    ambiguity of two byte-identical requests to the same model, the most
    recently sealed match wins.
    """
    capsules_path = Path(ledger_dir) / "capsules.jsonl"
    if not capsules_path.is_file():
        return None
    for raw_line in reversed(capsules_path.read_text().splitlines()):
        if not raw_line.strip():
            continue
        capsule = json.loads(raw_line)
        if _agent_input_digest(capsule) == agent_input_digest:
            return capsule
    return None


def join_hardware_provenance(
    sidecar_capsule: dict[str, Any],
    plugin_capsule: dict[str, Any],
    *,
    joiner_node_id: str,
    operator: str = "",
    developer: str = "",
) -> dict[str, Any]:
    """Mint the sidecar<->plugin hardware-provenance join capsule.

    *sidecar_capsule* is the sidecar's already-sealed real-I/O capsule for a
    real host-served exchange (`x-mesh-poc-v1.role == "served"`);
    *plugin_capsule* is the plugin's already-sealed host-observed-provenance
    capsule for the SAME exchange (also `role == "served"`, same
    `compute_attestation.agent_input_digest`). Returns a new capsule, chained
    onto the SIDECAR's own stream (`chain.parent_capsule_id ==
    sidecar_capsule["capsule_id"]`, `chain.relation == "confirms"`), whose
    `references` array cites the plugin capsule by CPB typed digest reference
    (`citation_purpose == "cites_host_provenance"`).

    This capsule is still, on its own, only a self-attestation -- call
    `sign_hardware_provenance_join()` on the return value to produce the
    actual signed statement a stranger can check.

    Raises :class:`UnverifiableHalfError` if either half fails its own
    `verify()`, :class:`RoleNotServedError` if either half's `role` is not
    `"served"`, :class:`IoDigestMismatchError` if they do not share one
    `agent_input_digest`, and :class:`JoinerNotServingNodeError` if
    *joiner_node_id* is not the node the sidecar half itself names as
    `served_by_node_id`.
    """
    from agent_action_capsule.contracts import Disposition
    from agent_action_capsule.emit import emit

    for half, label in ((sidecar_capsule, "sidecar"), (plugin_capsule, "plugin")):
        result = verify_capsule(half)
        if not result.ok:
            raise UnverifiableHalfError(f"{label} half fails verify(): {result.findings}")

    for half, label in ((sidecar_capsule, "sidecar"), (plugin_capsule, "plugin")):
        role = _role(half)
        if role != "served":
            raise RoleNotServedError(f"{label} half's x-mesh-poc-v1.role == {role!r}, expected 'served'")

    sidecar_digest = _agent_input_digest(sidecar_capsule)
    plugin_digest = _agent_input_digest(plugin_capsule)
    if not sidecar_digest or sidecar_digest != plugin_digest:
        raise IoDigestMismatchError(
            f"sidecar agent_input_digest {sidecar_digest!r} != "
            f"plugin agent_input_digest {plugin_digest!r} -- refusing to join"
        )

    served_by = _serving_provenance(sidecar_capsule).get("served_by_node_id")
    if joiner_node_id != served_by:
        raise JoinerNotServingNodeError(
            f"joiner_node_id {joiner_node_id!r} != sidecar half's own "
            f"serving_provenance.served_by_node_id {served_by!r} -- only the "
            f"node that actually served the exchange may mint this join"
        )

    compute_attestation = {
        "hardware_provenance_fold": {
            "schema": JOIN_SCHEMA,
            "agent_input_digest": sidecar_digest,
            "asserted_by_node_id": joiner_node_id,
            "vantage_caveat": HARDWARE_PROVENANCE_VANTAGE_CAVEAT,
        }
    }
    disposition = Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="executed")

    sealed = emit(
        action_type="fyi",
        operator=operator,
        developer=developer,
        compute_attestation=compute_attestation,
        disposition=disposition,
        prior_capsule_id=sidecar_capsule["capsule_id"],
        chain_relation=JOIN_CHAIN_RELATION,
        domain="action",
        provenance="collector",
        tool_name="provenance_fold_join",
    )
    joined = dict(sealed)
    joined["references"] = [
        build_reference(plugin_capsule["capsule_id"], citation_purpose=CITATION_PURPOSE_CITES_HOST_PROVENANCE)
    ]
    joined["capsule_id"] = compute_capsule_id(joined)

    result = verify_capsule(joined)
    if not result.ok:
        raise RuntimeError(f"join_hardware_provenance emitted a capsule that fails its own verify(): {result.findings}")
    return joined


def _asserted_by_node_id(joined_capsule: dict[str, Any]) -> str | None:
    ca = (joined_capsule.get("model_attestation") or {}).get("compute_attestation") or {}
    return (ca.get("hardware_provenance_fold") or {}).get("asserted_by_node_id")


def _canonical_join_payload(joined_capsule: dict[str, Any]) -> bytes:
    return json.dumps(joined_capsule, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_hardware_provenance_join(
    joined_capsule: dict[str, Any],
    *,
    signing_key_pem: bytes | str,
    signing_node_id: str,
) -> bytes:
    """Sign *joined_capsule* under the joiner's own node key.

    Raises :class:`SignerMismatchError` if *signing_node_id* is not this
    join's own `asserted_by_node_id`.
    """
    asserted_by = _asserted_by_node_id(joined_capsule)
    if signing_node_id != asserted_by:
        raise SignerMismatchError(
            f"signing_node_id {signing_node_id!r} != this join's own "
            f"asserted_by_node_id {asserted_by!r} -- refusing to sign a join "
            f"under an identity different from the one already sealed into "
            f"its content"
        )
    return scitt_cose.build_signed_statement(
        _canonical_join_payload(joined_capsule),
        alg=SIG_ALG,
        private_key_pem=signing_key_pem,
        issuer=signing_node_id,
        subject=joined_capsule["capsule_id"],
        content_type=JOIN_CONTENT_TYPE,
    )


def verify_hardware_provenance_join_signature(
    joined_capsule: dict[str, Any],
    signed_statement: bytes,
    *,
    public_key_pem: bytes | str,
) -> tuple[bool, str]:
    """Verify a join's signature. Returns `(valid, reason)` -- never raises."""
    parsed = scitt_cose.parse_signed_statement(signed_statement, public_key_pem=public_key_pem)
    if not parsed["signature_verified"]:
        return False, "join signature does not verify under the supplied public key"
    if parsed["payload"] != _canonical_join_payload(joined_capsule):
        return False, "join signature covers different bytes than this capsule"
    if parsed["subject"] != joined_capsule.get("capsule_id"):
        return False, (
            f"signed subject {parsed['subject']!r} != this capsule's own "
            f"capsule_id {joined_capsule.get('capsule_id')!r}"
        )
    asserted_by = _asserted_by_node_id(joined_capsule)
    if parsed["issuer"] != asserted_by:
        return False, (
            f"signature issuer {parsed['issuer']!r} does not match this "
            f"join's own asserted_by_node_id claim {asserted_by!r}"
        )
    return True, (
        f"join signature verified: {asserted_by!r} signed these exact bytes, "
        f"subject == this capsule's own capsule_id"
    )

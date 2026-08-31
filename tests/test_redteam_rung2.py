# SPDX-License-Identifier: Apache-2.0
"""B5b — adversarial red-team of the DEPLOYED config / identity rungs (RUNG 2+).

Where B5a (`test_redteam_rung1.py`) attacked what the signed/witnessed ledger
alone buys, this module attacks the rungs stacked ON TOP of it:

  * RUNG 2  — the config cross-check seam + its TRIVIAL baseline
              (`output_cross_check.check_output_against_config`, B2), plus the
              advertised-vs-served reconciliation it sits beside
              (`advertisement.reconcile_advertised_vs_served`).
  * RUNG 2  — self-measured binary attestation
              (`plugins/capsule-producer/src/runtime_attest.rs`, B3). The Rust
              side is red-teamed in that crate's own tests
              (`redteam_rung2_self_measured.rs`); the residual is RESTATED here
              so the rung-2+ findings table (`docs/REDTEAM-RUNG2.md`) is complete.
  * RUNG 2+ — the owner->node binding (`node_ownership.recheck_ownership_validity`,
              B4). Here we DEMAND the defence hold: forged / expired / mismatched
              certs must be CAUGHT/LABELED and never cited as a live owner.

Each attack builds a concrete harness against real (throwaway) capsule material
and records the outcome as one of:

    CAUGHT     -- the machinery rejects it / marks it invalid (never cited live)
    LABELED    -- not rejected, but named honestly in the record so a verifier
                  sees the degradation
    RESIDUAL   -- it succeeds and the current rung has no handle to see it. The
                  closing follow-on is named in the assertion.

THE HEADLINE FINDING (stated up front, proven below):
  Model-id spoof, quant swap, and hardware fake LARGELY SUCCEED against the
  current prototype. This is BY DESIGN and is the product of the exercise: the
  config claim is self-reported, so a node that lies CONSISTENTLY (lies in the
  advertisement AND in the served record) reconciles CLEAN — reconcile compares
  two self-attested claims from the SAME party. B2's trivial baseline is a
  token-rate / output-shape SANITY only; it reads plausibility, not identity,
  and cannot bind an output to a specific model/quant/hardware. Only a future
  REAL statistical reference model could, and even then only probabilistically.

  Owner-binding attacks, by contrast, are CAUGHT/LABELED — B4 holds.

The findings table is `docs/REDTEAM-RUNG2.md`. Each test below
is the executable evidence for one row; the docstrings and the table must agree.

NEUTRALITY: this harness reads metered facts (token counts, wall-clock ms) and
signed identity claims. It carries no currency, rate, or Authority. Meter, not
price.
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from advertisement import Advertisement, reconcile_advertised_vs_served
from node_ownership import (
    OWNER_STATUS_ABSENT,
    OWNER_STATUS_BOUND,
    OWNER_STATUS_INVALID,
    NodeOwnershipClaim,
    SignedNodeOwnership,
    canonical_claim_bytes,
    owner_provenance_block,
    recheck_ownership_validity,
)
from output_cross_check import (
    DIRECTION_LOWERS,
    DIRECTION_RAISES,
    ConfigClaim,
    check_output_against_config,
)


# ==========================================================================
# Shared throwaway material
# ==========================================================================

NODE_ID_HEX = "42" * 32
OTHER_NODE_HEX = "24" * 32


def _served_record(
    *,
    model_id: str,
    quantization: str,
    gpu: str | None,
    vram_bytes: int | None,
    is_soc: bool | None,
    node_id: str = NODE_ID_HEX,
) -> dict:
    """A serving-provenance block shaped like what the sidecar seals.

    The KEY adversarial property: this is the SAME node reporting what it served.
    A cheater controls every field here — it is self-reported, not measured by an
    independent party. So it can be filled in to match a lying advertisement.
    """
    return {
        "served_by_node_id": node_id,
        "model": {"model_id": model_id},
        "quantization": quantization,
        "hardware": {"gpu": gpu, "vram_bytes": vram_bytes, "is_soc": is_soc},
    }


def _response(*, completion: int, wall_clock_ms: str, prompt: int = 20) -> dict:
    return {
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
        "compute_meter": {"unit": "milliseconds", "wall_clock_ms": wall_clock_ms},
    }


def _owner_key():
    return Ed25519PrivateKey.generate()


def _pub_hex(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def _signed_cert(
    key,
    *,
    node_id_hex: str = NODE_ID_HEX,
    expires_ms: int | None = None,
    version: int = 1,
    owner_id: str = "owner-abc123",
    sign_key=None,
) -> SignedNodeOwnership:
    """Build a SignedNodeOwnership. ``sign_key`` (if given) signs INSTEAD of the
    embedded key — the forgery lever for the owner-binding attack."""
    now = int(time.time() * 1000)
    claim = NodeOwnershipClaim(
        version=version,
        cert_id="cert-0001",
        owner_id=owner_id,
        owner_sign_public_key=_pub_hex(key),
        node_endpoint_id=node_id_hex,
        issued_at_unix_ms=now,
        expires_at_unix_ms=expires_ms if expires_ms is not None else now + 60_000,
        node_label="studio",
        hostname_hint="studio-host",
    )
    signer = sign_key if sign_key is not None else key
    signature = signer.sign(canonical_claim_bytes(claim)).hex()
    return SignedNodeOwnership(claim=claim, signature=signature)


# ==========================================================================
# ATTACK 5 — MODEL-ID SPOOF  ->  outcome: RESIDUAL (uncaught by rung 1/2)
# ==========================================================================
#
# Mechanism: the node declares model X in its sealed config claim but the
# exchange actually served model Y. Because the config claim is SELF-REPORTED,
# a lying node fills BOTH the advertisement AND the served record with the same
# lie (X), so they are internally consistent. reconcile_advertised_vs_served
# only compares those two self-attested claims — it has nothing external to
# check X against. B2's baseline reads output SHAPE, not identity, so it cannot
# bind the output to model X vs Y at all.
# ==========================================================================


def test_attack5_model_spoof_reconciles_clean_when_lie_is_consistent():
    """Advertise model X, serve (in the record) model X, but the REAL model was
    Y. The advertisement and the record agree, so reconcile returns `match` —
    the spoof is invisible to the advertised-vs-served reconciliation.

    -> RESIDUAL (uncaught). The lie is self-consistent because one party wrote
    both sides. This is the honest-gap the advertisement module already names
    (`advertisement_self_signed`): reconciling two claims from ONE party cannot
    catch a party that lies on both.
    """
    lie = "meta/Llama-3.2-70B-Instruct"           # the node CLAIMS the big model
    ad = Advertisement(node_id=NODE_ID_HEX, model_id=lie, quantization="Q8_0")
    served = _served_record(
        model_id=lie,                              # ...and its record repeats the lie
        quantization="Q8_0",
        gpu="NVIDIA H100", vram_bytes=80 * 1024**3, is_soc=False,
    )

    result = reconcile_advertised_vs_served(ad, served)
    # No broken promise found — because the promise and the record are the SAME lie.
    assert result["overall"] == "match", result
    assert result["fields"]["model_id"]["verdict"] == "match"
    assert result["mismatches"] == []
    # The honesty caveat is the ONLY thing standing between this and a false
    # "verified": reconcile explicitly names that both sides are one party's claim.
    assert "advertisement_self_signed" in result
    # CLOSED BY: a counterparty-held / member-signed discovery note (two parties,
    # TRUST-MODEL §9.1) so the served model can be checked against an
    # INDEPENDENTLY-held claim; or a real statistical model that fingerprints the
    # output to a model family. Neither exists at rung 1/2.


def test_attack5_baseline_crosscheck_cannot_see_model_identity():
    """B2's trivial baseline gives the SAME (plausible) direction whether the
    claimed model is the 3B or the 70B — it reads token-rate/shape, never model
    identity. So it provides ZERO signal on a model-id spoof.

    -> RESIDUAL. The baseline is deliberately identity-blind; only the future
    real statistical reference model could attempt this, and only probabilistically.
    """
    resp = _response(completion=40, wall_clock_ms="600.000")   # ~66 tok/s
    req = {"max_tokens": 128}

    small = ConfigClaim(model_id="meta/Llama-3.2-3B", quantization="Q8_0",
                        hardware_gpu="NVIDIA H100", hardware_is_soc=False)
    big = ConfigClaim(model_id="meta/Llama-3.2-70B", quantization="Q8_0",
                      hardware_gpu="NVIDIA H100", hardware_is_soc=False)

    r_small = check_output_against_config(small, req, resp)
    r_big = check_output_against_config(big, req, resp)
    # Identical direction: the baseline literally does not consult model_id.
    assert r_small.confidence_direction == r_big.confidence_direction
    assert r_small.confidence_direction == DIRECTION_RAISES  # both read "plausible"
    # There is no observation anywhere that references the model identity.
    for r in (r_small, r_big):
        assert not any("model" in o.name.lower() for o in r.observations)


# ==========================================================================
# ATTACK 6 — QUANT SWAP  ->  outcome: RESIDUAL (uncaught by the trivial baseline)
# ==========================================================================
#
# Mechanism: claim Q8 (high fidelity) but serve Q4 (degraded, cheaper/faster).
# The economically-motivated swap. Does the token-rate / output-shape baseline
# flag it? Expect: mostly NO. Q4 and Q8 differ in OUTPUT QUALITY, which the
# baseline never inspects; and a Q4 that runs FASTER stays inside the same wide
# tokens/sec band. The baseline is deliberately trivial — that is the finding.
# ==========================================================================


def test_attack6_quant_swap_reconciles_clean_when_consistent():
    """Same self-report gap as the model spoof: advertise Q4, serve-record Q4,
    but REALLY the node promised Q8 elsewhere. Within the offline bundle the two
    self-attested claims agree, so reconcile is `match`.

    -> RESIDUAL. The economic swap (promise Q8, deliver Q4) is only visible if
    the ORIGINAL Q8 promise is independently held; the node's own bundle only
    ever shows the Q4 it decided to admit.
    """
    ad = Advertisement(node_id=NODE_ID_HEX, model_id="meta/Llama-3.2-3B", quantization="Q4_K_M")
    served = _served_record(
        model_id="meta/Llama-3.2-3B", quantization="Q4_K_M",
        gpu="Apple M4 Max", vram_bytes=42 * 1024**3, is_soc=True,
    )
    result = reconcile_advertised_vs_served(ad, served)
    assert result["overall"] == "match"
    assert result["fields"]["quantization"]["verdict"] == "match"


def test_attack6_baseline_does_not_flag_a_faster_degraded_quant():
    """A degraded Q4 that serves FASTER than a claimed-Q8 rate stays comfortably
    inside the same coarse tokens/sec band, and its completion length is
    plausible — so the baseline RAISES confidence on a QUALITY-degraded serve.

    -> RESIDUAL (uncaught). The baseline never inspects output QUALITY (the only
    thing that actually distinguishes Q4 from Q8); it reads rate + shape, which a
    quant swap leaves in-band. This is the finding: the trivial baseline cannot
    survive a quant swap. Closed by the REAL statistical reference model
    (expected output distribution per model/quant), which is future work.
    """
    claim_q8 = ConfigClaim(model_id="meta/Llama-3.2-3B", quantization="Q8_0",
                           hardware_gpu="NVIDIA A100", hardware_is_soc=False)
    # A Q4 serve: faster (higher tok/s) but still well inside the discrete-GPU band.
    resp = _response(completion=120, wall_clock_ms="800.000")   # 150 tok/s
    result = check_output_against_config(claim_q8, {"max_tokens": 256}, resp)
    assert result.confidence_direction == DIRECTION_RAISES, (
        "the trivial baseline RAISES on a degraded-quant serve — it never inspects "
        "quality, only rate/shape. This uncaught result is the point."
    )
    assert result.lowers() is False
    assert not any("quant" in o.name.lower() for o in result.observations)


# ==========================================================================
# ATTACK 7 — HARDWARE FAKE  ->  outcome: RESIDUAL (uncaught; coarse-only lever)
# ==========================================================================
#
# Mechanism: claim a better GPU / more VRAM than actually used (e.g. claim an
# H100/80GB while really running a modest card or a laptop SoC). Self-reported,
# so reconcile is clean. The ONLY lever the baseline has is tokens/sec-vs-claimed-
# hardware — and it is COARSE: the bands are wide and only two-kind (soc vs
# discrete_gpu), so a realistic fake stays in-band.
# ==========================================================================


def test_attack7_hardware_fake_reconciles_clean_when_consistent():
    ad = Advertisement(
        node_id=NODE_ID_HEX, model_id="meta/Llama-3.2-3B", quantization="Q4_K_M",
        hardware_gpu="NVIDIA H100", hardware_vram_bytes=80 * 1024**3, hardware_is_soc=False,
    )
    served = _served_record(
        model_id="meta/Llama-3.2-3B", quantization="Q4_K_M",
        gpu="NVIDIA H100", vram_bytes=80 * 1024**3, is_soc=False,   # the record repeats the fake
    )
    result = reconcile_advertised_vs_served(ad, served)
    assert result["overall"] == "match"
    assert result["fields"]["hardware_gpu"]["verdict"] == "match"
    assert result["fields"]["hardware_vram_bytes"]["verdict"] == "match"


def test_attack7_baseline_band_is_too_coarse_to_catch_a_plausible_hw_fake():
    """Claim a discrete H100 (80GB) while REALLY serving from a modest box. A
    realistic serve rate (say 60 tok/s) sits inside the WIDE discrete_gpu band
    [2, 2000], so the baseline RAISES — the fake is not flagged.

    -> RESIDUAL (uncaught). The tokens/sec-vs-hardware lever is real but coarse:
    two hardware KINDS and very wide bands mean only an ABSURD rate (attack 7b)
    trips it, and a merely-exaggerated GPU stays in-band. Closed by a real,
    per-(model,quant,hardware) reference distribution — future work.
    """
    claim = ConfigClaim(model_id="meta/Llama-3.2-3B", quantization="Q4_K_M",
                        hardware_gpu="NVIDIA H100", hardware_vram_bytes=80 * 1024**3,
                        hardware_is_soc=False)
    resp = _response(completion=60, wall_clock_ms="1000.000")   # 60 tok/s, plausible & in-band
    result = check_output_against_config(claim, {"max_tokens": 256}, resp)
    assert result.confidence_direction == DIRECTION_RAISES, (
        "an exaggerated-but-plausible hardware claim stays inside the wide band — uncaught"
    )
    assert not any("vram" in o.name.lower() or "gpu" in o.name.lower() for o in result.observations)


def test_attack7b_only_a_physically_absurd_rate_trips_the_coarse_band():
    """The ONE thing the coarse band DOES catch: a physically impossible rate for
    the claimed kind (e.g. claim on-device SoC but emit 5000 tok in 1ms). This is
    LABELED (lowers confidence) — the honest edge of the lever's usefulness.

    -> LABELED, but only for the absurd extreme. Recorded so the table is honest
    about what the coarse band CAN do, not only what it can't.
    """
    soc = ConfigClaim(model_id="meta/Llama-3.2-3B", quantization="Q4_K_M",
                      hardware_is_soc=True)
    resp = _response(completion=5000, wall_clock_ms="1.000")    # 5,000,000 tok/s — impossible on SoC
    result = check_output_against_config(soc, {"max_tokens": 8192}, resp)
    assert result.confidence_direction == DIRECTION_LOWERS
    assert result.lowers() is True
    assert any(o.name == "tokens_per_sec_band" and o.direction == DIRECTION_LOWERS
               for o in result.observations)


# ==========================================================================
# ATTACK 8 — OWNER-BINDING ATTACKS  ->  outcome: CAUGHT / LABELED (B4 holds)
# ==========================================================================
#
# Mechanism: present an EXPIRED, MISMATCHED, or FORGED SignedNodeOwnership and
# confirm B4's recheck marks it invalid/absent and NEVER cites it as a live
# owner. Unlike the config rungs, this defence SHOULD hold — the cert carries the
# owner's own Ed25519 signature over a domain-tagged canonical claim, so a lie
# here is cryptographically detectable. We DEMAND it holds.
# ==========================================================================


def test_attack8a_forged_signature_is_caught_and_never_cited_live():
    """Forge a cert: embed owner A's public key but sign with an ATTACKER key.
    recheck must reject (signature over the canonical claim fails), and the
    owner-provenance block must mark it INVALID and cite NO identity capsule.

    -> CAUGHT. The owner's signature is over a domain-tagged canonical claim; an
    attacker without A's private key cannot produce a verifying signature.
    """
    owner = _owner_key()
    attacker = _owner_key()
    forged = _signed_cert(owner, sign_key=attacker)   # A's pubkey, attacker's signature

    r = recheck_ownership_validity(forged, expected_node_endpoint_id=NODE_ID_HEX)
    assert not r.valid
    assert "failed to verify" in r.reason

    blk = owner_provenance_block(
        forged, expected_node_endpoint_id=NODE_ID_HEX, identity_capsule_id="cap-who-xyz"
    )
    assert blk["owner_status"] == OWNER_STATUS_INVALID
    assert blk["identity_capsule_id"] is None, "a forged cert must NEVER cite a who-record as bound"
    assert blk["recheck_valid"] is False


def test_attack8b_expired_cert_is_caught_and_not_bound():
    """Present a structurally-valid, correctly-signed cert that is EXPIRED.
    recheck must reject on liveness; the block marks it INVALID, never bound.

    -> CAUGHT (liveness). A node that sat idle past its cert expiry cannot cite
    a live owner from a stale cert.
    """
    owner = _owner_key()
    now = int(time.time() * 1000)
    expired = _signed_cert(owner, expires_ms=now - 1)

    r = recheck_ownership_validity(expired, expected_node_endpoint_id=NODE_ID_HEX)
    assert not r.valid
    assert "expired" in r.reason

    blk = owner_provenance_block(
        expired, expected_node_endpoint_id=NODE_ID_HEX, identity_capsule_id="cap-who-xyz"
    )
    assert blk["owner_status"] == OWNER_STATUS_INVALID
    assert blk["identity_capsule_id"] is None


def test_attack8c_cert_swapped_onto_a_different_node_is_caught():
    """Cert-swap: take a perfectly valid cert bound to node A and present it at
    node B (steal a reputable owner's binding). recheck must reject on the
    node_endpoint_id mismatch BEFORE it ever trusts the signature.

    -> CAUGHT. The node id is inside the signed canonical claim, so the cert is
    cryptographically bound to ONE node; presenting it at another mismatches.
    """
    owner = _owner_key()
    cert_for_node_a = _signed_cert(owner, node_id_hex=NODE_ID_HEX)

    # Present node A's valid cert while serving as node B.
    r = recheck_ownership_validity(cert_for_node_a, expected_node_endpoint_id=OTHER_NODE_HEX)
    assert not r.valid
    assert "node_endpoint_id mismatch" in r.reason

    blk = owner_provenance_block(
        cert_for_node_a, expected_node_endpoint_id=OTHER_NODE_HEX, identity_capsule_id="cap-who-xyz"
    )
    assert blk["owner_status"] == OWNER_STATUS_INVALID
    assert blk["identity_capsule_id"] is None


def test_attack8d_key_substitution_owner_id_still_bound_to_the_signing_key():
    """Substitution attempt: keep owner A's owner_id string but swap in the
    ATTACKER's public key (and sign with the attacker key so the signature
    verifies). The cert is now internally consistent and recheck passes — BUT it
    proves ownership only for the ATTACKER's key, and the honesty caveat says
    exactly that (owner_id is a self-asserted label, not externally verified).

    -> LABELED. This is the documented HONEST-GAP of B4: recheck confirms the
    signature is by the embedded key and the owner_id matches its own claim, but
    it CANNOT prove owner_id 'owner-A' is a real party. The caveat carries that
    limitation into every record. The binding is to the KEY; the human label is
    self-asserted, and never presented as externally verified.
    """
    attacker = _owner_key()
    # owner_id says "owner-A" but the embedded key + signature are the attacker's.
    impersonation = _signed_cert(attacker, owner_id="owner-A")

    r = recheck_ownership_validity(impersonation, expected_node_endpoint_id=NODE_ID_HEX)
    # It DOES verify — because it is a valid self-signed claim by the attacker's key.
    assert r.valid
    assert r.owner_id == "owner-A"

    blk = owner_provenance_block(
        impersonation, expected_node_endpoint_id=NODE_ID_HEX, identity_capsule_id="cap-who-xyz"
    )
    assert blk["owner_status"] == OWNER_STATUS_BOUND
    # The caveat is ALWAYS present when a cert is present — it is what stops this
    # "bound" from being read as externally-verified identity.
    assert blk["identity_limitation"] is not None
    assert "not" in blk["identity_limitation"].lower()
    assert "verified" in blk["identity_limitation"].lower()
    # LABELED: the binding is cryptographically to the attacker's KEY; the
    # owner_id label is self-asserted. Closed by a third-party-issued credential
    # / trusted root (out of scope for the opt-in self-asserted layer).


def test_attack8e_absent_cert_is_never_fabricated_into_an_owner():
    """The default (no cert) path: a node with no owner cert must degrade to
    owner ABSENT — never fabricate an owner_id to look accountable.

    -> CAUGHT (fabrication prevented). Absence is recorded as absence.
    """
    blk = owner_provenance_block(None, expected_node_endpoint_id=NODE_ID_HEX)
    assert blk["owner_status"] == OWNER_STATUS_ABSENT
    assert blk["owner_id"] is None
    assert blk["identity_capsule_id"] is None


# ==========================================================================
# RUNG-2 (B3) BINARY ATTESTATION — residual RESTATED from the Rust red-team.
# ==========================================================================
#
# The executable attack lives in the crate's own test file
# (plugins/capsule-producer/tests/redteam_rung2_self_measured.rs), because the
# attestation is Rust. It shows a compromised binary can sign the hash of a
# PRISTINE copy: self-measurement has no root of trust beneath the measurer, so
# the signature verifies while the RUNNING bytes differ. That is RESIDUAL,
# labeled self_measured, closed only by os_measured / tee_measured. We restate
# the finding here so the single findings table is complete; no Python code path
# exercises the Rust attestation.
# ==========================================================================


def test_b3_residual_is_documented_in_the_rust_redteam():
    """Guard: the Rust red-team file exists and states the self-measured
    residual, so the table's B3 row has real executable evidence behind it."""
    import pathlib

    rust = (
        pathlib.Path(__file__).resolve().parent.parent
        / "plugins" / "capsule-producer" / "tests" / "redteam_rung2_self_measured.rs"
    )
    assert rust.exists(), "the B3 self-measured red-team test must exist"
    text = rust.read_text(encoding="utf-8")
    assert "self_measured" in text
    assert "pristine" in text.lower()

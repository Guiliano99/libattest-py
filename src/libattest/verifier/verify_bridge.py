# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""One-shot verifier bridge for TPM key attestation.

Mirrors :mod:`libattest.attester.evidence_bridge`: a thin, stateless call surface
the verifier service uses without touching TPM/ASN.1 detail.  The session store
(seed retention, single-use, expiry) is the caller's — these two functions do the
cryptography only.

* :func:`make_credential_challenge` — nonce time; software ``TPM2_MakeCredential``.
* :func:`verify_key_attest` — evidence time; the design's checks 2-7.
"""

from __future__ import annotations

from libattest.types import VerifyResult
from libattest.verifier.tpm.tpm_keyattest_verifier import TpmKeyAttestVerifier

_VERIFIER = TpmKeyAttestVerifier()


def make_credential_challenge(ak_name: bytes, ek_public: bytes) -> tuple[str, bytes, bytes, bytes]:
    """Return ``(session_id, seed, enc_seed, enc_secret)`` for a MakeCredential challenge.

    The caller retains ``seed`` under ``session_id`` and never forwards it to the
    MockCA; only ``enc_seed``/``enc_secret`` (hex) go back in the ``KeyAttestResp``.
    """
    return _VERIFIER.make_challenge(ak_name, ek_public)


def verify_key_attest(
    evidence_der: bytes,
    *,
    seed: bytes,
    nonce: bytes,
    pubkey_pem: bytes,
    ak_chain_pem,
    trust_anchor,
) -> VerifyResult:
    """Appraise a ``KeyAttestEvidence`` statement against the retained seed + nonce.

    ``evidence_der`` is the ``KeyAttestEvidence`` statement DER the verifier
    service extracted from the ``AttestationBundle``; ``ak_chain_pem`` is the AK
    chain (PEM) also pulled from the bundle; ``trust_anchor`` is the trust-anchor
    PEM; ``pubkey_pem`` is the CSR SubjectPublicKeyInfo (DER or PEM).
    """
    return _VERIFIER.verify(
        evidence_der,
        seed=seed,
        nonce=nonce,
        pubkey_pem=pubkey_pem,
        ak_chain_pem=ak_chain_pem,
        trust_anchor=trust_anchor,
    )


__all__ = ["make_credential_challenge", "verify_key_attest"]

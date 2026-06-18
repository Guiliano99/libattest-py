# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the full TPM platform-quote appraisal (TpmPlatformVerifier.appraise_quote)."""

from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from libattest.formats.tpm import pcr_indices_to_mask
from libattest.verifier.reference import ReferenceCheckResult, VerifierReferenceHandler
from libattest.verifier.tpm.reference_values import PcrReferenceValues
from libattest.verifier.tpm.tpm_platform_verifier import (
    TPM_ALG_RSASSA,
    TPM_ALG_SHA256,
    TpmPlatformVerifier,
    TpmQuoteSignatureEvidence,
)

# SHA-256 over 5 zeroed 32-byte PCRs — the simulator reset digest for sha256:0-4.
SIMULATOR_RESET_DIGEST = hashlib.sha256(b"\x00" * 160).digest()


class AcceptAllReferenceHandler(VerifierReferenceHandler):
    def handle_evidence(self, evidence, *, attester_id=None):
        return ReferenceCheckResult(accepted=True, attester_id=attester_id)


def _quote_attestation(
    nonce: bytes,
    *,
    hash_alg: int = TPM_ALG_SHA256,
    pcrs: list[int] | None = None,
    pcr_digest: bytes = SIMULATOR_RESET_DIGEST,
) -> bytes:
    """Build a TPMS_ATTEST quote with a real TPML_PCR_SELECTION and digest."""
    mask = pcr_indices_to_mask(pcrs if pcrs is not None else [0, 1, 2, 3, 4])
    return b"".join(
        [
            struct.pack(">I", 0xFF544347),  # magic
            struct.pack(">H", 0x8018),  # type: TPM_ST_ATTEST_QUOTE
            struct.pack(">H", 0),  # qualifiedSigner: empty TPM2B_NAME
            struct.pack(">H", len(nonce)),  # extraData
            nonce,
            b"\x00" * 17,  # TPMS_CLOCK_INFO
            b"\x00" * 8,  # firmwareVersion
            struct.pack(">I", 1),  # TPML_PCR_SELECTION.count
            struct.pack(">H", hash_alg),  # TPMS_PCR_SELECTION.hash
            struct.pack(">B", len(mask)),  # sizeofSelect
            mask,
            struct.pack(">H", len(pcr_digest)),  # TPM2B_DIGEST
            pcr_digest,
        ]
    )


def _signed_evidence(attestation: bytes) -> TpmQuoteSignatureEvidence:
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return TpmQuoteSignatureEvidence(
        attestation=attestation,
        signature=ak_key.sign(attestation, padding.PKCS1v15(), hashes.SHA256()),
        signature_algorithm=TPM_ALG_RSASSA,
        signature_hash=TPM_ALG_SHA256,
        ak_public_key=ak_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _verifier() -> TpmPlatformVerifier:
    return TpmPlatformVerifier(reference_handler=AcceptAllReferenceHandler())


def _reference() -> PcrReferenceValues:
    return PcrReferenceValues(
        expected_pcr_digest_hex=SIMULATOR_RESET_DIGEST.hex(),
        description="simulator reset state",
    )


def test_appraise_quote_accepts_matching_quote():
    nonce = b"fresh verifier nonce"
    evidence = _signed_evidence(_quote_attestation(nonce))

    result = _verifier().appraise_quote(
        evidence,
        expected_nonce=nonce,
        reference=_reference(),
        expected_pcrs=[0, 1, 2, 3, 4],
        expected_hash_alg_id=TPM_ALG_SHA256,
    )
    assert result.accepted
    assert "pcr_appraisal" in result.payload


def test_appraise_quote_rejects_pcr_set_mismatch():
    nonce = b"fresh verifier nonce"
    evidence = _signed_evidence(_quote_attestation(nonce, pcrs=[0, 1, 2]))

    result = _verifier().appraise_quote(
        evidence,
        expected_nonce=nonce,
        reference=_reference(),
        expected_pcrs=[0, 1, 2, 3, 4],
    )
    assert not result.accepted
    assert any("does not match policy set" in error for error in result.errors)


def test_appraise_quote_rejects_bank_mismatch():
    nonce = b"fresh verifier nonce"
    evidence = _signed_evidence(_quote_attestation(nonce, hash_alg=0x000C))

    result = _verifier().appraise_quote(
        evidence,
        expected_nonce=nonce,
        reference=_reference(),
        expected_hash_alg_id=TPM_ALG_SHA256,
    )
    assert not result.accepted
    assert any("policy bank" in error for error in result.errors)


def test_appraise_quote_rejects_reference_digest_mismatch():
    nonce = b"fresh verifier nonce"
    evidence = _signed_evidence(_quote_attestation(nonce, pcr_digest=b"\xaa" * 32))

    result = _verifier().appraise_quote(
        evidence,
        expected_nonce=nonce,
        reference=_reference(),
        expected_pcrs=[0, 1, 2, 3, 4],
    )
    assert not result.accepted
    assert any("pcrDigest mismatch" in error for error in result.errors)


def test_appraise_quote_rejects_stale_nonce():
    evidence = _signed_evidence(_quote_attestation(b"old nonce"))

    result = _verifier().appraise_quote(
        evidence,
        expected_nonce=b"current nonce",
        reference=_reference(),
    )
    assert not result.accepted
    assert any("nonce mismatch" in error for error in result.errors)

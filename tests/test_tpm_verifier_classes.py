from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from libattest.types import EarStatus
from libattest.verifier.reference import ReferenceCheckResult, VerifierReferenceHandler
from libattest.verifier.tpm.tpm_platform_verifier import (
    TPM_ALG_RSASSA,
    TPM_ALG_SHA256,
    TpmPlatformVerifier,
    TpmQuoteSignatureEvidence,
)


class AcceptAllReferenceHandler(VerifierReferenceHandler):
    def handle_evidence(self, evidence, *, attester_id=None):
        return ReferenceCheckResult(accepted=True, attester_id=attester_id)


def _minimal_quote_attestation(nonce: bytes) -> bytes:
    # TPMS_ATTEST: magic, type, empty qualifiedSigner, extraData nonce,
    # TPMS_CLOCK_INFO, firmwareVersion, empty TPMS_QUOTE_INFO shell.
    return b"".join(
        [
            struct.pack(">I", 0xFF544347),
            struct.pack(">H", 0x8018),
            struct.pack(">H", 0),
            struct.pack(">H", len(nonce)),
            nonce,
            b"\x00" * 17,
            b"\x00" * 8,
            struct.pack(">I", 0),
            struct.pack(">H", 0),
        ]
    )


def test_platform_verifier_verifies_tpm_quote_signature_and_nonce():
    verifier = TpmPlatformVerifier(reference_handler=AcceptAllReferenceHandler())
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_spki_der = ak_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    nonce = b"fresh verifier nonce"
    attestation = _minimal_quote_attestation(nonce)
    signature = ak_key.sign(attestation, padding.PKCS1v15(), hashes.SHA256())

    result = verifier.verify_quote_signature(
        TpmQuoteSignatureEvidence(
            attestation=attestation,
            signature=signature,
            signature_algorithm=TPM_ALG_RSASSA,
            signature_hash=TPM_ALG_SHA256,
            ak_public_key=ak_spki_der,
        ),
        expected_nonce=nonce,
    )

    assert result.status == EarStatus.affirming


def test_platform_verifier_rejects_quote_signature_with_wrong_nonce():
    verifier = TpmPlatformVerifier(reference_handler=AcceptAllReferenceHandler())
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_spki_der = ak_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    attestation = _minimal_quote_attestation(b"actual nonce")
    signature = ak_key.sign(attestation, padding.PKCS1v15(), hashes.SHA256())

    result = verifier.verify_quote_signature(
        TpmQuoteSignatureEvidence(
            attestation=attestation,
            signature=signature,
            signature_algorithm=TPM_ALG_RSASSA,
            signature_hash=TPM_ALG_SHA256,
            ak_public_key=ak_spki_der,
        ),
        expected_nonce=b"expected nonce",
    )

    assert result.status == EarStatus.contraindicated
    assert "nonce" in result.errors[0]

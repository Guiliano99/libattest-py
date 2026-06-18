from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from libattest.formats.key_attest_pop import (
    compute_key_attest_pop,
    decode_key_attest_resp,
    encode_to_der,
    key_attest_resp_enc_secret,
    key_attest_resp_enc_seed,
    prepare_key_attest_chall,
)
from libattest.types import EarStatus
from libattest.verifier.reference import ReferenceCheckResult, VerifierReferenceHandler
from libattest.verifier.tpm.tpm_keyattest_verifier import TpmKeyAttestVerifier
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


def test_key_verifier_builds_activation_challenge_and_verifies_pop_after_activatecredential():
    verifier = TpmKeyAttestVerifier(reference_handler=AcceptAllReferenceHandler())
    requested_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki_der = requested_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    chall_der = encode_to_der(prepare_key_attest_chall(b"ak-name", [b"ek-cert"]))
    calls = []

    def fake_make_credential(*, ak_name: bytes, ek_cert_chain, seed: bytes):
        calls.append((ak_name, tuple(ek_cert_chain), seed))
        return b"enc-seed", b"enc-secret"

    challenge = verifier.build_activation_challenge(
        chall_der,
        transaction_id="txn-1",
        make_credential=fake_make_credential,
    )

    assert calls == [(b"ak-name", (b"ek-cert",), challenge.seed)]
    response = decode_key_attest_resp(challenge.response_der)
    assert key_attest_resp_enc_seed(response) == b"enc-seed"
    assert key_attest_resp_enc_secret(response) == b"enc-secret"

    # In the real flow the client TPM runs TPM2_ActivateCredential with the
    # response blobs and recovers challenge.seed.  The verifier then checks PoP.
    pop = compute_key_attest_pop(requested_key, challenge.seed)
    result = verifier.verify_activation_pop(
        seed=challenge.seed,
        spki_der=spki_der,
        pop_der=encode_to_der(pop),
    )

    assert result.status == EarStatus.affirming

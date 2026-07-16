# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM key-attestation verifier (v5 credential-activation).

Two one-shots the RA/verifier drives:

* :meth:`TpmKeyAttestVerifier.make_challenge` — nonce time.  Runs *software*
  ``TPM2_MakeCredential`` binding a fresh ``seed`` to ``(EK, AKName)``; the caller
  retains the seed and forwards only the two blobs to the client.
* :meth:`TpmKeyAttestVerifier.verify` — evidence time.  Appraises the
  ``KeyAttestEvidence`` statement against the retained seed and the issued nonce.

Every cryptographic check reuses a shared helper (``verify_tpm_signature``,
``compute_tpm_name``, ``extract_certify_name``, ``parse_tpms_attest``,
``validate_ek_chain``) — there is no TPM/ASN.1 parsing duplicated here.
"""

from __future__ import annotations

import secrets

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from libattest._pytss import require_pytss
from libattest.formats.key_attest_pop import decode_key_attest_evidence
from libattest.formats.tpm.tpm_name import compute_tpm_name
from libattest.formats.tpm.tpm_signature import verify_tpm_signature
from libattest.formats.tpm.tpms_attest import (
    TPM_GENERATED_VALUE,
    extract_certify_name,
    parse_tpms_attest,
)
from libattest.types import VerifyResult
from libattest.verifier.trust import validate_ek_chain

require_pytss()

from tpm2_pytss import (  # noqa: E402
    TPM2B_NAME,
    TPM2B_PUBLIC,
    TPMT_PUBLIC,
    TSS2_Exception,
)
from tpm2_pytss.utils import make_credential  # noqa: E402

_TPM_ST_ATTEST_CERTIFY = 0x8017


def _load_public_key(data: bytes) -> PublicKeyTypes:
    """Load a public key from SubjectPublicKeyInfo (DER or PEM) bytes."""
    for loader in (serialization.load_der_public_key, serialization.load_pem_public_key):
        try:
            return loader(bytes(data))
        except (ValueError, TypeError):
            pass
    raise ValueError("pubkey must be SubjectPublicKeyInfo (DER or PEM)")


def _spki_der(public_key: PublicKeyTypes) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _load_certs(pem: bytes | str) -> list[x509.Certificate]:
    data = pem if isinstance(pem, (bytes, bytearray)) else pem.encode()
    return x509.load_pem_x509_certificates(bytes(data))


class TpmKeyAttestVerifier:
    """Verifier for v5 TPM key-attestation (credential-activation) evidence."""

    def make_challenge(self, ak_name: bytes, ek_public: bytes) -> tuple[str, bytes, bytes, bytes]:
        """Software ``TPM2_MakeCredential``.  Returns ``(session_id, seed, enc_seed, enc_secret)``.

        ``ek_public`` is the marshalled ``TPM2B_PUBLIC`` of the client EK (its
        AES-128-CFB symmetric params are what MakeCredential needs); ``ak_name`` is
        the AK Name buffer bound into the credential.  ``enc_secret`` is the
        marshalled ``TPM2B_ID_OBJECT`` and ``enc_seed`` the marshalled
        ``TPM2B_ENCRYPTED_SECRET`` — the field-name inversion is deliberate and
        matches the attester's :meth:`~libattest.attester.tpm_client.TpmClient.recover_seed`.
        """
        ek_pub, _ = TPM2B_PUBLIC.unmarshal(bytes(ek_public))
        session_id = secrets.token_hex(16)
        seed = secrets.token_bytes(32)
        cred_blob, secret = make_credential(ek_pub, seed, TPM2B_NAME(bytes(ak_name)))
        enc_secret = bytes(cred_blob.marshal())
        enc_seed = bytes(secret.marshal())
        return session_id, seed, enc_seed, enc_secret

    def verify(
        self,
        evidence_der: bytes,
        *,
        seed: bytes,
        nonce: bytes,
        pubkey_pem: bytes,
        ak_chain_pem: bytes | str,
        trust_anchor: bytes | str,
    ) -> VerifyResult:
        """Appraise a ``KeyAttestEvidence`` statement (design checks 2-7).

        Session lookup / single-use (check 1) and EAR emission (check 8) are the
        caller's; this returns an affirming/contraindicated :class:`VerifyResult`.

        The checks below run out of numeric order (4, 5, 3, 6, 2, 7): they are
        sequenced by dependency and cost — parse the statement before testing
        freshness, validate the AK chain before the name binding, etc. — not by
        the design document's numbering.
        """
        try:
            evidence = decode_key_attest_evidence(bytes(evidence_der))
        except ValueError as exc:
            return VerifyResult.contraindicated(f"KeyAttestEvidence decode failed: {exc}")
        tcg_certify_info = bytes(evidence["tcgCertifyInfo"])
        tpm_signature = bytes(evidence["tpmSignature"])
        tpm_tpublic = bytes(evidence["tpmTPublic"])
        key_attest_signature = bytes(evidence["keyAttestSignature"])

        # Check 4 — certify magic + type.
        try:
            parsed = parse_tpms_attest(tcg_certify_info)
        except ValueError as exc:
            return VerifyResult.contraindicated(f"TPMS_ATTEST parse failed: {exc}")
        if parsed.magic != TPM_GENERATED_VALUE:
            return VerifyResult.contraindicated(f"TPMS_ATTEST magic is not TPM_GENERATED_VALUE: {parsed.magic:#010x}")
        if parsed.attest_type != _TPM_ST_ATTEST_CERTIFY:
            return VerifyResult.contraindicated(f"TPMS_ATTEST type is not ATTEST_CERTIFY: {parsed.attest_type:#06x}")

        # Check 5 — freshness: extraData echoes the issued nonce.
        if parsed.nonce != bytes(nonce):
            return VerifyResult.contraindicated(
                f"certify nonce mismatch: expected={bytes(nonce).hex()} got={parsed.nonce.hex()}"
            )

        # Check 3 — AK chain terminates at the trust anchor, then AK signs tcgCertifyInfo.
        try:
            ak_chain = _load_certs(ak_chain_pem)
            roots = _load_certs(trust_anchor)
        except (ValueError, TypeError) as exc:
            return VerifyResult.contraindicated(f"AK/trust-anchor PEM load failed: {exc}")
        if not ak_chain:
            return VerifyResult.contraindicated("empty AK certificate chain")
        try:
            validate_ek_chain(chain=ak_chain, roots=roots)
        except (InvalidSignature, ValueError) as exc:
            return VerifyResult.contraindicated(f"AK chain validation failed: {exc}")
        try:
            verify_tpm_signature(
                signed_bytes=tcg_certify_info,
                tpmt_signature=tpm_signature,
                public_key=ak_chain[0].public_key(),
            )
        except (InvalidSignature, ValueError, TSS2_Exception) as exc:
            return VerifyResult.contraindicated(f"AK signature does not verify: {exc}")

        # Check 6 — key-name binding: H(tpmTPublic) == TPMS_CERTIFY_INFO.name.
        try:
            certify_name = extract_certify_name(tcg_certify_info)
            if compute_tpm_name(tpm_tpublic) != certify_name:
                return VerifyResult.contraindicated("tpmTPublic does not match the certified key name")
        except ValueError as exc:
            return VerifyResult.contraindicated(f"name-binding check failed: {exc}")

        # Check 2 — the CSR public key IS the certified TPM key.
        try:
            csr_key = _load_public_key(pubkey_pem)
            tpm_spki = TPM2B_PUBLIC(publicArea=TPMT_PUBLIC.unmarshal(tpm_tpublic)[0]).to_der()
        except (ValueError, TypeError, TSS2_Exception) as exc:
            return VerifyResult.contraindicated(f"key-match check failed: {exc}")
        if _spki_der(csr_key) != bytes(tpm_spki):
            return VerifyResult.contraindicated("CSR public key does not match the certified TPM key")

        # Check 7 — PoP: keyAttestSignature verifies over the RAW seed with the subject key.
        try:
            verify_tpm_signature(
                signed_bytes=bytes(seed),
                tpmt_signature=key_attest_signature,
                public_key=csr_key,
            )
        except (InvalidSignature, ValueError, TSS2_Exception) as exc:
            return VerifyResult.contraindicated(f"PoP signature does not verify over seed: {exc}")

        return VerifyResult.affirming({"key_attest": "credential-activation PoP verified over seed"})


__all__ = ["TpmKeyAttestVerifier"]

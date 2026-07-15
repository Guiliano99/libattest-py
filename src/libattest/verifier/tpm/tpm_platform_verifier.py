# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM platform attestation verifier."""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from tpm2_pytss.types import TPMT_SIGNATURE

from libattest.formats.media_types import TPM_PLATFORM_MEDIA_TYPE
from libattest.formats.tpm.tpm_signature import to_tpm2b_public
from libattest.formats.tpm.tpms_attest import (
    TPM_ALG_ECDSA,
    TPM_ALG_RSAPSS,
    TPM_ALG_RSASSA,
    TPM_ALG_SHA1,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_ALG_SHA512,
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    ParsedAttest,
    TpmQuoteSignatureEvidence,
    parse_tpms_attest,
    pcr_mask_to_indices,
)
from libattest.types import VerifyResult
from libattest.verifier.tpm.base import TpmReferenceVerifier
from libattest.verifier.tpm.reference_values import PcrReferenceValues, verify_pcr_quote


def _load_ak_public_key(data: bytes):
    """Load an AK public key from SPKI or certificate bytes."""
    loaders = (
        serialization.load_der_public_key,
        serialization.load_pem_public_key,
    )
    for loader in loaders:
        try:
            return loader(data)
        except ValueError:
            pass
    cert_loaders = (x509.load_der_x509_certificate, x509.load_pem_x509_certificate)
    for loader in cert_loaders:
        try:
            return loader(data).public_key()
        except ValueError:
            pass
    raise ValueError("AK public key must be SPKI or X.509 certificate bytes")


def _build_tpmt_signature(evidence: TpmQuoteSignatureEvidence) -> TPMT_SIGNATURE:
    """Reconstruct a TPMT_SIGNATURE from the evidence's already-decomposed fields.

    ``TpmQuoteSignatureEvidence`` carries the signature pre-split into
    algorithm/hash/raw-value (unlike the wire-format bytes
    :func:`~libattest.formats.tpm.tpm_signature.verify_tpm_signature` takes),
    so this is the one place that still switches on the TPM signature scheme —
    to know which ``TPMT_SIGNATURE`` union field to populate. The actual
    cryptographic verification is delegated to tpm2-pytss either way.
    """
    signature = TPMT_SIGNATURE(sigAlg=evidence.signature_algorithm)
    if evidence.signature_algorithm == TPM_ALG_RSASSA:
        signature.signature.rsassa.hash = evidence.signature_hash
        signature.signature.rsassa.sig = evidence.signature
    elif evidence.signature_algorithm == TPM_ALG_RSAPSS:
        signature.signature.rsapss.hash = evidence.signature_hash
        signature.signature.rsapss.sig = evidence.signature
    elif evidence.signature_algorithm == TPM_ALG_ECDSA:
        half = len(evidence.signature) // 2
        if half == 0 or len(evidence.signature) % 2:
            raise ValueError("ECDSA quote signature must be r||s with even length")
        signature.signature.ecdsa.hash = evidence.signature_hash
        signature.signature.ecdsa.signatureR = evidence.signature[:half]
        signature.signature.ecdsa.signatureS = evidence.signature[half:]
    else:
        raise ValueError(f"unsupported TPM signature algorithm {evidence.signature_algorithm:#06x}")
    return signature


def _verify_ak_signature(evidence: TpmQuoteSignatureEvidence) -> tuple[bool, str]:
    try:
        signature = _build_tpmt_signature(evidence)
        public_key = to_tpm2b_public(_load_ak_public_key(evidence.ak_public_key))
        signature.verify_signature(public_key, evidence.attestation)
        return True, "quote signature verifies under AK public key"
    except InvalidSignature:
        return False, "quote signature does not verify under AK public key"
    except (TypeError, ValueError) as exc:
        return False, str(exc)


class TpmPlatformVerifier(TpmReferenceVerifier):
    """Verifier for TPM platform evidence."""

    media_type = TPM_PLATFORM_MEDIA_TYPE

    @staticmethod
    def _parse_attest_or_contraindicate(
        attestation: bytes,
    ) -> ParsedAttest | VerifyResult:
        """Parse a ``TPMS_ATTEST`` buffer or return a contraindicated result.

        Return the :class:`ParsedAttest` on success, or a contraindicated
        :class:`VerifyResult` carrying the parse error message on failure.
        """
        try:
            return parse_tpms_attest(attestation)
        except ValueError as exc:
            return VerifyResult.contraindicated(str(exc))

    def verify_quote_signature(
        self,
        evidence: TpmQuoteSignatureEvidence,
        *,
        expected_nonce: bytes,
    ) -> VerifyResult:
        """Verify TPM2_Quote freshness and AK signature.

        Ensure the signed ``TPMS_ATTEST`` is TPM-generated quote evidence, that
        ``extraData`` echoes the verifier nonce, and that the AK signature
        verifies over the exact attestation bytes.
        """
        parsed = self._parse_attest_or_contraindicate(evidence.attestation)
        if isinstance(parsed, VerifyResult):
            return parsed
        return self._verify_signed_quote(parsed, evidence, expected_nonce)

    def _verify_signed_quote(
        self,
        parsed: ParsedAttest,
        evidence: TpmQuoteSignatureEvidence,
        expected_nonce: bytes,
    ) -> VerifyResult:
        """Run the structural, freshness, and AK-signature checks on a parsed quote."""
        if parsed.magic != TPM_GENERATED_VALUE:
            return VerifyResult.contraindicated(f"TPMS_ATTEST magic is not TPM_GENERATED_VALUE: {parsed.magic:#010x}")
        if parsed.attest_type != TPM_ST_ATTEST_QUOTE:
            return VerifyResult.contraindicated(
                f"TPMS_ATTEST type is not TPM_ST_ATTEST_QUOTE: {parsed.attest_type:#06x}"
            )
        if parsed.nonce != expected_nonce:
            return VerifyResult.contraindicated(
                f"quote nonce mismatch: expected={expected_nonce.hex()} got={parsed.nonce.hex()}"
            )
        ok, reason = _verify_ak_signature(evidence)
        if not ok:
            return VerifyResult.contraindicated(reason)
        return VerifyResult.affirming({"quote_signature": reason})

    def appraise_quote(
        self,
        evidence: TpmQuoteSignatureEvidence,
        *,
        expected_nonce: bytes,
        reference: PcrReferenceValues,
        expected_pcrs: list[int] | None = None,
        expected_hash_alg_id: int | None = None,
    ) -> VerifyResult:
        """Run the full verifier-side appraisal of TPM2_Quote evidence.

        Parse the ``TPMS_ATTEST`` once, then combine the structural, freshness,
        and signature checks of :meth:`verify_quote_signature` with the
        PCR-selection binding check and the reference-digest comparison
        (VERIFY-TPM-PLATFORM checks 6-12 of ``TPM2_PLAT_ATTEST_DESIGN.md``).

        Nonce state management (expiry, single-use) and AK certificate-chain
        policy remain the caller's responsibility: ``evidence.ak_public_key``
        must already be trusted according to local policy.

        Parameters
        ----------
        evidence:
            The TPM2_Quote evidence under appraisal.
        expected_nonce:
            The freshness nonce issued by the RA/CA for this transaction.
        reference:
            Trusted PCR reference values for the platform profile.
        expected_pcrs:
            Policy-selected PCR indices.  When given, the quoted
            ``TPMS_QUOTE_INFO.pcrSelect`` must select exactly these PCRs.
        expected_hash_alg_id:
            Policy-selected PCR bank hash algorithm (e.g. ``0x000B``).  When
            given, every quoted selection must use this bank.

        """
        parsed = self._parse_attest_or_contraindicate(evidence.attestation)
        if isinstance(parsed, VerifyResult):
            return parsed

        result = self._verify_signed_quote(parsed, evidence, expected_nonce)
        if not result.accepted:
            return result

        if expected_pcrs is not None or expected_hash_alg_id is not None:
            if len(parsed.pcr_selections) != 1:
                return VerifyResult.contraindicated(
                    f"expected exactly one quoted PCR selection, got {len(parsed.pcr_selections)}"
                )
            selection = parsed.pcr_selections[0]
            if expected_hash_alg_id is not None and selection["hash_alg"] != expected_hash_alg_id:
                return VerifyResult.contraindicated(
                    f"quoted PCR bank {selection['hash_alg']:#06x} does not match "
                    f"policy bank {expected_hash_alg_id:#06x}"
                )
            if expected_pcrs is not None:
                quoted = pcr_mask_to_indices(selection["pcr_mask"])
                if quoted != sorted(set(expected_pcrs)):
                    return VerifyResult.contraindicated(
                        f"quoted PCR set {quoted} does not match policy set {sorted(set(expected_pcrs))}"
                    )

        ok, reason = verify_pcr_quote(parsed.pcr_selections, parsed.pcr_digest, reference)
        if not ok:
            return VerifyResult.contraindicated(reason)
        return VerifyResult.affirming(
            {
                "quote_signature": "quote signature verifies under AK public key",
                "pcr_appraisal": reason,
            }
        )


__all__ = [
    "TPM_ALG_ECDSA",
    "TPM_ALG_RSASSA",
    "TPM_ALG_RSAPSS",
    "TPM_ALG_SHA1",
    "TPM_ALG_SHA256",
    "TPM_ALG_SHA384",
    "TPM_ALG_SHA512",
    "TPM_GENERATED_VALUE",
    "TPM_ST_ATTEST_QUOTE",
    "TpmPlatformVerifier",
    "TpmQuoteSignatureEvidence",
]

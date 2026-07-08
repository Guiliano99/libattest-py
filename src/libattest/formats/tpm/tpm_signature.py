# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""TPMT_SIGNATURE verification helpers.

Verifies the wire-format ``TPMT_SIGNATURE`` blobs a TPM2 quote/certify command
emits, against a public key.  Delegates the actual RSASSA/RSAPSS/ECDSA
dispatch to tpm2-pytss's native ``TPMT_SIGNATURE.verify_signature`` instead of
reimplementing padding/hash selection with ``cryptography`` primitives here —
that dispatch used to be duplicated a second time in
:func:`~libattest.verifier.tpm.tpm_platform_verifier._verify_ak_signature`;
both now delegate to the same pytss call.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from tpm2_pytss.types import TPM2B_PUBLIC, TPMT_SIGNATURE


def to_tpm2b_public(public_key) -> TPM2B_PUBLIC:
    """Coerce *public_key* into a :class:`TPM2B_PUBLIC`.

    Accepts an already-built ``TPM2B_PUBLIC``, PEM/DER-encoded public-key
    bytes, or a ``cryptography`` public key object (e.g. from
    ``x509.Certificate.public_key()``). Shared by every verifier that needs to
    hand tpm2-pytss a key it can call ``TPMT_SIGNATURE.verify_signature``
    against — don't re-derive this conversion at another call site.
    """
    if isinstance(public_key, TPM2B_PUBLIC):
        return public_key
    if isinstance(public_key, (bytes, bytearray)):
        return TPM2B_PUBLIC.from_pem(bytes(public_key))
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return TPM2B_PUBLIC.from_pem(der)


def verify_tpm_signature(
    *,
    signed_bytes: bytes,
    tpmt_signature: bytes,
    public_key,
) -> None:
    """Verify a TPMT_SIGNATURE over *signed_bytes*.

    Accepts the wire-format TPMT_SIGNATURE blobs emitted by TPM2
    quote/certify commands. *public_key* may be a ``TPM2B_PUBLIC``, PEM/DER
    public-key bytes, or a ``cryptography`` public key object.

    Supported schemes: whatever tpm2-pytss's ``TPMT_SIGNATURE.verify_signature``
    supports (RSASSA, RSAPSS, ECDSA — see its docs for the current list).

    Raises
    ------
    cryptography.exceptions.InvalidSignature
        If the signature is cryptographically invalid.
    tpm2_pytss.TSS2_Exception
        If the TPMT_SIGNATURE bytes are malformed or truncated.
    ValueError
        If *public_key*'s encoding is unsupported.

    """
    signature, _consumed = TPMT_SIGNATURE.unmarshal(bytes(tpmt_signature))
    signature.verify_signature(to_tpm2b_public(public_key), bytes(signed_bytes))


__all__ = ["to_tpm2b_public", "verify_tpm_signature"]

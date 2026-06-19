# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""TPMT_SIGNATURE verification helpers.

Verifies the wire-format ``TPMT_SIGNATURE`` blobs a TPM2 quote/certify command
emits, against a ``cryptography`` public key.  This complements the typed
:class:`~libattest.formats.tpm.tpms_attest.TpmQuoteSignatureEvidence` /
:func:`~libattest.verifier.tpm.tpm_platform_verifier._verify_ak_signature`
path (which takes an already-decomposed signature): this helper parses the raw
``TPMT_SIGNATURE`` itself, which the tpm-verifier service relies on for both the
quote and certify legs.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

_TPM_ALG_RSASSA = 0x0014
_TPM_ALG_RSAPSS = 0x0016
_TPM_ALG_ECDSA = 0x0018

_TPM_ALG_SHA1 = 0x0004
_TPM_ALG_SHA256 = 0x000B
_TPM_ALG_SHA384 = 0x000C
_TPM_ALG_SHA512 = 0x000D

_HASH_ALGS = {
    _TPM_ALG_SHA1: hashes.SHA1,
    _TPM_ALG_SHA256: hashes.SHA256,
    _TPM_ALG_SHA384: hashes.SHA384,
    _TPM_ALG_SHA512: hashes.SHA512,
}


def _read_u16(buf: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(buf):
        raise ValueError("truncated TPMT_SIGNATURE")
    return int.from_bytes(buf[offset : offset + 2], "big"), offset + 2


def _read_tpm2b(buf: bytes, offset: int, label: str) -> tuple[bytes, int]:
    size, offset = _read_u16(buf, offset)
    end = offset + size
    if end > len(buf):
        raise ValueError(f"truncated TPMT_SIGNATURE {label}")
    return buf[offset:end], end


def _hash_algorithm(hash_alg_id: int) -> hashes.HashAlgorithm:
    try:
        return _HASH_ALGS[hash_alg_id]()
    except KeyError as exc:
        raise ValueError(f"unsupported TPM signature hash algorithm {hash_alg_id:#06x}") from exc


def _ensure_consumed(buf: bytes, offset: int) -> None:
    if offset != len(buf):
        raise ValueError(
            f"trailing bytes after TPMT_SIGNATURE: consumed {offset} of {len(buf)}"
        )


def verify_tpm_signature(
    *,
    signed_bytes: bytes,
    tpmt_signature: bytes,
    public_key,
) -> None:
    """Verify a TPMT_SIGNATURE over *signed_bytes*.

    The helper accepts the wire-format TPMT_SIGNATURE blobs emitted by TPM2
    quote/certify commands and verifies them with the corresponding
    ``cryptography`` public key.  It raises
    :class:`cryptography.exceptions.InvalidSignature` when the signature is
    cryptographically invalid and :class:`ValueError` when the TPMT_SIGNATURE
    shape or algorithm is unsupported.

    Supported schemes: RSASSA, RSAPSS, and ECDSA with SHA-1/256/384/512.
    """
    if not isinstance(tpmt_signature, bytes):
        tpmt_signature = bytes(tpmt_signature)
    if not isinstance(signed_bytes, bytes):
        signed_bytes = bytes(signed_bytes)

    sig_alg, offset = _read_u16(tpmt_signature, 0)
    hash_alg, offset = _read_u16(tpmt_signature, offset)
    hash_algorithm = _hash_algorithm(hash_alg)

    if sig_alg == _TPM_ALG_RSASSA:
        signature, offset = _read_tpm2b(tpmt_signature, offset, "rsassa.sig")
        _ensure_consumed(tpmt_signature, offset)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("RSASSA TPM signature requires an RSA public key")
        public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_algorithm)
        return

    if sig_alg == _TPM_ALG_RSAPSS:
        signature, offset = _read_tpm2b(tpmt_signature, offset, "rsapss.sig")
        _ensure_consumed(tpmt_signature, offset)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("RSAPSS TPM signature requires an RSA public key")
        public_key.verify(
            signature,
            signed_bytes,
            padding.PSS(
                mgf=padding.MGF1(hash_algorithm),
                salt_length=hash_algorithm.digest_size,
            ),
            hash_algorithm,
        )
        return

    if sig_alg == _TPM_ALG_ECDSA:
        r_bytes, offset = _read_tpm2b(tpmt_signature, offset, "ecdsa.signatureR")
        s_bytes, offset = _read_tpm2b(tpmt_signature, offset, "ecdsa.signatureS")
        _ensure_consumed(tpmt_signature, offset)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("ECDSA TPM signature requires an EC public key")
        signature = encode_dss_signature(
            int.from_bytes(r_bytes, "big"),
            int.from_bytes(s_bytes, "big"),
        )
        public_key.verify(signature, signed_bytes, ec.ECDSA(hash_algorithm))
        return

    raise ValueError(f"unsupported TPM signature algorithm {sig_alg:#06x}")


__all__ = ["verify_tpm_signature"]

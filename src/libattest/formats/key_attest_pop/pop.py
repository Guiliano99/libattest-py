# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Signature-only KeyAttestPoP helpers.

The current key-attestation design proves possession by signing the
CA/RA-generated ``seed`` recovered from ``TPM2_ActivateCredential``.
PBMAC1 and RSA-encrypted challenge forms are intentionally not supported.
"""

from __future__ import annotations

from typing import Union

import keyutils_py
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280

from libattest.formats.key_attest_pop.structures import (
    ID_ECDSA_WITH_SHA256,
    ID_SHA256_WITH_RSA_ENCRYPTION,
    KeyAttestPoP,
    key_attest_pop_algorithm_oid,
    key_attest_pop_signature,
    prepare_key_attest_pop,
)

_NULL_DER: bytes = bytes(_der_encoder.encode(univ.Null()))
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, bytes, bytearray, memoryview]


def _build_algorithm(oid: str, parameters: bytes | None = None) -> rfc5280.AlgorithmIdentifier:
    """Build an ``AlgorithmIdentifier``; set ``parameters`` only when provided."""
    alg = rfc5280.AlgorithmIdentifier()
    alg["algorithm"] = univ.ObjectIdentifier(oid)
    if parameters is not None:
        alg["parameters"] = parameters
    return alg


def build_sha256_rsa_algorithm() -> rfc5280.AlgorithmIdentifier:
    """Return ``AlgorithmIdentifier { sha256WithRSAEncryption, NULL }``."""
    return _build_algorithm(ID_SHA256_WITH_RSA_ENCRYPTION, _NULL_DER)


def build_ecdsa_sha256_algorithm() -> rfc5280.AlgorithmIdentifier:
    """Return ``AlgorithmIdentifier { ecdsa-with-SHA256 }``."""
    return _build_algorithm(ID_ECDSA_WITH_SHA256)


def _load_private_key(private_key: PrivateKey):
    if isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        return private_key
    raw = bytes(private_key)
    if raw.lstrip().startswith(b"-----BEGIN"):
        return serialization.load_pem_private_key(raw, password=None)
    return serialization.load_der_private_key(raw, password=None)


def compute_key_attest_pop(
    private_key: PrivateKey,
    seed: bytes,
) -> KeyAttestPoP:
    """Sign ``seed`` and return a ``KeyAttestPoP`` value."""
    key = _load_private_key(private_key)
    if isinstance(key, rsa.RSAPrivateKey):
        algorithm = build_sha256_rsa_algorithm()
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        algorithm = build_ecdsa_sha256_algorithm()
    else:
        raise TypeError(f"unsupported private key type for KeyAttestPoP: {type(key).__name__}")
    signature = keyutils_py.sign_with_alg_id(key, algorithm, seed)
    return prepare_key_attest_pop(algorithm, signature)


def verify_key_attest_pop(
    *,
    seed: bytes,
    spki_der: bytes,
    pop: KeyAttestPoP,
) -> bool:
    """Verify a ``KeyAttestPoP`` signature with the CSR/CertTemplate SPKI."""
    try:
        public_key = serialization.load_der_public_key(spki_der)
        algorithm_oid = key_attest_pop_algorithm_oid(pop)
        signature = key_attest_pop_signature(pop)
        if algorithm_oid == ID_SHA256_WITH_RSA_ENCRYPTION:
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False
            algorithm = build_sha256_rsa_algorithm()
        elif algorithm_oid == ID_ECDSA_WITH_SHA256:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            algorithm = build_ecdsa_sha256_algorithm()
        else:
            return False
        keyutils_py.verify_signature_with_alg_id(public_key, algorithm, seed, signature)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:  # noqa: BLE001
        return False


__all__ = [
    "build_ecdsa_sha256_algorithm",
    "build_sha256_rsa_algorithm",
    "compute_key_attest_pop",
    "verify_key_attest_pop",
]

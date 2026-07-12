# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""COSE-HPKE evidence sealing over a static EAR/EAT JWT (draft-ietf-cose-hpke).

Usage example + verification for :func:`libattest.attester.evidence_bridge.seal_cose_hpke_evidence`
/ :func:`~libattest.attester.evidence_bridge.open_cose_hpke_evidence`. Unlike
``test_eareat_hpke_flow.py`` (which generates a fresh EAT-JWS per test via ``jose_jws``),
STATIC_EAR_JWT below is a fixed, pre-generated JWT -- standing in for a real ``atgcli``
token without needing the Go CLI -- so the fixture and expected output never change
between runs. SIGNER_*/RECIPIENT_* are the matching fixed keypairs (signer verifies
STATIC_EAR_JWT and the re-signed CWT; recipient is the verifier's HPKE-0 key).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cwt.exceptions import DecodeError, VerifyError

from libattest.attester.evidence_bridge import open_cose_hpke_evidence, seal_cose_hpke_evidence

STATIC_EAR_JWT = (
    b"eyJhbGciOiJFUzI1NiIsImtpZCI6ImF0dC1zdGF0aWMtMDEiLCJ0eXAiOiJKV1QifQ."
    b"eyJpc3MiOiJodHRwczovL2F0dGVzdGVyLmV4YW1wbGUiLCJzdWIiOiJkZXZpY2UtMDAwNyIsImVhdF9ub25jZSI6"
    b"IkFRSURCQVVHQndnSkNnc01EUTRQRUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEEiLCJzdWJtb2RzIjp7IkFUR19QTFVH"
    b"SU4iOnsiZWFyLnN0YXR1cyI6ImFmZmlybWluZyJ9fX0."
    b"1vLNg-ork7-GLxalJivPBupCczDhWtpU0_FFY76G9M-6nXeEr7RV4AY1wwggSmcMH3Dfpde0ZTzKpm-CBwxa9A"
)

SIGNER_PRIVATE_PEM = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvd1NbqL9Ahats7As
7rJXcnWv9SsaMVaDfocdFI0DBNyhRANCAAT9xIUZItcBtRmErmGWGBfhnHTN8oOz
KtvfLRlHCj0ZPyjUKyQzz3kvRL8tOqu+Q39IvIAL7HPARkYgTiUR0M9O
-----END PRIVATE KEY-----
"""

SIGNER_PUBLIC_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/cSFGSLXAbUZhK5hlhgX4Zx0zfKD
syrb3y0ZRwo9GT8o1CskM895L0S/LTqrvkN/SLyAC+xzwEZGIE4lEdDPTg==
-----END PUBLIC KEY-----
"""

RECIPIENT_PRIVATE_PEM = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgMx94iUXHygI+BlyN
hnrfuNSfEv5XuKkvYcBKrdiccmChRANCAASNv7jTIzL2RI3xONxUkjTeWX8k0ewB
lNTdGymnL5kRkSmWZyWbjNB9Bac/8CVcYYCFgm4b46uplMI6FRrpccqe
-----END PRIVATE KEY-----
"""

RECIPIENT_PUBLIC_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjb+40yMy9kSN8TjcVJI03ll/JNHs
AZTU3Rsppy+ZEZEplmclm4zQfQWnP/AlXGGAhYJuG+OrqZTCOhUa6XHKng==
-----END PUBLIC KEY-----
"""


def _load_priv(pem: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return key


def _load_pub(pem: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem)
    assert isinstance(key, ec.EllipticCurvePublicKey)
    return key


def test_encrypt_only_roundtrip() -> None:
    """signing_key=None: RFC 8392 Appendix A.5 encrypted CWT, no signature layer."""
    recipient_pub = _load_pub(RECIPIENT_PUBLIC_PEM)
    recipient_priv = _load_priv(RECIPIENT_PRIVATE_PEM)

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub)
    claims = open_cose_hpke_evidence(sealed, recipient_priv)

    assert claims["sub"] == "device-0007"
    assert claims["submods"]["ATG_PLUGIN"]["ear.status"] == "affirming"


def test_sign_then_encrypt_roundtrip() -> None:
    """signing_key set: nested COSE_Sign1-in-COSE_Encrypt0; verify_key checks the signature.

    Also pins that eat_nonce survives signing byte-for-byte: the ``cwt.encode``
    convenience API would silently drop it (not a registered CWT claim), so
    ``seal_cose_hpke_evidence`` signs the raw CBOR claims map as an opaque payload
    instead (see its docstring).
    """
    recipient_pub = _load_pub(RECIPIENT_PUBLIC_PEM)
    recipient_priv = _load_priv(RECIPIENT_PRIVATE_PEM)
    signer_priv = _load_priv(SIGNER_PRIVATE_PEM)
    signer_pub = _load_pub(SIGNER_PUBLIC_PEM)

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub, signing_key=signer_priv)
    claims = open_cose_hpke_evidence(sealed, recipient_priv, verify_key=signer_pub)

    assert claims["sub"] == "device-0007"
    assert claims["submods"]["ATG_PLUGIN"]["ear.status"] == "affirming"
    assert claims["eat_nonce"] == "AQIDBAUGBwgJCgsMDQ4PEAECAwQFBgcICQoLDA0ODxA"


def test_sign_then_encrypt_wrong_verify_key_rejected() -> None:
    recipient_pub = _load_pub(RECIPIENT_PUBLIC_PEM)
    recipient_priv = _load_priv(RECIPIENT_PRIVATE_PEM)
    signer_priv = _load_priv(SIGNER_PRIVATE_PEM)
    wrong_pub = ec.generate_private_key(ec.SECP256R1()).public_key()

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub, signing_key=signer_priv)
    with pytest.raises(VerifyError):
        open_cose_hpke_evidence(sealed, recipient_priv, verify_key=wrong_pub)


def test_encrypt_only_wrong_recipient_key_rejected() -> None:
    recipient_pub = _load_pub(RECIPIENT_PUBLIC_PEM)
    wrong_priv = ec.generate_private_key(ec.SECP256R1())

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub)
    with pytest.raises(DecodeError):
        open_cose_hpke_evidence(sealed, wrong_priv)


def test_sign_with_non_p256_key_uses_its_own_alg() -> None:
    """Signer alg is derived from the key (ES384 here), not hardcoded to ES256.

    The recipient stays P-256 (HPKE-0's KEM); only the inner COSE_Sign1 alg varies.
    """
    recipient_pub = _load_pub(RECIPIENT_PUBLIC_PEM)
    recipient_priv = _load_priv(RECIPIENT_PRIVATE_PEM)
    p384_signer = ec.generate_private_key(ec.SECP384R1())

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub, signing_key=p384_signer)
    claims = open_cose_hpke_evidence(sealed, recipient_priv, verify_key=p384_signer.public_key())
    assert claims["sub"] == "device-0007"


def test_non_p256_recipient_rejected() -> None:
    """HPKE-0's KEM is DHKEM(P-256): a non-P-256 recipient must fail clearly, not deep in pyhpke."""
    wrong_curve_pub = ec.generate_private_key(ec.SECP384R1()).public_key()
    with pytest.raises(ValueError, match="P-256"):
        seal_cose_hpke_evidence(STATIC_EAR_JWT, wrong_curve_pub)

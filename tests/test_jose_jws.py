# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ES256 compact JWS + P-256 JWK helpers (libattest.formats.eat_ear.cwt_jwt_utils).

These cover the JOSE operations the JWT-HPKE EAR/EAT flow needs without python-jose:
ES256 sign/verify round-trip, tamper and wrong-alg rejection, PEM-key verification, and
P-256 JWK <-> EC-key round-tripping.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats.eat_ear import cwt_jwt_utils


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def test_sign_verify_roundtrip() -> None:
    key = _new_key()
    claims = {"eat_nonce": "AAA", "mock_claim": "secure", "iat": 0}
    token = cwt_jwt_utils.sign_es256(claims, key)
    assert cwt_jwt_utils.verify_es256(token, key.public_key()) == claims


def test_verify_with_pem_public_key() -> None:
    key = _new_key()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    token = cwt_jwt_utils.sign_es256({"a": 1}, key)
    assert cwt_jwt_utils.verify_es256(token, pem) == {"a": 1}


def test_tampered_signature_rejected() -> None:
    key = _new_key()
    token = cwt_jwt_utils.sign_es256({"a": 1}, key)
    header_b64, payload_b64, sig_b64 = token.split(".")
    flipped = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
    with pytest.raises(cwt_jwt_utils.InvalidSignature):
        cwt_jwt_utils.verify_es256(f"{header_b64}.{payload_b64}.{flipped}", key.public_key())


def test_wrong_signer_rejected() -> None:
    token = cwt_jwt_utils.sign_es256({"a": 1}, _new_key())
    with pytest.raises(cwt_jwt_utils.InvalidSignature):
        cwt_jwt_utils.verify_es256(token, _new_key().public_key())


def test_non_es256_alg_rejected() -> None:
    key = _new_key()
    # Forge a header claiming a different alg over an otherwise valid token.
    token = cwt_jwt_utils.sign_es256({"a": 1}, key)
    _, payload_b64, sig_b64 = token.split(".")
    bad_header = cwt_jwt_utils.b64u_encode(b'{"alg":"HS256","typ":"JWT"}')
    with pytest.raises(ValueError, match="unsupported JWS alg"):
        cwt_jwt_utils.verify_es256(f"{bad_header}.{payload_b64}.{sig_b64}", key.public_key())


def test_jwk_private_roundtrip() -> None:
    key = _new_key()
    jwk = cwt_jwt_utils.p256_private_to_jwk(key)
    assert (jwk["kty"], jwk["crv"]) == ("EC", "P-256") and "d" in jwk
    restored = cwt_jwt_utils.jwk_to_p256_private(jwk)
    assert restored.private_numbers().private_value == key.private_numbers().private_value


def test_jwk_public_roundtrip() -> None:
    pub = _new_key().public_key()
    restored = cwt_jwt_utils.jwk_to_p256_public(cwt_jwt_utils.p256_public_to_jwk(pub))
    assert restored.public_numbers() == pub.public_numbers()


def test_public_jwk_has_no_private_d() -> None:
    assert "d" not in cwt_jwt_utils.p256_public_to_jwk(_new_key().public_key())

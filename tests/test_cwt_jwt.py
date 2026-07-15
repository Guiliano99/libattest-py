# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for lossless JWT claim-set and COSE CWT conversion boundaries."""

from __future__ import annotations

import base64
from typing import Any

import cbor2
import jwt as pyjwt
import pytest
from cwt import COSE, COSEHeaders

from libattest.formats.eat_ear.cwt_jwt import (
    cose_cwt_to_jwt_view,
    cwt_claim_set_to_jwt_view,
    jwt_claims_to_cwt_claim_set,
    jwt_style_view_to_cwt_claim_set,
)
from libattest.formats.eat_ear.cwt_jwt_utils import generate_es256_keypair, verified_jwt_to_signed_cwt


def _b64u(value: bytes) -> str:
    """Return unpadded base64url text."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _sign_claim_set(claim_set: dict[int | str, object]) -> tuple[bytes, object]:
    """Return a raw-CBOR COSE_Sign1 and its matching verification key."""
    signing_key, verify_key, _private_pem, _public_pem = generate_es256_keypair("cwt-jwt-test")
    token = COSE.new().encode_and_sign(
        cbor2.dumps(claim_set),
        signing_key,
        protected={COSEHeaders.ALG: signing_key.alg, COSEHeaders.KID: b"cwt-jwt-test"},
    )
    return token, verify_key


def _jwt_pems(kid: str) -> tuple[bytes, bytes]:
    """Return a fresh private/public PEM pair for PyJWT tests."""
    _signing_key, _verify_key, private_pem, public_pem = generate_es256_keypair(kid)
    return private_pem, public_pem


def _cwt_keys(kid: str) -> tuple[Any, Any]:
    """Return a fresh signing/verification key pair for COSE tests."""
    signing_key, verify_key, _private_pem, _public_pem = generate_es256_keypair(kid)
    return signing_key, verify_key


def test_claim_set_conversion_maps_registered_byte_claims() -> None:
    """GIVEN JSON claims WHEN converted to a Claim Set THEN labels and byte values are preserved."""
    nonce = bytes(range(16))
    ueid = b"device-ueid"

    claim_set = jwt_claims_to_cwt_claim_set(
        {
            "iss": "https://issuer.example",
            "jti": "jwt-001",
            "eat_nonce": _b64u(nonce) + "=",
            "ueid": _b64u(ueid),
            "mock_claim": "secure",
        }
    )

    assert claim_set[1] == "https://issuer.example"
    assert claim_set[7] == b"jwt-001"
    assert claim_set[10] == nonce
    assert claim_set[256] == ueid
    assert claim_set["mock_claim"] == "secure"
    assert jwt_claims_to_cwt_claim_set({"eat_nonce": _b64u(nonce)})[10] == nonce


def test_claim_set_view_recursively_base64url_encodes_bytes() -> None:
    """GIVEN nested CBOR bytes WHEN rendered THEN the view uses unpadded base64url."""
    view = cwt_claim_set_to_jwt_view({"private": {"nested": b"\x00\xff"}})

    assert view == {"private": {"nested": "AP8"}}


def test_jwt_style_view_roundtrips_known_byte_claims() -> None:
    """GIVEN a Claim Set WHEN rendered and parsed THEN known byte claims round-trip exactly."""
    claim_set = {7: b"jwt-001", 10: b"nonce", 256: b"device-ueid", "private": "kept"}

    view = cwt_claim_set_to_jwt_view(claim_set)
    restored = jwt_style_view_to_cwt_claim_set(view)

    assert view["jti"] == _b64u(b"jwt-001")
    assert view["eat_nonce"] == _b64u(b"nonce")
    assert view["ueid"] == _b64u(b"device-ueid")
    assert restored == claim_set


def test_cose_cwt_view_handles_tags_and_trailing_bytes() -> None:
    """GIVEN COSE CWT bytes WHEN rendered THEN malformed framing is rejected."""
    token, _verify_key = _sign_claim_set({10: b"nonce", "mock_claim": "secure"})
    tagged_token = cbor2.dumps(cbor2.CBORTag(61, cbor2.loads(token)))

    view = cose_cwt_to_jwt_view(tagged_token)

    assert view["_meta"] == {"cose_type": "5"}
    assert view["header"]["alg"] == "ES256"
    assert view["header"]["kid"] == "cwt-jwt-test"
    assert view["payload"] == {"eat_nonce": _b64u(b"nonce"), "mock_claim": "secure"}
    with pytest.raises(ValueError, match="trailing bytes"):
        cose_cwt_to_jwt_view(token + b"\x00")


def test_cose_cwt_view_marks_encrypted_payloads_unreadable() -> None:
    """GIVEN an encrypted COSE message WHEN viewed THEN ciphertext is not decoded as CWT claims."""
    protected = cbor2.dumps({COSEHeaders.ALG.value: -16})
    encrypted = cbor2.dumps(cbor2.CBORTag(16, [protected, {}, b"opaque-ciphertext"]))

    view = cose_cwt_to_jwt_view(encrypted)

    assert view["_meta"] == {"cose_type": "1"}
    assert view["payload"] == "<no readable payload (encrypted?)>"


def test_verified_jwt_issuance_preserves_claims() -> None:
    """GIVEN a verified JWS WHEN reissued as CWT THEN raw-CBOR claims survive the new signature."""
    jwt_private_pem, jwt_public_pem = _jwt_pems("jwt-source")
    cwt_signing_key, cwt_verify_key = _cwt_keys("cwt-target")
    _wrong_private_pem, wrong_public_pem = _jwt_pems("wrong-source")
    claims = {
        "aud": "https://api.example",
        "jti": "jwt-001",
        "eat_nonce": _b64u(b"nonce"),
        "mock_claim": "secure",
    }
    token = pyjwt.encode(claims, jwt_private_pem, algorithm="ES256")

    issued_cwt = verified_jwt_to_signed_cwt(
        token,
        cwt_signing_key,
        jwt_verify_key=jwt_public_pem,
        jwt_algorithms=["ES256"],
        audience="https://api.example",
    )
    payload = COSE.new().decode(issued_cwt, cwt_verify_key)

    assert cbor2.loads(payload) == {
        3: "https://api.example",
        7: b"jwt-001",
        10: b"nonce",
        "mock_claim": "secure",
    }
    with pytest.raises(pyjwt.InvalidSignatureError):
        verified_jwt_to_signed_cwt(
            token,
            cwt_signing_key,
            jwt_verify_key=wrong_public_pem,
            jwt_algorithms=["ES256"],
            audience="https://api.example",
        )
    with pytest.raises(pyjwt.InvalidAudienceError):
        verified_jwt_to_signed_cwt(
            token,
            cwt_signing_key,
            jwt_verify_key=jwt_public_pem,
            jwt_algorithms=["ES256"],
            audience="https://wrong.example",
        )
    with pytest.raises(pyjwt.InvalidAlgorithmError):
        verified_jwt_to_signed_cwt(
            token,
            cwt_signing_key,
            jwt_verify_key=jwt_public_pem,
            jwt_algorithms=["ES384"],
            audience="https://api.example",
        )

    with pytest.raises(ValueError, match="audience"):
        verified_jwt_to_signed_cwt(
            token,
            cwt_signing_key,
            jwt_verify_key=jwt_public_pem,
            jwt_algorithms=["ES256"],
        )

    missing_audience_token = pyjwt.encode({"sub": "subject"}, jwt_private_pem, algorithm="ES256")
    with pytest.raises(pyjwt.MissingRequiredClaimError, match="aud"):
        verified_jwt_to_signed_cwt(
            missing_audience_token,
            cwt_signing_key,
            jwt_verify_key=jwt_public_pem,
            jwt_algorithms=["ES256"],
            audience="https://api.example",
        )

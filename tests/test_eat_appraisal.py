# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared plaintext EAT-JWT appraisal helpers.

Covers the kid-resolved multi-alg signature check, freshness, and mock_claim
appraisal shared by EarEatDemo's py-verifier and EarEatHpkeDemo's
challenge-response endpoint (and reused by EarEatHpkeVerifier's inner tail).
"""

from __future__ import annotations

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.verifier.eat_appraisal import appraise_eat_jwt, check_nonce_and_claim, eat_nonce_bytes

KID = "AYZTfot8SkI5u4aVAWvjXAGCNDIYF7yzwBipMLLzo8MM"
NONCE = b"\x02" * 16


def _ec_token(kid: str, nonce: bytes, mock_claim: str, key: ec.EllipticCurvePrivateKey) -> bytes:
    # cwt_jwt_utils.sign_es256 doesn't stamp a kid, so build the header via PyJWT directly
    # (the same library jose_jws itself wraps) to match what the demo verifiers receive.
    payload = {"eat_nonce": cwt_jwt_utils.b64u_encode(nonce), "mock_claim": mock_claim, "iat": 0}
    return jwt.encode(payload, key, algorithm="ES256", headers={"kid": kid}).encode()


def test_appraise_eat_jwt_affirming():
    key = ec.generate_private_key(ec.SECP256R1())
    token = _ec_token(KID, NONCE, "secure", key)
    trust_anchors = {KID: key.public_key()}

    status, reason = appraise_eat_jwt(token, trust_anchors, NONCE, "secure")

    assert status == "affirming", reason


def test_appraise_eat_jwt_unknown_kid_contraindicated():
    key = ec.generate_private_key(ec.SECP256R1())
    token = _ec_token("some-other-kid", NONCE, "secure", key)
    trust_anchors = {KID: key.public_key()}

    status, reason = appraise_eat_jwt(token, trust_anchors, NONCE, "secure")

    assert status == "contraindicated"
    assert "trust anchor" in reason


def test_appraise_eat_jwt_wrong_key_contraindicated():
    signing_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    token = _ec_token(KID, NONCE, "secure", signing_key)
    trust_anchors = {KID: other_key.public_key()}  # anchor does not match the signer

    status, _reason = appraise_eat_jwt(token, trust_anchors, NONCE, "secure")

    assert status == "contraindicated"


def test_appraise_eat_jwt_nonce_mismatch_contraindicated():
    key = ec.generate_private_key(ec.SECP256R1())
    token = _ec_token(KID, NONCE, "secure", key)
    trust_anchors = {KID: key.public_key()}

    status, reason = appraise_eat_jwt(token, trust_anchors, b"\x00" * 16, "secure")

    assert status == "contraindicated"
    assert "nonce" in reason


def test_appraise_eat_jwt_wrong_mock_claim_contraindicated():
    key = ec.generate_private_key(ec.SECP256R1())
    token = _ec_token(KID, NONCE, "insecure", key)
    trust_anchors = {KID: key.public_key()}

    status, reason = appraise_eat_jwt(token, trust_anchors, NONCE, "secure")

    assert status == "contraindicated"
    assert "mock_claim" in reason


def test_appraise_eat_jwt_rsa_ps256_supported():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = {"eat_nonce": cwt_jwt_utils.b64u_encode(NONCE), "mock_claim": "secure", "iat": 0}
    token = jwt.encode(payload, key, algorithm="PS256", headers={"kid": KID}).encode()
    trust_anchors = {KID: key.public_key()}

    status, reason = appraise_eat_jwt(token, trust_anchors, NONCE, "secure")

    assert status == "affirming", reason


def test_eat_nonce_bytes_tolerates_padding():
    unpadded = cwt_jwt_utils.b64u_encode(NONCE)
    padded = unpadded + "=" * (-len(unpadded) % 4)

    assert eat_nonce_bytes(unpadded) == NONCE
    assert eat_nonce_bytes(padded) == NONCE
    assert eat_nonce_bytes("") == b""


def test_check_nonce_and_claim_affirming():
    claims = {"eat_nonce": cwt_jwt_utils.b64u_encode(NONCE), "mock_claim": "secure"}

    status, reason = check_nonce_and_claim(claims, NONCE, "secure")

    assert status == "affirming", reason

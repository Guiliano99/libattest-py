# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the EAR JWT ES256 signature verifier (libattest.formats.eat_ear.cwt_jwt)."""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from libattest.formats.eat_ear.cwt_jwt import verify_ear_jwt


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _signed_jwt(private_key: ec.EllipticCurvePrivateKey, payload: dict) -> str:
    """Build a compact ES256 JWT with the raw R||S signature verify_ear_jwt expects."""
    header = _b64u(json.dumps({"alg": "ES256"}).encode())
    body = _b64u(json.dumps(payload).encode())
    message = f"{header}.{body}".encode("ascii")
    der_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{header}.{body}.{_b64u(raw_sig)}"


def test_valid_signature_verifies() -> None:
    """GIVEN a JWT signed by the matching key WHEN verified THEN it returns True."""
    key = ec.generate_private_key(ec.SECP256R1())
    jwt = _signed_jwt(key, {"iss": "attester"})

    assert verify_ear_jwt(jwt, key.public_key()) is True


def test_tampered_signature_fails_closed() -> None:
    """GIVEN a JWT with a corrupted signature WHEN verified THEN it returns False.

    Exercises the ``except InvalidSignature`` branch specifically.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    header, body, sig = _signed_jwt(key, {"iss": "attester"}).split(".")
    corrupted = bytearray(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
    corrupted[0] ^= 0xFF

    tampered_jwt = f"{header}.{body}.{_b64u(bytes(corrupted))}"

    assert verify_ear_jwt(tampered_jwt, key.public_key()) is False


def test_wrong_key_fails_closed() -> None:
    """GIVEN a JWT verified against a different key's public half THEN it returns False."""
    signer = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    jwt = _signed_jwt(signer, {"iss": "attester"})

    assert verify_ear_jwt(jwt, other.public_key()) is False


def test_malformed_token_fails_closed() -> None:
    """GIVEN a string that is not a compact JWT WHEN verified THEN it returns False."""
    key = ec.generate_private_key(ec.SECP256R1())

    assert verify_ear_jwt("not-a-jwt", key.public_key()) is False


def test_wrong_length_signature_fails_closed() -> None:
    """GIVEN a non-64-byte signature (not raw ES256 R||S) WHEN verified THEN it returns False."""
    key = ec.generate_private_key(ec.SECP256R1())
    header = _b64u(json.dumps({"alg": "ES256"}).encode())
    body = _b64u(json.dumps({"iss": "attester"}).encode())

    assert verify_ear_jwt(f"{header}.{body}.{_b64u(b'too-short')}", key.public_key()) is False

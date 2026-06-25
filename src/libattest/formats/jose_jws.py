# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""ES256 compact JWS (via PyJWT) and P-256 JWK helpers (RFC 7515 / RFC 7517 / RFC 7518).

The JWT-HPKE EAR/EAT flow needs JOSE for two ES256 operations: verifying the inner
signed EAT (produced by the attester) and signing the outgoing EAR JWT.  Both delegate
to :mod:`jwt` (PyJWT), which carries the ES256 signature in the fixed-width ``r || s``
form (RFC 7518 §3.4) over ``cryptography`` primitives.  :func:`verify_es256` pins the
accepted algorithm to ES256 (JWS alg-confusion defence) and translates PyJWT's
exceptions back to this module's contract: ``ValueError`` for a malformed token or a
non-ES256 ``alg``, and :class:`cryptography.exceptions.InvalidSignature` for a bad
signature.

The base64url and P-256 JWK helpers stay hand-rolled here because the HPKE layer
(:mod:`libattest.formats.jose_hpke`) and the EAR/EAT verifier import them and need
``cryptography`` key objects — and because no released JOSE library implements
draft-ietf-jose-hpke-encrypt.
"""

from __future__ import annotations

import base64
from typing import Any

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ALG = "ES256"

# Shared ES256 algorithm handle for EC P-256 <-> JWK conversion (PyJWT public API).
_ES256 = jwt.get_algorithm_by_name(ALG)


# ── base64url (unpadded, as JOSE requires) ──────────────────────────────────────
def b64u_decode(s: str) -> bytes:
    """base64url-decode a string, restoring the stripped ``=`` padding."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b: bytes) -> str:
    """base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ── P-256 JWK <-> cryptography EC keys (delegated to PyJWT) ───────────────────────
def p256_public_to_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """Return the public-half P-256 JWK (``kty``/``crv``/``x``/``y``)."""
    return _ES256.to_jwk(public_key, as_dict=True)


def p256_private_to_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    """Return the private P-256 JWK (the public JWK plus the ``d`` parameter)."""
    return _ES256.to_jwk(private_key, as_dict=True)


def _p256_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey:
    """Load an EC key from a P-256 JWK via PyJWT, enforcing the P-256 profile.

    PyJWT's ``from_jwk`` itself accepts other curves and raises ``InvalidKeyError``; this
    pins the curve and normalises failures to ``ValueError`` (this module's contract).
    """
    if jwk.get("crv") != "P-256":
        raise ValueError("expected a P-256 EC JWK")
    try:
        return _ES256.from_jwk(jwk)
    except jwt.PyJWTError as exc:
        raise ValueError(f"invalid P-256 EC JWK: {exc}") from exc


def jwk_to_p256_public(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Build a P-256 public key from a JWK dict."""
    key = _p256_key_from_jwk(jwk)
    return key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key


def jwk_to_p256_private(jwk: dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    """Build a P-256 private key from a JWK dict (must carry ``d``)."""
    if "d" not in jwk:
        raise ValueError("private JWK must contain the 'd' parameter")
    key = _p256_key_from_jwk(jwk)
    if not isinstance(key, ec.EllipticCurvePrivateKey):  # 'd' present ⇒ private; defensive
        raise ValueError("expected a private P-256 EC JWK")
    return key


# ── ES256 compact JWS ────────────────────────────────────────────────────────────
def _load_public_key(key: ec.EllipticCurvePublicKey | bytes | str) -> ec.EllipticCurvePublicKey:
    """Accept an EC public key, a PEM (str/bytes), or DER SPKI bytes."""
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key
    data = key.encode("ascii") if isinstance(key, str) else key
    for loader in (serialization.load_pem_public_key, serialization.load_der_public_key):
        try:
            loaded = loader(data)
        except ValueError:
            continue
        if isinstance(loaded, ec.EllipticCurvePublicKey):
            return loaded
        raise ValueError("JWS verification key is not an EC public key")
    raise ValueError("could not load an EC public key from the given PEM/DER bytes")


def sign_es256(payload: dict[str, Any], private_key: ec.EllipticCurvePrivateKey) -> str:
    """Sign *payload* as an ES256 compact JWS and return the token string."""
    # PyJWT already emits the {"alg": "ES256", "typ": "JWT"} header by default.
    return jwt.encode(payload, private_key, algorithm=ALG)


def verify_es256(token: str, key: ec.EllipticCurvePublicKey | bytes | str) -> dict[str, Any]:
    """Verify an ES256 compact JWS and return its claims.

    :raises ValueError: malformed token or non-ES256 ``alg``.
    :raises cryptography.exceptions.InvalidSignature: the signature does not verify.
    """
    public_key = _load_public_key(key)
    try:
        return jwt.decode(
            token,
            public_key,
            algorithms=[ALG],
            # Signature + alg stay enforced (verify_signature defaults on; algorithms pins ES256).
            # Every registered-claim check is disabled so claims are returned verbatim, exactly
            # like the old hand-rolled verify — freshness/appraisal is the verifier's job. Without
            # this PyJWT would reject e.g. a cross-machine inner-EAT ``iat`` skew or any ``aud``.
            options={
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
                "verify_sub": False,
                "verify_jti": False,
            },
        )
    except jwt.InvalidSignatureError as exc:  # subclass of DecodeError — must precede it
        raise InvalidSignature(str(exc)) from exc
    except jwt.InvalidAlgorithmError as exc:
        raise ValueError(f"unsupported JWS alg; expected {ALG}") from exc
    except jwt.PyJWTError as exc:  # malformed token, bad header, etc.
        raise ValueError(f"invalid compact JWS: {exc}") from exc


__all__ = [
    "ALG",
    "InvalidSignature",
    "b64u_decode",
    "b64u_encode",
    "jwk_to_p256_private",
    "jwk_to_p256_public",
    "p256_private_to_jwk",
    "p256_public_to_jwk",
    "sign_es256",
    "verify_es256",
]

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Shared EAT-JWT appraisal helpers for the software EAR/EAT demo verifiers.

Both the plaintext demo verifier (EarEatDemo's py-verifier) and the HPKE demo
verifier (:class:`libattest.verifier.eareat_hpke.EarEatHpkeVerifier`) apply the
same appraisal tail to a signed EAT-JWT once its bytes are in hand: resolve the
signing key by ``kid`` against a trust-anchor store, verify the signature under
only that key type's algorithms, check freshness against the RA-issued nonce,
and compare ``mock_claim`` against the reference value. This module is the one
place that logic lives, so demo verifiers stop reimplementing it by hand.

:func:`verify_eat_jwt` supports multiple key types (EC -> ES256, RSA -> RS256 /
PS256) because the EarEatDemo negative-scenario evidence-config exercises a
wrong-key-type case (``example-incorrect-key-ps256``). The HPKE demo's inner
EAT-JWS step uses a single fixed EC key instead of a kid-keyed trust store, so
it keeps using :func:`libattest.formats.eat_ear.cwt_jwt_utils.verify_es256` for signature
verification and only reuses :func:`eat_nonce_bytes` / :func:`check_nonce_and_claim`
from here for the freshness + claim tail.
"""

from __future__ import annotations

import base64
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

__all__ = [
    "TrustAnchorError",
    "appraise_eat_jwt",
    "check_nonce_and_claim",
    "eat_nonce_bytes",
    "verify_eat_jwt",
]


class TrustAnchorError(Exception):
    """Raised when a token's ``kid`` has no trust anchor, or an unsupported key type."""


def eat_nonce_bytes(b64: str) -> bytes:
    """Decode an ``eat_nonce`` base64url string to raw bytes, tolerating padding.

    JWT/JOSE base64url is unpadded, but some evidence producers (e.g. the ATG
    evidence generator's ``base64.URLEncoding``) emit ``=`` padding; comparing on
    bytes keeps the freshness check robust to either form. Returns ``b""`` on
    malformed input, which then fails the ``== expected_nonce`` comparison.
    """
    try:
        return base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    except (ValueError, TypeError):
        return b""


def verify_eat_jwt(token_bytes: bytes, trust_anchors: dict[str, Any]) -> dict[str, Any]:
    """Resolve the signing key by ``kid`` and verify the EAT-JWT's signature.

    ``trust_anchors`` maps ``kid -> cryptography public key`` (EC or RSA). The
    algorithm set is derived from the resolved key's type so a token signed with
    the wrong key type is rejected, not silently accepted under a mismatched alg.

    :returns: the verified claims dict.
    :raises TrustAnchorError: unknown ``kid`` or an unsupported trust-anchor key type.
    :raises jwt.PyJWTError: malformed token header or signature verification failure.
    """
    header = jwt.get_unverified_header(token_bytes)
    kid = header.get("kid", "")
    pubkey = trust_anchors.get(kid)
    if pubkey is None:
        raise TrustAnchorError(f"no trust anchor provisioned for kid {kid!r}")

    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        algs = ["ES256"]
    elif isinstance(pubkey, rsa.RSAPublicKey):
        algs = ["RS256", "PS256"]
    else:
        raise TrustAnchorError(f"unsupported trust-anchor key type: {type(pubkey).__name__}")

    return jwt.decode(
        token_bytes,
        pubkey,
        algorithms=algs,
        options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
    )


def check_nonce_and_claim(claims: dict[str, Any], expected_nonce: bytes, reference_mock_claim: str) -> tuple[str, str]:
    """Shared freshness + ``mock_claim`` appraisal tail.

    ``claims`` is an already signature-verified EAT-JWT claims dict (or, for the
    HPKE inner step, the CMW protected header). Returns ``(ear_status, reason)``.
    """
    if eat_nonce_bytes(claims.get("eat_nonce", "")) != expected_nonce:
        return "contraindicated", "nonce mismatch (stale or replayed evidence)"

    mock_claim = claims.get("mock_claim", "")
    if mock_claim != reference_mock_claim:
        return (
            "contraindicated",
            f"appraisal failed: mock_claim={mock_claim!r} != reference {reference_mock_claim!r}",
        )
    return "affirming", "all checks passed"


def appraise_eat_jwt(
    token_bytes: bytes,
    trust_anchors: dict[str, Any],
    expected_nonce: bytes,
    reference_mock_claim: str,
) -> tuple[str, str]:
    """Full plaintext EAT-JWT appraisal: kid-resolve + verify signature + nonce + claim.

    Convenience wrapper combining :func:`verify_eat_jwt` and
    :func:`check_nonce_and_claim`, translating their exceptions into the same
    ``(ear_status, reason)`` shape the demo verifiers return over HTTP.
    """
    try:
        claims = verify_eat_jwt(token_bytes, trust_anchors)
    except TrustAnchorError as exc:
        return "contraindicated", str(exc)
    except jwt.PyJWTError as exc:
        return "contraindicated", f"signature verification failed: {exc}"
    return check_nonce_and_claim(claims, expected_nonce, reference_mock_claim)

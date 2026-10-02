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
import hmac
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

__all__ = [
    "LABEL_PROFILES",
    "TrustAnchorError",
    "appraise_eat_jwt",
    "check_nonce_and_claim",
    "eat_nonce_bytes",
    "verify_eat_jwt",
]


# Claim-label profiles for :func:`check_nonce_and_claim`: JWT-style string labels
# (``eat_nonce`` / ``mock_claim``, the default) or CWT integer labels (RFC 9711
# ``eat_nonce`` = 10 as a raw byte string; the appraisal claim lives at a private int label).
LABEL_PROFILES = ("jwt-string", "cwt-int")
_CWT_EAT_NONCE_LABEL = 10


class TrustAnchorError(Exception):
    """Raised when a token's ``kid`` has no trust anchor, or an unsupported key type."""


def eat_nonce_bytes(nonce: str | bytes) -> bytes:
    """Decode an ``eat_nonce`` claim to raw bytes: base64url for a string, as-is for a byte string.

    JWT/JOSE base64url is unpadded, but some evidence producers (e.g. the ATG
    evidence generator's ``base64.URLEncoding``) emit ``=`` padding; comparing on
    bytes keeps the freshness check robust to either form. Returns ``b""`` on
    malformed input, which then fails the nonce comparison. A CWT
    ``eat_nonce`` (RFC 9711, label 10) is already a raw byte string and is returned unchanged.
    """
    if isinstance(nonce, bytes):
        return nonce
    try:
        return base64.urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
    except (ValueError, TypeError):
        return b""


def _nonce_matches(nonce: Any, expected_nonce: bytes, nonce_type: type) -> bool:
    """Constant-time compare an ``eat_nonce`` claim of the profile's type to the RA nonce; other types never match."""
    if not isinstance(nonce, nonce_type):
        return False
    return hmac.compare_digest(eat_nonce_bytes(nonce), expected_nonce)


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


def check_nonce_and_claim(
    claims: dict[Any, Any],
    expected_nonce: bytes,
    reference_mock_claim: str,
    *,
    label_profile: str = "jwt-string",
    appraisal_label: int = -70000,
) -> tuple[str, str]:
    """Shared freshness + ``mock_claim`` appraisal tail.

    ``claims`` is an already signature-verified EAT-JWT claims dict (or, for the
    HPKE inner step, the CMW protected header). Returns ``(ear_status, reason)``.

    ``label_profile`` selects where the two claims live: ``"jwt-string"`` (default) reads
    ``eat_nonce`` / ``mock_claim``; ``"cwt-int"`` reads the nonce at integer label 10 and
    the appraisal claim at ``appraisal_label``. Profiles never cross-accept: under
    ``"cwt-int"`` a claims map carrying the string labels as well is rejected.
    The nonce type follows the profile: a base64url string for ``"jwt-string"`` (unchanged), a raw
    byte string for ``"cwt-int"`` (RFC 9711); any other type is a mismatch. Compared in constant time.

    :raises ValueError: unknown ``label_profile``.
    """
    if label_profile == "jwt-string":
        nonce_label, claim_label, nonce_type = "eat_nonce", "mock_claim", str
    elif label_profile == "cwt-int":
        nonce_label, claim_label, nonce_type = _CWT_EAT_NONCE_LABEL, appraisal_label, bytes
        mixed = [k for k in ("eat_nonce", "mock_claim") if k in claims]
        if mixed:
            return "contraindicated", f"mixed claim labels: string label(s) {mixed} in a cwt-int claims set"
        if nonce_label not in claims and claim_label not in claims:
            return "contraindicated", f"claims set carries neither label {nonce_label} nor {claim_label}"
    else:
        raise ValueError(f"unknown label_profile {label_profile!r}; expected one of {LABEL_PROFILES}")

    if not _nonce_matches(claims.get(nonce_label, ""), expected_nonce, nonce_type):
        return "contraindicated", "nonce mismatch (stale or replayed evidence)"

    mock_claim = claims.get(claim_label, "")
    claim_name = "mock_claim" if label_profile == "jwt-string" else f"claim {claim_label}"
    if mock_claim != reference_mock_claim:
        return (
            "contraindicated",
            f"appraisal failed: {claim_name}={mock_claim!r} != reference {reference_mock_claim!r}",
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

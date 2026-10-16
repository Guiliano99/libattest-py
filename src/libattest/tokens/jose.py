# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""JOSE-side codecs: signed EAT-JWT and unsigned JSON claim sets (UJCS).

Two properties this replaces in the pre-existing helpers:

* **No algorithm pinning.** ``sign_es256``/``verify_es256`` hardwire ES256/P-256 and
  a single key. Here the accepted algorithms are an explicit allowlist and the key
  comes from a resolver, so RS256/PS256/EdDSA deployments need no library change.
* **The header is checked before the key is chosen.** ``alg`` must be in the
  allowlist *and* must match the resolved key, so a token cannot select its own
  verification algorithm (the classic alg-confusion shape).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import jwt as pyjwt

from libattest.formats.eat_ear.cwt_jwt import cwt_claim_set_to_jwt_view, jwt_claims_to_cwt_claim_set
from libattest.formats.media_types import EAT_JWT, EAT_UCS_JSON
from libattest.tokens.model import ClaimSet, KeyResolver, Token, resolve_key

#: Signature algorithms accepted by default. ``none`` is absent deliberately and
#: must never be added: an unsigned token is a UJCS, which has its own media type.
DEFAULT_JWS_ALGORITHMS = frozenset({"ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"})


class JwsCodec:
    """Codec for ``application/eat+jwt`` — a signed compact JWS carrying EAT claims."""

    media_types = frozenset({EAT_JWT})

    def __init__(self, algorithms: frozenset[str] | set[str] | None = None) -> None:
        """Restrict this codec to *algorithms* (default :data:`DEFAULT_JWS_ALGORITHMS`)."""
        allowed = frozenset(algorithms) if algorithms else DEFAULT_JWS_ALGORITHMS
        if "none" in {alg.lower() for alg in allowed}:
            raise ValueError("the 'none' JWS algorithm is never acceptable for evidence")
        self.algorithms = allowed

    def decode(
        self,
        raw: bytes,
        *,
        keys: KeyResolver | Mapping[str, Any] | Any = None,
        aad: bytes | None = None,  # noqa: ARG002 - JWS compact has no AAD input
    ) -> Token:
        """Verify a compact JWS and return its claims as a canonical claim set.

        :raises ValueError: malformed token, disallowed ``alg``, or no key resolved.
        :raises jwt.PyJWTError: the signature does not verify.
        """
        token = raw.decode("ascii") if isinstance(raw, bytes | bytearray) else str(raw)
        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.PyJWTError as exc:
            raise ValueError(f"malformed JWS header: {exc}") from exc

        alg = header.get("alg")
        if alg not in self.algorithms:
            raise ValueError(f"JWS alg {alg!r} is not accepted; allowed: {sorted(self.algorithms)}")

        key = resolve_key(keys, header)
        if key is None:
            raise ValueError(f"no verification key for kid={header.get('kid')!r}")

        # Pin the algorithm to the one the header declared AND the allowlist admits,
        # so the token cannot widen the accepted set.
        claims = pyjwt.decode(
            token,
            key,
            algorithms=[alg],
            options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
        )
        return Token(
            media_type=EAT_JWT,
            claims=jwt_claims_to_cwt_claim_set(claims),
            protected=header,
            verified=True,
        )

    def encode(
        self,
        claims: ClaimSet,
        *,
        signer: Any = None,
        aad: bytes | None = None,  # noqa: ARG002
        algorithm: str = "ES256",
        headers: Mapping[str, Any] | None = None,
    ) -> bytes:
        """Sign *claims* as a compact JWS, rendering them through the JSON view."""
        if signer is None:
            raise ValueError("signing a JWS requires a private key")
        if algorithm not in self.algorithms:
            raise ValueError(f"JWS alg {algorithm!r} is not accepted by this codec")
        token = pyjwt.encode(
            cwt_claim_set_to_jwt_view(claims),
            signer,
            algorithm=algorithm,
            headers=dict(headers or {}),
        )
        return token.encode("ascii") if isinstance(token, str) else token


class UjcsCodec:
    """Codec for ``application/eat-ucs+json`` — an *unsigned* JSON claim set (RFC 9782 §2.1.5).

    Decodes successfully and reports ``verified=False``. Callers must treat the
    claims as unauthenticated; the media type is the signal that no signature was
    ever present, as distinct from one that failed to verify.
    """

    media_types = frozenset({EAT_UCS_JSON})

    def decode(
        self,
        raw: bytes,
        *,
        keys: KeyResolver | Mapping[str, Any] | Any = None,  # noqa: ARG002 - unsigned by definition
        aad: bytes | None = None,  # noqa: ARG002
    ) -> Token:
        """Parse an unsigned JSON claim set into a canonical claim set."""
        try:
            claims = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"unsigned JSON claim set is not valid JSON: {exc}") from exc
        if not isinstance(claims, dict):
            raise ValueError(f"unsigned JSON claim set must be an object, got {type(claims).__name__}")
        return Token(media_type=EAT_UCS_JSON, claims=jwt_claims_to_cwt_claim_set(claims), verified=False)

    def encode(
        self,
        claims: ClaimSet,
        *,
        signer: Any = None,  # noqa: ARG002 - unsigned by definition
        aad: bytes | None = None,  # noqa: ARG002
    ) -> bytes:
        """Serialise *claims* as an unsigned JSON claim set."""
        return json.dumps(cwt_claim_set_to_jwt_view(claims), separators=(",", ":")).encode()


__all__ = ["DEFAULT_JWS_ALGORITHMS", "JwsCodec", "UjcsCodec"]

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""COSE-side codecs: signed CWT and unsigned CBOR claim sets (UCCS).

The COSE structure is determined *before* any key is used, and an unexpected one is
a rejection rather than a fall-through. That matters because the existing
``cose_cwt_to_jwt_view`` renders a ``COSE_Mac0`` as ordinary claims and lets the
unprotected header shadow the protected one — a decoder that cannot tell a signed
token from an unsigned one cannot be the basis for an appraisal.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import cbor2
from cwt import COSE

from libattest.formats.media_types import EAT_CWT, EAT_UCS_CBOR
from libattest.tokens.model import ClaimSet, KeyResolver, Token, resolve_key

#: CBOR tag numbers (RFC 8152 / RFC 8392) this module distinguishes.
CWT_TAG = 61
COSE_ENCRYPT0_TAG = 16
COSE_MAC0_TAG = 17
COSE_SIGN1_TAG = 18
COSE_SIGN_TAG = 98

#: COSE algorithm labels accepted for a signed CWT: ES256/384/512, PS256, EdDSA.
DEFAULT_COSE_ALGORITHMS = frozenset({-7, -35, -36, -37, -8})

_COSE_ALG_LABEL = 1
_COSE_KID_LABEL = 4


def _strip_cwt_tag(decoded: Any) -> Any:
    """Unwrap the optional CWT tag 61 that may enclose a COSE message."""
    if isinstance(decoded, cbor2.CBORTag) and decoded.tag == CWT_TAG:
        return decoded.value
    return decoded


def _cose_structure(decoded: Any) -> tuple[int | None, Any]:
    """Return ``(tag, value)`` for a COSE message, tolerating the untagged form.

    An untagged 4-element array is a ``COSE_Sign1`` by RFC 8152 convention; anything
    else has no signature layer and is reported as ``(None, value)``.
    """
    if isinstance(decoded, cbor2.CBORTag):
        return decoded.tag, decoded.value
    if isinstance(decoded, list) and len(decoded) == 4:
        return COSE_SIGN1_TAG, decoded
    return None, decoded


def _protected_header(value: Any) -> dict[int, Any]:
    """Decode the protected bucket of a COSE message. Only this bucket is trusted."""
    try:
        protected = value[0]
        return cbor2.loads(protected) if protected else {}
    except (IndexError, TypeError, ValueError):
        return {}


class CwtCodec:
    """Codec for ``application/eat+cwt`` — a signed ``COSE_Sign1`` CWT."""

    media_types = frozenset({EAT_CWT})

    def __init__(self, algorithms: frozenset[int] | set[int] | None = None) -> None:
        """Restrict this codec to *algorithms* (default :data:`DEFAULT_COSE_ALGORITHMS`)."""
        self.algorithms = frozenset(algorithms) if algorithms else DEFAULT_COSE_ALGORITHMS

    def decode(
        self,
        raw: bytes,
        *,
        keys: KeyResolver | Mapping[str, Any] | Any = None,
        aad: bytes | None = None,
    ) -> Token:
        """Verify a ``COSE_Sign1`` CWT and return its claim set.

        :raises ValueError: not CBOR, not a COSE_Sign1, or a disallowed algorithm.
        """
        try:
            decoded = _strip_cwt_tag(cbor2.loads(raw))
        except Exception as exc:  # noqa: BLE001 - any CBOR failure is a rejection
            raise ValueError(f"CWT is not valid CBOR: {exc}") from exc

        tag, value = _cose_structure(decoded)
        if tag != COSE_SIGN1_TAG:
            found = "an untagged/unsigned claim set" if tag is None else f"COSE tag {tag}"
            raise ValueError(f"expected a COSE_Sign1 CWT, got {found}")

        header = _protected_header(value)
        alg = header.get(_COSE_ALG_LABEL)
        if alg not in self.algorithms:
            raise ValueError(f"COSE alg {alg!r} is not accepted; allowed: {sorted(self.algorithms)}")

        key = resolve_key(keys, {"kid": _kid_of(header), "alg": alg})
        if key is None:
            raise ValueError(f"no verification key for kid={_kid_of(header)!r}")

        payload = cast(bytes, COSE.new().decode(raw, key, external_aad=aad or b""))
        claims = cbor2.loads(payload) if isinstance(payload, bytes | bytearray) else payload
        if not isinstance(claims, dict):
            raise ValueError("CWT payload is not a claim set")
        return Token(media_type=EAT_CWT, claims=claims, protected=header, verified=True)

    def encode(
        self,
        claims: ClaimSet,
        *,
        signer: Any = None,
        aad: bytes | None = None,
    ) -> bytes:
        """Sign *claims* as a ``COSE_Sign1`` over the raw CBOR claim set.

        The claim set is signed as an opaque payload rather than through
        ``cwt.encode``, which silently drops claims it does not recognise (including
        ``eat_nonce``).
        """
        if signer is None:
            raise ValueError("signing a CWT requires a COSE key")
        # The alg MUST be in the protected bucket: it is the only header the decoder
        # trusts, and it is what the allowlist check on decode reads.
        protected: dict[int, Any] = {_COSE_ALG_LABEL: signer.alg}
        if getattr(signer, "kid", None):
            protected[_COSE_KID_LABEL] = signer.kid
        return cast(
            bytes,
            COSE.new().encode_and_sign(cbor2.dumps(claims), signer, protected=protected, external_aad=aad or b""),
        )


class UccsCodec:
    """Codec for ``application/eat-ucs+cbor`` — an *unsigned* CBOR claim set (RFC 9782 §2.1.5).

    Decodes with ``verified=False``. A payload that turns out to carry a COSE
    signature layer is rejected: it should have been sent as ``application/eat+cwt``
    and verified, not accepted unverified under the unsigned media type.
    """

    media_types = frozenset({EAT_UCS_CBOR})

    def decode(
        self,
        raw: bytes,
        *,
        keys: KeyResolver | Mapping[str, Any] | Any = None,  # noqa: ARG002 - unsigned by definition
        aad: bytes | None = None,  # noqa: ARG002
    ) -> Token:
        """Parse an unsigned CBOR claim set into a canonical claim set."""
        try:
            decoded = _strip_cwt_tag(cbor2.loads(raw))
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"unsigned CBOR claim set is not valid CBOR: {exc}") from exc

        tag, _value = _cose_structure(decoded)
        if tag is not None:
            raise ValueError(f"payload carries a COSE structure (tag {tag}); send it as {EAT_CWT!r} so it is verified")
        if not isinstance(decoded, dict):
            raise ValueError(f"unsigned CBOR claim set must be a map, got {type(decoded).__name__}")
        return Token(media_type=EAT_UCS_CBOR, claims=decoded, verified=False)

    def encode(
        self,
        claims: ClaimSet,
        *,
        signer: Any = None,  # noqa: ARG002 - unsigned by definition
        aad: bytes | None = None,  # noqa: ARG002
    ) -> bytes:
        """Serialise *claims* as an unsigned CBOR claim set."""
        return cast(bytes, cbor2.dumps(claims))


def _kid_of(header: Mapping[int, Any]) -> str:
    """Return the protected header's ``kid`` as text, or ``""`` when absent."""
    kid = header.get(_COSE_KID_LABEL)
    if isinstance(kid, bytes | bytearray):
        return kid.decode("utf-8", "replace")
    return "" if kid is None else str(kid)


__all__ = [
    "COSE_ENCRYPT0_TAG",
    "COSE_MAC0_TAG",
    "COSE_SIGN1_TAG",
    "COSE_SIGN_TAG",
    "CWT_TAG",
    "DEFAULT_COSE_ALGORITHMS",
    "CwtCodec",
    "UccsCodec",
]

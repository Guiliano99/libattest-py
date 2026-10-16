# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Media-type → codec dispatch: the extension seam for new token formats.

Today a new evidence shape means a new bespoke verifier class. Here it means one
:class:`TokenCodec` registration. The media type is the dispatch key because it is
already on the wire — a CMW record names it (``["application/jose", …]``) — so
nothing new has to be carried to make this work.

The statement OID keeps its own job: selecting the ASN.1 *wire structure*. It does
not select the token format; that is what the media type is for.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Protocol, runtime_checkable

from libattest.formats.media_types import base_media_type
from libattest.tokens.model import ClaimSet, KeyResolver, Token


class UnknownMediaTypeError(KeyError):
    """Raised when no codec is registered for a media type.

    A distinct type so dispatch failure ("nobody handles this format") is never
    confused with appraisal failure ("this evidence is bad").
    """


@runtime_checkable
class TokenCodec(Protocol):
    """Decode/encode one family of media types into :class:`Token`."""

    #: The RFC 9782 media types this codec claims, without parameters.
    media_types: frozenset[str]

    def decode(
        self,
        raw: bytes,
        *,
        keys: KeyResolver | Mapping[str, Any] | Any = None,
        aad: bytes | None = None,
    ) -> Token:
        """Decode *raw* into a :class:`Token`, verifying it when the format allows."""
        ...

    def encode(
        self,
        claims: ClaimSet,
        *,
        signer: Any = None,
        aad: bytes | None = None,
    ) -> bytes:
        """Serialise a canonical claim set into this codec's wire form."""
        ...


class TokenRegistry:
    """Media-type → :class:`TokenCodec` lookup.

    Registration happens at import; lookups are read-only, so no locking is needed
    (the same contract as
    :class:`~libattest.formats.respinfo.RespInfoRegistry`).
    """

    def __init__(self) -> None:
        """Initialise an empty media-type → codec map."""
        self._codecs: dict[str, TokenCodec] = {}

    def register(self, codec: TokenCodec) -> TokenCodec:
        """Register *codec* under each media type it declares.

        Re-registering a media type replaces the prior codec, so a deployment can
        refine a built-in one without editing this module.
        """
        for media_type in codec.media_types:
            self._codecs[base_media_type(media_type)] = codec
        return codec

    def codec_for(self, media_type: str) -> TokenCodec:
        """Return the codec handling *media_type* (parameters ignored)."""
        try:
            return self._codecs[base_media_type(media_type)]
        except KeyError:
            raise UnknownMediaTypeError(
                f"no token codec registered for {media_type!r}; known: {sorted(self._codecs)}"
            ) from None

    def handles(self, media_type: str) -> bool:
        """Return whether any codec claims *media_type*."""
        return base_media_type(media_type) in self._codecs

    def media_types(self) -> list[str]:
        """Return every registered media type."""
        return sorted(self._codecs)

    def decode(
        self,
        raw: bytes,
        media_type: str,
        *,
        keys: KeyResolver | Mapping[str, Any] | Any = None,
        aad: bytes | None = None,
    ) -> Token:
        """Decode *raw* using the codec registered for *media_type*."""
        return self.codec_for(media_type).decode(raw, keys=keys, aad=aad)


def build_default_registry(codecs: Iterable[TokenCodec]) -> TokenRegistry:
    """Return a registry seeded with *codecs*."""
    registry = TokenRegistry()
    for codec in codecs:
        registry.register(codec)
    return registry


__all__ = [
    "TokenCodec",
    "TokenRegistry",
    "UnknownMediaTypeError",
    "build_default_registry",
]

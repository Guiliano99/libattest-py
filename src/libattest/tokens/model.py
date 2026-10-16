# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""The one representation every EAT/EAR token decodes to, whatever its wire form.

A :class:`Token` is what a :mod:`~libattest.tokens.registry` codec returns. Its
``claims`` are always a **CWT Claim Set**: integer labels, CBOR-native values,
byte strings as ``bytes``. That direction is canonical because it is the lossless
one — a JSON view can always be rendered from integer labels
(:func:`~libattest.formats.eat_ear.cwt_jwt.cwt_claim_set_to_jwt_view`), whereas
JSON→CBOR drops every byte string outside the registered-name allowlist.

Appraisal therefore reads one shape regardless of whether the evidence arrived as
``application/eat+jwt`` or ``application/eat+cwt``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from libattest.formats.eat_ear.cwt_jwt import ClaimLabel, ClaimSet, cwt_claim_set_to_jwt_view

#: Resolve a verification/decryption key from a token's (still unverified) header.
#: Returning ``None`` means "no key for this token" and the codec rejects it, which
#: is how a ``kid`` that is not provisioned becomes a rejection rather than a crash.
KeyResolver = Callable[[Mapping[str, Any]], Any]


@dataclass(frozen=True)
class Token:
    """One decoded EAT/EAR token.

    Attributes
    ----------
    media_type:
        The RFC 9782 media type this token was decoded as, e.g.
        ``application/eat+cwt``. Set by the codec, not guessed from content.
    claims:
        Canonical CWT Claim Set — integer labels, ``bytes`` for byte-valued claims.
    protected:
        The *verified* header (JOSE protected header, or COSE protected bucket).
        Never the unprotected/unauthenticated one: a codec that cannot authenticate
        a header leaves this empty rather than filling it from untrusted bytes.
    verified:
        Whether a signature over ``claims`` was checked. ``False`` is a value, not
        an omission — unsigned claim sets (UCCS/UJCS) decode successfully and say so.
    inner:
        For nested tokens (encrypted-then-signed), the token recovered from inside.

    """

    media_type: str
    claims: ClaimSet
    protected: Mapping[str, Any] = field(default_factory=dict)
    verified: bool = False
    inner: Token | None = None

    def claim(self, label: ClaimLabel, default: Any = None) -> Any:
        """Return one claim by its canonical integer label."""
        return self.claims.get(label, default)

    def as_json_view(self) -> dict[str, Any]:
        """Render the claims as a readable JWT-style JSON object.

        A *view*, not a token: it carries no signature and must not be re-parsed as
        evidence. Use it for logging, diffing and human output.
        """
        return cwt_claim_set_to_jwt_view(self.claims)


def resolve_key(keys: KeyResolver | Mapping[str, Any] | Any, header: Mapping[str, Any]) -> Any:
    """Normalise the three accepted key inputs into one resolved key.

    Accepts a resolver callable, a ``kid``→key mapping, or a single bare key. The
    mapping form looks up the token's ``kid``; a single key is returned as-is (the
    caller has already decided which key applies).
    """
    if callable(keys) and not isinstance(keys, Mapping):
        return keys(header)
    if isinstance(keys, Mapping):
        return keys.get(str(header.get("kid", "")))
    return keys


__all__ = ["ClaimLabel", "ClaimSet", "KeyResolver", "Token", "resolve_key"]

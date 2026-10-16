# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""One token layer for every EAT/EAR rendering — JOSE or COSE, signed or unsigned.

Adding a token format is a codec registration, not a new verifier class::

    from libattest.tokens import TOKENS, Token

    token = TOKENS.decode(raw, "application/eat+cwt", keys={"ak-1": verify_key})
    nonce = token.claim(10)  # canonical integer label, bytes value
    assert token.verified

The dispatch key is the media type because it is already on the wire: a CMW record
names it. The statement OID keeps selecting the ASN.1 *wire structure*; it does not
select the token format.

Claims are always a CWT Claim Set (integer labels, ``bytes`` values) whichever media
type they arrived as, so appraisal reads one shape. Render
:meth:`~libattest.tokens.model.Token.as_json_view` for human output only — it is a
view, never evidence.

This package deliberately depends on nothing in ``ra/``, ``verifier/`` or
``attester/``: it is the shared layer they all sit on.
"""

from __future__ import annotations

from libattest.tokens.cose import (
    DEFAULT_COSE_ALGORITHMS,
    CwtCodec,
    UccsCodec,
)
from libattest.tokens.jose import (
    DEFAULT_JWS_ALGORITHMS,
    JwsCodec,
    UjcsCodec,
)
from libattest.tokens.model import ClaimLabel, ClaimSet, KeyResolver, Token
from libattest.tokens.registry import (
    TokenCodec,
    TokenRegistry,
    UnknownMediaTypeError,
    build_default_registry,
)

#: The process-wide registry. A deployment adds a format with
#: ``TOKENS.register(MyCodec())`` and overrides a built-in the same way.
TOKENS: TokenRegistry = build_default_registry(
    [
        JwsCodec(),
        CwtCodec(),
        UjcsCodec(),
        UccsCodec(),
    ]
)

__all__ = [
    "DEFAULT_COSE_ALGORITHMS",
    "DEFAULT_JWS_ALGORITHMS",
    "TOKENS",
    "ClaimLabel",
    "ClaimSet",
    "CwtCodec",
    "JwsCodec",
    "KeyResolver",
    "Token",
    "TokenCodec",
    "TokenRegistry",
    "UccsCodec",
    "UjcsCodec",
    "UnknownMediaTypeError",
    "build_default_registry",
]

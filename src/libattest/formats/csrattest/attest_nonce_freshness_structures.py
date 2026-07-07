# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""ASN.1 structures for the attestation freshness nonce exchange."""

from __future__ import annotations

from pyasn1.type import constraint, namedtype, univ

id_it_nonceRequest = univ.ObjectIdentifier("1.3.6.1.5.5.7.4.98")
id_it_nonceResponse = univ.ObjectIdentifier("1.3.6.1.5.5.7.4.99")

_MIN_NONCE_LEN = 8
_MAX_NONCE_LEN = 64

NonceLengthConstraint = constraint.ValueRangeConstraint(_MIN_NONCE_LEN, _MAX_NONCE_LEN)
NonceValueSizeConstraint = constraint.ConstraintsUnion(
    constraint.ValueSizeConstraint(0, 0),
    constraint.ValueSizeConstraint(_MIN_NONCE_LEN, _MAX_NONCE_LEN),
)


class NonceRequestTypeInfo(univ.Sequence):
    """Type-specific request selector and optional open value."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("reqInfo", univ.Any()),
    )


class NonceResponseTypeInfo(univ.Sequence):
    """Type-specific response selector and optional open value."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("respInfo", univ.Any()),
    )


class NonceRequest(univ.Sequence):
    """NonceRequest ::= SEQUENCE { len, reqTypeInfo }.

    ``reqTypeInfo`` groups the selected open type OID and its optional request
    payload.  pyasn1 cannot model the information object set directly, so the
    open value remains an ``ANY`` containing the selected DER/BER encoding.
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "len",
            univ.Integer().subtype(subtypeSpec=NonceLengthConstraint),
        ),
        namedtype.OptionalNamedType("reqTypeInfo", NonceRequestTypeInfo()),
    )


class NonceResponse(univ.Sequence):
    """NonceResponse ::= SEQUENCE { nonce, expiry, respTypeInfo }.

    ``nonce`` is constrained to ``SIZE(0 | 8..64)``.  A zero-length value means
    the RA/CA does not require a freshness proof for the upcoming certificate
    request.  ``respTypeInfo`` groups the response open type OID and its
    optional payload.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "nonce",
            univ.OctetString().subtype(subtypeSpec=NonceValueSizeConstraint),
        ),
        namedtype.OptionalNamedType("expiry", univ.Integer()),
        namedtype.OptionalNamedType("respTypeInfo", NonceResponseTypeInfo()),
    )


def nonce_request_type_oid(nonce_request: NonceRequest) -> str | None:
    """Return ``reqTypeInfo.type`` as dotted text when present."""
    req_type_info = nonce_request["reqTypeInfo"]
    if not req_type_info.isValue:
        return None
    return str(req_type_info["type"])


def nonce_request_info(nonce_request: NonceRequest) -> bytes | None:
    """Return raw ``reqTypeInfo.reqInfo`` bytes when present."""
    req_type_info = nonce_request["reqTypeInfo"]
    if not req_type_info.isValue or not req_type_info["reqInfo"].isValue:
        return None
    return bytes(req_type_info["reqInfo"])


def nonce_response_type_oid(nonce_response: NonceResponse) -> str | None:
    """Return ``respTypeInfo.type`` as dotted text when present."""
    resp_type_info = nonce_response["respTypeInfo"]
    if not resp_type_info.isValue:
        return None
    return str(resp_type_info["type"])


def nonce_response_info(nonce_response: NonceResponse) -> bytes | None:
    """Return raw ``respTypeInfo.respInfo`` bytes when present."""
    resp_type_info = nonce_response["respTypeInfo"]
    if not resp_type_info.isValue or not resp_type_info["respInfo"].isValue:
        return None
    return bytes(resp_type_info["respInfo"])


# Backward-compatible ``*ASN1`` aliases.  The TPMDemo libattest exported these
# pyasn1 structures under an ``ASN1`` suffix; downstream code (the cmp-test-suite
# MockCA's compatibility wrappers) still imports the suffixed names.  Keep the
# aliases so the base switch (TPMDemo → Updatev7) does not break those imports.
NonceRequestASN1 = NonceRequest
NonceResponseASN1 = NonceResponse


__all__ = [
    "NonceLengthConstraint",
    "NonceRequest",
    "NonceRequestASN1",
    "NonceRequestTypeInfo",
    "NonceResponse",
    "NonceResponseASN1",
    "NonceResponseTypeInfo",
    "NonceValueSizeConstraint",
    "id_it_nonceRequest",
    "id_it_nonceResponse",
    "nonce_request_info",
    "nonce_request_type_oid",
    "nonce_response_info",
    "nonce_response_type_oid",
]

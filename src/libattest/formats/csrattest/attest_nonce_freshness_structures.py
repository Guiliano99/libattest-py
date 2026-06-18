# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""ASN.1 structures for attestation freshness nonce exchange.

Specification links:
* Datatracker: https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/
* GitHub repository: https://github.com/lamps-wg/lamps-attestation-freshness
* ASN.1 redesign PR: https://github.com/lamps-wg/lamps-attestation-freshness/pull/26

This module follows the generic ASN.1 representation introduced by PR #26:
``NonceRequest`` and ``NonceResponse`` carry one optional ``type`` OID and one
matching open-type payload (``reqInfo`` or ``respInfo``).  The previous local
``challengeParams`` / ``responseParams`` ``SEQUENCE OF ChallengeParam`` design is
not part of the current draft shape.

Current draft ASN.1 excerpt (old-style display form used in the draft)::

    ATTESTATION-NONCE-REQUEST ::= TYPE-IDENTIFIER
    AttestationNonceRequestSet ATTESTATION-NONCE-REQUEST ::= {
       ... -- None defined in this document --
    }

    ATTESTATION-NONCE-RESPONSE ::= TYPE-IDENTIFIER
    AttestationNonceResponseSet ATTESTATION-NONCE-RESPONSE ::= {
       ... -- None defined in this document --
    }

    NonceRequest ::= SEQUENCE {
       len INTEGER (8..64) OPTIONAL,
       -- Indicates the required length of the requested nonce
       type ATTESTATION-NONCE-REQUEST.&id(
          {AttestationNonceRequestSet}) OPTIONAL,
       -- Identifies the nonce-request syntax for the
       --   selected Attestation statement type
       reqInfo ATTESTATION-NONCE-REQUEST.&Type(
          {AttestationNonceRequestSet}{@type}) OPTIONAL
       -- Contains type-specific nonce-request information
    }

    NonceResponse ::= SEQUENCE {
       nonce OCTET STRING (SIZE(0 | 8..64)),
       -- Contains the nonce of length len
       expiry INTEGER OPTIONAL,
       -- Indicates how long in seconds the nonce issuer
       --   considers the nonce valid
       type ATTESTATION-NONCE-RESPONSE.&id(
          {AttestationNonceResponseSet}) OPTIONAL,
       -- Identifies the nonce-response syntax for the
       --   selected Attestation statement type
       respInfo ATTESTATION-NONCE-RESPONSE.&Type(
          {AttestationNonceResponseSet}{@type}) OPTIONAL
       -- Contains type-specific nonce-response information
    }

The ``TYPE-IDENTIFIER`` object sets are not modelled directly in pyasn1.  The
wire-level representation is still an OBJECT IDENTIFIER discriminator plus an
``ANY`` value containing the selected type-specific encoding.
"""

from __future__ import annotations

from pyasn1.type import constraint, namedtype, univ

id_it_nonceRequest = univ.ObjectIdentifier("1.2.840.113549.1.9.16.2.8888")
id_it_nonceResponse = univ.ObjectIdentifier("1.2.840.113549.1.9.16.2.8889")

_MIN_NONCE_LEN = 8
_MAX_NONCE_LEN = 64

NonceLengthConstraint = constraint.ValueRangeConstraint(_MIN_NONCE_LEN, _MAX_NONCE_LEN)
NonceValueSizeConstraint = constraint.ConstraintsUnion(
    constraint.ValueSizeConstraint(0, 0),
    constraint.ValueSizeConstraint(_MIN_NONCE_LEN, _MAX_NONCE_LEN),
)


class NonceRequest(univ.Sequence):
    """NonceRequest ::= SEQUENCE { len, type, reqInfo }.

    ``len`` is constrained to the draft range of 8..64 octets.
    ``type`` identifies the type-specific request syntax.
    ``reqInfo`` is an open type encoded as DER/BER bytes in ``ANY`` and MUST be
    omitted unless ``type`` is present.
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "len",
            univ.Integer().subtype(subtypeSpec=NonceLengthConstraint),
        ),
        namedtype.OptionalNamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("reqInfo", univ.Any()),
    )


class NonceResponse(univ.Sequence):
    """NonceResponse ::= SEQUENCE { nonce, expiry, type, respInfo }.

    ``nonce`` is constrained to ``SIZE(0 | 8..64)``.  A zero-length value means
    the RA/CA does not require a freshness proof for the upcoming certificate
    request (an RA/CA that is unable or unwilling to provide a nonce signals a
    protocol error instead).  ``type`` identifies the type-specific response
    syntax.  ``respInfo`` is an open type encoded as DER/BER bytes in ``ANY``
    and MUST be omitted unless ``type`` is present.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "nonce",
            univ.OctetString().subtype(subtypeSpec=NonceValueSizeConstraint),
        ),
        namedtype.OptionalNamedType("expiry", univ.Integer()),
        namedtype.OptionalNamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("respInfo", univ.Any()),
    )


__all__ = [
    "NonceLengthConstraint",
    "NonceRequest",
    "NonceResponse",
    "NonceValueSizeConstraint",
    "id_it_nonceRequest",
    "id_it_nonceResponse",
]

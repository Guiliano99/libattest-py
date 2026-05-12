# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""ASN.1 structures for CMP remote-attestation nonce freshness.

The provisional `id-it` arcs match the MockCA prototype values so this package
can be tested locally before the IANA values are final.

The :class:`NonceRequestASN1` SEQUENCE carries an optional
``challengeParams SEQUENCE OF ChallengeParam`` field (SPEC §DR-2).  Each
:class:`ChallengeParamASN1` is a typed ``{type OID, value ANY}`` pair that
lets attesters attach arbitrary per-evidence-type parameters without
changing the top-level schema.

For ``type == KEY_ATTEST_POP_OID`` the attester MUST include a
:class:`ChallengeParamASN1` entry whose ``type`` equals the evidence OID
and whose ``value`` is the DER-encoded SubjectPublicKeyInfo of the
to-be-attested key.  The MockCA extracts that entry and RSA-OAEP-encrypts
the freshly issued nonce against the SPKI before returning it.

The :class:`NonceResponseASN1` schema is unchanged.  Per SPEC §C-6, when
the corresponding request OID is ``KEY_ATTEST_POP_OID``, the
``nonce`` OCTET STRING in the response carries the OAEP **ciphertext**
instead of plaintext nonce bytes.  The discriminator is purely the
type-OID; legacy senders that don't set a type still receive plaintext.
"""

from pyasn1.type import char, constraint, namedtype, univ

id_it_nonceRequest = univ.ObjectIdentifier("1.2.840.113549.1.9.16.2.8888")
id_it_nonceResponse = univ.ObjectIdentifier("1.2.840.113549.1.9.16.2.8889")

_MAX_SEQUENCE_SIZE = float("inf")


class ChallengeParamASN1(univ.Sequence):
    """ChallengeParam ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }.

    A typed key-value pair for per-OID attester parameters carried in
    ``NonceRequest.challengeParams``.  The ``value`` is DER-encoded bytes
    whose interpretation is defined by ``type``.

    Example — KeyAttestPoP SPKI binding (SPEC §DR-2):
        type  = KEY_ATTEST_POP_OID
        value = DER(SubjectPublicKeyInfo)  -- the to-be-attested RSA key
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType("value", univ.Any()),
    )


class ChallengeParamsASN1(univ.SequenceOf):
    """ChallengeParams ::= SEQUENCE OF ChallengeParam."""

    componentType = ChallengeParamASN1()


class NonceRequestASN1(univ.Sequence):
    """NonceRequest ::= SEQUENCE { len, type, hint, challengeParams }.

    The ``challengeParams`` field is appended at the end as
    ``OptionalNamedType`` so legacy DER decoders silently ignore it
    (SPEC §C-3).  When ``type == KEY_ATTEST_POP_OID``,
    ``challengeParams`` MUST contain an entry with that OID carrying the
    SubjectPublicKeyInfo of the to-be-attested RSA key.
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("len", univ.Integer()),
        namedtype.OptionalNamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("hint", char.UTF8String()),
        namedtype.OptionalNamedType("challengeParams", ChallengeParamsASN1()),
    )


class NonceRequestValueASN1(univ.SequenceOf):
    """NonceRequestValue ::= SEQUENCE SIZE (1..MAX) OF NonceRequest."""

    componentType = NonceRequestASN1()
    subtypeSpec = constraint.ValueSizeConstraint(1, _MAX_SEQUENCE_SIZE)


class NonceResponseASN1(univ.Sequence):
    """NonceResponse ::= SEQUENCE { nonce, expiry, type, hint, responseParams }.

    Per SPEC §C-6 the ``nonce`` field is an overload: plaintext nonce
    bytes when ``type != KEY_ATTEST_POP_OID``, OAEP ciphertext when
    ``type == KEY_ATTEST_POP_OID``.  The schema is unchanged because the
    field type is OCTET STRING in both cases.

    The ``responseParams`` field (SPEC §DR-11) is a ``SEQUENCE OF
    ChallengeParam`` carrying verifier-driven, per-evidence-type
    parameters back to the attester — symmetric with
    :attr:`NonceRequestASN1.challengeParams`.  It reuses the same
    :class:`ChallengeParamASN1` wire shape; only the field name differs.
    Appended at the end as ``OptionalNamedType`` for backward compat
    (SPEC §C-3).

    For ``type == id-tcg-attest-quote`` (2.23.133.20.2), the MockCA
    emits a ``responseParams`` entry whose ``type`` is the configured
    ``TPM_PCR_SELECTION_OID`` and whose ``value`` is the DER-encoded
    :class:`TpmAttestationParamsASN1` listing the PCRs the verifier
    wants quoted plus the negotiated hash algorithm ID
    (SPEC §DR-11).
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("nonce", univ.OctetString()),
        namedtype.OptionalNamedType("expiry", univ.Integer()),
        namedtype.OptionalNamedType("type", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("hint", char.UTF8String()),
        namedtype.OptionalNamedType("responseParams", ChallengeParamsASN1()),
    )


class NonceResponseValueASN1(univ.SequenceOf):
    """NonceResponseValue ::= SEQUENCE SIZE (1..MAX) OF NonceResponse."""

    componentType = NonceResponseASN1()
    subtypeSpec = constraint.ValueSizeConstraint(1, _MAX_SEQUENCE_SIZE)


NonceRequest = NonceRequestASN1
NonceRequestValue = NonceRequestValueASN1
NonceResponse = NonceResponseASN1
NonceResponseValue = NonceResponseValueASN1

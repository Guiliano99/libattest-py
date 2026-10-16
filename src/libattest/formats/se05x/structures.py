# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""SE05x attestation OIDs and the ``Se05xAttestEvidence`` statement.

The Evidence carries the two byte strings a Verifier needs to check an SE05x
attested read (AN13254 §3.1 step 5)::

    Se05xAttestEvidence ::= SEQUENCE {
        commandApdu   OCTET STRING,  -- the command without Le, as the SE hashed it
        responseBody  OCTET STRING   -- the response TLVs, without the status word
    }

There is no separate nonce field and no copy of the algorithm: the Verifier reads
the freshness (``TAG_7``) and the algorithm (``TAG_6``) out of ``commandApdu``,
which the SE's signature covers. The byte-level codec is :mod:`.apdu`.

The request and response OIDs select the nonce type only; they carry no
``reqInfo``/``respInfo`` payload.
"""

from __future__ import annotations

from pyasn1.type import namedtype, univ

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1

# ponytail: fixed placeholder arc, no env override; add resolve_env_oid when a deployment needs another arc.
id_se05x_attest_request = univ.ObjectIdentifier("1.3.6.1.4.1.99999.7.1")
id_se05x_attest_response = univ.ObjectIdentifier("1.3.6.1.4.1.99999.7.2")
id_se05x_attest_statement = univ.ObjectIdentifier("1.3.6.1.4.1.99999.7.3")


class Se05xAttestEvidence(univ.Sequence):
    """Se05xAttestEvidence ::= SEQUENCE { commandApdu OCTET STRING, responseBody OCTET STRING }."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("commandApdu", univ.OctetString()),
        namedtype.NamedType("responseBody", univ.OctetString()),
    )


def prepare_se05x_attest_evidence(command_apdu: bytes, response_body: bytes) -> Se05xAttestEvidence:
    """Build an :class:`Se05xAttestEvidence` from the recorded command and the response body."""
    value = Se05xAttestEvidence()
    value["commandApdu"] = command_apdu
    value["responseBody"] = response_body
    return value


def encode_se05x_attest_evidence(command_apdu: bytes, response_body: bytes) -> bytes:
    """DER-encode an :class:`Se05xAttestEvidence`."""
    return encode_to_der(prepare_se05x_attest_evidence(command_apdu, response_body))


def decode_se05x_attest_evidence(der: bytes | bytearray | univ.Any) -> Se05xAttestEvidence:
    """DER-decode into :class:`Se05xAttestEvidence`.

    Raises
    ------
    ValueError
        On malformed DER or trailing bytes after the SEQUENCE.

    """
    return try_decode_pyasn1(der, Se05xAttestEvidence)


__all__ = [
    "Se05xAttestEvidence",
    "decode_se05x_attest_evidence",
    "encode_se05x_attest_evidence",
    "id_se05x_attest_request",
    "id_se05x_attest_response",
    "id_se05x_attest_statement",
    "prepare_se05x_attest_evidence",
]

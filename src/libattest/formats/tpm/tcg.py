# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TCG TPM attestation structures."""

from pyasn1.type import namedtype, univ

from libattest.asn1_utils import try_decode_pyasn1

id_tcg_attest_certify = univ.ObjectIdentifier("2.23.133.20.1")
id_tcg_attest_quote = univ.ObjectIdentifier("2.23.133.20.2")


class TcgAttestCertify(univ.Sequence):
    """TCG TPM certify evidence carried inside an AttestationStatement."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tpmSAttest", univ.OctetString()),
        namedtype.NamedType("signature", univ.OctetString()),
        namedtype.OptionalNamedType("tpmTPublic", univ.OctetString()),
    )


def prepare_tcg_attest_certify(
    tpm_s_attest: bytes,
    signature: bytes,
    tpm_tpublic: bytes | None = None,
) -> TcgAttestCertify:
    """Build a populated `TcgAttestCertify` value."""
    value = TcgAttestCertify()
    value["tpmSAttest"] = tpm_s_attest
    value["signature"] = signature
    if tpm_tpublic is not None:
        value["tpmTPublic"] = tpm_tpublic
    return value


def decode_tcg_attest_certify(der: bytes | bytearray | univ.Any) -> TcgAttestCertify:
    """Decode DER into :class:`TcgAttestCertify`.

    The same ``TcgAttestCertify`` SEQUENCE serves both key attestation (OID
    2.23.133.20.1) and platform/quote attestation (OID 2.23.133.20.2): both
    are ``SEQUENCE { tpmSAttest, signature, <opt 3rd field> }`` on the wire,
    dispatched by the outer ``AttestationStatement.type`` OID rather than by a
    distinct pyasn1 type.

    Raises
    ------
    ValueError
        On malformed DER or trailing bytes after the value.

    """
    return try_decode_pyasn1(der, TcgAttestCertify)


__all__ = [
    "TcgAttestCertify",
    "decode_tcg_attest_certify",
    "id_tcg_attest_certify",
    "id_tcg_attest_quote",
    "prepare_tcg_attest_certify",
]

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TCG TPM attestation structures."""

from pyasn1.type import namedtype, univ

id_tcg_attest_certify = univ.ObjectIdentifier("2.23.133.20.1")


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

__all__ = [
    "TcgAttestCertify",
    "id_tcg_attest_certify",
    "prepare_tcg_attest_certify",
]

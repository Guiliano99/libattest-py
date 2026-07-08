# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""One-shot TPM evidence generator for the CSR-attestation seam.

The whole point of this module is a single call surface a non-Python client
(gencmpclient, embedding this via ``Py_Initialize``) can use without knowing
any TPM or ASN.1 structure: :func:`generate_tpm_evidence` drives the TPM
(``tpm2_pytss`` via :class:`~libattest.attester.tpm_client.TpmClient`), builds
the ``TcgAttestQuote``/``TcgAttestCertify`` DER, and hands back
``(evidence_der, type_oid)``. The caller wraps that pair in an
``AttestationStatement``/``AttestationBundle`` — this module never sees that
envelope, mirroring how ``atg_generate_evidence`` hands the software EAR/EAT
path an opaque token plus its type OID.

All parameters are positional-friendly (no keyword-only arguments) so the
CPython C-API glue can call this with a plain argument tuple.
"""

from __future__ import annotations

from typing import Optional, Tuple, Union

from pyasn1.codec.der import encoder as der_encoder

from libattest.attester.tpm_client import TpmClient
from libattest.formats.tpm.tcg import (
    id_tcg_attest_certify,
    id_tcg_attest_quote,
    prepare_tcg_attest_certify,
)

_KINDS = ("quote", "certify")


def generate_tpm_evidence(
    kind: str,
    nonce: Union[bytes, str],
    tcti: str,
    ak_handle: int,
    pcr_selection: Optional[str] = None,
    subject_key_pem: Optional[str] = None,
    corrupt_signature: bool = False,
) -> Tuple[bytes, str]:
    """Drive the TPM and return ``(evidence_der, type_oid)`` for one evidence kind.

    Parameters
    ----------
    kind:
        ``"quote"`` (``TPM2_Quote`` over PCRs) or ``"certify"`` (``TPM2_Certify``
        of a subject key). Selects both the TPM operation and the returned OID.
    nonce:
        The verifier's freshness nonce (qualifyingData).
    tcti:
        TCTI connection string (e.g. ``"mssim:host=tpmsim,port=2321"``).
    ak_handle:
        Persistent handle of the already-provisioned AK (e.g. ``0x81010002``).
        Never re-provisioned here — see :meth:`TpmClient.load_ak`.
    pcr_selection:
        ``kind="quote"`` only. tpm2-tools-style ``"bank:idx,idx,..."``. When
        omitted, falls back to :meth:`TpmClient.quote`'s own default
        (``"sha256:0,1,2,3,4"``) — the caller only needs to pass this when the
        verifier selected specific PCRs.
    subject_key_pem:
        Required for ``kind="certify"``. Path to the subject key's "TSS2
        PRIVATE KEY" PEM (the key being certified — must be the same TPM key
        backing the CSR).
    corrupt_signature:
        Negative-test hook only — never set outside a negative-test run. Flips
        one bit of the first signature-payload byte (wire-format offset 6,
        common to RSASSA/RSAPSS/ECDSA — the 6-byte sigAlg/hashAlg/size header
        precedes it) so the verifier's AK-signature check rejects. This used
        to be applied by gencmpclient's C caller directly on the raw signature
        buffer; now that the DER this function returns is opaque to the
        caller (by design — see the module docstring), only this function
        still has structured access to flip that byte, so the hook moved here.

    Returns
    -------
    tuple[bytes, str]
        ``(evidence_der, type_oid)`` — the DER-encoded ``TcgAttestQuote`` /
        ``TcgAttestCertify`` statement and its ``AttestationStatement.type`` OID
        (dotted-decimal). The caller treats ``evidence_der`` as opaque.

    Raises
    ------
    ValueError
        On an unknown ``kind`` or a missing kind-specific argument.

    """
    if kind not in _KINDS:
        raise ValueError(f"unknown kind {kind!r}; expected one of {_KINDS}")
    if kind == "certify" and not subject_key_pem:
        raise ValueError("kind='certify' requires subject_key_pem")

    with TpmClient(tcti=tcti) as tpm:
        tpm.load_ak(ak_handle)

        if kind == "quote":
            quote_kwargs = {"pcr_selection": pcr_selection} if pcr_selection else {}
            result = tpm.quote(nonce, include_pcr_values=True, **quote_kwargs)
            third_field = result.pcr_values or None
            type_oid = id_tcg_attest_quote
        else:
            result = tpm.certify(subject_key_pem, nonce)
            third_field = result.tpmt_public
            type_oid = id_tcg_attest_certify

    signature_wire_bytes = result.signature_wire_bytes
    if corrupt_signature and len(signature_wire_bytes) > 6:
        corrupted = bytearray(signature_wire_bytes)
        corrupted[6] ^= 0x01
        signature_wire_bytes = bytes(corrupted)

    statement = prepare_tcg_attest_certify(
        tpm_s_attest=result.attestation_bytes,
        signature=signature_wire_bytes,
        tpm_tpublic=third_field,
    )
    return der_encoder.encode(statement), str(type_oid)


__all__ = ["generate_tpm_evidence"]

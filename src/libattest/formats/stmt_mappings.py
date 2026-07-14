# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""OID-selected CMP nonce payload structures and evidence-statement structures.

The type-specific ``reqInfo`` and ``respInfo`` fields, and the evidence
``AttestationStatement.stmt`` field, are ASN.1 ``ANY`` values. Their
surrounding OID selects the only ASN.1 structure that is safe to decode them
against. ``NONCE_REQUEST_STATEMENT_STRUCTURES`` and
``NONCE_RESPONSE_STATEMENT_STRUCTURES`` are the explicit reqInfo/respInfo
OID-to-ASN.1 structure dictionaries. ``ATTESTATION_STATEMENT_STRUCTURES`` maps
evidence statement OIDs to their proper ASN.1 payload structures.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias

from pyasn1.type import base, univ
from pyasn1_alt_modules import rfc5280

from libattest.asn1_utils import try_decode_pyasn1
from libattest.formats.eareat_hpke import EVIDENCE_ENC_PARAMS_OID, resolve_evidence_enc_oid
from libattest.formats.key_attest_pop import (
    KeyAttestChall,
    KeyAttestEvidence,
    KeyAttestResp,
    resolve_key_attest_evidence_oid,
)
from libattest.formats.tpm import (
    TPM20QuoteReqInfoASN1,
    TPM20QuoteRespInfoASN1,
    decode_tpm20_quote_req_info_asn1,
    id_tpm20_quote_res,
)
from libattest.formats.tpm.pcr_selection import resolve_tpm_pcr_selection_oid
from libattest.formats.tpm.tcg import id_tcg_attest_quote
from libattest.x509 import CMW, ID_PE_CMW

StatementValue: TypeAlias = bytes
StatementDecoder: TypeAlias = Callable[[StatementValue], object]
StatementStructure: TypeAlias = type[base.Asn1Item]

NONCE_REQUEST_STATEMENT_STRUCTURES: dict[str, StatementStructure] = {
    resolve_tpm_pcr_selection_oid(): TPM20QuoteReqInfoASN1,
    resolve_key_attest_evidence_oid(): KeyAttestChall,
}

NONCE_RESPONSE_STATEMENT_STRUCTURES: dict[str, StatementStructure] = {
    resolve_tpm_pcr_selection_oid(): TPM20QuoteRespInfoASN1,
    str(id_tpm20_quote_res): TPM20QuoteRespInfoASN1,
    str(id_tcg_attest_quote): TPM20QuoteRespInfoASN1,
    resolve_key_attest_evidence_oid(): KeyAttestResp,
    EVIDENCE_ENC_PARAMS_OID: rfc5280.SubjectPublicKeyInfo,
}

ATTESTATION_STATEMENT_STRUCTURES: dict[str, StatementStructure] = {
    resolve_key_attest_evidence_oid(): KeyAttestEvidence,
    resolve_evidence_enc_oid(): univ.OctetString,
    str(ID_PE_CMW): CMW,
}


def get_nonce_request_statement_structure(
    oid: str | univ.ObjectIdentifier,
) -> StatementStructure | None:
    """Return the ASN.1 structure selected by a ``NonceRequest.reqTypeInfo.type`` OID."""
    return NONCE_REQUEST_STATEMENT_STRUCTURES.get(str(oid))


def get_nonce_response_statement_structure(
    oid: str | univ.ObjectIdentifier,
) -> StatementStructure | None:
    """Return the ASN.1 structure selected by a ``NonceResponse.respTypeInfo.type`` OID."""
    return NONCE_RESPONSE_STATEMENT_STRUCTURES.get(str(oid))


def nonce_request_statement_decoders() -> dict[str, StatementDecoder]:
    """Return the resolved ``NonceRequest.reqInfo`` OID-to-decoder mapping.

    Deprecated: prefer :data:`NONCE_REQUEST_STATEMENT_STRUCTURES` /
    :func:`get_nonce_request_statement_structure`. Kept for callers that still
    want a callable decoder rather than a structure to decode themselves; each
    decoder is a thin :func:`~libattest.asn1_utils.try_decode_pyasn1` wrapper
    over the registered structure.
    """
    return {
        oid: _request_decoder_for(structure)
        for oid, structure in NONCE_REQUEST_STATEMENT_STRUCTURES.items()
    }


def _request_decoder_for(structure: StatementStructure) -> StatementDecoder:
    """Pick a reqInfo decoder for *structure*.

    ``TPM20QuoteReqInfoASN1``'s two OPTIONAL fields share the universal SEQUENCE
    tag and cannot be schema-decoded (X.680 §8), so it routes through the
    inner-tag disambiguating object decoder; every other structure decodes
    directly via :func:`~libattest.asn1_utils.try_decode_pyasn1`.
    """
    if structure is TPM20QuoteReqInfoASN1:
        return decode_tpm20_quote_req_info_asn1
    return lambda der, spec=structure: try_decode_pyasn1(der, spec)


def get_nonce_request_statement_decoder(
    oid: str | univ.ObjectIdentifier,
) -> StatementDecoder | None:
    """Return the decoder selected by a ``NonceRequest.reqTypeInfo.type`` OID.

    Deprecated: prefer :func:`get_nonce_request_statement_structure`.
    """
    return nonce_request_statement_decoders().get(str(oid))


__all__ = [
    "ATTESTATION_STATEMENT_STRUCTURES",
    "NONCE_REQUEST_STATEMENT_STRUCTURES",
    "NONCE_RESPONSE_STATEMENT_STRUCTURES",
    "StatementDecoder",
    "StatementStructure",
    "StatementValue",
    "get_nonce_request_statement_decoder",
    "get_nonce_request_statement_structure",
    "get_nonce_response_statement_structure",
    "nonce_request_statement_decoders",
]

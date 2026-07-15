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
from libattest.formats.cmw import CMW, ID_PE_CMW
from libattest.formats.eareat_hpke import (
    EVIDENCE_ENC_PARAMS_OID,
    resolve_cose_evidence_enc_oid,
    resolve_evidence_enc_oid,
)
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
from libattest.formats.tpm.tcg import id_tcg_attest_certify, id_tcg_attest_quote

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
    resolve_cose_evidence_enc_oid(): CMW,
    str(ID_PE_CMW): CMW,
    ID_PE_CMW: CMW,
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
    return {oid: _request_decoder_for(structure) for oid, structure in NONCE_REQUEST_STATEMENT_STRUCTURES.items()}


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


# ── name → OID exposure (the blessed way to reference project OIDs; see the README) ──
# Every OID this project selects on is reachable by a stable human name through the four
# accessors below (re-exported from ``libattest``). Prefer them over importing the raw OID
# constants/resolvers directly.
_STMT_OID_BY_NAME: dict[str, str] = {
    "cmw": str(ID_PE_CMW),
    "id_cmw": str(ID_PE_CMW),  # alias for "cmw" (the id-pe-cmw OID)
    "key-attest": resolve_key_attest_evidence_oid(),
    "jose-hpke-evidence": resolve_evidence_enc_oid(),
    "cose-hpke-evidence": resolve_cose_evidence_enc_oid(),
}

_NONCE_REQUEST_OID_BY_NAME: dict[str, str] = {
    "tpm-quote": resolve_tpm_pcr_selection_oid(),
    "key-attest": resolve_key_attest_evidence_oid(),
    "jose-hpke-evidence-params": EVIDENCE_ENC_PARAMS_OID,
}

_NONCE_RESPONSE_OID_BY_NAME: dict[str, str] = {
    "tpm-quote": resolve_tpm_pcr_selection_oid(),
    "tpm-quote-result": str(id_tpm20_quote_res),
    "tcg-attest-quote": str(id_tcg_attest_quote),
    "key-attest": resolve_key_attest_evidence_oid(),
    "jose-hpke-evidence-params": EVIDENCE_ENC_PARAMS_OID,
}


def _merge_oid_names(*registries: dict[str, str]) -> dict[str, str]:
    """Merge name→OID registries, rejecting any name that maps to two different OIDs."""
    merged: dict[str, str] = {}
    for registry in registries:
        for name, oid in registry.items():
            existing = merged.get(name)
            if existing is not None and existing != oid:
                raise AssertionError(f"OID name {name!r} maps to both {existing} and {oid}")
            merged[name] = oid
    return merged


# Every named OID known to this project: the statement + nonce positions plus the
# stand-alone TPM evidence OIDs.
_OID_BY_NAME: dict[str, str] = _merge_oid_names(
    _STMT_OID_BY_NAME,
    _NONCE_REQUEST_OID_BY_NAME,
    _NONCE_RESPONSE_OID_BY_NAME,
    {"tcg-attest-certify": str(id_tcg_attest_certify)},
)


def _lookup_oid(registry: dict[str, str], name: str, kind: str) -> str:
    """Return the OID registered under *name*, or raise ValueError listing the valid names."""
    try:
        return registry[name]
    except KeyError:
        raise ValueError(f"unknown {kind} name {name!r}; known names: {sorted(registry)}") from None


def get_oid_for_stmt_name(name: str) -> str:
    """Return the dot-decimal OID for a named attestation-statement type (e.g. ``"cmw"``)."""
    return _lookup_oid(_STMT_OID_BY_NAME, name, "statement")


def get_nonce_request_oid_for_name(name: str) -> str:
    """Return the dot-decimal OID for a named ``NonceRequest.reqTypeInfo`` type."""
    return _lookup_oid(_NONCE_REQUEST_OID_BY_NAME, name, "nonce-request")


def get_nonce_response_oid_for_name(name: str) -> str:
    """Return the dot-decimal OID for a named ``NonceResponse.respTypeInfo`` type."""
    return _lookup_oid(_NONCE_RESPONSE_OID_BY_NAME, name, "nonce-response")


def get_oid_by_name(name: str) -> str:
    """Return the dot-decimal OID for any name known to this project (see the README).

    The union of every named OID across all statement/nonce positions plus the stand-alone
    TPM evidence OIDs — the single blessed entry point for referencing a project OID.
    """
    return _lookup_oid(_OID_BY_NAME, name, "OID")


__all__ = [
    "ATTESTATION_STATEMENT_STRUCTURES",
    "NONCE_REQUEST_STATEMENT_STRUCTURES",
    "NONCE_RESPONSE_STATEMENT_STRUCTURES",
    "StatementDecoder",
    "StatementStructure",
    "StatementValue",
    "get_nonce_request_oid_for_name",
    "get_nonce_request_statement_decoder",
    "get_nonce_request_statement_structure",
    "get_nonce_response_oid_for_name",
    "get_nonce_response_statement_structure",
    "get_oid_by_name",
    "get_oid_for_stmt_name",
    "nonce_request_statement_decoders",
]

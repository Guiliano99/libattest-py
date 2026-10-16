# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""All TPM wire structures + their OIDs + codecs, in one module.

Consolidates the three TPM attestation profiles that previously lived in separate
modules (``quote_profile`` for the PCR quote, ``tcg`` for the TCG certify carrier,
``key_attest_pop`` for key attestation) so they share the single primitive set in
:mod:`asn1_types` instead of redefining it.  Pure pyasn1 — importable on the
MockCA image, which has no ``tpm2-pytss``.

Sections: PCR quote · TCG certify · IAK key-attestation (v6) · LDevID key-attestation (v6).
TPM 2.0 structures are not ASN.1 types; each native value travels in an OCTET STRING
whose contract (see :mod:`asn1_types`) names the exact marshalled TPM structure.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable

from pyasn1.type import char, namedtype, tag, univ
from pyasn1_alt_modules import rfc9480

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1
from libattest.formats._oid_json import resolve_env_oid
from libattest.formats.csrattest import pem_chain_to_cmp_certs
from libattest.formats.tpm.asn1_types import (
    EkCertChain,
    PCRIndex,
    Tpm2bEncryptedSecret,
    Tpm2bIdObject,
    Tpm2bPublic,
    TPMAlgId,
    TpmsAttest,
    TpmtPublic,
    TpmtSignature,
    _CertificateNameSequence,
    _PCRIndexSequence,
    _TPMAlgIdSequence,
    validate_certificate_names,
    validate_hash_alg_id,
    validate_hash_alg_ids,
    validate_pcr_selection,
)

# ══════════════════════════════════════════════════════════════════════════════
# OIDs — every TPM-format OID is defined here exactly once (the owning module).
# ══════════════════════════════════════════════════════════════════════════════

# PCR quote — distinct request/response OIDs, env-overridable under the names the
# gencmpclient C attester reads.
TPM_QUOTE_REQ_OID_ENV: str = "TPM_PCR_SELECTION_OID"
TPM_QUOTE_REQ_OID_DEFAULT: str = "1.2.3.4.5"
TPM_QUOTE_RES_OID_ENV: str = "TPM_QUOTE_RESP_OID"
TPM_QUOTE_RES_OID_DEFAULT: str = "1.2.3.4.6"

id_tpm20_quote_req = univ.ObjectIdentifier(resolve_env_oid(TPM_QUOTE_REQ_OID_ENV, TPM_QUOTE_REQ_OID_DEFAULT))
id_tpm20_quote_res = univ.ObjectIdentifier(resolve_env_oid(TPM_QUOTE_RES_OID_ENV, TPM_QUOTE_RES_OID_DEFAULT))

# Key-attestation (certify leg) request type — the syntax OID the client sends at
# GenM carrying a KeyAttestChall reqInfo. Env name matches the gencmpclient C
# attester's ``TPM_KEY_ATTEST_OID_DEFAULT``. Defined here rather than in the RA so
# the format package stays the single owner of every TPM OID.
TPM_KEY_ATTEST_REQ_OID_ENV: str = "TPM_KEY_ATTEST_OID"
TPM_KEY_ATTEST_REQ_OID_DEFAULT: str = "1.3.6.1.4.1.99999.4"

id_tpm_key_attest_req = univ.ObjectIdentifier(
    resolve_env_oid(TPM_KEY_ATTEST_REQ_OID_ENV, TPM_KEY_ATTEST_REQ_OID_DEFAULT)
)

# TCG certify / quote statement OIDs (fixed TCG assignments).
id_tcg_attest_certify = univ.ObjectIdentifier("2.23.133.20.1")
id_tcg_attest_quote = univ.ObjectIdentifier("2.23.133.20.2")

# IAK key-attestation (v6, base .5) — separate request/response/statement OIDs.
TPM_IAK_KEY_ATTEST_REQUEST_OID_ENV: str = "TPM_IAK_KEY_ATTEST_REQUEST_OID"
TPM_IAK_KEY_ATTEST_REQUEST_OID_DEFAULT: str = "1.3.6.1.4.1.99999.5.1"
TPM_IAK_KEY_ATTEST_RESPONSE_OID_ENV: str = "TPM_IAK_KEY_ATTEST_RESPONSE_OID"
TPM_IAK_KEY_ATTEST_RESPONSE_OID_DEFAULT: str = "1.3.6.1.4.1.99999.5.2"
TPM_IAK_KEY_ATTEST_STATEMENT_OID_ENV: str = "TPM_IAK_KEY_ATTEST_STATEMENT_OID"
TPM_IAK_KEY_ATTEST_STATEMENT_OID_DEFAULT: str = "1.3.6.1.4.1.99999.5.3"

id_tpm_iak_key_attest_request = univ.ObjectIdentifier(
    resolve_env_oid(TPM_IAK_KEY_ATTEST_REQUEST_OID_ENV, TPM_IAK_KEY_ATTEST_REQUEST_OID_DEFAULT)
)
id_tpm_iak_key_attest_response = univ.ObjectIdentifier(
    resolve_env_oid(TPM_IAK_KEY_ATTEST_RESPONSE_OID_ENV, TPM_IAK_KEY_ATTEST_RESPONSE_OID_DEFAULT)
)
id_tpm_iak_key_attest_statement = univ.ObjectIdentifier(
    resolve_env_oid(TPM_IAK_KEY_ATTEST_STATEMENT_OID_ENV, TPM_IAK_KEY_ATTEST_STATEMENT_OID_DEFAULT)
)

# LDevID key-attestation (v6, base .6) — separate request/response/statement OIDs.
TPM_LDEVID_KEY_ATTEST_REQUEST_OID_ENV: str = "TPM_LDEVID_KEY_ATTEST_REQUEST_OID"
TPM_LDEVID_KEY_ATTEST_REQUEST_OID_DEFAULT: str = "1.3.6.1.4.1.99999.6.1"
TPM_LDEVID_KEY_ATTEST_RESPONSE_OID_ENV: str = "TPM_LDEVID_KEY_ATTEST_RESPONSE_OID"
TPM_LDEVID_KEY_ATTEST_RESPONSE_OID_DEFAULT: str = "1.3.6.1.4.1.99999.6.2"
TPM_LDEVID_KEY_ATTEST_STATEMENT_OID_ENV: str = "TPM_LDEVID_KEY_ATTEST_STATEMENT_OID"
TPM_LDEVID_KEY_ATTEST_STATEMENT_OID_DEFAULT: str = "1.3.6.1.4.1.99999.6.3"

id_tpm_ldevid_key_attest_request = univ.ObjectIdentifier(
    resolve_env_oid(TPM_LDEVID_KEY_ATTEST_REQUEST_OID_ENV, TPM_LDEVID_KEY_ATTEST_REQUEST_OID_DEFAULT)
)
id_tpm_ldevid_key_attest_response = univ.ObjectIdentifier(
    resolve_env_oid(TPM_LDEVID_KEY_ATTEST_RESPONSE_OID_ENV, TPM_LDEVID_KEY_ATTEST_RESPONSE_OID_DEFAULT)
)
id_tpm_ldevid_key_attest_statement = univ.ObjectIdentifier(
    resolve_env_oid(TPM_LDEVID_KEY_ATTEST_STATEMENT_OID_ENV, TPM_LDEVID_KEY_ATTEST_STATEMENT_OID_DEFAULT)
)


# ══════════════════════════════════════════════════════════════════════════════
# PCR quote profile
# ══════════════════════════════════════════════════════════════════════════════


class TPM20QuoteReqInfoASN1(univ.Sequence):
    """TPM20QuoteReqInfo ::= SEQUENCE { certificateName [0], supportedHashAlgo [1] }.

    Both OPTIONAL fields are IMPLICIT context-tagged (0/1): without distinguishing
    tags the two adjacent ``SEQUENCE OF`` components would be structurally
    ambiguous for a schema-driven decode.  The gencmpclient C encoder
    (``i2d_TPM20_QUOTE_REQ_INFO``) must emit the matching ``[0]``/``[1]`` tags.
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "certificateName",
            _CertificateNameSequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),
        ),
        namedtype.OptionalNamedType(
            "supportedHashAlgo",
            _TPMAlgIdSequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
        ),
    )


class TPM20QuoteRespInfoASN1(univ.Sequence):
    """TPM20QuoteRespInfo ::= SEQUENCE { certificateName, pcrSelection, hashAlgo }."""

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("certificateName", char.UTF8String()),
        namedtype.NamedType("pcrSelection", _PCRIndexSequence()),
        namedtype.NamedType("hashAlgo", TPMAlgId()),
    )


def _build_quote_req_info(names: list[str] | None, algos: list[int] | None) -> TPM20QuoteReqInfoASN1:
    if names is None and algos is None:
        raise ValueError("TPM20QuoteReqInfo: at least one optional field must be present")
    value = TPM20QuoteReqInfoASN1()
    if names is not None:
        for name in names:
            value["certificateName"].append(char.UTF8String(name))
    if algos is not None:
        for hash_alg_id in algos:
            value["supportedHashAlgo"].append(TPMAlgId(hash_alg_id))
    return value


def encode_tpm20_quote_req_info(
    *,
    certificate_names: Iterable[str] | None = None,
    supported_hash_algos: Iterable[int] | None = None,
) -> bytes:
    """DER-encode ``TPM20QuoteReqInfo``."""
    names = validate_certificate_names(certificate_names)
    algos = validate_hash_alg_ids(supported_hash_algos)
    return encode_to_der(_build_quote_req_info(names, algos))


def encode_tpm20_quote_resp_info(
    *,
    pcr_selection: Iterable[int],
    hash_algo: int,
    certificate_name: str | None = None,
) -> bytes:
    """DER-encode ``TPM20QuoteRespInfo``."""
    pcrs = validate_pcr_selection(pcr_selection)
    hash_alg_id = validate_hash_alg_id(hash_algo)
    if certificate_name is not None and not certificate_name:
        raise ValueError("TPM20QuoteRespInfo: certificateName must be non-empty when present")

    value = TPM20QuoteRespInfoASN1()
    if certificate_name is not None:
        value["certificateName"] = certificate_name
    for pcr_index in pcrs:
        value["pcrSelection"].append(PCRIndex(pcr_index))
    value["hashAlgo"] = TPMAlgId(hash_alg_id)
    return encode_to_der(value)


def decode_tpm20_quote_req_info_asn1(der: bytes | bytearray | univ.Any) -> TPM20QuoteReqInfoASN1:
    """Decode ``TPM20QuoteReqInfo`` into a populated pyasn1 object (for display)."""
    return try_decode_pyasn1(der, TPM20QuoteReqInfoASN1)


def decode_tpm20_quote_req_info(
    der: bytes | bytearray | univ.Any,
) -> tuple[list[str] | None, list[int] | None]:
    """Decode ``TPM20QuoteReqInfo`` into ``(certificate_names, supported_hash_algos)``."""
    value = decode_tpm20_quote_req_info_asn1(der)
    names = (
        validate_certificate_names(str(entry) for entry in value["certificateName"])
        if value["certificateName"].isValue
        else None
    )
    algos = (
        validate_hash_alg_ids(int(entry) for entry in value["supportedHashAlgo"])
        if value["supportedHashAlgo"].isValue
        else None
    )
    if names is None and algos is None:
        raise ValueError("TPM20QuoteReqInfo: at least one optional field must be present")
    return names, algos


def decode_tpm20_quote_resp_info(
    der: bytes | bytearray | univ.Any,
) -> tuple[str | None, list[int], int]:
    """Decode ``TPM20QuoteRespInfo``."""
    value = try_decode_pyasn1(der, TPM20QuoteRespInfoASN1)
    certificate_name = str(value["certificateName"]) if value["certificateName"].isValue else None
    pcr_selection = validate_pcr_selection(int(pcr_index) for pcr_index in value["pcrSelection"])
    hash_algo = validate_hash_alg_id(int(value["hashAlgo"]))
    return certificate_name, pcr_selection, hash_algo


def tpm20_quote_request_info(
    *,
    certificate_names: Iterable[str] | None = None,
    supported_hash_algos: Iterable[int] | None = None,
) -> univ.Any:
    """Build a ``NonceRequestTypeInfo.reqInfo`` ANY value for the quote profile."""
    return univ.Any(
        hexValue=encode_tpm20_quote_req_info(
            certificate_names=certificate_names,
            supported_hash_algos=supported_hash_algos,
        ).hex()
    )


def tpm20_quote_response_info(
    *,
    pcr_selection: Iterable[int],
    hash_algo: int,
    certificate_name: str | None = None,
) -> univ.Any:
    """Build a ``NonceResponseTypeInfo.respInfo`` ANY value for the quote profile."""
    return univ.Any(
        hexValue=encode_tpm20_quote_resp_info(
            certificate_name=certificate_name,
            pcr_selection=pcr_selection,
            hash_algo=hash_algo,
        ).hex()
    )


def tpm20_quote_resp_info_from_response_info(
    response_info: bytes | bytearray | univ.Any | None,
) -> tuple[str | None, list[int], int] | None:
    """Decode a ``NonceResponseTypeInfo.respInfo`` value, or ``None``."""
    if response_info is None:
        return None
    return decode_tpm20_quote_resp_info(response_info)


# ══════════════════════════════════════════════════════════════════════════════
# TCG certify carrier
# ══════════════════════════════════════════════════════════════════════════════


class TcgAttestCertify(univ.Sequence):
    """TCG TPM certify evidence carried inside an AttestationStatement.

    The same SEQUENCE serves TCG certify (``2.23.133.20.1``) and platform/quote
    (``2.23.133.20.2``); dispatch is by the outer ``AttestationStatement.type``
    OID, not by a distinct pyasn1 type.
    """

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
    """Build a populated :class:`TcgAttestCertify` value."""
    value = TcgAttestCertify()
    value["tpmSAttest"] = tpm_s_attest
    value["signature"] = signature
    if tpm_tpublic is not None:
        value["tpmTPublic"] = tpm_tpublic
    return value


def decode_tcg_attest_certify(der: bytes | bytearray | univ.Any) -> TcgAttestCertify:
    """Decode DER into :class:`TcgAttestCertify` (strict; rejects trailing bytes)."""
    return try_decode_pyasn1(der, TcgAttestCertify)


# ══════════════════════════════════════════════════════════════════════════════
# IAK key-attestation (v6, base .5)
# ══════════════════════════════════════════════════════════════════════════════


class IakKeyAttestReqInfo(univ.Sequence):
    """IakKeyAttestReqInfo ::= SEQUENCE { akPublic, supportedHashAlgo, ekCertChain, ekPublic }.

    ``akPublic``/``ekPublic`` are full ``TPM2B_PUBLIC`` (not SPKIs) so the Verifier
    can check objectAttributes and derive the AK Name.  All fields mandatory.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("akPublic", Tpm2bPublic()),
        namedtype.NamedType("supportedHashAlgo", _TPMAlgIdSequence()),
        namedtype.NamedType("ekCertChain", EkCertChain()),
        namedtype.NamedType("ekPublic", Tpm2bPublic()),
    )


class IakKeyAttestRespInfo(univ.Sequence):
    """IakKeyAttestRespInfo ::= SEQUENCE { encSeed, encSecret, pcrSelection, hashAlgo }.

    ``encSeed`` is the ``TPM2B_ENCRYPTED_SECRET`` (ActivateCredential ``secret``);
    ``encSecret`` is the ``TPM2B_ID_OBJECT`` (ActivateCredential ``credential_blob``).
    The pairing looks inverted vs the TPM *type* names but matches the deployed
    field names and is right on *semantics* (OQ-B: rename deferred).
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("encSeed", Tpm2bEncryptedSecret()),
        namedtype.NamedType("encSecret", Tpm2bIdObject()),
        namedtype.NamedType("pcrSelection", _PCRIndexSequence()),
        namedtype.NamedType("hashAlgo", TPMAlgId()),
    )


class IakKeyAttestEvidence(univ.Sequence):
    """IakKeyAttestEvidence ::= SEQUENCE { tpmsAttest, quoteSignature, activationSignature, pcrValues OPTIONAL }.

    ``pcrValues`` is deliberately the LAST component: it and ``activationSignature``
    are both OCTET STRINGs, and an OPTIONAL OCTET STRING placed before another
    would be DER-ambiguous when absent (X.680 clause 28).  Trailing-optional
    resolves it without context tags; all other components are mandatory.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tpmsAttest", TpmsAttest()),
        namedtype.NamedType("quoteSignature", TpmtSignature()),
        namedtype.NamedType("activationSignature", TpmtSignature()),
        namedtype.OptionalNamedType("pcrValues", univ.OctetString()),
    )


def prepare_iak_key_attest_req_info(
    ak_public: bytes,
    supported_hash_algos: Iterable[int],
    ek_cert_chain_pem: str,
    ek_public: bytes,
) -> IakKeyAttestReqInfo:
    """Build an :class:`IakKeyAttestReqInfo`."""
    algos = validate_hash_alg_ids(supported_hash_algos)
    if algos is None:
        raise ValueError("IakKeyAttestReqInfo: supportedHashAlgo is required")
    value = IakKeyAttestReqInfo()
    value["akPublic"] = ak_public
    for hash_alg_id in algos:
        value["supportedHashAlgo"].append(TPMAlgId(hash_alg_id))
    value["ekCertChain"].extend(pem_chain_to_cmp_certs(ek_cert_chain_pem))
    value["ekPublic"] = ek_public
    return value


def prepare_iak_key_attest_resp_info(
    enc_seed: bytes,
    enc_secret: bytes,
    pcr_selection: Iterable[int],
    hash_algo: int,
) -> IakKeyAttestRespInfo:
    """Build an :class:`IakKeyAttestRespInfo`."""
    pcrs = validate_pcr_selection(pcr_selection)
    hash_alg_id = validate_hash_alg_id(hash_algo)
    value = IakKeyAttestRespInfo()
    value["encSeed"] = enc_seed
    value["encSecret"] = enc_secret
    for pcr_index in pcrs:
        value["pcrSelection"].append(PCRIndex(pcr_index))
    value["hashAlgo"] = TPMAlgId(hash_alg_id)
    return value


def prepare_iak_key_attest_evidence(
    tpms_attest: bytes,
    quote_signature: bytes,
    activation_signature: bytes,
    pcr_values: bytes | None = None,
) -> IakKeyAttestEvidence:
    """Build an :class:`IakKeyAttestEvidence` (``pcr_values`` optional, trailing)."""
    value = IakKeyAttestEvidence()
    value["tpmsAttest"] = tpms_attest
    value["quoteSignature"] = quote_signature
    value["activationSignature"] = activation_signature
    if pcr_values is not None:
        value["pcrValues"] = pcr_values
    return value


def decode_iak_key_attest_req_info(der: bytes | bytearray | univ.Any) -> IakKeyAttestReqInfo:
    """DER-decode into :class:`IakKeyAttestReqInfo` (strict)."""
    return try_decode_pyasn1(der, IakKeyAttestReqInfo)


def decode_iak_key_attest_resp_info(der: bytes | bytearray | univ.Any) -> IakKeyAttestRespInfo:
    """DER-decode into :class:`IakKeyAttestRespInfo` (strict)."""
    return try_decode_pyasn1(der, IakKeyAttestRespInfo)


def decode_iak_key_attest_evidence(der: bytes | bytearray | univ.Any) -> IakKeyAttestEvidence:
    """DER-decode into :class:`IakKeyAttestEvidence` (strict)."""
    return try_decode_pyasn1(der, IakKeyAttestEvidence)


# ══════════════════════════════════════════════════════════════════════════════
# LDevID key-attestation (v6, base .6)
# ══════════════════════════════════════════════════════════════════════════════


class LdevidKeyAttestReqInfo(univ.Sequence):
    """LdevidKeyAttestReqInfo ::= SEQUENCE { ldevidPublic, certificateName }."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("ldevidPublic", Tpm2bPublic()),
        namedtype.NamedType("certificateName", _CertificateNameSequence()),
    )


class LdevidKeyAttestRespInfo(univ.Sequence):
    """LdevidKeyAttestRespInfo ::= SEQUENCE { certificateName }."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("certificateName", char.UTF8String()),
    )


class LdevidKeyAttestEvidence(univ.Sequence):
    """LdevidKeyAttestEvidence ::= SEQUENCE { tpmsAttest, tpmtSignature, tpmTPublic }.

    Structurally like :class:`TcgAttestCertify` but ``tpmTPublic`` is MANDATORY
    and it is selected by the project ``.6.3`` OID, never the TCG ``2.23.133.20.1``
    OID — so the Verifier can select the IAK-chain-required LDevID appraisal.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tpmsAttest", TpmsAttest()),
        namedtype.NamedType("tpmtSignature", TpmtSignature()),
        namedtype.NamedType("tpmTPublic", TpmtPublic()),
    )


def prepare_ldevid_key_attest_req_info(
    ldevid_public: bytes,
    certificate_names: Iterable[str],
) -> LdevidKeyAttestReqInfo:
    """Build an :class:`LdevidKeyAttestReqInfo`."""
    names = validate_certificate_names(certificate_names)
    if names is None:
        raise ValueError("LdevidKeyAttestReqInfo: certificateName is required")
    value = LdevidKeyAttestReqInfo()
    value["ldevidPublic"] = ldevid_public
    for name in names:
        value["certificateName"].append(char.UTF8String(name))
    return value


def prepare_ldevid_key_attest_resp_info(certificate_name: str) -> LdevidKeyAttestRespInfo:
    """Build an :class:`LdevidKeyAttestRespInfo`."""
    if not certificate_name:
        raise ValueError("LdevidKeyAttestRespInfo: certificateName must be non-empty")
    value = LdevidKeyAttestRespInfo()
    value["certificateName"] = certificate_name
    return value


def prepare_ldevid_key_attest_evidence(
    tpms_attest: bytes,
    tpmt_signature: bytes,
    tpm_tpublic: bytes,
) -> LdevidKeyAttestEvidence:
    """Build an :class:`LdevidKeyAttestEvidence` (all fields mandatory)."""
    value = LdevidKeyAttestEvidence()
    value["tpmsAttest"] = tpms_attest
    value["tpmtSignature"] = tpmt_signature
    value["tpmTPublic"] = tpm_tpublic
    return value


def decode_ldevid_key_attest_req_info(der: bytes | bytearray | univ.Any) -> LdevidKeyAttestReqInfo:
    """DER-decode into :class:`LdevidKeyAttestReqInfo` (strict)."""
    return try_decode_pyasn1(der, LdevidKeyAttestReqInfo)


def decode_ldevid_key_attest_resp_info(der: bytes | bytearray | univ.Any) -> LdevidKeyAttestRespInfo:
    """DER-decode into :class:`LdevidKeyAttestRespInfo` (strict)."""
    return try_decode_pyasn1(der, LdevidKeyAttestRespInfo)


def decode_ldevid_key_attest_evidence(der: bytes | bytearray | univ.Any) -> LdevidKeyAttestEvidence:
    """DER-decode into :class:`LdevidKeyAttestEvidence` (strict)."""
    return try_decode_pyasn1(der, LdevidKeyAttestEvidence)


# ══════════════════════════════════════════════════════════════════════════════
# JSON adapters (RA engine ↔ Verifier, the single DER↔JSON translation point)
# ══════════════════════════════════════════════════════════════════════════════


def _cert_to_pem(cert: rfc9480.CMPCertificate) -> str:
    der = encode_to_der(cert)
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def _certs_to_pem(certs: Iterable[rfc9480.CMPCertificate]) -> str:
    return "".join(_cert_to_pem(cert) for cert in certs)


def iak_key_attest_req_info_to_json(req_info_der: bytes) -> dict[str, str]:
    """Decode an ``IakKeyAttestReqInfo`` DER into the ``/makeCredential`` JSON.

    Returns ``{akPublic: hex, ekPublic: hex, ekCertChain: PEM}``.  ``akName`` is
    deliberately absent — the Verifier computes it from ``akPublic`` (design M4).
    """
    req = decode_iak_key_attest_req_info(req_info_der)
    return {
        "akPublic": bytes(req["akPublic"]).hex(),
        "ekPublic": bytes(req["ekPublic"]).hex(),
        "ekCertChain": _certs_to_pem(req["ekCertChain"]),
    }


__all__ = [
    # OIDs
    "TPM_IAK_KEY_ATTEST_REQUEST_OID_DEFAULT",
    "TPM_IAK_KEY_ATTEST_REQUEST_OID_ENV",
    "TPM_IAK_KEY_ATTEST_RESPONSE_OID_DEFAULT",
    "TPM_IAK_KEY_ATTEST_RESPONSE_OID_ENV",
    "TPM_IAK_KEY_ATTEST_STATEMENT_OID_DEFAULT",
    "TPM_IAK_KEY_ATTEST_STATEMENT_OID_ENV",
    "TPM_LDEVID_KEY_ATTEST_REQUEST_OID_DEFAULT",
    "TPM_LDEVID_KEY_ATTEST_REQUEST_OID_ENV",
    "TPM_LDEVID_KEY_ATTEST_RESPONSE_OID_DEFAULT",
    "TPM_LDEVID_KEY_ATTEST_RESPONSE_OID_ENV",
    "TPM_LDEVID_KEY_ATTEST_STATEMENT_OID_DEFAULT",
    "TPM_LDEVID_KEY_ATTEST_STATEMENT_OID_ENV",
    "TPM_KEY_ATTEST_REQ_OID_DEFAULT",
    "TPM_KEY_ATTEST_REQ_OID_ENV",
    "TPM_QUOTE_REQ_OID_DEFAULT",
    "TPM_QUOTE_REQ_OID_ENV",
    "TPM_QUOTE_RES_OID_DEFAULT",
    "TPM_QUOTE_RES_OID_ENV",
    "id_tcg_attest_certify",
    "id_tcg_attest_quote",
    "id_tpm20_quote_req",
    "id_tpm_key_attest_req",
    "id_tpm20_quote_res",
    "id_tpm_iak_key_attest_request",
    "id_tpm_iak_key_attest_response",
    "id_tpm_iak_key_attest_statement",
    "id_tpm_ldevid_key_attest_request",
    "id_tpm_ldevid_key_attest_response",
    "id_tpm_ldevid_key_attest_statement",
    # structures
    "IakKeyAttestEvidence",
    "IakKeyAttestReqInfo",
    "IakKeyAttestRespInfo",
    "LdevidKeyAttestEvidence",
    "LdevidKeyAttestReqInfo",
    "LdevidKeyAttestRespInfo",
    "TPM20QuoteReqInfoASN1",
    "TPM20QuoteRespInfoASN1",
    "TcgAttestCertify",
    # codecs / builders
    "decode_iak_key_attest_evidence",
    "decode_iak_key_attest_req_info",
    "decode_iak_key_attest_resp_info",
    "decode_ldevid_key_attest_evidence",
    "decode_ldevid_key_attest_req_info",
    "decode_ldevid_key_attest_resp_info",
    "decode_tcg_attest_certify",
    "decode_tpm20_quote_req_info",
    "decode_tpm20_quote_req_info_asn1",
    "decode_tpm20_quote_resp_info",
    "encode_tpm20_quote_req_info",
    "encode_tpm20_quote_resp_info",
    "encode_to_der",
    "iak_key_attest_req_info_to_json",
    "prepare_iak_key_attest_evidence",
    "prepare_iak_key_attest_req_info",
    "prepare_iak_key_attest_resp_info",
    "prepare_ldevid_key_attest_evidence",
    "prepare_ldevid_key_attest_req_info",
    "prepare_ldevid_key_attest_resp_info",
    "prepare_tcg_attest_certify",
    "tpm20_quote_request_info",
    "tpm20_quote_resp_info_from_response_info",
    "tpm20_quote_response_info",
]

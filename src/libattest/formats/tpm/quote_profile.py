# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""TPM 2.0 quote profile payloads for the nonce freshness exchange."""

from __future__ import annotations

from collections.abc import Iterable

from pyasn1.type import char, constraint, namedtype, tag, univ

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1

id_tpm20_quote_req = univ.ObjectIdentifier("1.2.3.4.5")
id_tpm20_quote_res = univ.ObjectIdentifier("1.2.3.4.6")

_PCR_INDEX_MAX = 23  # Hardware TPMs expose 24 PCRs per bank (indices 0..23)
_TPM_ALG_ID_MAX = 0xFFFF


class TPMAlgId(univ.Integer):
    """TPM_ALG_ID encoded as INTEGER (0..65535)."""

    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, _TPM_ALG_ID_MAX)


class PCRIndex(univ.Integer):
    """PCR index encoded as INTEGER (0..23)."""

    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, _PCR_INDEX_MAX)


class _CertificateNameSequence(univ.SequenceOf):
    componentType = char.UTF8String()


class _TPMAlgIdSequence(univ.SequenceOf):
    componentType = TPMAlgId()


class _PCRIndexSequence(univ.SequenceOf):
    componentType = PCRIndex()


class TPM20QuoteReqInfoASN1(univ.Sequence):
    """TPM20QuoteReqInfo ::= SEQUENCE { certificateName [0], supportedHashAlgo [1] }.

    Both OPTIONAL fields are IMPLICIT context-tagged (0/1) so pyasn1's
    automatic named-type decode can disambiguate them; without distinguishing
    tags they'd share the same universal SEQUENCE tag and be structurally
    undecodable (ASN.1 X.680 SS8: ambiguous OPTIONAL SEQUENCE components
    require distinguishing tags). This changed the wire encoding from the
    historical untagged form -- see
    docs/adr/0003-asn1-utils-and-strict-der-decoding.md.
    """

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            "certificateName",
            _CertificateNameSequence().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ),
        ),
        namedtype.OptionalNamedType(
            "supportedHashAlgo",
            _TPMAlgIdSequence().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            ),
        ),
    )


class TPM20QuoteRespInfoASN1(univ.Sequence):
    """TPM20QuoteRespInfo ::= SEQUENCE { certificateName, pcrSelection, hashAlgo }."""

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("certificateName", char.UTF8String()),
        namedtype.NamedType("pcrSelection", _PCRIndexSequence()),
        namedtype.NamedType("hashAlgo", TPMAlgId()),
    )


def _validate_certificate_names(names: Iterable[str] | None) -> list[str] | None:
    if names is None:
        return None
    values = list(names)
    if not values:
        raise ValueError("TPM20QuoteReqInfo: certificateName must not be empty")
    for name in values:
        if not isinstance(name, str) or not name:
            raise ValueError("TPM20QuoteReqInfo: certificateName entries must be non-empty strings")
    return values


def _validate_hash_alg_id(hash_alg_id: int) -> int:
    if isinstance(hash_alg_id, bool) or not isinstance(hash_alg_id, int):
        raise ValueError("TPM20QuoteReqInfo: TPMAlgId must be an int")
    if not 0 <= hash_alg_id <= _TPM_ALG_ID_MAX:
        raise ValueError(f"TPM20QuoteReqInfo: TPMAlgId {hash_alg_id:#x} outside TPM_ALG_ID range")
    return hash_alg_id


def _validate_hash_alg_ids(hash_algos: Iterable[int] | None) -> list[int] | None:
    if hash_algos is None:
        return None
    values = [_validate_hash_alg_id(hash_alg_id) for hash_alg_id in hash_algos]
    if not values:
        raise ValueError("TPM20QuoteReqInfo: supportedHashAlgo must not be empty")
    return values


def _validate_pcr_selection(pcr_selection: Iterable[int]) -> list[int]:
    seen: set[int] = set()
    values: list[int] = []
    for pcr_index in pcr_selection:
        if isinstance(pcr_index, bool) or not isinstance(pcr_index, int):
            raise ValueError("TPM20QuoteRespInfo: PCRIndex entries must be integers")
        if not 0 <= pcr_index <= _PCR_INDEX_MAX:
            raise ValueError(f"TPM20QuoteRespInfo: PCRIndex {pcr_index} outside PCRIndex range")
        if pcr_index not in seen:
            seen.add(pcr_index)
            values.append(pcr_index)
    if not values:
        raise ValueError("TPM20QuoteRespInfo: pcrSelection must not be empty")
    values.sort()
    return values


def encode_tpm20_quote_req_info(
    *,
    certificate_names: Iterable[str] | None = None,
    supported_hash_algos: Iterable[int] | None = None,
) -> bytes:
    """DER-encode ``TPM20QuoteReqInfo``."""
    names = _validate_certificate_names(certificate_names)
    algos = _validate_hash_alg_ids(supported_hash_algos)
    if names is None and algos is None:
        raise ValueError("TPM20QuoteReqInfo: at least one optional field must be present")

    value = TPM20QuoteReqInfoASN1()
    if names is not None:
        for name in names:
            value["certificateName"].append(char.UTF8String(name))
    if algos is not None:
        for hash_alg_id in algos:
            value["supportedHashAlgo"].append(TPMAlgId(hash_alg_id))
    return encode_to_der(value)


def encode_tpm20_quote_resp_info(
    *,
    pcr_selection: Iterable[int],
    hash_algo: int,
    certificate_name: str | None = None,
) -> bytes:
    """DER-encode ``TPM20QuoteRespInfo``."""
    pcrs = _validate_pcr_selection(pcr_selection)
    hash_alg_id = _validate_hash_alg_id(hash_algo)
    if certificate_name is not None and not certificate_name:
        raise ValueError("TPM20QuoteRespInfo: certificateName must be non-empty when present")

    value = TPM20QuoteRespInfoASN1()
    if certificate_name is not None:
        value["certificateName"] = certificate_name
    for pcr_index in pcrs:
        value["pcrSelection"].append(PCRIndex(pcr_index))
    value["hashAlgo"] = TPMAlgId(hash_alg_id)
    return encode_to_der(value)


def decode_tpm20_quote_req_info(
    der: bytes | bytearray | univ.Any,
) -> tuple[list[str] | None, list[int] | None]:
    """Decode ``TPM20QuoteReqInfo``.

    Fields must appear in canonical (declared) SEQUENCE order, per DER.
    """
    value = try_decode_pyasn1(der, TPM20QuoteReqInfoASN1)

    names = (
        _validate_certificate_names(str(entry) for entry in value["certificateName"])
        if value["certificateName"].isValue
        else None
    )
    algos = (
        _validate_hash_alg_ids(int(entry) for entry in value["supportedHashAlgo"])
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
    pcr_selection = _validate_pcr_selection(int(pcr_index) for pcr_index in value["pcrSelection"])
    hash_algo = _validate_hash_alg_id(int(value["hashAlgo"]))
    return certificate_name, pcr_selection, hash_algo


def tpm20_quote_request_info(
    *,
    certificate_names: Iterable[str] | None = None,
    supported_hash_algos: Iterable[int] | None = None,
) -> univ.Any:
    """Build a ``NonceRequestTypeInfo.reqInfo`` ANY value."""
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
    """Build a ``NonceResponseTypeInfo.respInfo`` ANY value."""
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
    """Decode a ``NonceResponseTypeInfo.respInfo`` value."""
    if response_info is None:
        return None
    return decode_tpm20_quote_resp_info(response_info)


__all__ = [
    "PCRIndex",
    "TPM20QuoteReqInfoASN1",
    "TPM20QuoteRespInfoASN1",
    "TPMAlgId",
    "decode_tpm20_quote_req_info",
    "decode_tpm20_quote_resp_info",
    "encode_tpm20_quote_req_info",
    "encode_tpm20_quote_resp_info",
    "id_tpm20_quote_req",
    "id_tpm20_quote_res",
    "tpm20_quote_request_info",
    "tpm20_quote_resp_info_from_response_info",
    "tpm20_quote_response_info",
]

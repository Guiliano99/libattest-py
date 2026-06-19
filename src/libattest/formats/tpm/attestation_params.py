# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""TPM quote parameters carried as a typed ASN.1 SEQUENCE.

The attestation-freshness draft defines ``NonceRequest.reqInfo`` and
``NonceResponse.respInfo`` as type-specific open values.  This module
implements the typed ASN.1 profile for TPM quote parameter negotiation:

    TpmAttestationParams ::= SEQUENCE {
        pcrs       SEQUENCE OF INTEGER OPTIONAL,
        hashAlgId  INTEGER OPTIONAL
    }

This shape is wire-compatible with the OpenSSL/gencmpclient C implementation
(``LOCAL_TPM_ATTESTATION_PARAMS``), where it is handled by macro-generated
``d2i_``/``i2d_`` codecs and the PCR indices feed ``TPML_PCR_SELECTION``
directly as integers.  It is the preferred reqInfo/respInfo encoding for this
profile; :mod:`libattest.formats.tpm.pcr_selection` provides the alternative
OID + UTF8String JSON representation.

Typical use:

* request direction (client proposes only the hash bank)::

      reqInfo = DER(TpmAttestationParams { hashAlgId: 0x000B })

* response direction (RA/CA selects PCRs and hash by policy)::

      respInfo = DER(TpmAttestationParams { pcrs: [0,1,2,3,4],
                                            hashAlgId: 0x000B })

The quoted PCR digest itself is not transported here.  It remains inside the
TPM2_Quote evidence as ``TPMS_QUOTE_INFO.pcrDigest``.
"""

from __future__ import annotations

from collections.abc import Iterable

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import namedtype, univ

from libattest.formats.tpm.pcr_selection import _validate_pcr_indices

_TPM_ALG_ID_MAX: int = 0xFFFF  # TPM_ALG_ID is a UINT16


class _PcrIndexSequence(univ.SequenceOf):
    """``SEQUENCE OF INTEGER`` holding PCR indices."""

    componentType = univ.Integer()


class TpmAttestationParamsASN1(univ.Sequence):
    """``TpmAttestationParams ::= SEQUENCE { pcrs ..., hashAlgId ... }``."""

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("pcrs", _PcrIndexSequence()),
        namedtype.OptionalNamedType("hashAlgId", univ.Integer()),
    )


def _validate_hash_alg_id(hash_alg_id: int | None) -> int | None:
    if hash_alg_id is None:
        return None
    if isinstance(hash_alg_id, bool) or not isinstance(hash_alg_id, int):
        raise ValueError("TpmAttestationParams: hashAlgId must be an int")
    if not 0 < hash_alg_id <= _TPM_ALG_ID_MAX:
        raise ValueError(f"TpmAttestationParams: hashAlgId {hash_alg_id:#x} outside TPM_ALG_ID range")
    return hash_alg_id


def encode_tpm_attestation_params(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
) -> bytes:
    """DER-encode ``TpmAttestationParams`` from PCR indices and hash ID.

    Parameters
    ----------
    pcrs:
        PCR indices to quote (deduplicated and sorted), or ``None`` to omit.
    hash_alg_id:
        TPM hash algorithm ID (e.g. ``0x000B`` for SHA-256), or ``None``.

    Raises
    ------
    ValueError
        If both fields are absent or either field is out of range.

    """
    hash_alg_id = _validate_hash_alg_id(hash_alg_id)
    if pcrs is None and hash_alg_id is None:
        raise ValueError("at least one of pcrs or hash_alg_id must be present")

    params = TpmAttestationParamsASN1()
    if pcrs is not None:
        for index in _validate_pcr_indices(list(pcrs)):
            params["pcrs"].append(univ.Integer(index))
    if hash_alg_id is not None:
        params["hashAlgId"] = univ.Integer(hash_alg_id)
    return der_encoder.encode(params)


def decode_tpm_attestation_params(
    der: bytes | bytearray | univ.Any,
) -> tuple[list[int] | None, int | None]:
    """Decode ``TpmAttestationParams`` and return ``(pcrs, hash_alg_id)``.

    Raises
    ------
    ValueError
        On malformed DER, trailing data, out-of-range values, or when both
        fields are absent.

    """
    data = bytes(der)
    try:
        params, rest = der_decoder.decode(data, asn1Spec=TpmAttestationParamsASN1())
    except Exception as exc:  # pyasn1 raises PyAsn1Error subclasses
        raise ValueError(f"TpmAttestationParams: cannot decode DER: {exc}") from exc
    if rest:
        raise ValueError("TpmAttestationParams: trailing bytes after DER value")

    pcrs: list[int] | None = None
    if params["pcrs"].isValue:
        pcrs = _validate_pcr_indices([int(entry) for entry in params["pcrs"]])

    hash_alg_id: int | None = None
    if params["hashAlgId"].isValue:
        hash_alg_id = _validate_hash_alg_id(int(params["hashAlgId"]))

    if pcrs is None and hash_alg_id is None:
        raise ValueError("TpmAttestationParams: at least one of pcrs or hashAlgId must be present")
    return pcrs, hash_alg_id


def attestation_params_request_info(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
) -> univ.Any:
    """Build a ``NonceRequest.reqInfo`` value carrying ``TpmAttestationParams``."""
    return univ.Any(hexValue=encode_tpm_attestation_params(pcrs, hash_alg_id).hex())


def attestation_params_response_info(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
) -> univ.Any:
    """Build a ``NonceResponse.respInfo`` value carrying ``TpmAttestationParams``."""
    return univ.Any(hexValue=encode_tpm_attestation_params(pcrs, hash_alg_id).hex())


def make_pcr_selection_resp_info(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
) -> univ.Any:
    """Compatibility name for TPM platform PCR-selection ``respInfo``.

    The value is DER(TpmAttestationParams), matching the OpenSSL/gencmpclient
    TPM platform-attestation profile.
    """
    return attestation_params_response_info(pcrs, hash_alg_id)


def attestation_params_from_response_info(
    response_info: bytes | bytearray | univ.Any | None,
) -> tuple[list[int] | None, int | None] | None:
    """Decode a ``NonceResponse.respInfo`` value as ``TpmAttestationParams``."""
    if response_info is None:
        return None
    return decode_tpm_attestation_params(response_info)


__all__ = [
    "TpmAttestationParamsASN1",
    "attestation_params_from_response_info",
    "attestation_params_request_info",
    "attestation_params_response_info",
    "decode_tpm_attestation_params",
    "encode_tpm_attestation_params",
    "make_pcr_selection_resp_info",
]

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""TPM platform-attestation PCR selection carried as ASN.1 OID + JSON.

The attestation-freshness draft defines ``NonceRequest.reqInfo`` and
``NonceResponse.respInfo`` as type-specific open values.  This profile keeps the
outer freshness exchange ASN.1-friendly while allowing the type-specific PCR
selection to be represented as JSON text:

    TpmPcrSelectionInfo ::= SEQUENCE {
        type   OBJECT IDENTIFIER,
        value  UTF8String
    }

``type`` identifies the private TPM PCR-selection JSON schema.  ``value`` is a
JSON object encoded as a UTF8String.  This shape is convenient for OpenSSL-based
clients because the ASN.1 layer only needs to construct an OID and a UTF8String;
the application can use any JSON library for the value.

Example ``value`` for the response direction::

    {"pcrSelection": [{"hash": "sha256", "pcrs": [0, 1, 2, 3, 4]}]}

The quoted PCR digest itself is not transported here.  It remains inside the
TPM2_Quote evidence as ``TPMS_QUOTE_INFO.pcrDigest``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from pyasn1.type import univ

from libattest.formats._oid_json import (
    OidUtf8Json,
    decode_oid_json_der,
    encode_oid_json_der,
    resolve_env_oid,
)

logger = logging.getLogger(__name__)

TPM_PCR_SELECTION_OID_DEFAULT: str = "1.3.6.1.4.1.99999.3"
TPM_PCR_SELECTION_OID_ENV: str = "TPM_PCR_SELECTION_OID"

_HASH_ALG_ID_TO_NAME: dict[int, str] = {
    0x000B: "sha256",
    0x000C: "sha384",
    0x000D: "sha512",
}
_HASH_NAME_TO_ALG_ID: dict[str, int] = {v: k for k, v in _HASH_ALG_ID_TO_NAME.items()}
_PCR_INDEX_MAX: int = 23  # Hardware TPMs expose 24 PCRs per bank (indices 0..23)


def resolve_tpm_pcr_selection_oid() -> str:
    """Return the configured PCR-selection JSON schema OID."""
    return resolve_env_oid(TPM_PCR_SELECTION_OID_ENV, TPM_PCR_SELECTION_OID_DEFAULT)


class TpmPcrSelectionInfoASN1(OidUtf8Json):
    """``TpmPcrSelectionInfo ::= SEQUENCE { type OID, value UTF8String }``."""


def _validate_pcr_indices(pcrs: Sequence[int]) -> list[int]:
    if pcrs is None:
        raise ValueError("pcrSelection.pcrs: list must not be None")
    seen: set[int] = set()
    coerced: list[int] = []
    duplicates = 0
    for value in pcrs:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"pcrSelection.pcrs: entry {value!r} is not an int")
        if value < 0:
            raise ValueError(f"pcrSelection.pcrs: entry {value} must be non-negative")
        if value > _PCR_INDEX_MAX:
            raise ValueError(f"pcrSelection.pcrs: entry {value} exceeds max PCR index {_PCR_INDEX_MAX}")
        if value in seen:
            duplicates += 1
            continue
        seen.add(value)
        coerced.append(value)
    if not coerced:
        raise ValueError("pcrSelection.pcrs: list must not be empty")
    if duplicates:
        logger.warning("pcrSelection.pcrs: dropped %d duplicate index/indices", duplicates)
    coerced.sort()
    return coerced


def _hash_alg_name(hash_alg_id: int | None) -> str | None:
    if hash_alg_id is None:
        return None
    if isinstance(hash_alg_id, bool) or not isinstance(hash_alg_id, int):
        raise ValueError("hash_alg_id must be a non-negative integer")
    if hash_alg_id < 0:
        raise ValueError(f"hash_alg_id must be non-negative, got {hash_alg_id}")
    return _HASH_ALG_ID_TO_NAME.get(hash_alg_id, f"tpm-alg-0x{hash_alg_id:04x}")


def _hash_alg_id(hash_name: object | None) -> int | None:
    if hash_name is None:
        return None
    if not isinstance(hash_name, str) or not hash_name:
        raise ValueError("TpmPcrSelectionInfo: hash must be a non-empty string")
    if hash_name in _HASH_NAME_TO_ALG_ID:
        return _HASH_NAME_TO_ALG_ID[hash_name]
    if hash_name.startswith("tpm-alg-0x"):
        return int(hash_name.removeprefix("tpm-alg-0x"), 16)
    raise ValueError(f"unsupported PCR hash algorithm name: {hash_name!r}")


def build_tpm_pcr_selection_json(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
) -> dict[str, Any]:
    """Build the JSON object carried in ``TpmPcrSelectionInfo.value``."""
    selection: dict[str, Any] = {}
    hash_name = _hash_alg_name(hash_alg_id)
    if hash_name is not None:
        selection["hash"] = hash_name
    if pcrs is not None:
        selection["pcrs"] = _validate_pcr_indices(list(pcrs))
    if not selection:
        raise ValueError("at least one of pcrs or hash_alg_id must be present")
    return {"pcrSelection": [selection]}


def encode_tpm_pcr_selection_info(
    json_value: Mapping[str, Any],
    *,
    oid: str | None = None,
) -> bytes:
    """DER-encode ``TpmPcrSelectionInfo`` with JSON in a UTF8String."""
    return encode_oid_json_der(
        TpmPcrSelectionInfoASN1,
        oid or resolve_tpm_pcr_selection_oid(),
        json_value,
    )


def tpm_pcr_selection_json_value(der: bytes | bytearray | univ.Any) -> dict[str, Any]:
    """Decode ``TpmPcrSelectionInfo`` and return the JSON object."""
    return decode_oid_json_der(
        der,
        TpmPcrSelectionInfoASN1(),
        expected_oid=resolve_tpm_pcr_selection_oid(),
        name="TpmPcrSelectionInfo",
    )


def encode_tpm_pcr_selection_info_from_parts(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
) -> bytes:
    """DER-encode ``TpmPcrSelectionInfo`` from PCR indices and hash ID."""
    return encode_tpm_pcr_selection_info(build_tpm_pcr_selection_json(pcrs, hash_alg_id))


def decode_tpm_pcr_selection_info(der: bytes) -> tuple[list[int] | None, int | None]:
    """Decode the PCR-selection JSON and return ``(pcrs, hash_alg_id)``."""
    value = tpm_pcr_selection_json_value(der)
    selections = value.get("pcrSelection")
    if not isinstance(selections, list) or len(selections) != 1:
        raise ValueError("TpmPcrSelectionInfo: pcrSelection must contain exactly one entry")
    selection = selections[0]
    if not isinstance(selection, dict):
        raise ValueError("TpmPcrSelectionInfo: pcrSelection entry must be an object")

    pcrs: list[int] | None = None
    if "pcrs" in selection:
        raw_pcrs = selection["pcrs"]
        if not isinstance(raw_pcrs, list):
            raise ValueError("TpmPcrSelectionInfo: pcrs must be an array")
        pcrs = _validate_pcr_indices(raw_pcrs)

    hash_alg_id = _hash_alg_id(selection.get("hash"))
    if pcrs is None and hash_alg_id is None:
        raise ValueError("TpmPcrSelectionInfo: at least one of pcrs or hash must be present")
    return pcrs, hash_alg_id


def pcr_selection_response_info(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
    *,
    oid: str | None = None,
) -> univ.Any:
    """Build a ``NonceResponse.respInfo`` value for PCR selection JSON.

    The returned ANY contains DER(TpmPcrSelectionInfo).  The outer
    ``NonceResponse.type`` still identifies the selected freshness open type;
    the inner ``type`` identifies the JSON schema carried in ``value``.
    """
    selection_der = encode_tpm_pcr_selection_info(
        build_tpm_pcr_selection_json(pcrs, hash_alg_id),
        oid=oid,
    )
    return univ.Any(hexValue=selection_der.hex())


def pcr_selection_from_response_info(
    response_info: bytes | bytearray | univ.Any,
) -> tuple[list[int] | None, int | None] | None:
    """Decode a ``NonceResponse.respInfo`` value as PCR-selection JSON."""
    if response_info is None:
        return None
    return decode_tpm_pcr_selection_info(bytes(response_info))


__all__ = [
    "TPM_PCR_SELECTION_OID_DEFAULT",
    "TPM_PCR_SELECTION_OID_ENV",
    "TpmPcrSelectionInfoASN1",
    "build_tpm_pcr_selection_json",
    "decode_tpm_pcr_selection_info",
    "encode_tpm_pcr_selection_info",
    "encode_tpm_pcr_selection_info_from_parts",
    "pcr_selection_from_response_info",
    "pcr_selection_response_info",
    "resolve_tpm_pcr_selection_oid",
    "tpm_pcr_selection_json_value",
]

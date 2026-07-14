# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""OID-keyed lookup that serializes a type's ``respInfo`` to/from JSON.

On the CMP wire ``NonceResponseTypeInfo.respInfo`` is DER-encoded ASN.1.  When
the CA forwards the selection to an out-of-band verifier over HTTP, a JSON form
is more convenient than DER.

This module owns the DER↔JSON mapping **per attestation-type OID** so the CA
stays generic: register ``(oid, to_json, from_json)`` once and the dispatcher
handles any type.  Adding a new attestation type that needs a different respInfo
shape is a single :meth:`RespInfoRegistry.register` call — no edits to the CA
dispatch logic.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from pyasn1.type import univ

from libattest.formats.key_attest_pop import (
    key_attest_resp_from_json,
    key_attest_resp_to_json,
    resolve_key_attest_evidence_oid,
)
from libattest.formats.tpm.pcr_selection import resolve_tpm_pcr_selection_oid
from libattest.formats.tpm.quote_profile import (
    decode_tpm20_quote_resp_info,
    encode_tpm20_quote_resp_info,
)
from libattest.formats.tpm.tcg import id_tcg_attest_quote

#: A DER(respInfo) → JSON-serialisable dict converter.
ToJson = Callable[["bytes | bytearray | univ.Any"], dict[str, Any]]
#: A JSON dict → DER(respInfo) converter.
FromJson = Callable[[Mapping[str, Any]], bytes]


def tpm20_quote_resp_info_to_json(der: bytes | bytearray | univ.Any) -> dict[str, Any]:
    """Convert DER ``TPM20QuoteRespInfo`` into JSON.

    The JSON field names mirror the ASN.1 field names:
    ``certificateName``, ``pcrSelection``, and ``hashAlgo``.
    """
    certificate_name, pcr_selection, hash_algo = decode_tpm20_quote_resp_info(der)
    out: dict[str, Any] = {
        "pcrSelection": pcr_selection,
        "hashAlgo": hash_algo,
    }
    if certificate_name is not None:
        out["certificateName"] = certificate_name
    return out


def tpm20_quote_resp_info_from_json(payload: Mapping[str, Any]) -> bytes:
    """Convert JSON back into DER ``TPM20QuoteRespInfo``.

    Raises
    ------
    ValueError
        If required fields are absent or values are out of range.

    """
    pcr_selection = payload.get("pcrSelection", payload.get("pcrs"))
    hash_algo = payload.get("hashAlgo", payload.get("hashAlgId"))
    if pcr_selection is None:
        raise ValueError("TPM20QuoteRespInfo JSON requires pcrSelection")
    if hash_algo is None:
        raise ValueError("TPM20QuoteRespInfo JSON requires hashAlgo")
    return encode_tpm20_quote_resp_info(
        certificate_name=payload.get("certificateName"),
        pcr_selection=pcr_selection,
        hash_algo=hash_algo,
    )


class RespInfoRegistry:
    """Thread-unsafe* OID→(to_json, from_json) lookup for respInfo codecs.

    (*Registration happens once at import/startup; lookups are read-only, so no
    locking is needed for the CA's request-path usage.)
    """

    def __init__(self) -> None:
        """Initialise an empty OID→codec map."""
        self._codecs: dict[str, tuple[ToJson, FromJson]] = {}

    def register(self, oid: str | univ.ObjectIdentifier, to_json: ToJson, from_json: FromJson) -> None:
        """Register the JSON codec used for a given attestation-type OID."""
        self._codecs[str(oid)] = (to_json, from_json)

    def is_registered(self, oid: str | univ.ObjectIdentifier) -> bool:
        """Return whether a codec is registered for *oid*."""
        return str(oid) in self._codecs

    def registered_oids(self) -> list[str]:
        """Return the OIDs (dotted form) that have a registered codec."""
        return sorted(self._codecs)

    def to_json(self, oid: str | univ.ObjectIdentifier, der: bytes | bytearray | univ.Any) -> dict[str, Any]:
        """Serialise a DER respInfo to JSON using the codec registered for *oid*."""
        return self._require(oid)[0](der)

    def from_json(self, oid: str | univ.ObjectIdentifier, payload: Mapping[str, Any]) -> bytes:
        """Deserialise a JSON respInfo to DER using the codec registered for *oid*."""
        return self._require(oid)[1](payload)

    def _require(self, oid: str | univ.ObjectIdentifier) -> tuple[ToJson, FromJson]:
        try:
            return self._codecs[str(oid)]
        except KeyError:
            raise KeyError(f"no respInfo JSON codec registered for OID {oid}") from None


def _build_default_registry() -> RespInfoRegistry:
    registry = RespInfoRegistry()
    registry.register(
        resolve_tpm_pcr_selection_oid(),
        tpm20_quote_resp_info_to_json,
        tpm20_quote_resp_info_from_json,
    )
    registry.register(
        id_tcg_attest_quote,
        tpm20_quote_resp_info_to_json,
        tpm20_quote_resp_info_from_json,
    )
    registry.register(
        resolve_key_attest_evidence_oid(),
        key_attest_resp_to_json,
        key_attest_resp_from_json,
    )
    return registry


#: Default registry instance seeded with the built-in TPM platform codec.
DEFAULT_RESP_INFO_REGISTRY = _build_default_registry()


__all__ = [
    "DEFAULT_RESP_INFO_REGISTRY",
    "FromJson",
    "RespInfoRegistry",
    "ToJson",
    "tpm20_quote_resp_info_from_json",
    "tpm20_quote_resp_info_to_json",
]

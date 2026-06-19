# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""OID-keyed lookup that serializes a type's ``respInfo`` to/from JSON.

On the CMP wire ``NonceResponse.respInfo`` is DER-encoded ASN.1 (for the TPM
platform profile, ``TpmAttestationParams``).  When the CA forwards the selection
to an out-of-band verifier over HTTP, a JSON form is more convenient than DER.

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

from libattest.formats.tpm.attestation_params import (
    decode_tpm_attestation_params,
    encode_tpm_attestation_params,
)
from libattest.formats.tpm.pcr_selection import resolve_tpm_pcr_selection_oid
from libattest.formats.tpm.tcg import id_tcg_attest_quote

#: A DER(respInfo) → JSON-serialisable dict converter.
ToJson = Callable[["bytes | bytearray | univ.Any"], dict[str, Any]]
#: A JSON dict → DER(respInfo) converter.
FromJson = Callable[[Mapping[str, Any]], bytes]


def tpm_attestation_params_to_json(der: bytes | bytearray | univ.Any) -> dict[str, Any]:
    """Convert DER ``TpmAttestationParams`` into ``{"pcrs": [...], "hashAlgId": N}``.

    Absent optional fields are omitted from the JSON object (mirroring the
    ASN.1 OPTIONAL semantics).
    """
    pcrs, hash_alg_id = decode_tpm_attestation_params(der)
    out: dict[str, Any] = {}
    if pcrs is not None:
        out["pcrs"] = pcrs
    if hash_alg_id is not None:
        out["hashAlgId"] = hash_alg_id
    return out


def tpm_attestation_params_from_json(payload: Mapping[str, Any]) -> bytes:
    """Convert ``{"pcrs": [...], "hashAlgId": N}`` back into DER ``TpmAttestationParams``.

    Raises
    ------
    ValueError
        If the payload carries neither field or values are out of range
        (delegated to :func:`encode_tpm_attestation_params`).

    """
    return encode_tpm_attestation_params(payload.get("pcrs"), payload.get("hashAlgId"))


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
    """Registry pre-seeded with the TPM platform-attestation respInfo codec.

    The platform profile negotiates PCR selection under ``TPM_PCR_SELECTION_OID``
    (the NonceRequest.type) and routes evidence under ``TcgAttestQuote``
    (the AttestationStatement.type); both share the ``TpmAttestationParams``
    codec, so a caller can look the codec up by whichever OID it holds.
    """
    registry = RespInfoRegistry()
    registry.register(
        resolve_tpm_pcr_selection_oid(),
        tpm_attestation_params_to_json,
        tpm_attestation_params_from_json,
    )
    registry.register(
        id_tcg_attest_quote,
        tpm_attestation_params_to_json,
        tpm_attestation_params_from_json,
    )
    return registry


#: Default registry instance seeded with the built-in TPM platform codec.
DEFAULT_RESP_INFO_REGISTRY = _build_default_registry()


__all__ = [
    "DEFAULT_RESP_INFO_REGISTRY",
    "FromJson",
    "RespInfoRegistry",
    "ToJson",
    "tpm_attestation_params_from_json",
    "tpm_attestation_params_to_json",
]

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Verifier-driven TPM attestation parameters (SPEC §DR-11).

Wire format::

    TpmAttestationParams ::= SEQUENCE {
        pcrs       SEQUENCE OF INTEGER OPTIONAL,   -- PCR indices, e.g. [0,1,4,7]
        hashAlgId  INTEGER             OPTIONAL    -- TPM algorithm ID, e.g. 0x000B
    }

Used in both directions under ``TPM_PCR_SELECTION_OID``:

* **Attester → MockCA** (challengeParams): ``{hashAlgId=0x000B}`` — hash proposal;
  ``pcrs`` absent.
* **MockCA → attester** (responseParams): ``{pcrs=[...], hashAlgId=0x000B}`` — full
  response; ``hashAlgId`` echoed or counter-proposed.

Replaces ``TpmPcrSelection`` (retired).  Same OID, new structure.
"""

from __future__ import annotations

import logging
import os
from typing import Iterable, List, Optional, Sequence, Tuple

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

from libattest.formats.csrattest.attest_nonce_freshness_structures import (
    ChallengeParamASN1,
)

logger = logging.getLogger(__name__)

TPM_PCR_SELECTION_OID_DEFAULT: str = "1.3.6.1.4.1.99999.3"
TPM_PCR_SELECTION_OID_ENV: str = "TPM_PCR_SELECTION_OID"


def resolve_tpm_pcr_selection_oid() -> str:
    """Return the configured PCR-selection OID, env override or default."""
    value = os.environ.get(TPM_PCR_SELECTION_OID_ENV)
    if value is not None and value.strip():
        return value.strip()
    return TPM_PCR_SELECTION_OID_DEFAULT


class _PcrIndexSequence(univ.SequenceOf):
    componentType = univ.Integer()


class TpmAttestationParamsASN1(univ.Sequence):
    """TpmAttestationParams ::= SEQUENCE { pcrs OPTIONAL, hashAlgId OPTIONAL }."""

    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType("pcrs", _PcrIndexSequence()),
        namedtype.OptionalNamedType("hashAlgId", univ.Integer()),
    )


_PCR_INDEX_MAX: int = 23  # Hardware TPMs expose 24 PCRs per bank (indices 0..23)


def _validate_pcr_indices(pcrs: Sequence[int]) -> List[int]:
    if pcrs is None:
        raise ValueError("TpmAttestationParams.pcrs: list must not be None")
    seen: set[int] = set()
    coerced: List[int] = []
    duplicates = 0
    for value in pcrs:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"TpmAttestationParams.pcrs: entry {value!r} is not an int")
        if value < 0:
            raise ValueError(f"TpmAttestationParams.pcrs: entry {value} must be non-negative")
        if value > _PCR_INDEX_MAX:
            raise ValueError(
                f"TpmAttestationParams.pcrs: entry {value} exceeds max PCR index "
                f"{_PCR_INDEX_MAX}"
            )
        if value in seen:
            duplicates += 1
            continue
        seen.add(value)
        coerced.append(value)
    if not coerced:
        raise ValueError("TpmAttestationParams.pcrs: list must not be empty")
    if duplicates:
        logger.warning(
            "TpmAttestationParams.pcrs: dropped %d duplicate index/indices",
            duplicates,
        )
    coerced.sort()
    return coerced


def encode_tpm_attestation_params(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
) -> bytes:
    """DER-encode a ``TpmAttestationParams``.

    Both fields are optional.  Pass ``pcrs=None`` to omit the PCR list
    (attester proposal shape).  Pass ``hash_alg_id=None`` to omit the
    algorithm ID.
    """
    params = TpmAttestationParamsASN1()
    if pcrs is not None:
        indices = _validate_pcr_indices(list(pcrs))
        pcr_seq = _PcrIndexSequence()
        for i, idx in enumerate(indices):
            pcr_seq[i] = idx
        params["pcrs"] = pcr_seq
    if hash_alg_id is not None:
        if isinstance(hash_alg_id, bool) or not isinstance(hash_alg_id, int):
            raise ValueError("hash_alg_id must be a non-negative integer")
        if hash_alg_id < 0:
            raise ValueError(f"hash_alg_id must be non-negative, got {hash_alg_id}")
        params["hashAlgId"] = univ.Integer(hash_alg_id)
    return bytes(encoder.encode(params))


def decode_tpm_attestation_params(der: bytes) -> Tuple[Optional[List[int]], Optional[int]]:
    """Decode a ``TpmAttestationParams`` DER blob.

    :returns: ``(pcrs, hash_alg_id)`` where either field may be ``None`` when absent.
    :raises ValueError: on malformed DER.
    """
    if not der:
        raise ValueError("TpmAttestationParams: empty DER input")
    try:
        decoded, rest = decoder.decode(der, asn1Spec=TpmAttestationParamsASN1())
    except Exception as exc:
        raise ValueError(f"TpmAttestationParams: DER did not decode: {exc}") from exc
    if rest:
        raise ValueError("TpmAttestationParams: trailing bytes after SEQUENCE")

    pcrs: Optional[List[int]] = None
    if decoded["pcrs"].isValue:
        raw = [int(v) for v in decoded["pcrs"]]
        if not raw:
            raise ValueError("TpmAttestationParams: pcrs present but empty")
        for v in raw:
            if v < 0:
                raise ValueError(f"TpmAttestationParams: pcr index {v} must be non-negative")
            if v > _PCR_INDEX_MAX:
                raise ValueError(
                    f"TpmAttestationParams: pcr index {v} exceeds max PCR index "
                    f"{_PCR_INDEX_MAX}"
                )
        pcrs = raw

    hash_alg_id: Optional[int] = None
    if decoded["hashAlgId"].isValue:
        hash_alg_id = int(decoded["hashAlgId"])
        if hash_alg_id < 0:
            raise ValueError(
                f"TpmAttestationParams: hashAlgId {hash_alg_id} must be non-negative"
            )

    return pcrs, hash_alg_id


def make_pcr_selection_response_param(
    pcrs: Iterable[int] | None = None,
    hash_alg_id: int | None = None,
    *,
    oid: str | None = None,
) -> ChallengeParamASN1:
    """Build a ``ChallengeParam`` carrying a ``TpmAttestationParams`` value.

    :param pcrs: PCR indices (verifier response) or ``None`` (attester proposal).
    :param hash_alg_id: TPM algorithm ID, e.g. ``0x000B`` for SHA-256.
    :param oid: Override the type OID; defaults to :func:`resolve_tpm_pcr_selection_oid`.
    """
    selection_der = encode_tpm_attestation_params(pcrs, hash_alg_id)
    param = ChallengeParamASN1()
    param["type"] = univ.ObjectIdentifier(oid or resolve_tpm_pcr_selection_oid())
    param["value"] = univ.Any(hexValue=selection_der.hex())
    return param


def extract_pcr_selection_from_response_params(
    response_params: Sequence[ChallengeParamASN1],
    *,
    oid: str | None = None,
) -> Tuple[Optional[List[int]], Optional[int]] | None:
    """Walk ``responseParams`` for the ``TpmAttestationParams`` entry.

    Returns ``(pcrs, hash_alg_id)`` for the first entry matching *oid*.
    Either element may be ``None`` when absent in the structure.
    Returns ``None`` when no matching entry is found.
    """
    target = oid or resolve_tpm_pcr_selection_oid()
    for param in response_params:
        if str(param["type"]) == target:
            return decode_tpm_attestation_params(bytes(param["value"]))
    return None


__all__ = [
    "TPM_PCR_SELECTION_OID_DEFAULT",
    "TPM_PCR_SELECTION_OID_ENV",
    "TpmAttestationParamsASN1",
    "decode_tpm_attestation_params",
    "encode_tpm_attestation_params",
    "extract_pcr_selection_from_response_params",
    "make_pcr_selection_response_param",
    "resolve_tpm_pcr_selection_oid",
]

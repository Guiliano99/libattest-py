# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Shared pyasn1 primitives for the TPM wire formats.

Single definition site for the ASN.1 types reused across the PCR-quote, TCG
certify, and IAK/LDevID key-attestation structures in :mod:`structures`.  Pure
pyasn1 — no ``tpm2-pytss`` — so the MockCA (which has no native binding) imports
it freely.

TPM 2.0 native values are not ASN.1 types; each travels in an ``OCTET STRING``
whose contract names the exact TPM-marshalled structure it carries.  The typedefs
below make the ``TPM2B_*`` (size-prefixed) vs bare ``TPMT_*`` distinction — a real
foot-gun — visible at the type level.
"""

from __future__ import annotations

from collections.abc import Iterable

from pyasn1.type import char, constraint, univ
from pyasn1_alt_modules import rfc9480

_PCR_INDEX_MAX = 23  # Hardware TPMs expose 24 PCRs per bank (indices 0..23)
_TPM_ALG_ID_MAX = 0xFFFF


class TPMAlgId(univ.Integer):
    """TPM_ALG_ID encoded as INTEGER (0..65535), e.g. 0x000B = SHA-256."""

    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, _TPM_ALG_ID_MAX)


class PCRIndex(univ.Integer):
    """PCR index encoded as INTEGER (0..23)."""

    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, _PCR_INDEX_MAX)


# ── OCTET STRING typedefs: each carries one exact TPM-marshalled structure ─────


class Tpm2bPublic(univ.OctetString):
    """Complete ``TPM2B_PUBLIC``, including the 2-byte size prefix."""


class TpmtPublic(univ.OctetString):
    """BARE marshalled ``TPMT_PUBLIC`` — NO ``TPM2B`` size prefix."""


class Tpm2bIdObject(univ.OctetString):
    """Complete ``TPM2B_ID_OBJECT`` (the ActivateCredential credential blob)."""


class Tpm2bEncryptedSecret(univ.OctetString):
    """Complete ``TPM2B_ENCRYPTED_SECRET`` (the ActivateCredential secret/seed)."""


class TpmsAttest(univ.OctetString):
    """Exact marshalled ``TPMS_ATTEST`` — NO ``TPM2B_ATTEST`` size prefix.

    TPM signatures cover these exact bytes, not the outer size prefix.
    """


class TpmtSignature(univ.OctetString):
    """Exact marshalled ``TPMT_SIGNATURE`` (self-describing: hashAlg + sig bytes)."""


# ── SEQUENCE OF helpers ────────────────────────────────────────────────────────
# NB: ``_PCRIndexSequence`` name is asserted on by tests/test_pretty_print_stmt.py.


class _CertificateNameSequence(univ.SequenceOf):
    componentType = char.UTF8String()


class _TPMAlgIdSequence(univ.SequenceOf):
    componentType = TPMAlgId()


class _PCRIndexSequence(univ.SequenceOf):
    componentType = PCRIndex()


class EkCertChain(univ.SequenceOf):
    """``SEQUENCE OF Certificate`` — an EK (or IAK) certificate chain."""

    componentType = rfc9480.CMPCertificate()


# ── shared validators ──────────────────────────────────────────────────────────


def validate_hash_alg_id(hash_alg_id: int) -> int:
    """Return *hash_alg_id* if it is a valid ``TPM_ALG_ID`` int, else raise."""
    if isinstance(hash_alg_id, bool) or not isinstance(hash_alg_id, int):
        raise ValueError("TPMAlgId must be an int")
    if not 0 <= hash_alg_id <= _TPM_ALG_ID_MAX:
        raise ValueError(f"TPMAlgId {hash_alg_id:#x} outside TPM_ALG_ID range")
    return hash_alg_id


def validate_hash_alg_ids(hash_algos: Iterable[int] | None) -> list[int] | None:
    """Validate a non-empty ``SEQUENCE OF TPMAlgId`` (or ``None``)."""
    if hash_algos is None:
        return None
    values = [validate_hash_alg_id(hash_alg_id) for hash_alg_id in hash_algos]
    if not values:
        raise ValueError("supportedHashAlgo must not be empty")
    return values


def validate_certificate_names(names: Iterable[str] | None) -> list[str] | None:
    """Validate a non-empty ``SEQUENCE OF UTF8String`` (or ``None``)."""
    if names is None:
        return None
    values = list(names)
    if not values:
        raise ValueError("certificateName must not be empty")
    for name in values:
        if not isinstance(name, str) or not name:
            raise ValueError("certificateName entries must be non-empty strings")
    return values


def validate_pcr_selection(pcr_selection: Iterable[int]) -> list[int]:
    """Validate + normalise a ``SEQUENCE OF PCRIndex`` (dedup, ascending)."""
    seen: set[int] = set()
    values: list[int] = []
    for pcr_index in pcr_selection:
        if isinstance(pcr_index, bool) or not isinstance(pcr_index, int):
            raise ValueError("PCRIndex entries must be integers")
        if not 0 <= pcr_index <= _PCR_INDEX_MAX:
            raise ValueError(f"PCRIndex {pcr_index} outside PCRIndex range")
        if pcr_index not in seen:
            seen.add(pcr_index)
            values.append(pcr_index)
    if not values:
        raise ValueError("pcrSelection must not be empty")
    values.sort()
    return values


__all__ = [
    "EkCertChain",
    "PCRIndex",
    "TPMAlgId",
    "Tpm2bEncryptedSecret",
    "Tpm2bIdObject",
    "Tpm2bPublic",
    "TpmsAttest",
    "TpmtPublic",
    "TpmtSignature",
    "validate_certificate_names",
    "validate_hash_alg_id",
    "validate_hash_alg_ids",
    "validate_pcr_selection",
]

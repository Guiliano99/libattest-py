# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""The shared TPM quote model: constants, ``TPMS_ATTEST`` parsing, and evidence.

This module is the single source of truth for the TPM2_Quote concept that both
the attester (:mod:`libattest.attester.tpm_client`) and the verifier
(:mod:`libattest.verifier.tpm.tpm_platform_verifier`) depend on:

* the TPM constants and algorithm ids (sourced from ``tpm2-pytss`` so they can
  never drift from the TCG registry),
* :func:`parse_tpms_attest`, the one ``TPMS_ATTEST`` parser, and
* :class:`TpmQuoteSignatureEvidence`, the typed producer -> verifier seam.

``tpm2-pytss`` is a mandatory dependency of this package, so it is imported at
module load time.

References
----------
TCG TPM 2.0 Library Part 2: Structures, Section 10.12.8 (TPMS_ATTEST)
TCG TPM 2.0 Library Part 2: Structures, Section 10.12.4 (TPMS_QUOTE_INFO)

"""

from __future__ import annotations

from dataclasses import dataclass

from tpm2_pytss import TPM2_ALG, TPMS_ATTEST

#: ``TPM_GENERATED_VALUE`` prefixes every TPM-produced attestation block.
TPM_GENERATED_VALUE = 0xFF544347
#: ``TPMS_ATTEST.type`` selector for a quote (Part 2, Table 152).
TPM_ST_ATTEST_QUOTE = 0x8018

# Canonical TPM algorithm ids, sourced from the pytss enum (which is generated
# from the TCG Algorithm Registry).  Both the attester and the verifier import
# these so the ids are defined exactly once.
TPM_ALG_SHA1 = int(TPM2_ALG.SHA1)
TPM_ALG_SHA256 = int(TPM2_ALG.SHA256)
TPM_ALG_SHA384 = int(TPM2_ALG.SHA384)
TPM_ALG_SHA512 = int(TPM2_ALG.SHA512)
TPM_ALG_RSASSA = int(TPM2_ALG.RSASSA)
TPM_ALG_RSAPSS = int(TPM2_ALG.RSAPSS)
TPM_ALG_ECDSA = int(TPM2_ALG.ECDSA)


@dataclass(frozen=True)
class TpmQuoteSignatureEvidence:
    """Typed producer -> verifier seam for TPM2_Quote signature evidence.

    ``attestation`` is the exact marshalled ``TPMS_ATTEST`` buffer signed by the
    AK.  ``signature`` is the raw TPM signature value: RSA bytes for RSASSA/PSS,
    or ``r || s`` for ECDSA.  ``ak_public_key`` is the AK public key as DER/PEM
    SubjectPublicKeyInfo or a PEM/DER X.509 AK certificate.

    Build one from a producer's :class:`~libattest.attester.tpm_client.QuoteResult`
    via :meth:`QuoteResult.to_evidence`; appraise it with
    :class:`~libattest.verifier.tpm.tpm_platform_verifier.TpmPlatformVerifier`.
    """

    attestation: bytes
    signature: bytes
    signature_algorithm: int
    signature_hash: int
    ak_public_key: bytes


@dataclass(frozen=True)
class ParsedAttest:
    """The ``TPMS_ATTEST`` fields a verifier needs, from a single pytss unmarshal.

    ``pcr_selections`` / ``pcr_digest`` are populated only for quotes
    (``attest_type == TPM_ST_ATTEST_QUOTE``) and are empty otherwise.

    Attributes
    ----------
    magic:
        ``TPMS_ATTEST.magic`` (``TPM_GENERATED_VALUE`` for genuine evidence).
    attest_type:
        ``TPMS_ATTEST.type`` selector.
    nonce:
        ``extraData`` / qualifyingData — the freshness nonce.
    pcr_selections:
        ``[{"hash_alg": int, "pcr_mask": bytes}, ...]`` from ``TPMS_QUOTE_INFO``.
    pcr_digest:
        ``TPMS_QUOTE_INFO.pcrDigest``.

    The remaining fields (``qualified_signer`` .. ``firmware_version``) are read
    from every ``TPMS_ATTEST`` regardless of type; the appraisal logic ignores
    them, but a producer's ``QuoteResult`` surfaces them for operator output.

    """

    magic: int
    attest_type: int
    nonce: bytes
    pcr_selections: list[dict]
    pcr_digest: bytes
    qualified_signer: bytes = b""
    clock: int = 0
    reset_count: int = 0
    restart_count: int = 0
    safe: bool = False
    firmware_version: int = 0


def parse_tpms_attest(tpm_s_attest: bytes) -> ParsedAttest:
    """Parse raw ``TPMS_ATTEST`` bytes into a :class:`ParsedAttest` via pytss.

    A single ``tpm2_pytss.TPMS_ATTEST.unmarshal`` yields every field a verifier
    checks (and every field a producer surfaces), so the buffer is parsed once.

    Parameters
    ----------
    tpm_s_attest:
        Raw marshalled ``TPMS_ATTEST`` bytes (no outer ``TPM2B`` size prefix).

    Raises
    ------
    ValueError
        If the buffer is not a valid ``TPMS_ATTEST`` encoding.

    """
    try:
        attest, _consumed = TPMS_ATTEST.unmarshal(bytes(tpm_s_attest))
    except Exception as exc:  # pytss raises TSS2_Exception / ValueError on bad input
        raise ValueError(f"failed to unmarshal TPMS_ATTEST: {exc}") from exc

    attest_type = int(attest.type)

    pcr_selections: list[dict] = []
    pcr_digest = b""
    if attest_type == TPM_ST_ATTEST_QUOTE:
        quote = attest.attested.quote
        selection_list = quote.pcrSelect
        for i in range(selection_list.count):
            sel = selection_list.pcrSelections[i]
            size = int(sel.sizeofSelect)
            pcr_selections.append(
                {
                    "hash_alg": int(sel.hash),
                    # pytss fixed-size arrays reject implicit-start slices; index explicitly.
                    "pcr_mask": bytes(sel.pcrSelect[j] for j in range(size)),
                }
            )
        pcr_digest = bytes(quote.pcrDigest)

    return ParsedAttest(
        magic=int(attest.magic),
        attest_type=attest_type,
        nonce=bytes(attest.extraData),
        pcr_selections=pcr_selections,
        pcr_digest=pcr_digest,
        qualified_signer=bytes(attest.qualifiedSigner),
        clock=int(attest.clockInfo.clock),
        reset_count=int(attest.clockInfo.resetCount),
        restart_count=int(attest.clockInfo.restartCount),
        safe=bool(attest.clockInfo.safe),
        firmware_version=int(attest.firmwareVersion),
    )


def pcr_mask_to_indices(pcr_mask: bytes) -> list[int]:
    """Convert a ``TPMS_PCR_SELECTION.pcrSelect`` bitmask to PCR indices.

    Byte 0 covers PCRs 0..7 (bit 0 = PCR 0), byte 1 covers PCRs 8..15, and
    so on — the TPM-native selection encoding produced by ``TPM2_Quote``.

    Parameters
    ----------
    pcr_mask:
        The ``pcr_mask`` bytes from one :class:`ParsedAttest` selection.

    Returns
    -------
    list[int]
        Sorted PCR indices selected by the bitmask.

    """
    indices: list[int] = []
    for byte_index, byte_value in enumerate(pcr_mask):
        for bit in range(8):
            if byte_value & (1 << bit):
                indices.append(byte_index * 8 + bit)
    return indices


def pcr_indices_to_mask(indices: list[int], *, min_size: int = 3) -> bytes:
    """Convert PCR indices to a ``TPMS_PCR_SELECTION.pcrSelect`` bitmask.

    Parameters
    ----------
    indices:
        Non-negative PCR indices to select.
    min_size:
        Minimum ``sizeofSelect`` in bytes.  TPMs commonly require 3 bytes
        (24 PCRs) even when high indices are unused.

    Raises
    ------
    ValueError
        If an index is negative.

    """
    if any(index < 0 for index in indices):
        raise ValueError("PCR indices must be non-negative")
    size = max(min_size, (max(indices) // 8) + 1 if indices else 0)
    mask = bytearray(size)
    for index in indices:
        mask[index // 8] |= 1 << (index % 8)
    return bytes(mask)

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Binary helpers for TPMS_ATTEST and TPMT_SIGNATURE structures.

References
----------
TCG TPM 2.0 Library Part 2: Structures, Section 10.12.8 (TPMS_ATTEST)
TCG TPM 2.0 Library Part 2: Structures, Section 11.3.4 (TPMT_SIGNATURE)
"""

from __future__ import annotations

import struct

# TPM_GENERATED_VALUE = 0xFF544347 (big-endian: 0xFF 'T' 'C' 'G')
_TPM_GENERATED_VALUE = b"\xff\x54\x43\x47"
_MAGIC_LEN = 4
_TYPE_LEN = 2
_HEADER_LEN = _MAGIC_LEN + _TYPE_LEN

# TPMS_CLOCK_INFO: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17 bytes
_CLOCK_INFO_LEN = 17
# firmwareVersion: UINT64 = 8 bytes
_FIRMWARE_VERSION_LEN = 8


def _attested_start_offset(data: bytes) -> int:
    """Return byte offset of the ``attested`` union in a raw TPMS_ATTEST buffer.

    Raises
    ------
    ValueError
        If the buffer is truncated or the TPM magic does not match.
    """
    if len(data) < _HEADER_LEN:
        raise ValueError("TPMS_ATTEST too short for header")
    if data[:_MAGIC_LEN] != _TPM_GENERATED_VALUE:
        raise ValueError(f"Unexpected TPMS_ATTEST magic: {data[:_MAGIC_LEN].hex()}")

    offset = _HEADER_LEN

    if offset + 2 > len(data):
        raise ValueError("TPMS_ATTEST too short for qualifiedSigner.size")
    qs_size = struct.unpack_from(">H", data, offset)[0]
    offset += 2 + qs_size

    if offset + 2 > len(data):
        raise ValueError("TPMS_ATTEST too short for extraData.size")
    ed_size = struct.unpack_from(">H", data, offset)[0]
    offset += 2 + ed_size

    offset += _CLOCK_INFO_LEN + _FIRMWARE_VERSION_LEN

    if offset > len(data):
        raise ValueError("TPMS_ATTEST too short to contain attested union")
    return offset


def extract_qualifying_data(tpm_s_attest: bytes) -> bytes:
    """Return the ``qualifyingData`` (nonce) field from a raw TPMS_ATTEST buffer.

    TPMS_ATTEST binary layout (all multi-byte integers big-endian):

    .. code-block:: text

        magic           UINT32  (must be 0xFF544743)
        type            UINT16
        qualifiedSigner TPM2B_NAME  (2-byte size + data)
        extraData       TPM2B_DATA  (2-byte size + data)  ← returned here
        ...

    Parameters
    ----------
    tpm_s_attest:
        Raw bytes of the TPMS_ATTEST structure, as returned by TPM2_Certify.

    Returns
    -------
    bytes
        The ``extraData`` / ``qualifyingData`` value, which carries the
        freshness nonce bound at certify time.

    Raises
    ------
    ValueError
        If the buffer is truncated or the TPM magic does not match.
    """
    if len(tpm_s_attest) < _HEADER_LEN:
        raise ValueError("TPMS_ATTEST buffer is too short to contain header")
    if tpm_s_attest[:_MAGIC_LEN] != _TPM_GENERATED_VALUE:
        raise ValueError(
            f"Unexpected TPMS_ATTEST magic: {tpm_s_attest[:_MAGIC_LEN].hex()}"
        )
    offset = _HEADER_LEN
    # qualifiedSigner: TPM2B_NAME = uint16 size + bytes
    if offset + 2 > len(tpm_s_attest):
        raise ValueError("TPMS_ATTEST too short for qualifiedSigner size field")
    (qs_size,) = struct.unpack_from(">H", tpm_s_attest, offset)
    offset += 2 + qs_size
    # extraData: TPM2B_DATA = uint16 size + bytes
    if offset + 2 > len(tpm_s_attest):
        raise ValueError("TPMS_ATTEST too short for extraData size field")
    (extra_size,) = struct.unpack_from(">H", tpm_s_attest, offset)
    offset += 2
    if offset + extra_size > len(tpm_s_attest):
        raise ValueError("TPMS_ATTEST buffer truncated inside extraData")
    return tpm_s_attest[offset : offset + extra_size]


def extract_certify_name(tpm_s_attest: bytes) -> bytes:
    """Extract ``TPMS_CERTIFY_INFO.name`` from a TPMS_ATTEST (type 0x8017).

    The returned value is the TPM name of the certified key:
    ``nameAlg (2 bytes) || H_{nameAlg}(TPMT_PUBLIC)``.

    Used by the verifier to check
    ``TPMS_CERTIFY_INFO.name == compute_tpm_name(tpmTPublic)`` (G1 check).

    Parameters
    ----------
    tpm_s_attest:
        Raw TPMS_ATTEST bytes (no outer TPM2B size prefix).

    Returns
    -------
    bytes
        The ``TPMS_CERTIFY_INFO.name`` value.

    Raises
    ------
    ValueError
        On malformed input.
    """
    offset = _attested_start_offset(tpm_s_attest)
    data = tpm_s_attest

    if offset + 2 > len(data):
        raise ValueError("TPMS_CERTIFY_INFO too short for name.size")
    name_size = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if offset + name_size > len(data):
        raise ValueError("TPMS_CERTIFY_INFO.name truncated")
    return data[offset : offset + name_size]


def extract_quote_info(tpm_s_attest: bytes) -> tuple:
    """Extract PCR selection list and digest from a TPMS_ATTEST (type 0x8018).

    Used by the verifier to perform PCR value appraisal (G2 check).

    Parameters
    ----------
    tpm_s_attest:
        Raw TPMS_ATTEST bytes (no outer TPM2B size prefix).

    Returns
    -------
    tuple[list[dict], bytes]
        A 2-tuple of:

        - ``pcr_selections``: list of dicts, each with:
          ``"hash_alg"`` (int, TPM algorithm ID) and
          ``"pcr_mask"`` (bytes, bitmask of selected PCR indices).
        - ``pcr_digest``: bytes — the ``TPM2B_DIGEST`` value from
          ``TPMS_QUOTE_INFO.pcrDigest``.

    Raises
    ------
    ValueError
        On malformed input.
    """
    offset = _attested_start_offset(tpm_s_attest)
    data = tpm_s_attest

    # TPML_PCR_SELECTION: count UINT32
    if offset + 4 > len(data):
        raise ValueError("TPMS_QUOTE_INFO too short for pcrSelect.count")
    count = struct.unpack_from(">I", data, offset)[0]
    offset += 4

    pcr_selections: list[dict] = []
    for _ in range(count):
        # TPMS_PCR_SELECTION: hash(2) + sizeofSelect(1) + pcrSelect[sizeofSelect]
        if offset + 3 > len(data):
            raise ValueError("TPMS_PCR_SELECTION truncated")
        hash_alg = struct.unpack_from(">H", data, offset)[0]
        size_of_select = data[offset + 2]
        offset += 3
        if offset + size_of_select > len(data):
            raise ValueError("TPMS_PCR_SELECTION.pcrSelect truncated")
        pcr_mask = data[offset : offset + size_of_select]
        offset += size_of_select
        pcr_selections.append({"hash_alg": hash_alg, "pcr_mask": bytes(pcr_mask)})

    # TPM2B_DIGEST: size(2) + buffer[size]
    if offset + 2 > len(data):
        raise ValueError("TPMS_QUOTE_INFO too short for pcrDigest.size")
    digest_size = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if offset + digest_size > len(data):
        raise ValueError("TPMS_QUOTE_INFO.pcrDigest truncated")
    return pcr_selections, data[offset : offset + digest_size]

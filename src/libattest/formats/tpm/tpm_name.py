# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM name computation for key identity verification.

Per TPM spec Part 1 §16::

    name = nameAlg (2 bytes, big-endian) || H_{nameAlg}(TPMT_PUBLIC)

Used by the verifier to check
``TPMS_CERTIFY_INFO.name == compute_tpm_name(tpmTPublic)``.

References
----------
TCG TPM 2.0 Library Part 1: Architecture, §16 (Name)
TCG TPM 2.0 Library Part 2: Structures, §12.2.4 (TPMT_PUBLIC)
"""

from __future__ import annotations

import hashlib
import struct

# TPM algorithm IDs for supported hash algorithms
_TPM_ALG_SHA256 = 0x000B

_HASH_FOR_ALG: dict[int, str] = {
    _TPM_ALG_SHA256: "sha256",
}


def compute_tpm_name(tpmt_public: bytes) -> bytes:
    """Compute the TPM name for a key from its marshalled TPMT_PUBLIC bytes.

    Per TPM spec Part 1 §16, the name is::

        name = nameAlg (2 bytes, big-endian) || H_{nameAlg}(TPMT_PUBLIC)

    The ``nameAlg`` field is the second 16-bit word in ``TPMT_PUBLIC``
    (at byte offset 2, immediately after the 2-byte ``type`` field).

    Parameters
    ----------
    tpmt_public:
        Marshalled TPMT_PUBLIC bytes.  Must NOT include the 2-byte size prefix
        of the outer ``TPM2B_PUBLIC`` wrapper.

    Returns
    -------
    bytes
        The TPM name: 2-byte ``nameAlg`` followed by the hash digest.
        For SHA-256 keys this is 34 bytes (2 + 32).

    Raises
    ------
    ValueError
        If the buffer is too short or the ``nameAlg`` is not supported.

    """
    if len(tpmt_public) < 4:
        raise ValueError(
            f"TPMT_PUBLIC too short to contain nameAlg: {len(tpmt_public)} bytes"
        )
    name_alg = struct.unpack_from(">H", tpmt_public, 2)[0]
    hash_name = _HASH_FOR_ALG.get(name_alg)
    if hash_name is None:
        raise ValueError(
            f"Unsupported TPMT_PUBLIC.nameAlg: {name_alg:#06x} "
            f"(supported: {[hex(k) for k in _HASH_FOR_ALG]})"
        )
    digest = hashlib.new(hash_name, tpmt_public).digest()
    return struct.pack(">H", name_alg) + digest


__all__ = ["compute_tpm_name"]

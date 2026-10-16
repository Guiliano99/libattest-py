# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPMA_OBJECT object-attribute floor parser (design checks M3 / B3 / C9).

Pure struct — no pyasn1, no ``tpm2-pytss`` — so both the Verifier and (later) the
MockCA's pre-nonce LDevID gate, which runs on an image without the native binding,
share one enforcement helper.

Input contract (security-hardened): callers pass a **canonical bare
``TPMT_PUBLIC``** (no ``TPM2B`` size prefix).  A ``TPM2B_PUBLIC`` value must be run
through :func:`strip_tpm2b_prefix` first — the ``objectAttributes`` field sits at a
different offset in the two encodings (offset 4 bare vs offset 6 prefixed), so a
mis-stripped buffer would read the wrong bytes and could pass an unrestricted key
as restricted.  Every read is bounds-checked: an under-length buffer is rejected
cleanly rather than crashing.
"""

from __future__ import annotations

from dataclasses import dataclass

# TPMT_PUBLIC (bare) leading layout:  type: UINT16 | nameAlg: UINT16 | objectAttributes: UINT32
_OBJECT_ATTRIBUTES_OFFSET = 4
_OBJECT_ATTRIBUTES_END = _OBJECT_ATTRIBUTES_OFFSET + 4

# TPMA_OBJECT bit definitions ([TPM-LIB] Part 2, Table 31).
_FIXED_TPM = 0x00000002
_FIXED_PARENT = 0x00000010
_SENSITIVE_DATA_ORIGIN = 0x00000020
_RESTRICTED = 0x00010000
_DECRYPT = 0x00020000
_SIGN = 0x00040000


@dataclass(frozen=True)
class TpmaObject:
    """The parsed ``objectAttributes`` word, with the bits the floors care about."""

    raw: int

    @property
    def fixed_tpm(self) -> bool:
        """The key cannot be duplicated to a different TPM."""
        return bool(self.raw & _FIXED_TPM)

    @property
    def fixed_parent(self) -> bool:
        """The key cannot be re-parented."""
        return bool(self.raw & _FIXED_PARENT)

    @property
    def sensitive_data_origin(self) -> bool:
        """The TPM generated the sensitive area (not an imported key)."""
        return bool(self.raw & _SENSITIVE_DATA_ORIGIN)

    @property
    def restricted(self) -> bool:
        """The key may only sign/decrypt TPM-generated data."""
        return bool(self.raw & _RESTRICTED)

    @property
    def decrypt(self) -> bool:
        """The key may be used for decryption."""
        return bool(self.raw & _DECRYPT)

    @property
    def sign(self) -> bool:
        """The key may be used for signing."""
        return bool(self.raw & _SIGN)

    def __repr__(self):
        """Render the raw mask plus every decoded attribute bit, for failure messages."""
        return (
            f"TpmaObject(raw={self.raw:#010x}, "
            f"fixed_tpm={self.fixed_tpm}, "
            f"fixed_parent={self.fixed_parent}, "
            f"sensitive_data_origin={self.sensitive_data_origin}, "
            f"restricted={self.restricted}, "
            f"decrypt={self.decrypt}, "
            f"sign={self.sign})"
        )


def strip_tpm2b_prefix(tpm2b_public: bytes) -> bytes:
    """Return the bare ``TPMT_PUBLIC`` body of a ``TPM2B_PUBLIC``, validating the prefix.

    Raises ``ValueError`` if the 2-byte size prefix does not equal the body length
    (a malformed or mis-framed buffer), rather than silently reading past it.
    """
    if len(tpm2b_public) < 2:
        raise ValueError("TPM2B_PUBLIC too short to carry a size prefix")
    size = int.from_bytes(tpm2b_public[:2], "big")
    body = tpm2b_public[2:]
    if size != len(body):
        raise ValueError(f"TPM2B_PUBLIC size prefix {size} != body length {len(body)}")
    return body


def read_object_attributes(tpmt_public: bytes) -> TpmaObject:
    """Read ``objectAttributes`` from a **bare** ``TPMT_PUBLIC`` (offset 4, UINT32).

    Bounds-checked: raises ``ValueError`` on an under-length buffer instead of
    crashing (the MockCA pre-nonce gate parses unauthenticated client input).
    """
    if len(tpmt_public) < _OBJECT_ATTRIBUTES_END:
        raise ValueError(f"TPMT_PUBLIC too short ({len(tpmt_public)} bytes) to hold objectAttributes")
    raw = int.from_bytes(tpmt_public[_OBJECT_ATTRIBUTES_OFFSET:_OBJECT_ATTRIBUTES_END], "big")
    return TpmaObject(raw)


def _enforce_floor(
    attrs: TpmaObject,
    *,
    restricted: bool,
    role: str,
) -> None:
    """Assert the shared DevID floor plus the role-specific ``restricted`` bit."""
    expected = {
        "restricted": restricted,
        "sign": True,
        "decrypt": False,
        "fixed_tpm": True,
        "fixed_parent": True,
    }
    actual = {
        "restricted": attrs.restricted,
        "sign": attrs.sign,
        "decrypt": attrs.decrypt,
        "fixed_tpm": attrs.fixed_tpm,
        "fixed_parent": attrs.fixed_parent,
    }
    bad = {k: actual[k] for k in expected if actual[k] != expected[k]}
    if bad:
        raise ValueError(
            f"{role} objectAttributes floor not met (raw={attrs.raw:#010x}): expected {expected}, offending bits {bad}"
        )


def enforce_iak_floor(tpmt_public: bytes) -> TpmaObject:
    """M3/B3: IAK floor — ``restricted=1, sign=1, decrypt=0, fixedTPM=1, fixedParent=1``."""
    attrs = read_object_attributes(tpmt_public)
    _enforce_floor(attrs, restricted=True, role="IAK")
    return attrs


def enforce_ldevid_floor(tpmt_public: bytes) -> TpmaObject:
    """C9: LDevID floor — ``restricted=0, sign=1, decrypt=0, fixedTPM=1, fixedParent=1``."""
    attrs = read_object_attributes(tpmt_public)
    _enforce_floor(attrs, restricted=False, role="LDevID")
    return attrs


__all__ = [
    "TpmaObject",
    "enforce_iak_floor",
    "enforce_ldevid_floor",
    "read_object_attributes",
    "strip_tpm2b_prefix",
]

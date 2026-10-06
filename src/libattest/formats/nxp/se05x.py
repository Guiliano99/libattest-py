# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""SE05x attested-read statement codec (AN13254 §3.1).

The SE05x attestation primitive is the ``ATTEST`` flag (``0x20``) on a
Read / Self-Test / I²C-Master read.  The response is an object value plus an
attestation TLV block, signed by the chip-unique attestation key.

Tag map (single-byte tags, per pinned ``NXP/plug-and-trust @ 7102413e``
``hostlib/hostLib/inc/se05x_enums.h`` ``kSE05x_TAG_*`` and the validated
``se050sim_attestation_probe.py``)::

    0x41 TAG_1  object value (read bytes)          — absent if no READ policy
    0x42 TAG_2  object attributes (incl. origin)
    0x43 TAG_3  timestamp (12 B; SE-internal monotonic)
    0x44 TAG_4  echoed freshness random
    0x45 TAG_5  chip unique ID (UID)
    0x46 TAG_6  attestation algorithm (or signature, per context)
    0x47 TAG_7  freshness random (echoed back)
    0x4F TAG_TIMESTAMP  timestamp (variant ≥07.02)
    0x52 TAG_SIGNATURE  signature (variant ≥07.02)

Request fields (what the host supplies): ``TAG_5`` attestation key id,
``TAG_6`` attestation algorithm, ``TAG_7`` freshness random.  The SE signs a
TLV composition over (hashed request, object value, UID, attributes, size,
timestamp) with the attestation key — **there is no verifier-nonce binding**;
freshness is the SE-internal monotonic timestamp only (weaker than ELE/TPM).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from libattest.formats.nxp.tlv import TlvEntry, format_tlv_line, parse_tlvs, find_tlv

logger = logging.getLogger("libattest.formats.nxp.se05x")

__all__ = [
    "Se05xAttestStatement",
    "Se05xAttestError",
    "decode_se05x_attest",
    "pretty_print_se05x_attest",
    "TAG",
]


class Se05xAttestError(ValueError):
    """Raised when an SE05x attested-read block cannot be parsed."""


class TAG:  # noqa: D101 - namespace for the SE05x tag constants
    """SE05x attestation TLV tag constants (1-byte tags)."""

    T1_OBJECT_VALUE = 0x41
    T2_ATTRIBUTES = 0x42
    T3_TIMESTAMP = 0x43
    T4_ECHO_RANDOM = 0x44
    T5_CHIP_UID = 0x45
    T6_ALGO_OR_SIG = 0x46
    T7_FRESHNESS = 0x47
    TAG_TIMESTAMP = 0x4F
    TAG_SIGNATURE = 0x52


#: Tag -> human name (for prettyPrint).  Mirrors plug-and-trust ``kSE05x_TAG_*``.
_TAG_NAMES: dict[int, str] = {
    TAG.T1_OBJECT_VALUE: "object_value",
    TAG.T2_ATTRIBUTES: "attributes",
    TAG.T3_TIMESTAMP: "timestamp",
    TAG.T4_ECHO_RANDOM: "echo_random",
    TAG.T5_CHIP_UID: "chip_uid",
    TAG.T6_ALGO_OR_SIG: "algo_or_signature",
    TAG.T7_FRESHNESS: "freshness_random",
    TAG.TAG_TIMESTAMP: "timestamp(v7.2+)",
    TAG.TAG_SIGNATURE: "signature(v7.2+)",
}


@dataclass
class Se05xAttestStatement:
    """Decoded SE05x attested-read TLV block."""

    entries: list[TlvEntry] = field(default_factory=list)
    raw: bytes = field(repr=False, default=b"")

    # ── accessors ──────────────────────────────────────────────────────────
    def _one(self, tag: int) -> bytes | None:
        e = find_tlv(self.entries, tag)
        return e.value if e else None

    @property
    def object_value(self) -> bytes | None:
        return self._one(TAG.T1_OBJECT_VALUE)

    @property
    def attributes(self) -> bytes | None:
        return self._one(TAG.T2_ATTRIBUTES)

    @property
    def timestamp(self) -> bytes | None:
        return self._one(TAG.T3_TIMESTAMP) or self._one(TAG.TAG_TIMESTAMP)

    @property
    def chip_uid(self) -> bytes | None:
        return self._one(TAG.T5_CHIP_UID)

    @property
    def signature(self) -> bytes | None:
        return self._one(TAG.TAG_SIGNATURE) or self._one(TAG.T6_ALGO_OR_SIG)

    @property
    def freshness(self) -> bytes | None:
        return self._one(TAG.T7_FRESHNESS) or self._one(TAG.T4_ECHO_RANDOM)

    def freshness_ok(self, expected: bytes) -> bool:
        """Compare the echoed freshness random to *expected* (bytes).

        SE05x freshness is echo/timestamp-based (no verifier-nonce binding),
        so this is a weaker replay check than the ELE 16-byte signed nonce.
        """
        f = self.freshness
        return f is not None and bytes(f) == bytes(expected)

    def attested_tags_present(self) -> list[str]:
        """Names of the attestation tags actually present (replay/downgrade probe)."""
        return [
            _TAG_NAMES.get(e.tag, f"0x{e.tag:02X}")
            for e in self.entries
            if e.tag in _TAG_NAMES
        ]

    def verify_signature(self, pubkey) -> bool:  # pragma: no cover - see docstring
        raise NotImplementedError(
            "SE05x attested-read signature verification requires the "
            "attestation-key trust anchor and the exact signed-TLV "
            "composition (hashed request ‖ value ‖ UID ‖ attrs ‖ size ‖ "
            "timestamp); see module docstring"
        )

    def pretty(self) -> str:
        return pretty_print_se05x_attest(self)


def decode_se05x_attest(raw: bytes) -> Se05xAttestStatement:
    """Parse an SE05x attested-read TLV block into a structured object.

    :raises Se05xAttestError: if the block is empty or not a valid TLV stream.
    """
    if not raw:
        raise Se05xAttestError("SE05x attested-read block is empty")
    try:
        entries = parse_tlvs(raw)
    except ValueError as exc:
        raise Se05xAttestError(f"not a valid SE05x TLV stream: {exc}") from exc
    logger.debug("decoded SE05x attested-read: %d TLVs, %dB", len(entries), len(raw))
    return Se05xAttestStatement(entries=entries, raw=raw)


def pretty_print_se05x_attest(stmt: Se05xAttestStatement) -> str:
    """Render an SE05x attested-read block as a readable block."""
    lines = [
        f"SE05x attested-read statement (TLV block, {len(stmt.raw)} B, {len(stmt.entries)} TLVs)",
    ]
    for e in stmt.entries:
        lines.append(format_tlv_line(e.tag, _TAG_NAMES.get(e.tag, f"unknown(0x{e.tag:02X})"), e.value, e.offset))
    return "\n".join(lines)


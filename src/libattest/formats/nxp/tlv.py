# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""EdgeLock TLV walker (1-byte and 0x81/0x82 length forms).

Shared by the SE05x attested-read codec (tags ``0x41``+) and the ELE key-attest
codec (format-agnostic walk of the EdgeLock 2GO-TLV certificate).  The 2GO cert
tag semantics are intentionally *labeled best-effort*: known tags are decoded,
unknown ones are surfaced verbatim rather than dropped, so a wrong guess can
never silently corrupt a field.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator

__all__ = ["TlvEntry", "parse_tlvs", "encode_tlv", "find_tlv", "format_tlv_line"]


@dataclass(frozen=True)
class TlvEntry:
    """One parsed TLV: ``tag`` (16-bit), ``value`` bytes, byte ``offset``."""

    tag: int
    value: bytes
    offset: int

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"tag=0x{self.tag:02X} len={len(self.value)} off={self.offset}"


def parse_tlvs(buf: bytes) -> list[TlvEntry]:
    """Parse a sequence of TLVs, accepting 1-byte and 0x81/0x82 length forms.

    Tag is a single byte; the length byte ``n`` is the length when ``n < 0x80``,
    the number of length bytes that follow when ``n in (0x81, 0x82)``.

    :raises ValueError: on a truncated record or an unsupported length form.
    """
    out: list[TlvEntry] = []
    i = 0
    n = len(buf)
    while i < n:
        if i + 2 > n:
            raise ValueError(f"TLV truncated at offset {i}")
        tag = buf[i]
        first = buf[i + 1]
        if first < 0x80:
            length = first
            value_start = i + 2
        elif first == 0x81:
            if i + 3 > n:
                raise ValueError(f"TLV 0x81 length truncated at offset {i}")
            length = buf[i + 2]
            value_start = i + 3
        elif first == 0x82:
            if i + 4 > n:
                raise ValueError(f"TLV 0x82 length truncated at offset {i}")
            length = struct.unpack(">H", buf[i + 2 : i + 4])[0]
            value_start = i + 4
        else:
            raise ValueError(f"unsupported TLV length form 0x{first:02X} at offset {i}")
        if value_start + length > n:
            raise ValueError(f"TLV value truncated: tag 0x{tag:02X} needs {length}, has {n - value_start}")
        out.append(TlvEntry(tag, buf[value_start : value_start + length], i))
        i = value_start + length
    return out


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode one TLV (1-byte tag; 1-byte/0x81/0x82 length as needed)."""
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    if n < 0x100:
        return bytes([tag, 0x81, n]) + value
    return bytes([tag, 0x82]) + struct.pack(">H", n) + value


def find_tlv(entries: Iterator[TlvEntry] | list[TlvEntry], tag: int) -> TlvEntry | None:
    """Return the first entry with *tag*, or ``None``."""
    for entry in entries:
        if entry.tag == tag:
            return entry
    return None


def format_tlv_line(tag: int, name: str, value: bytes, offset: int, name_width: int = 18) -> str:
    """Render one TLV entry as a prettyPrint row.

    Long values (>48 B) are truncated with a ``(+NB)`` count so a statement
    stays human-readable.  *name* is the resolved human tag name (the caller
    decides how unknown tags are labeled).
    """
    shown = value.hex()
    if len(value) > 48:
        shown = value[:48].hex() + f"... (+{len(value) - 48}B)"
    return f"  [off {offset:3d}] 0x{tag:02X} {name:<{name_width}} {shown}"



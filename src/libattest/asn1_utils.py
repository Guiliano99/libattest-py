# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Shared strict-DER encode/decode primitives.

Every wire-format module in :mod:`libattest` decodes ``ANY``-typed statement
payloads against a known pyasn1 spec. :func:`try_decode_pyasn1` is the single
place that DER-strictness (no trailing bytes, no BER leniency) and error
wrapping (a clean ``ValueError`` instead of pyasn1's internal exception zoo)
are enforced, so every format gets the same strictness for free.
"""

from __future__ import annotations

from typing import TypeVar

from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import base, univ

Asn1ItemT = TypeVar("Asn1ItemT", bound=base.Asn1Item)


def encode_to_der(value: base.Asn1Item) -> bytes:
    """DER-encode any pyasn1 structure."""
    return bytes(_der_encoder.encode(value))


def try_decode_pyasn1(
    der: bytes | bytearray | univ.Any,
    spec: Asn1ItemT | type[Asn1ItemT],
) -> Asn1ItemT:
    """DER-decode *der* against *spec*.

    *spec* may be a pyasn1 class or an instance; a class is instantiated
    before decoding.

    Raises
    ------
    ValueError
        On malformed DER or trailing bytes after the decoded value.

    """
    asn1_spec = spec() if isinstance(spec, type) else spec
    name = type(asn1_spec).__name__
    try:
        decoded, rest = _der_decoder.decode(bytes(der), asn1Spec=asn1_spec)
    except Exception as exc:  # noqa: BLE001 - pyasn1 raises PyAsn1Error subclasses
        raise ValueError(f"{name}: cannot decode DER: {exc}") from exc
    if rest:
        raise ValueError(f"{name}: trailing bytes after DER value")
    return decoded


__all__ = [
    "encode_to_der",
    "try_decode_pyasn1",
]

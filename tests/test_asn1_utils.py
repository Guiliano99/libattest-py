# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared strict-DER encode/decode primitives."""

from __future__ import annotations

import pytest
from pyasn1.type import univ

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1


def test_round_trips_through_class_and_instance_spec() -> None:
    """GIVEN a valid DER value WHEN decoded via a class or an instance THEN both agree."""
    der = encode_to_der(univ.OctetString(b"hello"))

    decoded_via_class = try_decode_pyasn1(der, univ.OctetString)
    decoded_via_instance = try_decode_pyasn1(der, univ.OctetString())

    assert bytes(decoded_via_class) == b"hello"
    assert bytes(decoded_via_instance) == b"hello"


def test_trailing_bytes_raise() -> None:
    """GIVEN DER with trailing bytes WHEN decoded THEN a ValueError is raised."""
    der = encode_to_der(univ.OctetString(b"hello")) + b"\x00"

    with pytest.raises(ValueError, match="trailing bytes"):
        try_decode_pyasn1(der, univ.OctetString)


def test_malformed_der_raises_value_error() -> None:
    """GIVEN bytes that are not valid DER WHEN decoded THEN a ValueError is raised."""
    with pytest.raises(ValueError, match="cannot decode DER"):
        try_decode_pyasn1(b"\xff\xff\xff", univ.OctetString)

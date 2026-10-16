# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the pure-struct TPMA_OBJECT floor parser (design M3/B3/C9, security-06)."""

from __future__ import annotations

import pytest

from libattest.formats.tpm.attributes import (
    enforce_iak_floor,
    enforce_ldevid_floor,
    read_object_attributes,
    strip_tpm2b_prefix,
)

_FIXED_TPM = 0x00000002
_FIXED_PARENT = 0x00000010
_SENSITIVE_DATA_ORIGIN = 0x00000020
_RESTRICTED = 0x00010000
_DECRYPT = 0x00020000
_SIGN = 0x00040000

_IAK_ATTRS = _RESTRICTED | _SIGN | _FIXED_TPM | _FIXED_PARENT | _SENSITIVE_DATA_ORIGIN
_LDEVID_ATTRS = _SIGN | _FIXED_TPM | _FIXED_PARENT | _SENSITIVE_DATA_ORIGIN


def _bare_tpmt_public(attrs: int, *, type_: int = 0x0001, name_alg: int = 0x000B) -> bytes:
    """A minimal bare TPMT_PUBLIC: type(2) | nameAlg(2) | objectAttributes(4) | tail."""
    return type_.to_bytes(2, "big") + name_alg.to_bytes(2, "big") + attrs.to_bytes(4, "big") + b"\x00\x00"


def test_read_object_attributes_bits():
    a = read_object_attributes(_bare_tpmt_public(_IAK_ATTRS))
    assert a.restricted and a.sign and a.fixed_tpm and a.fixed_parent and a.sensitive_data_origin
    assert not a.decrypt


def test_iak_floor_accepts_iak():
    assert enforce_iak_floor(_bare_tpmt_public(_IAK_ATTRS)).restricted


def test_iak_floor_rejects_unrestricted():
    with pytest.raises(ValueError, match="IAK objectAttributes floor"):
        enforce_iak_floor(_bare_tpmt_public(_LDEVID_ATTRS))  # restricted=0


def test_iak_floor_rejects_decrypt_set():
    with pytest.raises(ValueError, match="IAK objectAttributes floor"):
        enforce_iak_floor(_bare_tpmt_public(_IAK_ATTRS | _DECRYPT))


def test_ldevid_floor_accepts_ldevid():
    assert not enforce_ldevid_floor(_bare_tpmt_public(_LDEVID_ATTRS)).restricted


def test_ldevid_floor_rejects_restricted():
    # A restricted key must NOT pass the LDevID (restricted=0) floor.
    with pytest.raises(ValueError, match="LDevID objectAttributes floor"):
        enforce_ldevid_floor(_bare_tpmt_public(_IAK_ATTRS))


def test_read_rejects_underlength_without_crashing():
    with pytest.raises(ValueError, match="too short"):
        read_object_attributes(b"\x00" * 7)  # need >= 8 bytes for offset 4 + 4


def test_strip_tpm2b_prefix_roundtrip():
    bare = _bare_tpmt_public(_IAK_ATTRS)
    prefixed = len(bare).to_bytes(2, "big") + bare
    assert strip_tpm2b_prefix(prefixed) == bare
    # And parsing the stripped body yields the same attributes as the bare form.
    assert read_object_attributes(strip_tpm2b_prefix(prefixed)).raw == read_object_attributes(bare).raw


def test_strip_tpm2b_prefix_rejects_size_mismatch():
    bare = _bare_tpmt_public(_IAK_ATTRS)
    bad = (len(bare) + 1).to_bytes(2, "big") + bare  # prefix lies about length
    with pytest.raises(ValueError, match="size prefix"):
        strip_tpm2b_prefix(bad)

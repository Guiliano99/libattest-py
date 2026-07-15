# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""CMW JSON/CBOR payload codec tests."""

from __future__ import annotations

import json

import cbor2
import pytest

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1
from libattest.formats.cmw import (
    CMW,
    decode_cmw_cbor_record,
    decode_cmw_json_record,
    encode_cmw_json_record,
)


def test_encode_cmw_json_record_can_emit_a_cbor_record() -> None:
    """GIVEN raw COSE bytes WHEN CBOR is selected THEN DER(CMW cbor) preserves them verbatim."""
    cose_encrypt0 = bytes.fromhex("d08343a10126a040")

    der = encode_cmw_json_record("application/cose", cose_encrypt0, cbor=True)

    cmw = try_decode_pyasn1(der, CMW)
    assert cmw.getName() == "cbor"
    assert cbor2.loads(bytes(cmw["cbor"])) == ["application/cose", cose_encrypt0]
    assert decode_cmw_cbor_record(der) == ("application/cose", cose_encrypt0, None)


def test_decode_cmw_cbor_record_rejects_trailing_cbor_data() -> None:
    """GIVEN a CMW cbor record with an extra item WHEN decoded THEN framing is rejected."""
    cmw = CMW()
    cmw["cbor"] = cbor2.dumps(["application/cose", b"cose"]) + b"\x00"

    with pytest.raises(ValueError, match="trailing bytes"):
        decode_cmw_cbor_record(encode_to_der(cmw))


@pytest.mark.parametrize(
    ("media_type", "cmw_type"),
    [(True, None), ("application/cose", True)],
)
def test_encode_cmw_cbor_record_rejects_noncanonical_record_labels(
    media_type: str | int,
    cmw_type: int | None,
) -> None:
    """GIVEN invalid CMW labels WHEN encoded THEN values outside the decoder contract are rejected."""
    with pytest.raises(TypeError, match="CMW CBOR record"):
        encode_cmw_json_record(media_type, b"cose", cmw_type, cbor=True)


@pytest.mark.parametrize("record", [[True, b"cose"], ["application/cose", b"cose", True]])
def test_decode_cmw_cbor_record_rejects_boolean_integer_labels(record: list[object]) -> None:
    """GIVEN boolean CMW labels WHEN decoded THEN they are not accepted as integer labels."""
    cmw = CMW()
    cmw["cbor"] = cbor2.dumps(record)

    with pytest.raises(ValueError, match="malformed CMW"):
        decode_cmw_cbor_record(encode_to_der(cmw))


def test_decode_cmw_json_record_rejects_boolean_cmw_type() -> None:
    """GIVEN a JSON CMW boolean type WHEN decoded THEN it is not accepted as an integer label."""
    cmw = CMW()
    cmw["json"] = json.dumps(["application/jose", "jwe", True])

    with pytest.raises(ValueError, match="malformed CMW"):
        decode_cmw_json_record(encode_to_der(cmw))

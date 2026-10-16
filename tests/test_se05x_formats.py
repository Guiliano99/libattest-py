# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the SE05x attested-read codec and the ``Se05xAttestEvidence`` statement."""

from __future__ import annotations

import dataclasses
import hashlib

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.type import univ

from libattest.asn1_utils import encode_to_der
from libattest.formats.se05x.apdu import (
    ALGO_ECDSA_SHA256,
    ATTEST_KEY_ID,
    ORIGIN_INTERNAL,
    P256_KEY_SIZE,
    POLICY_ALLOW_DELETE,
    POLICY_ALLOW_SIGN,
    TYPE_EC_KEY_PAIR_NIST_P256,
    AttestedReadCommand,
    ObjectAttributes,
    build_attested_read,
    decode_tlvs,
    encode_tlv,
    parse_attested_read_command,
    parse_attested_read_response,
    parse_attributes,
    recorded_command,
    signed_message,
)
from libattest.formats.se05x.structures import (
    decode_se05x_attest_evidence,
    encode_se05x_attest_evidence,
    prepare_se05x_attest_evidence,
)

# Live capture from the patched SE050Sim (exploration artifact spike/live_vector.json,
# SHA-256 6b955e36b662445d9da51ffccc9810d77e0388d55698e00a22928090e028bc2a). Its
# freshness came from the superseded labelled derivation over a 32-byte nonce; that
# does not matter for the command bytes, the signed message or the signature here.
_LIVE_OBJECT_ID = 0x10AA0002
_LIVE_FRESHNESS = bytes.fromhex("94e6c2714dca3ec5e89e41e14f8353f7")
_LIVE_COMMAND_WIRE = bytes.fromhex(
    "80220000000021410410aa00024504f0000012460121471094e6c2714dca3ec5e89e41e14f8353f70000"
)
_LIVE_RESPONSE = bytes.fromhex(
    "41820041047f0a30d3af6cf4790ac27bd17d3ad36ab9bb4e270ebd38295c25f940edfed556c8c72b600a8c581569e652"
    "4dcc1aad2ea9d0d38ae2f193c6600c7a97201999f9428200128a938c757fa75ad5a711a20a04b9a0d78e844382001310"
    "aa00022901000000000000000002000000004482000200204f82000c6ab382d6000000000000000352483046022100e4"
    "f48aa4b18e38ac02bad1a5db7b657dd5f713a8438beb782cfa1c24b7c6e3420221008da4c2c30fcfe4378f02eed59fcf"
    "a7cfc7b33df15bd32a3148bfb391cd7f5fa5"
)
_LIVE_ATTEST_SPKI = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004f7e5ffb960bc8b60414c2d60842e5bfe59054d62eb"
    "0e02ffb1d231150693e69b5aa77898a036d7d9356eb636993e8569cd67175e38ab7b9758e9d5b30b2862ef"
)
_LIVE_CHIP_ID = bytes.fromhex("8a938c757fa75ad5a711a20a04b9a0d78e84")
# The same capture's read of 0x10AA0003, whose policy lacks ALLOW_READ: no TAG_1.
_LIVE_NO_VALUE_COMMAND = bytes.fromhex(
    "80220000000021410410aa00034504f0000012460121471094e6c2714dca3ec5e89e41e14f8353f7"
)
_LIVE_NO_VALUE_RESPONSE = bytes.fromhex(
    "428200128a938c757fa75ad5a711a20a04b9a0d78e844382001c10aa0003290100000000000000000800000000100400"
    "0002000000004482000200204f82000c6ab382d6000000000000000652483046022100ef4e508e3fd3474eef0c2cf4af"
    "b456ea939366db8688a56a7d2b85857e46d74402210097cdb9ccf42bfae0bf821eca7c1ac0c6ae243197be7aa7cc0e02"
    "c50ec3e6a827"
)

_FRESHNESS = bytes(range(16))
_HEADER = bytes.fromhex("80220000")


def _tlv(tag: int, value: bytes) -> bytes:
    """Return a short-form TLV, written independently of the codec under test."""
    return bytes((tag, len(value))) + value


def _command(data: bytes, header: bytes = _HEADER) -> bytes:
    """Return a recorded command: *header*, an extended Lc that matches *data*, no Le."""
    return header + b"\x00" + len(data).to_bytes(2, "big") + data


_OBJ = _tlv(0x41, bytes.fromhex("7f000101"))
_KEY = _tlv(0x45, bytes.fromhex("f0000012"))
_ALGO = _tlv(0x46, b"\x21")
_FRESH = _tlv(0x47, _FRESHNESS)
_GOOD_DATA = _OBJ + _KEY + _ALGO + _FRESH

_POINT = b"\x04" + bytes(64)
_ATTRS = bytes.fromhex("7f000101290100000000000000000200000000")
_SIZE = b"\x00\x20"
_TIMESTAMP = bytes(12)
_SIGNATURE = bytes.fromhex("3006020101020101")


def _live_key() -> ec.EllipticCurvePublicKey:
    """Return the capture's attestation public key."""
    key = serialization.load_der_public_key(_LIVE_ATTEST_SPKI)
    assert isinstance(key, ec.EllipticCurvePublicKey)
    return key


# ── TLV codec ────────────────────────────────────────────────────────────────────


def test_encode_tlv_uses_the_short_form_below_128_and_82_otherwise() -> None:
    """GIVEN values around the 128-byte boundary WHEN encoded THEN short or 82 hh ll, never 81."""
    assert encode_tlv(0x41, b"\xaa" * 127)[:2] == bytes.fromhex("417f")
    assert encode_tlv(0x41, b"\xaa" * 128)[:4] == bytes.fromhex("41820080")
    assert encode_tlv(0x41, b"\xaa" * 300)[:4] == bytes.fromhex("4182012c")
    assert encode_tlv(0x44, _SIZE, extended=True) == bytes.fromhex("448200020020")


def test_encode_tlv_rejects_a_value_longer_than_65535_bytes() -> None:
    """GIVEN a value too long for 82 hh ll WHEN encoded THEN ValueError."""
    with pytest.raises(ValueError, match="do not fit"):
        encode_tlv(0x41, bytes(0x10000))


def test_decode_tlvs_accepts_the_short_81_and_82_length_forms() -> None:
    """GIVEN TLVs in each length form, minimal or not WHEN decoded THEN each value is returned in order."""
    data = (
        bytes.fromhex("4102aabb")
        + bytes.fromhex("428103ccddee")
        + bytes.fromhex("43820001ff")
        + bytes.fromhex("448180")
        + b"\x11" * 0x80
    )

    assert decode_tlvs(data) == [
        (0x41, bytes.fromhex("aabb")),
        (0x42, bytes.fromhex("ccddee")),
        (0x43, b"\xff"),
        (0x44, b"\x11" * 0x80),
    ]
    assert decode_tlvs(encode_tlv(0x41, bytes(300))) == [(0x41, bytes(300))]
    assert decode_tlvs(b"") == []


@pytest.mark.parametrize(
    ("hex_data", "message"),
    [
        ("41", "truncated header"),
        ("4180", "unsupported length byte 80"),
        ("4183000001ff", "unsupported length byte 83"),
        ("4181", "truncated length"),
        ("418200", "truncated length"),
        ("4105aabb", "past the end"),
        ("41820005aa", "past the end"),
        ("4101aa42", "truncated header"),
    ],
    ids=["lone-tag", "indefinite-80", "83-form", "81-no-byte", "82-one-byte", "short-overrun", "82-overrun", "tail"],
)
def test_decode_tlvs_rejects_malformed_lengths(hex_data: str, message: str) -> None:
    """GIVEN a malformed TLV length WHEN decoded THEN ValueError names the defect."""
    with pytest.raises(ValueError, match=message):
        decode_tlvs(bytes.fromhex(hex_data))


# ── Command ──────────────────────────────────────────────────────────────────────


def test_build_attested_read_reproduces_the_live_wire_command() -> None:
    """GIVEN the capture's object id and freshness WHEN built THEN the exact 42 wire bytes.

    AND recorded_command drops only the extended Le, leaving the 40 bytes the SE hashed.
    """
    wire = build_attested_read(_LIVE_OBJECT_ID, _LIVE_FRESHNESS)

    assert wire == _LIVE_COMMAND_WIRE
    assert len(wire) == 42
    assert wire[4:7] == bytes.fromhex("000021")
    assert recorded_command(wire) == _LIVE_COMMAND_WIRE[:-2]
    assert len(recorded_command(wire)) == 40


def test_build_attested_read_encodes_a_custom_key_and_algorithm() -> None:
    """GIVEN a non-default key id and algorithm WHEN built THEN TAG_5 and TAG_6 carry them."""
    wire = build_attested_read(0x7F000101, _FRESHNESS, attest_key_id=0x12345678, algo=0x22)

    assert wire == _command(_OBJ + _tlv(0x45, bytes.fromhex("12345678")) + _tlv(0x46, b"\x22") + _FRESH) + b"\x00\x00"


@pytest.mark.parametrize("length", [0, 15, 17, 32])
def test_build_attested_read_rejects_freshness_that_is_not_16_bytes(length: int) -> None:
    """GIVEN a freshness of the wrong length WHEN built THEN ValueError, never pad or truncate."""
    with pytest.raises(ValueError, match="16 bytes"):
        build_attested_read(0x7F000101, bytes(length))


@pytest.mark.parametrize(
    "apdu",
    [
        _command(_GOOD_DATA),
        _HEADER + bytes((len(_GOOD_DATA),)) + _GOOD_DATA + b"\x00",
        _command(_GOOD_DATA) + b"\x00\x00\x00",
    ],
    ids=["no-le", "short-lc", "le-mismatch"],
)
def test_recorded_command_rejects_anything_but_extended_lc_with_le(apdu: bytes) -> None:
    """GIVEN an APDU without the extended Lc/Le framing WHEN recorded THEN ValueError."""
    with pytest.raises(ValueError, match="extended-length"):
        recorded_command(apdu)


def test_parse_attested_read_command_reads_the_live_command() -> None:
    """GIVEN the capture's recorded command WHEN parsed THEN its four fields come back."""
    parsed = parse_attested_read_command(recorded_command(_LIVE_COMMAND_WIRE))

    assert parsed == AttestedReadCommand(
        object_id=_LIVE_OBJECT_ID,
        attest_key_id=ATTEST_KEY_ID,
        algo=ALGO_ECDSA_SHA256,
        freshness=_LIVE_FRESHNESS,
    )


@pytest.mark.parametrize(
    ("cmd", "message"),
    [
        (_HEADER + bytes((len(_GOOD_DATA),)) + _GOOD_DATA, "extended Lc"),
        (_command(_GOOD_DATA) + b"\x00\x00", "Lc does not match"),
        (_command(_GOOD_DATA)[:-1], "Lc does not match"),
        (_command(_OBJ + _tlv(0x42, b"\x00\x10") + _KEY + _ALGO + _FRESH), "not 41 45 46 47"),
        (_command(_GOOD_DATA + _tlv(0x48, b"\x00")), "not 41 45 46 47"),
        (_command(_GOOD_DATA + _FRESH), "not 41 45 46 47"),
        (_command(_OBJ + _KEY + _ALGO), "not 41 45 46 47"),
        (_command(_KEY + _OBJ + _ALGO + _FRESH), "not 41 45 46 47"),
        (_command(_OBJ + _KEY + _ALGO + _tlv(0x47, bytes(15))), "freshness must be 16"),
        (_command(_OBJ + _KEY + _ALGO + _tlv(0x47, bytes(17))), "freshness must be 16"),
        (_command(_tlv(0x41, b"\x7f\x00\x01") + _KEY + _ALGO + _FRESH), "wrong length"),
        (_command(_OBJ + _KEY + _tlv(0x46, b"\x21\x00") + _FRESH), "wrong length"),
        (_command(_GOOD_DATA, header=bytes.fromhex("84220000")), "header"),
        (_command(_GOOD_DATA, header=bytes.fromhex("80020000")), "header"),
        (_command(_GOOD_DATA, header=bytes.fromhex("80220100")), "header"),
        (_command(_GOOD_DATA, header=bytes.fromhex("8022003b")), "header"),
    ],
    ids=[
        "short-lc",
        "le-present",
        "truncated",
        "extra-tag-42",
        "unknown-tag-48",
        "duplicate-tag-47",
        "missing-tag-47",
        "reordered",
        "freshness-15",
        "freshness-17",
        "object-id-3-bytes",
        "algo-2-bytes",
        "cla-84",
        "ins-plain-read",
        "p1-01",
        "p2-attributes",
    ],
)
def test_parse_attested_read_command_is_strict(cmd: bytes, message: str) -> None:
    """GIVEN a command that deviates from the key-pair read in one way WHEN parsed THEN ValueError."""
    with pytest.raises(ValueError, match=message):
        parse_attested_read_command(cmd)


# ── Response ─────────────────────────────────────────────────────────────────────


def test_parse_attested_read_response_reads_the_live_response() -> None:
    """GIVEN the capture's response body WHEN parsed THEN every field in order."""
    response = parse_attested_read_response(_LIVE_RESPONSE)

    assert response.value is not None
    assert len(response.value) == 65
    assert response.value[0] == 0x04
    assert response.chip_id == _LIVE_CHIP_ID
    assert response.object_size == P256_KEY_SIZE
    assert response.timestamp == bytes.fromhex("6ab382d60000000000000003")
    assert response.signature[0] == 0x30


def test_parse_attested_read_response_accepts_a_missing_tag_1() -> None:
    """GIVEN the capture's response for an object without ALLOW_READ WHEN parsed THEN value is None."""
    response = parse_attested_read_response(_LIVE_NO_VALUE_RESPONSE)

    assert response.value is None
    assert response.chip_id == _LIVE_CHIP_ID
    assert response.object_size == P256_KEY_SIZE


_GOOD_RESPONSE = (
    _tlv(0x41, _POINT)
    + _tlv(0x42, bytes(18))
    + _tlv(0x43, _ATTRS)
    + _tlv(0x44, _SIZE)
    + _tlv(0x4F, _TIMESTAMP)
    + _tlv(0x52, _SIGNATURE)
)
# AN12413 Table 106 (applet 3.x): value, attributes, timestamp, freshness, chip id, signature.
_LEGACY_RESPONSE = (
    _tlv(0x41, _POINT)
    + _tlv(0x42, _ATTRS)
    + _tlv(0x43, _TIMESTAMP)
    + _tlv(0x44, _FRESHNESS)
    + _tlv(0x45, bytes(18))
    + _tlv(0x46, _SIGNATURE)
)


def test_parse_attested_read_response_accepts_the_short_length_form() -> None:
    """GIVEN a response written with short TLV lengths WHEN parsed THEN it is accepted like the 82 form."""
    assert parse_attested_read_response(_GOOD_RESPONSE).value == _POINT


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (_LEGACY_RESPONSE, "are not"),
        (_LIVE_RESPONSE + b"\x90\x00", "are not"),
        (_LIVE_RESPONSE + b"\x00", "truncated header"),
        (_LIVE_RESPONSE[: -(2 + 0x48)], "are not"),
        (_GOOD_RESPONSE[: -len(_tlv(0x52, _SIGNATURE))] + _tlv(0x52, b""), "signature is empty"),
        (
            _tlv(0x41, _POINT)
            + _tlv(0x43, _ATTRS)
            + _tlv(0x42, bytes(18))
            + _tlv(0x44, _SIZE)
            + _tlv(0x4F, _TIMESTAMP)
            + _tlv(0x52, _SIGNATURE),
            "are not",
        ),
        (_GOOD_RESPONSE.replace(_tlv(0x42, bytes(18)), _tlv(0x42, bytes(17))), "wrong length"),
        (_GOOD_RESPONSE.replace(_tlv(0x44, _SIZE), _tlv(0x44, b"\x00\x00\x00\x20")), "wrong length"),
        (_GOOD_RESPONSE.replace(_tlv(0x4F, _TIMESTAMP), _tlv(0x4F, bytes(8))), "wrong length"),
        (_tlv(0x41, _POINT) + _tlv(0x41, _POINT) + _GOOD_RESPONSE[len(_tlv(0x41, _POINT)) :], "are not"),
        (_tlv(0x41, b"") + _GOOD_RESPONSE[len(_tlv(0x41, _POINT)) :], "TAG_1 is present but empty"),
    ],
    ids=[
        "legacy-table-106",
        "trailing-status-word",
        "trailing-byte",
        "missing-signature",
        "empty-signature",
        "42-43-swapped",
        "chip-id-17",
        "size-4-bytes",
        "timestamp-8",
        "tag-1-twice",
        "tag-1-empty",
    ],
)
def test_parse_attested_read_response_is_strict(body: bytes, message: str) -> None:
    """GIVEN a response that deviates from [41] 42 43 44 4F 52 WHEN parsed THEN ValueError."""
    with pytest.raises(ValueError, match=message):
        parse_attested_read_response(body)


# ── Signed message and signature ─────────────────────────────────────────────────


def test_signed_message_verifies_against_the_live_signature() -> None:
    """GIVEN the capture's command and response WHEN the signed message is rebuilt THEN the SE's signature verifies.

    AND, because the simulator already sends 82 hh ll on the wire, the message equals
    SHA-256(command) followed by the response body up to the signature TLV.
    """
    command = recorded_command(_LIVE_COMMAND_WIRE)
    response = parse_attested_read_response(_LIVE_RESPONSE)

    message = signed_message(command, response)

    assert message == hashlib.sha256(command).digest() + _LIVE_RESPONSE[: -(2 + len(response.signature))]
    _live_key().verify(response.signature, message, ec.ECDSA(hashes.SHA256()))


def test_signed_message_leaves_out_a_missing_tag_1() -> None:
    """GIVEN the capture's response without TAG_1 WHEN the signed message is rebuilt THEN the signature verifies."""
    response = parse_attested_read_response(_LIVE_NO_VALUE_RESPONSE)

    message = signed_message(_LIVE_NO_VALUE_COMMAND, response)

    assert message[32:36] == bytes.fromhex("42820012")
    _live_key().verify(response.signature, message, ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize(
    "tamper",
    ["freshness", "timestamp", "chip_id", "value-dropped", "wire-short-form"],
)
def test_signed_message_detects_tampering(tamper: str) -> None:
    """GIVEN the capture with one input changed WHEN verified THEN InvalidSignature."""
    command = recorded_command(_LIVE_COMMAND_WIRE)
    response = parse_attested_read_response(_LIVE_RESPONSE)
    if tamper == "freshness":
        message = signed_message(command[:-1] + bytes((command[-1] ^ 1,)), response)
    elif tamper == "timestamp":
        message = signed_message(command, dataclasses.replace(response, timestamp=bytes(12)))
    elif tamper == "chip_id":
        message = signed_message(command, dataclasses.replace(response, chip_id=bytes(18)))
    elif tamper == "value-dropped":
        message = signed_message(command, dataclasses.replace(response, value=None))
    else:
        assert response.value is not None
        short_form = (
            _tlv(0x41, response.value)
            + _tlv(0x42, response.chip_id)
            + _tlv(0x43, response.attributes)
            + _tlv(0x44, _SIZE)
            + _tlv(0x4F, response.timestamp)
        )
        message = hashlib.sha256(command).digest() + short_form

    with pytest.raises(InvalidSignature):
        _live_key().verify(response.signature, message, ec.ECDSA(hashes.SHA256()))


# ── Attributes ───────────────────────────────────────────────────────────────────


def test_parse_attributes_reads_the_live_key_pair_attributes() -> None:
    """GIVEN the capture's TAG_3 for an SE-generated P-256 key pair WHEN parsed THEN id, type 0x29, origin 0x02."""
    attributes = parse_attributes(parse_attested_read_response(_LIVE_RESPONSE).attributes)

    assert attributes == ObjectAttributes(
        object_id=_LIVE_OBJECT_ID,
        type_code=TYPE_EC_KEY_PAIR_NIST_P256,
        policies=(),
        origin=ORIGIN_INTERNAL,
    )


def test_parse_attributes_reads_a_live_policy_entry() -> None:
    """GIVEN the capture's TAG_3 with one policy entry WHEN parsed THEN (auth object, AR header) and origin."""
    attributes = parse_attributes(parse_attested_read_response(_LIVE_NO_VALUE_RESPONSE).attributes)

    assert attributes.object_id == 0x10AA0003
    assert attributes.policies == ((0x00000000, POLICY_ALLOW_SIGN | POLICY_ALLOW_DELETE),)
    assert attributes.origin == ORIGIN_INTERNAL


@pytest.mark.parametrize("trailer", [b"", bytes(4)], ids=["no-trailer", "version-trailer"])
def test_parse_attributes_accepts_a_block_without_policy_entries(trailer: bytes) -> None:
    """GIVEN 14 fixed bytes, no policy entry and the origin WHEN parsed THEN no policies; the trailer is ignored."""
    block = bytes.fromhex("7f000101 29 01 0000 00000000 0000 02") + trailer

    assert parse_attributes(block) == ObjectAttributes(
        object_id=0x7F000101,
        type_code=0x29,
        policies=(),
        origin=0x02,
    )


def test_parse_attributes_keeps_several_policy_entries_and_skips_their_extensions() -> None:
    """GIVEN two policy entries, one with extension bytes WHEN parsed THEN both pairs in order."""
    block = (
        bytes.fromhex("7f000101 29 01 0000 00000000 0000")
        + bytes.fromhex("0a 00000001 10200000 aabb")
        + bytes.fromhex("08 00000002 00040000")
        + b"\x02"
    )

    assert parse_attributes(block).policies == ((1, 0x10200000), (2, 0x00040000))


@pytest.mark.parametrize(
    ("hex_block", "message"),
    [
        ("7f000101 29 01 0000 00000000 0000", "before the origin"),
        ("7f000101 29 01 0000 00000000 0000 08 00000000 10240000", "before the origin"),
        ("7f000101 29 01 0000 00000000 0000 08 000000", "runs past"),
        ("7f000101 29 01", "before the origin"),
    ],
    ids=["no-origin", "policy-then-no-origin", "policy-overrun", "short-header"],
)
def test_parse_attributes_rejects_a_truncated_block(hex_block: str, message: str) -> None:
    """GIVEN an attribute block that ends too early WHEN parsed THEN ValueError."""
    with pytest.raises(ValueError, match=message):
        parse_attributes(bytes.fromhex(hex_block))


# ── Se05xAttestEvidence ──────────────────────────────────────────────────────────


def test_se05x_attest_evidence_der_round_trip() -> None:
    """GIVEN the capture's command and response WHEN encoded and decoded THEN both byte strings survive."""
    command = recorded_command(_LIVE_COMMAND_WIRE)

    der = encode_se05x_attest_evidence(command, _LIVE_RESPONSE)
    decoded = decode_se05x_attest_evidence(der)

    assert der == encode_to_der(prepare_se05x_attest_evidence(command, _LIVE_RESPONSE))
    assert der[0] == 0x30
    assert bytes(decoded["commandApdu"]) == command
    assert bytes(decoded["responseBody"]) == _LIVE_RESPONSE
    assert encode_to_der(decoded) == der


@pytest.mark.parametrize(
    "der",
    [
        encode_se05x_attest_evidence(b"\x01", b"\x02") + b"\x00",
        bytes.fromhex("3003040101"),
        bytes.fromhex("30090401010401020401ff"),
        encode_to_der(univ.OctetString(b"\x01")),
        bytes.fromhex("300604010102010a"),
    ],
    ids=["trailing-byte", "one-field", "three-fields", "not-a-sequence", "integer-field"],
)
def test_decode_se05x_attest_evidence_is_strict(der: bytes) -> None:
    """GIVEN DER that is not exactly one Se05xAttestEvidence WHEN decoded THEN ValueError."""
    with pytest.raises(ValueError, match="Se05xAttestEvidence"):
        decode_se05x_attest_evidence(der)

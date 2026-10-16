# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Byte-level codec for the SE05x applet-7.2 attested ``ReadObject``.

Stdlib only. The wire format (AN12413 Table 105; AN13254 §3.1; NXP Plug & Trust
``Se05x_API_ReadObject_W_Attst_V2``)::

    command   80 22 00 00 | 00 Lc_hi Lc_lo | 41 04 objId | 45 04 attestKeyId
              | 46 01 algo | 47 10 freshness | 00 00
    recorded  the command without its Le 00 00: what the SE hashes, and what
              Se05xAttestEvidence.commandApdu carries
    response  [41 value] 42 chipId(18) 43 attributes 44 size(2) 4F timestamp(12)
              52 signature(DER), then SW 90 00 (not part of the body)
    signed    SHA-256(recorded) || [41 82 hh ll value] || 42 82 hh ll chipId
              || 43 82 hh ll attributes || 44 82 00 02 size || 4F 82 00 0C timestamp

The SE signs ``signed`` with ECDSA; the signature is a DER ``Ecdsa-Sig-Value``.
The signed TLVs always use the ``82 hh ll`` length form, whatever form the wire
used, so a verifier re-encodes them and never hashes the wire bytes. ``TAG_1`` is
signed only when the SE returned it (wolfSSL's rule): an object without
``ALLOW_READ`` has no value in the response. The freshness is the RA nonce
itself, exactly 16 bytes; the SE's signature covers it through the command hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

INS_READ_ATTEST = 0x22  # INS_READ 0x02 | INS_ATTEST 0x20
_HEADER = bytes((0x80, INS_READ_ATTEST, 0x00, 0x00))
_LE_EXTENDED = b"\x00\x00"

# TLV tags (AN12413 Table 105; P&T ``SE05x_TAG_t``).
TAG_1 = 0x41
TAG_2 = 0x42
TAG_3 = 0x43
TAG_4 = 0x44
TAG_5 = 0x45
TAG_6 = 0x46
TAG_7 = 0x47
TAG_TIMESTAMP = 0x4F
TAG_SIGNATURE = 0x52

# Object ids of the demo SE (AN12436 Table 15 for the attestation key and chip id).
ATTEST_KEY_ID = 0xF0000012
CERT_OBJECT_ID = 0xF0000013
UNIQUE_ID_OBJECT_ID = 0x7FFF0206

ALGO_ECDSA_SHA256 = 0x21  # AttestationAlgo / ECSignatureAlgo SIG_ECDSA_SHA_256
FRESHNESS_LEN = 16
ORIGIN_INTERNAL = 0x02  # generated inside the SE (AN12413 Table 26)
TYPE_EC_KEY_PAIR_NIST_P256 = 0x29  # applet-7.2 SecureObjectType
P256_KEY_SIZE = 0x0020  # TAG_4 of a P-256 key: the curve size in bytes

# Access-rule header bits (AN12413 Table 7; P&T ``se05x_const.h``).
POLICY_ALLOW_SIGN = 0x10000000
POLICY_ALLOW_VERIFY = 0x08000000
POLICY_ALLOW_READ = 0x00200000
POLICY_ALLOW_DELETE = 0x00040000
POLICY_ALLOW_ATTESTATION = 0x00008000

_CHIP_ID_LEN = 18
_OBJECT_SIZE_LEN = 2
_TIMESTAMP_LEN = 12
_ATTR_FIXED_LEN = 14  # object id 4 | type 1 | auth indicator 1 | 2 | owner 4 | 2
_POLICY_MIN_LEN = 8  # authObjId 4 | AR header 4 | extension 0..36
_RESPONSE_TAGS = [TAG_2, TAG_3, TAG_4, TAG_TIMESTAMP, TAG_SIGNATURE]


@dataclass(frozen=True)
class AttestedReadCommand:
    """The fields of a recorded attested-read command."""

    object_id: int
    attest_key_id: int
    algo: int
    freshness: bytes


@dataclass(frozen=True)
class AttestedReadResponse:
    """The fields of an attested-read response body; ``value`` is ``None`` when ``TAG_1`` was left out."""

    value: bytes | None
    chip_id: bytes
    attributes: bytes
    object_size: int
    timestamp: bytes
    signature: bytes


@dataclass(frozen=True)
class ObjectAttributes:
    """The attribute fields a verifier relies on; ``policies`` holds ``(auth_object_id, ar_header)`` pairs."""

    object_id: int
    type_code: int
    policies: tuple[tuple[int, int], ...]
    origin: int


def encode_tlv(tag: int, value: bytes, *, extended: bool = False) -> bytes:
    """Encode one TLV.

    The length is one byte below 128 and ``82 hh ll`` otherwise; *extended* forces
    ``82 hh ll``, the form the SE signs. ``81 ll`` is never emitted: the simulator's
    parser refuses it, and the SE accepts ``82 hh ll`` for any length
    (AN12413 §4.1.3.2).

    Raises
    ------
    ValueError
        If *value* is longer than 65535 bytes.

    """
    length = len(value)
    if length > 0xFFFF:
        raise ValueError(f"TLV {tag:02X}: {length} bytes do not fit the 82 hh ll length form")
    if length < 0x80 and not extended:
        return bytes((tag, length)) + value
    return bytes((tag, 0x82)) + length.to_bytes(2, "big") + value


def decode_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    """Split *data* into ``(tag, value)`` pairs, in order.

    Accepts the short, ``81 ll`` and ``82 hh ll`` length forms, minimal or not
    (AN12413 §4.1.3.2: an R-APDU may use ``82 hh ll`` below 128 bytes).

    Raises
    ------
    ValueError
        On a truncated header or value, or any other length form.

    """
    tlvs: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError(f"TLV at offset {offset}: truncated header")
        tag, first = data[offset], data[offset + 1]
        offset += 2
        if first < 0x80:
            length = first
        elif first in (0x81, 0x82):
            width = first & 0x7F
            if offset + width > len(data):
                raise ValueError(f"TLV {tag:02X}: truncated length")
            length = int.from_bytes(data[offset : offset + width], "big")
            offset += width
        else:
            raise ValueError(f"TLV {tag:02X}: unsupported length byte {first:02X}")
        if offset + length > len(data):
            raise ValueError(f"TLV {tag:02X}: value runs past the end of the data")
        tlvs.append((tag, bytes(data[offset : offset + length])))
        offset += length
    return tlvs


def build_attested_read(
    object_id: int,
    freshness: bytes,
    *,
    attest_key_id: int = ATTEST_KEY_ID,
    algo: int = ALGO_ECDSA_SHA256,
) -> bytes:
    """Return the wire APDU that reads *object_id* with attestation.

    The APDU has an extended Lc and the extended Le ``00 00``, as NXP's middleware
    sends it. Short Lc is never used: what an SE hashes for it is undocumented.

    Raises
    ------
    ValueError
        If *freshness* is not exactly 16 bytes.

    """
    if len(freshness) != FRESHNESS_LEN:
        raise ValueError(f"SE05x freshness must be {FRESHNESS_LEN} bytes, got {len(freshness)}")
    data = (
        encode_tlv(TAG_1, object_id.to_bytes(4, "big"))
        + encode_tlv(TAG_5, attest_key_id.to_bytes(4, "big"))
        + encode_tlv(TAG_6, bytes((algo,)))
        + encode_tlv(TAG_7, freshness)
    )
    return _HEADER + b"\x00" + len(data).to_bytes(2, "big") + data + _LE_EXTENDED


def recorded_command(apdu: bytes) -> bytes:
    """Return *apdu* without its Le: the bytes the SE hashes.

    Raises
    ------
    ValueError
        Unless *apdu* has an extended Lc that matches its data and ends in Le ``00 00``.

    """
    if len(apdu) < 9 or apdu[4] != 0 or apdu[-2:] != _LE_EXTENDED or int.from_bytes(apdu[5:7], "big") != len(apdu) - 9:
        raise ValueError("not an extended-length command APDU ending in Le 00 00")
    return bytes(apdu[:-2])


def parse_attested_read_command(cmd: bytes) -> AttestedReadCommand:
    """Parse a recorded attested-read command strictly.

    Accepts only the header ``80 22 00 00``, an extended Lc equal to the data length
    (so no Le), and exactly the TLVs ``41 45 46 47`` in that order with value lengths
    4, 4, 1 and 16: the key-pair read that NXP's middleware sends.

    Raises
    ------
    ValueError
        On any other shape.

    """
    if cmd[:4] != _HEADER:
        raise ValueError(f"command header {cmd[:4].hex()} is not 80220000")
    if len(cmd) < 7 or cmd[4] != 0:
        raise ValueError("command does not use an extended Lc")
    if int.from_bytes(cmd[5:7], "big") != len(cmd) - 7:
        raise ValueError("Lc does not match the data length (Le present or data truncated)")
    tlvs = decode_tlvs(cmd[7:])
    tags = [tag for tag, _ in tlvs]
    if tags != [TAG_1, TAG_5, TAG_6, TAG_7]:
        raise ValueError(f"command TLVs {bytes(tags).hex(' ')} are not 41 45 46 47")
    (_, object_id), (_, attest_key_id), (_, algo), (_, freshness) = tlvs
    if len(object_id) != 4 or len(attest_key_id) != 4 or len(algo) != 1:
        raise ValueError("object id, attestation key id or algorithm has the wrong length")
    if len(freshness) != FRESHNESS_LEN:
        raise ValueError(f"freshness must be {FRESHNESS_LEN} bytes, got {len(freshness)}")
    return AttestedReadCommand(
        object_id=int.from_bytes(object_id, "big"),
        attest_key_id=int.from_bytes(attest_key_id, "big"),
        algo=algo[0],
        freshness=freshness,
    )


def parse_attested_read_response(body: bytes) -> AttestedReadResponse:
    """Parse an applet-7.2 attested-read response body strictly.

    The TLVs must be exactly ``[41] 42 43 44 4F 52`` in that order, with a non-empty
    ``TAG_1`` when present, an 18-byte chip id, a 2-byte object size and a 12-byte
    timestamp, and nothing after the signature. This rejects the legacy applet-3.x layout and a trailing status word.

    Raises
    ------
    ValueError
        On any other shape.

    """
    tlvs = decode_tlvs(body)
    value = tlvs.pop(0)[1] if tlvs and tlvs[0][0] == TAG_1 else None
    if value == b"":
        # P&T would sign it as 41 82 00 00, wolfSSL would skip it: no single signed form.
        raise ValueError("response TAG_1 is present but empty")
    tags = [tag for tag, _ in tlvs]
    if tags != _RESPONSE_TAGS:
        raise ValueError(f"response TLVs {bytes(tags).hex(' ')} are not [41] 42 43 44 4f 52")
    (_, chip_id), (_, attributes), (_, object_size), (_, timestamp), (_, signature) = tlvs
    if len(chip_id) != _CHIP_ID_LEN or len(object_size) != _OBJECT_SIZE_LEN or len(timestamp) != _TIMESTAMP_LEN:
        raise ValueError("chip id, object size or timestamp has the wrong length")
    if not signature:
        raise ValueError("response signature is empty")
    return AttestedReadResponse(
        value=value,
        chip_id=chip_id,
        attributes=attributes,
        object_size=int.from_bytes(object_size, "big"),
        timestamp=timestamp,
        signature=signature,
    )


def signed_message(command: bytes, response: AttestedReadResponse) -> bytes:
    """Return the bytes the SE signs for *command* (recorded, no Le) and *response*.

    ``SHA-256(command)`` followed by the response TLVs re-encoded with ``82 hh ll``;
    ``TAG_1`` only when present. Verify the signature over it with ECDSA and SHA-256.
    """
    # ponytail: SHA-256 only (algo 0x21); pick the hash from TAG_6 when 0x22/0x26 are accepted.
    parts = [hashlib.sha256(command).digest()]
    if response.value is not None:
        parts.append(encode_tlv(TAG_1, response.value, extended=True))
    parts += [
        encode_tlv(TAG_2, response.chip_id, extended=True),
        encode_tlv(TAG_3, response.attributes, extended=True),
        encode_tlv(TAG_4, response.object_size.to_bytes(_OBJECT_SIZE_LEN, "big"), extended=True),
        encode_tlv(TAG_TIMESTAMP, response.timestamp, extended=True),
    ]
    return b"".join(parts)


def parse_attributes(attributes: bytes) -> ObjectAttributes:
    """Parse the object id, type, policies and origin out of a ``TAG_3`` attribute block.

    Layout: 14 fixed bytes (object id 4, type 1, then 9 bytes not interpreted here),
    then zero or more policy entries ``len(1) || authObjId(4) || AR header(4) || ext``
    with ``len >= 8``, then the origin byte. Bytes after the origin are ignored, as
    wolfSSL does: PR #19 appends a 4-byte object version that no NXP document
    confirms.

    Raises
    ------
    ValueError
        If the block ends before the origin or a policy entry runs past its end.

    """
    offset = _ATTR_FIXED_LEN
    policies: list[tuple[int, int]] = []
    while offset < len(attributes) and attributes[offset] >= _POLICY_MIN_LEN:
        entry_len = attributes[offset]
        if offset + 1 + entry_len > len(attributes):
            raise ValueError("policy entry runs past the end of the attributes")
        entry = attributes[offset + 1 : offset + 1 + entry_len]
        policies.append((int.from_bytes(entry[:4], "big"), int.from_bytes(entry[4:8], "big")))
        offset += 1 + entry_len
    if offset >= len(attributes):
        raise ValueError("attributes end before the origin byte")
    return ObjectAttributes(
        object_id=int.from_bytes(attributes[:4], "big"),
        type_code=attributes[4],
        policies=tuple(policies),
        origin=attributes[offset],
    )


__all__ = [
    "ALGO_ECDSA_SHA256",
    "ATTEST_KEY_ID",
    "CERT_OBJECT_ID",
    "FRESHNESS_LEN",
    "INS_READ_ATTEST",
    "ORIGIN_INTERNAL",
    "P256_KEY_SIZE",
    "POLICY_ALLOW_ATTESTATION",
    "POLICY_ALLOW_DELETE",
    "POLICY_ALLOW_READ",
    "POLICY_ALLOW_SIGN",
    "POLICY_ALLOW_VERIFY",
    "TAG_1",
    "TAG_2",
    "TAG_3",
    "TAG_4",
    "TAG_5",
    "TAG_6",
    "TAG_7",
    "TAG_SIGNATURE",
    "TAG_TIMESTAMP",
    "TYPE_EC_KEY_PAIR_NIST_P256",
    "UNIQUE_ID_OBJECT_ID",
    "AttestedReadCommand",
    "AttestedReadResponse",
    "ObjectAttributes",
    "build_attested_read",
    "decode_tlvs",
    "encode_tlv",
    "parse_attested_read_command",
    "parse_attested_read_response",
    "parse_attributes",
    "recorded_command",
    "signed_message",
]

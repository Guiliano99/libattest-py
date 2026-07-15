# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""RATS Conceptual Message Wrapper (CMW) codecs.

CMW is the reusable serialization layer shared by PKIX extensions and
attestation-statement payloads.  Its DER encoding selects either a JSON
``UTF8String`` or a CBOR ``OCTET STRING`` payload.

ref: https://datatracker.ietf.org/doc/draft-ietf-rats-msg-wrap/
version: 23

"""

from __future__ import annotations

import json
from io import BytesIO

import cbor2
from pyasn1.type import char, namedtype, univ

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1

#: ``id-pe-cmw`` OID: the PKIX certificate-extension OID under which a CMW is carried
#: (draft-ietf-rats-msg-wrap §5). Do not import this constant directly to reference the
#: OID elsewhere — go through the OID accessors (e.g. ``get_oid_by_name("cmw")``); see the
#: README "OID access" note.
ID_PE_CMW: univ.ObjectIdentifier = univ.ObjectIdentifier("1.3.6.1.5.5.7.1.35")


class CMW(univ.Choice):
    """``CMW ::= CHOICE { json UTF8String, cbor OCTET STRING }``."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("json", char.UTF8String()),
        namedtype.NamedType("cbor", univ.OctetString()),
    )


def encode_cmw_json_record(
    media_type: str | int,
    value: str | bytes,
    cmw_type: int | None = None,
    *,
    cbor: bool = False,
) -> bytes:
    """Return ``DER(CMW)`` for a JSON or CBOR Record CMW.

    ``cbor=False`` preserves the existing JSON-record behavior: *media_type*
    and *value* must be text and are encoded as compact JSON in CMW's ``json``
    alternative.  With ``cbor=True``, *value* must be raw bytes and the record
    is CBOR-encoded in CMW's ``cbor`` alternative.  In particular, COSE bytes
    are not base64url-encoded for the CBOR form.
    """
    cmw = CMW()

    if cbor:
        _validate_cmw_record_labels(media_type, cmw_type, cbor=True)
        if not isinstance(value, bytes):
            raise TypeError("a CMW CBOR record value must be bytes")
        record = [media_type, value] if cmw_type is None else [media_type, value, cmw_type]
        cmw["cbor"] = cbor2.dumps(record)
    else:
        _validate_cmw_record_labels(media_type, cmw_type, cbor=False)
        if not isinstance(media_type, str) or not isinstance(value, str):
            raise TypeError("a CMW JSON record media type and value must be strings")
        record = [media_type, value] if cmw_type is None else [media_type, value, cmw_type]
        cmw["json"] = json.dumps(record, separators=(",", ":"))

    return encode_to_der(cmw)


def decode_cmw_json_record(der: bytes) -> tuple[str, str, int | None]:
    """Decode a CMW JSON Record from ``DER(CMW)``."""
    cmw = try_decode_pyasn1(der, CMW)
    if cmw.getName() != "json":
        raise ValueError("CMW is not a json record (expected the UTF8String alternative)")
    record = json.loads(str(cmw["json"]))
    if not isinstance(record, list) or len(record) not in (2, 3):
        raise ValueError(f"malformed CMW json record: {record!r}")
    if not isinstance(record[0], str) or not isinstance(record[1], str):
        raise ValueError(f"malformed CMW json record: {record!r}")
    if len(record) == 3 and not _is_cmw_integer(record[2]):
        raise ValueError(f"malformed CMW json record: {record!r}")
    return record[0], record[1], record[2] if len(record) == 3 else None


def decode_cmw_cbor_record(der: bytes) -> tuple[str | int, bytes, int | None]:
    """Decode a CMW CBOR Record from ``DER(CMW)``."""
    cmw = try_decode_pyasn1(der, CMW)
    if cmw.getName() != "cbor":
        raise ValueError("CMW is not a cbor record (expected the OCTET STRING alternative)")
    encoded_record = BytesIO(bytes(cmw["cbor"]))
    try:
        record = cbor2.load(encoded_record)
    except (cbor2.CBORDecodeError, ValueError, TypeError) as exc:
        raise ValueError("malformed CMW cbor record") from exc
    if encoded_record.read(1):
        raise ValueError("CMW cbor record contains trailing bytes")
    if not isinstance(record, list) or len(record) not in (2, 3):
        raise ValueError(f"malformed CMW cbor record: {record!r}")
    if not isinstance(record[0], (str, int)) or isinstance(record[0], bool) or not isinstance(record[1], bytes):
        raise ValueError(f"malformed CMW cbor record: {record!r}")
    if len(record) == 3 and not _is_cmw_integer(record[2]):
        raise ValueError(f"malformed CMW cbor record: {record!r}")
    return record[0], record[1], record[2] if len(record) == 3 else None


def _validate_cmw_record_labels(media_type: object, cmw_type: object, *, cbor: bool) -> None:
    """Reject values the paired CMW decoder cannot represent safely."""
    if cbor:
        if not isinstance(media_type, (str, int)) or isinstance(media_type, bool):
            raise TypeError("a CMW CBOR record media type must be a string or integer")
    elif not isinstance(media_type, str):
        raise TypeError("a CMW JSON record media type must be a string")
    if cmw_type is not None and not _is_cmw_integer(cmw_type):
        record_format = "CBOR" if cbor else "JSON"
        raise TypeError(f"a CMW {record_format} record type must be an integer")


def _is_cmw_integer(value: object) -> bool:
    """Return whether *value* is an integer label, excluding Python booleans."""
    return isinstance(value, int) and not isinstance(value, bool)


__all__ = [
    "CMW",
    "ID_PE_CMW",
    "decode_cmw_cbor_record",
    "decode_cmw_json_record",
    "encode_cmw_json_record",
]

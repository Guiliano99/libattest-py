# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Helpers for ASN.1 ``{ type OBJECT IDENTIFIER, value UTF8String }`` payloads.

Several attestation-freshness profile values use an ASN.1 wrapper so CMP / CMC
implementations can handle the outer type with normal ASN.1 tooling while the
profile-specific content remains JSON text.
"""

from __future__ import annotations

import json
import os
from typing import Any, Mapping, TypeVar

from pyasn1.type import char, namedtype, univ

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1


def resolve_env_oid(env_name: str, default: str) -> str:
    """Return the OID from ``env_name`` (stripped) or *default* if unset/blank."""
    value = os.environ.get(env_name)
    if value is not None and value.strip():
        return value.strip()
    return default


class OidUtf8Json(univ.Sequence):
    """Generic schema: ``SEQUENCE { type OBJECT IDENTIFIER, value UTF8String }``."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType("value", char.UTF8String()),
    )


OidJsonT = TypeVar("OidJsonT", bound=OidUtf8Json)


def canonical_json(data: Mapping[str, Any]) -> str:
    """Return deterministic compact JSON for ASN.1 UTF8String transport."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def prepare_oid_json_value(schema: type[OidJsonT], oid: str, payload: Mapping[str, Any]) -> OidJsonT:
    """Instantiate *schema* and populate its OID and JSON payload."""
    value = schema()
    value["type"] = univ.ObjectIdentifier(oid)
    value["value"] = canonical_json(payload)
    return value


def decode_oid_json_value(value: univ.Sequence, *, expected_oid: str, name: str) -> dict[str, Any]:
    """Validate OID and decode the JSON payload from a parsed ASN.1 value."""
    oid = str(value["type"])
    if oid != expected_oid:
        raise ValueError(f"{name}: unexpected type OID {oid}, expected {expected_oid}")

    try:
        payload = json.loads(str(value["value"]))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name}: value is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{name}: JSON value must be an object")
    return payload


def encode_oid_json_der(schema: type[OidUtf8Json], oid: str, payload: Mapping[str, Any]) -> bytes:
    """DER-encode a typed OID + UTF8String JSON value."""
    return encode_to_der(prepare_oid_json_value(schema, oid, payload))


def decode_oid_json_der(
    der: bytes | bytearray | univ.Any, schema: OidUtf8Json, *, expected_oid: str, name: str
) -> dict[str, Any]:
    """DER-decode a typed OID + UTF8String JSON value and return its payload."""
    decoded = try_decode_pyasn1(der, schema)
    return decode_oid_json_value(decoded, expected_oid=expected_oid, name=name)


__all__ = [
    "OidJsonT",
    "OidUtf8Json",
    "canonical_json",
    "decode_oid_json_der",
    "decode_oid_json_value",
    "encode_oid_json_der",
    "prepare_oid_json_value",
    "resolve_env_oid",
]

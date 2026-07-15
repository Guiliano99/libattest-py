# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""ASN.1 syntax and OID for the EAR certificate extension.

The extension value is the DER encoding of ``EARExtension``, whose wire syntax
is a single ``UTF8String`` containing the compact EAR JWT. The extension OID
is carried by the surrounding X.509 ``Extension`` and is therefore not part of
the ASN.1 value itself.
"""

from __future__ import annotations

from pyasn1.type import char, univ

from libattest.asn1_utils import encode_to_der
from libattest.formats._oid_json import resolve_env_oid

# Format-owned default OID. ``EAR_OID`` can override it for a deployment before
# the format registry is imported. Code outside ``libattest.formats`` resolves
# this value through the named accessors in ``libattest`` rather than importing
# the raw constant.
EAR_EXTENSION_OID_ENV: str = "EAR_OID"
EAR_EXTENSION_OID_DEFAULT: str = "1.7.6.5.123"
EAR_EXTENSION_OID: str = resolve_env_oid(EAR_EXTENSION_OID_ENV, EAR_EXTENSION_OID_DEFAULT)
id_ear_extension: univ.ObjectIdentifier = univ.ObjectIdentifier(EAR_EXTENSION_OID)

# Backwards-compatible names retained for callers that used the initial
# deployment-only constant or the project's uppercase OID naming convention.
DEMO_EAR_EXTENSION_OID: str = EAR_EXTENSION_OID
ID_EAR_EXTENSION: univ.ObjectIdentifier = id_ear_extension


class EARExtension(char.UTF8String):
    """EAR certificate-extension value encoded as an ASN.1 ``UTF8String``."""


def prepare_ear_extension(ear_jwt: str) -> EARExtension:
    """Build an :class:`EARExtension` from a compact-serialised EAR JWT.

    Parameters
    ----------
    ear_jwt:
        The EAR JWT text to carry in the extension.

    Returns
    -------
    EARExtension
        A populated UTF8String value. Use :func:`encode_to_der` when the
        extension's ``extnValue`` bytes are required.

    Raises
    ------
    TypeError
        If *ear_jwt* is not text.

    """
    if not isinstance(ear_jwt, str):
        raise TypeError("EAR extension value must be a string")
    return EARExtension(ear_jwt)


def encode_ear_extension_value(ear_jwt: str) -> bytes:
    """DER-encode an EAR JWT as an ``EARExtension`` UTF8String value."""
    return encode_to_der(prepare_ear_extension(ear_jwt))


__all__ = [
    "DEMO_EAR_EXTENSION_OID",
    "EAR_EXTENSION_OID",
    "EAR_EXTENSION_OID_DEFAULT",
    "EAR_EXTENSION_OID_ENV",
    "EARExtension",
    "ID_EAR_EXTENSION",
    "encode_ear_extension_value",
    "id_ear_extension",
    "prepare_ear_extension",
]

# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Media-type helpers for EAT-based RATS payloads.

References
----------
RFC 9782: Entity Attestation Token (EAT) Media Types
  https://www.rfc-editor.org/rfc/rfc9782
"""

from __future__ import annotations

EAT_CWT = "application/eat+cwt"
EAT_JWT = "application/eat+jwt"
EAT_BUNDLE_CBOR = "application/eat-bun+cbor"
EAT_BUNDLE_JSON = "application/eat-bun+json"
# Unsigned CWT Claim Set (CBOR encoding, RFC 9782 §2.1.5)
EAT_UCS_CBOR = "application/eat-ucs+cbor"
# Unsigned JSON Claim Set (JSON encoding, RFC 9782 §2.1.5)
EAT_UCS_JSON = "application/eat-ucs+json"

# Backward-compatible aliases using older (misleading) UCCS/UJCS names
EAT_UCCS_CBOR = EAT_UCS_CBOR
EAT_UJCS_JSON = EAT_UCS_JSON

RFC9782_EAT_MEDIA_TYPES = frozenset(
    {
        EAT_CWT,
        EAT_JWT,
        EAT_BUNDLE_CBOR,
        EAT_BUNDLE_JSON,
        EAT_UCS_CBOR,
        EAT_UCS_JSON,
    }
)


def base_media_type(media_type: str) -> str:
    """Return the lowercase type/subtype without media-type parameters."""
    return media_type.split(";", 1)[0].strip().lower()


def is_eat_media_type(media_type: str) -> bool:
    """Return whether ``media_type`` is one of the RFC 9782 EAT types."""
    return base_media_type(media_type) in RFC9782_EAT_MEDIA_TYPES


def with_eat_profile(media_type: str, eat_profile: str | None) -> str:
    """Attach an RFC 9782 ``eat_profile`` parameter when one is supplied.

    Numeric OID arc values are left unquoted per the RFC; all other profile
    strings are double-quoted with internal double-quotes escaped.
    """
    if eat_profile is None:
        return media_type
    if eat_profile.replace(".", "").isdigit():
        return f"{media_type}; eat_profile={eat_profile}"
    escaped = eat_profile.replace("\\", "\\\\").replace('"', '\\"')
    return f'{media_type}; eat_profile="{escaped}"'

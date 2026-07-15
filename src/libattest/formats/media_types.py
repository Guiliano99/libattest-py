# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Media types used by attestation formats and verifier endpoints.

This module is the single source of truth for media-type constants used by
libattest. Format-specific helpers live here as well so callers do not need to
know which format package originally introduced a media type.

References
----------
RFC 9782: Entity Attestation Token (EAT) Media Types
  https://www.rfc-editor.org/rfc/rfc9782

"""

from __future__ import annotations

# EAT media types from RFC 9782.
EAT_CWT = "application/eat+cwt"
EAT_JWT = "application/eat+jwt"
EAT_BUNDLE_CBOR = "application/eat-bun+cbor"
EAT_BUNDLE_JSON = "application/eat-bun+json"
# Unsigned CWT Claim Set (CBOR encoding, RFC 9782 section 2.1.5).
EAT_UCS_CBOR = "application/eat-ucs+cbor"
# Unsigned JSON Claim Set (JSON encoding, RFC 9782 section 2.1.5).
EAT_UCS_JSON = "application/eat-ucs+json"

# Existing names retained for callers using the older UCCS/UJCS terminology.
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


# CMW payload media types used by the JOSE and COSE HPKE bridges.
CMW_MEDIA_JOSE = "application/jose"
CMW_MEDIA_COSE = "application/cose"

# TPM platform attestation media type.
TPM_PLATFORM_MEDIA_TYPE = "application/vnd.tcg.platform"

# Verifier endpoint media types.
SESSION_MEDIA_TYPE = "application/vnd.veraison.challenge-response-session+json"
PROVISIONING_MEDIA_TYPE = "application/vnd.veraison.provisioning-session+json"
CORIM_MEDIA_TYPE = "application/rim+cbor"


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


__all__ = [
    "CMW_MEDIA_COSE",
    "CMW_MEDIA_JOSE",
    "CORIM_MEDIA_TYPE",
    "EAT_BUNDLE_CBOR",
    "EAT_BUNDLE_JSON",
    "EAT_CWT",
    "EAT_JWT",
    "EAT_UCCS_CBOR",
    "EAT_UCS_CBOR",
    "EAT_UCS_JSON",
    "EAT_UJCS_JSON",
    "PROVISIONING_MEDIA_TYPE",
    "RFC9782_EAT_MEDIA_TYPES",
    "SESSION_MEDIA_TYPE",
    "TPM_PLATFORM_MEDIA_TYPE",
    "base_media_type",
    "is_eat_media_type",
    "with_eat_profile",
]

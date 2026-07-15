# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""X.509 helpers for libattest.

Exposes the Conceptual Messages Wrapper (CMW) extension defined in
:rfc-draft:`draft-ietf-rats-msg-wrap-23` and the EAR extension encoding.

See :mod:`libattest.x509.extensions` for X.509 OIDs and validation helpers.
The reusable CMW ASN.1 schema and codecs live in :mod:`libattest.formats.cmw`.
"""

from libattest.formats.cmw import CMW, decode_cmw_json_record, encode_cmw_json_record
from libattest.x509.extensions import (
    CMWCriticalityWarning,
    encode_ear_extension,
    parse_cmw_extension_value,
    unwrap_context_tag,
    validate_cmw_extension,
    warn_if_cmw_critical,
    wrap_ear_in_cmw_json,
)

__all__ = [
    "CMW",
    "CMWCriticalityWarning",
    "decode_cmw_json_record",
    "encode_cmw_json_record",
    "encode_ear_extension",
    "parse_cmw_extension_value",
    "unwrap_context_tag",
    "validate_cmw_extension",
    "warn_if_cmw_critical",
    "wrap_ear_in_cmw_json",
]

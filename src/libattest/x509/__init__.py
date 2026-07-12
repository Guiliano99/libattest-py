# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""X.509 helpers for libattest.

Exposes the Conceptual Messages Wrapper (CMW) extension defined in
:rfc-draft:`draft-ietf-rats-msg-wrap-23` and the EAR extension encoding.

See :mod:`libattest.x509.extensions` for OIDs, ASN.1 schemas, and
validation helpers.
"""

from libattest.x509.extensions import (
    CMW,
    ID_PE_CMW,
    ID_PE_CMW_DOTTED,
    CMWCriticalityWarning,
    decode_cmw_json_record,
    encode_cmw_json_record,
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
    "ID_PE_CMW",
    "ID_PE_CMW_DOTTED",
    "decode_cmw_json_record",
    "encode_cmw_json_record",
    "encode_ear_extension",
    "parse_cmw_extension_value",
    "unwrap_context_tag",
    "validate_cmw_extension",
    "warn_if_cmw_critical",
    "wrap_ear_in_cmw_json",
]

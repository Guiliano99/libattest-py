# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""X.509 helpers for libattest.

Exposes:

* The Conceptual Messages Wrapper (CMW) extension defined in
  :rfc-draft:`draft-ietf-rats-msg-wrap-23`.
* The KeyAttestPoP extension (SPEC §DR-1, §DR-8) used by the TPM
  key-attestation PoP scheme.

See :mod:`libattest.x509.extensions` for OIDs, ASN.1 schemas, and
validation helpers.
"""

from libattest.x509.extensions import (
    CMW,
    ID_KEY_ATTEST_POP,
    ID_KEY_ATTEST_POP_DOTTED,
    ID_PE_CMW,
    ID_PE_CMW_DOTTED,
    CMWCriticalityWarning,
    KeyAttestPoPCriticalityWarning,
    decode_cmw_json_record,
    encode_cmw_json_record,
    encode_ear_extension,
    get_key_attest_pop_oid,
    get_key_attest_pop_oid_dotted,
    parse_cmw_extension_value,
    parse_key_attest_pop_extension_value,
    unwrap_context_tag,
    validate_cmw_extension,
    validate_key_attest_pop_extension,
    warn_if_cmw_critical,
    warn_if_key_attest_pop_critical,
    wrap_ear_in_cmw_json,
)

__all__ = [
    "CMW",
    "CMWCriticalityWarning",
    "decode_cmw_json_record",
    "encode_cmw_json_record",
    "ID_KEY_ATTEST_POP",
    "ID_KEY_ATTEST_POP_DOTTED",
    "ID_PE_CMW",
    "ID_PE_CMW_DOTTED",
    "KeyAttestPoPCriticalityWarning",
    "encode_ear_extension",
    "get_key_attest_pop_oid",
    "get_key_attest_pop_oid_dotted",
    "parse_cmw_extension_value",
    "parse_key_attest_pop_extension_value",
    "unwrap_context_tag",
    "validate_cmw_extension",
    "validate_key_attest_pop_extension",
    "warn_if_cmw_critical",
    "warn_if_key_attest_pop_critical",
    "wrap_ear_in_cmw_json",
]

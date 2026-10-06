# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""NXP EdgeLock attestation statement formats (i.MX ELE + SE05x).

Opaque ``OCTET STRING`` statement payloads for the LAMPS
``AttestationBundle`` (draft-ietf-lamps-csr-attestation-24).  The inner bytes
are NXP-native wire formats (little-endian C structs / EdgeLock TLVs) — they
are carried opaquely, keyed by statement OID, and parsed here, not by ASN.1.

Modules
-------
* :mod:`.ele_dev_attest`  — ``hsm_dev_attest`` (0xDB) 280-byte statement codec.
* :mod:`.ele_key_attest`  — ``hsm_pub_key_attest`` (0x74) EdgeLock 2GO-TLV key
  attestation certificate codec.
* :mod:`.se05x`           — SE05x attested read (AN13254) TLV codec.
* :mod:`.pretty`          — human-readable prettyPrint + debug logging.
"""

from __future__ import annotations

from libattest.formats.nxp.ele_dev_attest import (
    EleDevAttestStatement,
    canonical_signed_bytes,
    decode_ele_dev_attest,
    pretty_print_ele_dev_attest,
    verify_ele_dev_attest_signature,
)
from libattest.formats.nxp.ele_key_attest import (
    EleKeyAttestStatement,
    decode_ele_key_attest,
    pretty_print_ele_key_attest,
)
from libattest.formats.nxp.oid import (
    ELE_DEV_ATTEST_OID,
    ELE_DEV_ATTEST_OID_DEFAULT,
    ELE_KEY_ATTEST_OID,
    ELE_KEY_ATTEST_OID_DEFAULT,
    SE05X_ATTEST_OID,
    SE05X_ATTEST_OID_DEFAULT,
    resolve_ele_dev_attest_oid,
    resolve_ele_key_attest_oid,
    resolve_se05x_attest_oid,
)
from libattest.formats.nxp.pretty import (
    log_statement_debug,
    pretty_print_statement,
    pretty_print_stmt_bundle,
)
from libattest.formats.nxp.se05x import (
    Se05xAttestStatement,
    decode_se05x_attest,
    pretty_print_se05x_attest,
)
from libattest.formats.nxp.tlv import parse_tlvs, tlv

__all__ = [
    "ELE_DEV_ATTEST_OID",
    "ELE_DEV_ATTEST_OID_DEFAULT",
    "ELE_KEY_ATTEST_OID",
    "ELE_KEY_ATTEST_OID_DEFAULT",
    "EleDevAttestStatement",
    "EleKeyAttestStatement",
    "SE05X_ATTEST_OID",
    "SE05X_ATTEST_OID_DEFAULT",
    "Se05xAttestStatement",
    "canonical_signed_bytes",
    "decode_ele_dev_attest",
    "decode_ele_key_attest",
    "decode_se05x_attest",
    "parse_tlvs",
    "pretty_print_ele_dev_attest",
    "pretty_print_ele_key_attest",
    "pretty_print_se05x_attest",
    "pretty_print_statement",
    "pretty_print_stmt_bundle",
    "verify_ele_dev_attest_signature",
    "log_statement_debug",
    "resolve_ele_dev_attest_oid",
    "resolve_ele_key_attest_oid",
    "resolve_se05x_attest_oid",
    "tlv",
]

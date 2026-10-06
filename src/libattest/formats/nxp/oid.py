# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Statement OIDs for the NXP EdgeLock families.

Allocated from the demo's private enterprise ``1.3.6.1.4.1.99999`` subtree,
continuing the existing numbering (20 = COSE-HPKE, 21 = xclaim-CWT).  Each OID
selects the evidence format; the CA/RA routes by OID and the verifier parses by
OID, so a new format is pure configuration on the CA side.

Overridable via env, mirroring the existing ``resolve_*_oid`` helpers.
"""

from __future__ import annotations

import os

#: ELE device-attest statement (``hsm_dev_attest``, 0xDB) — 280-byte LE struct.
ELE_DEV_ATTEST_OID_DEFAULT = "1.3.6.1.4.1.99999.30"

#: ELE key-attest statement (``hsm_pub_key_attest``, 0x74) — 2GO-TLV cert.
ELE_KEY_ATTEST_OID_DEFAULT = "1.3.6.1.4.1.99999.31"

#: SE05x attested read (AN13254) — attestation TLV block.
SE05X_ATTEST_OID_DEFAULT = "1.3.6.1.4.1.99999.32"

def _env_or(env_name: str, default: str) -> str:
    value = os.environ.get(env_name)
    return value.strip() if value and value.strip() else default


def resolve_ele_dev_attest_oid() -> str:
    """Return the ELE device-attest statement OID (env override allowed)."""
    return _env_or("ELE_DEV_ATTEST_OID", ELE_DEV_ATTEST_OID_DEFAULT)


def resolve_ele_key_attest_oid() -> str:
    """Return the ELE key-attest statement OID (env override allowed)."""
    return _env_or("ELE_KEY_ATTEST_OID", ELE_KEY_ATTEST_OID_DEFAULT)


def resolve_se05x_attest_oid() -> str:
    """Return the SE05x attested-read statement OID (env override allowed)."""
    return _env_or("SE05X_ATTEST_OID", SE05X_ATTEST_OID_DEFAULT)


__all__ = [
    "ELE_DEV_ATTEST_OID_DEFAULT",
    "ELE_KEY_ATTEST_OID_DEFAULT",
    "SE05X_ATTEST_OID_DEFAULT",
    "resolve_ele_dev_attest_oid",
    "resolve_ele_key_attest_oid",
    "resolve_se05x_attest_oid",
]

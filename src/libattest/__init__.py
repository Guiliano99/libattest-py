# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Remote attestation helpers for Veraison-compatible backends and MockCA integration."""

from libattest.formats.stmt_mappings import (
    get_nonce_request_oid_for_name,
    get_nonce_response_oid_for_name,
    get_oid_by_name,
    get_oid_for_stmt_name,
)
from libattest.types import AttestResult, BundleVerifyResult, EarStatus, VerifyResult

__all__ = [
    "AttestResult",
    "BundleVerifyResult",
    "EarStatus",
    "VerifyResult",
    "__version__",
    # OID accessors — the only supported way to reference project OIDs (see README).
    "get_nonce_request_oid_for_name",
    "get_nonce_response_oid_for_name",
    "get_oid_by_name",
    "get_oid_for_stmt_name",
]

__version__ = "0.1.0"

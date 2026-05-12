# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Remote attestation helpers for Veraison-compatible backends and MockCA integration."""

from libattest.types import AttestResult, BundleVerifyResult, EarStatus, VerifyResult

__all__ = [
    "AttestResult",
    "BundleVerifyResult",
    "EarStatus",
    "VerifyResult",
    "__version__",
]

__version__ = "0.1.0"

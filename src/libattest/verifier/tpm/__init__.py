# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM verifier backends."""

from libattest.verifier.tpm.reference_values import (
    PcrReferenceValues,
    load_pcr_reference_values,
    verify_pcr_quote,
)
from libattest.verifier.tpm.tpm_keyattest_verifier import TpmKeyAttestVerifier
from libattest.verifier.tpm.tpm_platform_verifier import TpmPlatformVerifier

__all__ = [
    "PcrReferenceValues",
    "TpmKeyAttestVerifier",
    "TpmPlatformVerifier",
    "load_pcr_reference_values",
    "verify_pcr_quote",
]

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
from libattest.verifier.tpm.tpm_platform_verifier import (
    TPM_ALG_ECDSA,
    TPM_ALG_RSAPSS,
    TPM_ALG_RSASSA,
    TPM_ALG_SHA1,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_ALG_SHA512,
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    TpmPlatformVerifier,
    TpmQuoteSignatureEvidence,
)

__all__ = [
    "PcrReferenceValues",
    "TPM_ALG_ECDSA",
    "TPM_ALG_RSASSA",
    "TPM_ALG_RSAPSS",
    "TPM_ALG_SHA1",
    "TPM_ALG_SHA256",
    "TPM_ALG_SHA384",
    "TPM_ALG_SHA512",
    "TPM_GENERATED_VALUE",
    "TPM_ST_ATTEST_QUOTE",
    "TpmKeyAttestVerifier",
    "TpmPlatformVerifier",
    "TpmQuoteSignatureEvidence",
    "load_pcr_reference_values",
    "verify_pcr_quote",
]

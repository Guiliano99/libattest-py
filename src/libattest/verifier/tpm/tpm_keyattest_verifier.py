# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM key-attestation verifier."""

from libattest.verifier.tpm.base import TpmReferenceVerifier


class TpmKeyAttestVerifier(TpmReferenceVerifier):
    """Verifier for TPM key-attestation evidence."""

    media_type = "application/vnd.tcg.attest-certify"

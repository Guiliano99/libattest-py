# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM platform attestation verifier."""

from libattest.verifier.tpm.base import TpmReferenceVerifier


class TpmPlatformVerifier(TpmReferenceVerifier):
    """Verifier for TPM platform evidence."""

    media_type = "application/vnd.tcg.platform"

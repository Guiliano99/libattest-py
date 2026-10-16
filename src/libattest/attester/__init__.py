# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Client-side helpers for generating and packaging attestation evidence.

Beyond producing Evidence, an attester makes two decisions about the exchange it is
in: what the verifier told it (:class:`VerifierInfo`, parsed once from the
``NonceResponse``) and what it is willing to tell the verifier back
(:class:`ClaimReleasePolicy`).  Both reach a provider as one
:class:`EvidenceRequest`.
"""

from libattest.attester.claim_release import ESSENTIAL_CLAIMS, ClaimReleasePolicy, release_claims
from libattest.attester.client import AttesterClient, AttesterProvider, EvidenceRequest
from libattest.attester.verifier_info import VerifierInfo, parse_verifier_info
from libattest.types import AttestResult

__all__ = [
    "ESSENTIAL_CLAIMS",
    "AttestResult",
    "AttesterClient",
    "AttesterProvider",
    "ClaimReleasePolicy",
    "EvidenceRequest",
    "VerifierInfo",
    "parse_verifier_info",
    "release_claims",
]

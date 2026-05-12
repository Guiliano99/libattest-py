# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Structured error hierarchy for libattest."""


class AttestError(Exception):
    """Base class for all libattest errors."""


class AttestEvidenceError(AttestError):
    """Raised when attestation evidence is malformed or cannot be parsed."""


class AttestRoutingError(AttestError):
    """Raised when no verifier route can be selected for given evidence."""


class AttestVerificationError(AttestError):
    """Raised when evidence fails verification due to a verifier-side problem."""


class AttestProviderError(AttestError):
    """Raised when an attester provider fails to generate evidence."""

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Reference-value handling abstractions for verifier backends."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ReferenceCheckResult:
    """Result of comparing evidence against verifier reference values."""

    accepted: bool
    attester_id: str | None = None
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class VerifierReferenceHandler(ABC):
    """Abstract handler for verifier-owned reference-value checks.

    Implementations own the format-specific parsing and comparison logic. The
    evidence argument is deliberately typed as `Any` so handlers can accept
    JWT strings, DER bytes, decoded ASN.1 values, CBOR objects, or other
    evidence formats without forcing a common representation too early.
    """

    @abstractmethod
    def handle_evidence(self, evidence: Any, *, attester_id: str | None = None) -> ReferenceCheckResult:
        """Compare evidence from an Attester against local reference values."""


class AcceptAllReferenceHandler(VerifierReferenceHandler):
    """Reference handler that accepts any evidence unconditionally.

    Useful for flows where the appraisal decision is driven entirely by other
    inputs (for example explicit ``PcrReferenceValues`` or a proof-of-possession
    check) and the reference-value comparison itself should not reject anything.
    """

    def handle_evidence(self, evidence: Any, *, attester_id: str | None = None) -> ReferenceCheckResult:
        """Accept the evidence, echoing back the supplied ``attester_id``."""
        return ReferenceCheckResult(accepted=True, attester_id=attester_id)

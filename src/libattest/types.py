# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Shared result types for attestation flows."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


# ---------------------------------------------------------------------------
# EAR verdict
# ---------------------------------------------------------------------------


class EarStatus(str, Enum):
    """Possible EAR (Entity Attestation Result) verdict values.

    References
    ----------
    draft-ietf-rats-ar4si: Attestation Results for Secure Interactions
    """

    affirming = "affirming"
    contraindicated = "contraindicated"
    unknown = "unknown"


@dataclass(frozen=True)
class VerifyResult:
    """Typed outcome of a single evidence verification step.

    Attributes
    ----------
    status:
        EAR verdict produced by the verifier.  ``affirming`` means the
        evidence was accepted; ``contraindicated`` means it was rejected;
        ``unknown`` means the verifier could not evaluate it (wrong media
        type, missing nonce, or unsupported format).
    payload:
        Optional result string or data returned by the verifier on success
        (e.g. an EAR JWT or a JSON policy result).
    errors:
        Human-readable error messages.  Non-empty when *status* is not
        ``affirming``.
    warnings:
        Advisory messages that do not change the verdict.

    """

    status: EarStatus
    payload: str | bytes | dict | None = None
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        """Return ``True`` iff the evidence was affirmed."""
        return self.status == EarStatus.affirming

    @classmethod
    def affirming(cls, payload: str | bytes | dict | None = None) -> "VerifyResult":
        """Return an affirming result with an optional payload."""
        return cls(status=EarStatus.affirming, payload=payload)

    @classmethod
    def contraindicated(cls, *errors: str) -> "VerifyResult":
        """Return a contraindicated result with optional error messages."""
        return cls(status=EarStatus.contraindicated, errors=errors)

    @classmethod
    def unknown(cls, *warnings: str) -> "VerifyResult":
        """Return an unknown-status result with optional warnings."""
        return cls(status=EarStatus.unknown, warnings=warnings)

    def payload_bytes(self) -> bytes:
        """Return the payload in byte form for transport."""
        if self.payload is None:
            return b""
        if isinstance(self.payload, bytes):
            return self.payload
        if isinstance(self.payload, str):
            return self.payload.encode("utf-8")
        return json.dumps(self.payload, sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Attester evidence result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestResult:
    """Generated attestation evidence and routing metadata.

    This is the canonical, immutable result type shared between
    ``AttesterClient`` (dispatch-only) and ``AttestClient`` (HTTP).

    Attributes
    ----------
    oid:
        Object identifier that identifies the evidence format.
    evidence:
        DER-encoded evidence bytes or a compact JWT string.
    media_type:
        IANA media type for the evidence payload.
    cert_chain:
        Optional certificate chain.  A :class:`~pathlib.Path` points to a
        PEM file; a ``str`` contains the PEM-encoded chain directly.
    verifier_hint:
        Optional verifier route name or base URL.  Used to disambiguate
        when multiple verifiers handle the same evidence-type OID
        (e.g. two TPM verifiers, each with its own trust anchor).
    is_asn1_evidence:
        ``True`` when ``evidence`` is an already DER-encoded ASN.1 SEQUENCE
        (e.g. ``TcgAttestCertify``) and should be embedded directly into
        the bundle's ``ANY`` slot.  ``False`` (default) wraps the bytes in
        an OCTET STRING — appropriate for opaque payloads such as JWTs.

    """

    oid: str
    evidence: bytes | str
    media_type: str
    cert_chain: Path | str | None = None
    verifier_hint: str | None = None
    is_asn1_evidence: bool = False

    def evidence_bytes(self) -> bytes:
        """Return evidence in the byte form required for HTTP submission."""
        if isinstance(self.evidence, bytes):
            return self.evidence
        return self.evidence.encode("utf-8")

    def as_tuple(self) -> tuple[str, bytes | str, str]:
        """Return ``(oid, evidence, media_type)`` for tuple-style consumers."""
        return self.oid, self.evidence, self.media_type


# ---------------------------------------------------------------------------
# Aggregated bundle verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleVerifyResult:
    """Aggregated outcome of verifying every statement in one bundle.

    Attributes
    ----------
    per_statement:
        One :class:`VerifyResult` per :class:`AttestationStatement` in the
        bundle, in the same order the statements appeared.
    routes:
        Names of the verifier routes that were dispatched to, parallel to
        ``per_statement``.
    """

    per_statement: tuple[VerifyResult, ...] = ()
    routes: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        """Return ``True`` iff every statement was affirmed (and at least one)."""
        return bool(self.per_statement) and all(
            v.status == EarStatus.affirming for v in self.per_statement
        )

    @property
    def first_failure(self) -> VerifyResult | None:
        """Return the first non-affirming verdict, or ``None`` if all affirming."""
        for v in self.per_statement:
            if v.status != EarStatus.affirming:
                return v
        return None

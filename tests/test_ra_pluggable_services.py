# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Replaceability proof for the RA engine's two pluggable seams.

A developer adds a brand-new attestation OID, a custom
:class:`AttestationVerifier`, and a custom :class:`VerifierReferenceHandler` by
**registration only** — the engine and the profile dataclass are never edited.
These tests assert the engine dispatches to the registered services and that the
reference handler's verdict actually gates acceptance.
"""

from __future__ import annotations

from typing import Any

from pyasn1.codec.der import encoder as der_encoder

from libattest.formats.csrattest import (
    prepare_attestation_bundle,
    prepare_opaque_attestation_statement,
)
from libattest.ra import (
    ProfileRegistry,
    RemoteAttestationEngine,
    ServiceRegistry,
    jwt_profile,
)
from libattest.types import EarStatus, VerifyResult
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.reference import ReferenceCheckResult, VerifierReferenceHandler

NEW_OID = "1.3.6.1.4.1.88888.7"
TX = b"\x07" * 16


class CountingVerifier(AttestationVerifier):
    """Custom verifier that records calls and returns a fixed verdict."""

    media_type = "application/vnd.custom+der"

    def __init__(self, verdict: VerifyResult) -> None:
        self._verdict = verdict
        self.calls: list[tuple[bytes, str, bytes | None]] = []

    def get_nonce(self, nonce_size: int = 32) -> bytes:
        return b""

    def verify_token(self, token_bytes: bytes, media_type: str, nonce: bytes | None = None) -> VerifyResult:
        self.calls.append((token_bytes, media_type, nonce))
        return self._verdict


class RecordingReferenceHandler(VerifierReferenceHandler):
    """Custom reference handler that records evidence and returns a fixed result."""

    def __init__(self, accepted: bool, reason: str | None = None) -> None:
        self._accepted = accepted
        self._reason = reason
        self.calls: list[tuple[Any, str | None]] = []

    def handle_evidence(self, evidence: Any, *, attester_id: str | None = None) -> ReferenceCheckResult:
        self.calls.append((evidence, attester_id))
        return ReferenceCheckResult(accepted=self._accepted, attester_id=attester_id, reason=self._reason)


def _bundle(payload: bytes = b"custom-evidence") -> bytes:
    return bytes(der_encoder.encode(prepare_attestation_bundle([prepare_opaque_attestation_statement(NEW_OID, payload)])))


def _engine_with_registered_services(verifier, reference_handler) -> RemoteAttestationEngine:
    """Wire a new OID purely by registration — no engine/profile edits."""
    services = ServiceRegistry()
    services.register_verifier(NEW_OID, verifier)
    services.register_reference_handler(NEW_OID, reference_handler)

    # The developer builds a profile pulling the services from the registry by
    # name (the statement OID).  This is the only "wiring" required.
    profiles = ProfileRegistry()
    profiles.register(
        jwt_profile(
            request_type_oid=NEW_OID,
            statement_oid=NEW_OID,
            verifier=services.get_verifier(NEW_OID),
            reference_handler=services.get_reference_handler(NEW_OID),
        )
    )
    return RemoteAttestationEngine(profiles)


def test_engine_dispatches_to_custom_verifier_and_reference_handler():
    verifier = CountingVerifier(VerifyResult.affirming("custom.ear.jwt"))
    reference_handler = RecordingReferenceHandler(accepted=True)
    engine = _engine_with_registered_services(verifier, reference_handler)

    state = engine.issue_nonce(TX, NEW_OID)
    outcome = engine.verify_bundle(_bundle(), TX)

    # The CUSTOM verifier was used, with the engine-issued nonce + evidence.
    assert len(verifier.calls) == 1
    token_bytes, media_type, nonce = verifier.calls[0]
    assert token_bytes == b"custom-evidence"
    assert media_type == "application/vnd.custom+der"
    assert nonce == state.nonce

    # The CUSTOM reference handler was consulted with the unwrapped evidence.
    assert reference_handler.calls == [(b"custom-evidence", NEW_OID)]

    assert outcome.accepted
    assert outcome.first_ear == "custom.ear.jwt"


def test_reference_handler_rejection_overrides_affirming_verifier():
    # The verifier affirms, but the custom reference handler rejects → the
    # aggregate verdict is contraindicated (the reference seam actually gates).
    verifier = CountingVerifier(VerifyResult.affirming("custom.ear.jwt"))
    reference_handler = RecordingReferenceHandler(accepted=False, reason="unknown PCR digest")
    engine = _engine_with_registered_services(verifier, reference_handler)

    engine.issue_nonce(TX, NEW_OID)
    outcome = engine.verify_bundle(_bundle(), TX)

    assert not outcome.accepted
    failure = outcome.first_failure
    assert failure is not None
    assert failure.status == EarStatus.contraindicated
    assert "unknown PCR digest" in failure.errors[0]
    # The verifier still ran (rejection happens after, not instead).
    assert len(verifier.calls) == 1


def test_service_registry_round_trip_and_snapshot():
    services = ServiceRegistry()
    v = CountingVerifier(VerifyResult.affirming())
    r = RecordingReferenceHandler(accepted=True)
    services.register_verifier(NEW_OID, v)
    services.register_reference_handler(NEW_OID, r)

    assert services.get_verifier(NEW_OID) is v
    assert services.get_reference_handler(NEW_OID) is r
    assert services.get_verifier("nope") is None
    snap = services.snapshot()
    assert snap["verifiers"] == [NEW_OID]
    assert snap["reference_handlers"] == [NEW_OID]

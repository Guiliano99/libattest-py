# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""In-memory fakes for unit-testing verifiers and attester providers.

These classes let test code compose a complete local attestation flow
without any network connections or TPM hardware.

Example:
-------
::

    from libattest.testing.fakes import InMemoryVerifier, EchoAttesterProvider
    from libattest.verifier.router import VerifierRouter
    from libattest.attester.client import AttesterClient
    from libattest.types import EarStatus

    oid = "2.23.133.20.1"
    verifier = InMemoryVerifier()
    router = VerifierRouter()
    router.register("tpm", verifier, evidence_types=[oid], default=True)

    provider = EchoAttesterProvider(oid=oid, evidence=b"test-evidence")
    attester = AttesterClient(providers={oid: provider})

    nonce = router.get_nonce(size=32)
    result = attester.generate_evidence(oid, nonce=nonce)
    verdict = router.verify_token(result.evidence_bytes(), result.media_type, nonce=nonce)
    assert verdict.accepted

"""

from __future__ import annotations

from libattest.types import AttestResult, VerifyResult
from libattest.verifier.base import AttestationVerifier


class InMemoryVerifier(AttestationVerifier):
    """Verifier that returns a pre-configured verdict without any I/O.

    Useful for checking router dispatch, bundle construction, and CMP
    nonce flow without standing up a real Veraison service.

    Parameters
    ----------
    nonce:
        Fixed nonce returned by :meth:`get_nonce`.
    result:
        Verdict returned by :meth:`verify_token`.  Defaults to an
        affirming result with no payload.
    reject_media_types:
        Set of media types for which :meth:`verify_token` returns an
        *unknown* result (simulates a type mismatch).

    """

    def __init__(
        self,
        nonce: bytes = b"test-nonce-32bytes-padding000000",
        result: VerifyResult | None = None,
        reject_media_types: set[str] | None = None,
    ) -> None:
        """Configure the fake verifier with fixed nonce and canned verification result."""
        self._nonce = nonce
        self._result = result if result is not None else VerifyResult.affirming()
        self._reject_media_types: set[str] = reject_media_types or set()
        self.nonce_calls: list[int] = []
        self.verify_calls: list[tuple[bytes, str, bytes | None]] = []

    def get_nonce(self, nonce_size: int = 32) -> bytes:
        """Return the configured fixed nonce."""
        self.nonce_calls.append(nonce_size)
        return self._nonce[:nonce_size].ljust(nonce_size, b"\x00")

    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: bytes | None = None,
    ) -> VerifyResult:
        """Return the configured result, or *unknown* for rejected media types."""
        self.verify_calls.append((token_bytes, media_type, nonce))
        if media_type in self._reject_media_types:
            return VerifyResult.unknown(f"unsupported media type: {media_type!r}")
        return self._result


class EchoAttesterProvider:
    """Attester provider that returns a constant evidence payload.

    The provider satisfies the :class:`~libattest.attester.client.AttesterProvider`
    protocol without needing TPM hardware or network access.

    Parameters
    ----------
    oid:
        Evidence format OID returned in the result.
    evidence:
        Fixed evidence bytes returned on every call.  The nonce is
        appended when *bind_nonce* is ``True``.
    media_type:
        IANA media type for the evidence.
    bind_nonce:
        When ``True`` (default), the nonce is appended to the evidence
        bytes so that tests can verify nonce binding.

    """

    def __init__(
        self,
        oid: str,
        evidence: bytes = b"echo-evidence",
        media_type: str = "application/octet-stream",
        bind_nonce: bool = True,
    ) -> None:
        """Configure the fake provider with a fixed OID, evidence payload, and media type."""
        self.oid = oid
        self._evidence = evidence
        self._media_type = media_type
        self._bind_nonce = bind_nonce
        self.nonces: list[bytes | None] = []

    def generate_evidence(self, nonce: bytes | None = None) -> AttestResult:
        """Return an :class:`~libattest.types.AttestResult` with the configured evidence."""
        self.nonces.append(nonce)
        payload = self._evidence
        if self._bind_nonce and nonce:
            payload = self._evidence + b":" + nonce
        return AttestResult(oid=self.oid, evidence=payload, media_type=self._media_type)

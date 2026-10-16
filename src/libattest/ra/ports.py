# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""The verifier port the **RA** owns (RFC 9334 Relying Party → Verifier).

Before this module the engine imported the Verifier package's
:class:`~libattest.verifier.base.AttestationVerifier` abstraction *and* special-cased
one concrete implementation::

    if isinstance(verifier, VeraisonVerifierClient):
        verifier.submit_evidence(..., resp_info_json=..., session_id=..., pubkey=...)
    return verifier.verify_token(stmt_bytes, media_type, nonce)  # everyone else

That ``isinstance`` was not a shortcut, it was a **capability cliff**: the negotiated
``respInfo``, the key-attestation session id and the to-be-certified public key were
reachable only by the one class the engine named, so a custom verifier could never
receive them no matter what it implemented.

:class:`AppraisalRequest` makes that context part of the request instead of part of one
class's signature, and :class:`EvidenceVerifier` is the whole port: *given an appraisal
request, return a verdict*.  There is deliberately **no** ``get_nonce`` — under the
RA-issued-nonce model the RA owns freshness, which is why three of the four shipped
``AttestationVerifier`` implementations stub ``get_nonce`` to ``return b""``.

Existing verifiers keep working unchanged: :func:`as_evidence_verifier` returns a native
port implementation as-is and otherwise wraps the older ABC in
:class:`LegacyVerifierPort`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from libattest.formats.media_types import media_type_set
from libattest.types import VerifyResult

#: Transport default when a verifier declares no media type of its own.
OCTET_STREAM = "application/octet-stream"


@dataclass(frozen=True)
class AppraisalRequest:
    """One statement's worth of Evidence plus everything the RA knows about it.

    Attributes
    ----------
    evidence:
        The unwrapped ``AttestationStatement.stmt`` bytes to appraise.
    media_type:
        IANA media type of *evidence*.
    nonce:
        The RA-issued freshness nonce this Evidence must be bound to.
    statement_oid:
        Dot-form ``AttestationStatement.type`` OID (which Evidence format this is).
    bundle:
        The full ``AttestationBundle`` DER *evidence* was unwrapped from — populated
        **only** for a verifier that declares ``needs_bundle = True`` because it parses
        the container itself.  Every other verifier gets ``None`` here and reads the AK
        chain from *endorsements*, so it never sees the other statements in the bundle.
    endorsements:
        The bundle's ``certs`` as DER (RFC 9334 Endorsements — the AK/EK chain vouching
        for the Attester), decoded once for the whole bundle rather than re-parsed per
        statement.  Empty when the bundle carried none.
    resp_info:
        The negotiated ``NonceResponse.respTypeInfo.respInfo`` as JSON, so the verifier
        can confirm the parameters the RA actually promised the attester (e.g. the PCR
        set and hash algorithm).  ``None`` for profiles that negotiate nothing.
    subject_key:
        The to-be-certified ``SubjectPublicKeyInfo`` DER, for key-attestation profiles
        where the verifier must bind the certified TPM key to the CSR key.
    session_id:
        Verifier session id bound to the nonce by a challenge round-trip (the
        key-attestation MakeCredential leg).

    """

    evidence: bytes
    media_type: str
    nonce: bytes
    statement_oid: str
    bundle: bytes | None = None
    endorsements: tuple[bytes, ...] = ()
    resp_info: Mapping[str, Any] | None = None
    subject_key: bytes | None = None
    session_id: str | None = None


class EvidenceVerifier(Protocol):
    """What the RA requires of a verifier: declare what you take, and appraise it."""

    #: Media types this verifier will appraise.  Empty means "anything".
    accepts: frozenset[str]

    def appraise(self, request: AppraisalRequest) -> VerifyResult:
        """Appraise *request* and return a typed verdict."""
        ...  # pragma: no cover - structural typing only


class LegacyVerifierPort:
    """Present an :class:`~libattest.verifier.base.AttestationVerifier` as the RA port.

    The ABC's ``verify_token(bytes, media_type, nonce)`` carries no room for the
    negotiated ``respInfo``, session id, or subject key, so those fields of the request
    are dropped here — visibly, in one place, rather than silently at every call site.
    A verifier that needs them implements :meth:`appraise` directly.
    """

    def __init__(self, verifier: Any) -> None:
        """Wrap *verifier*, deriving :attr:`accepts` from its declared media type."""
        self._verifier = verifier
        declared = getattr(verifier, "accepts", None) or getattr(verifier, "media_type", None)
        self.accepts = media_type_set(declared)

    def appraise(self, request: AppraisalRequest) -> VerifyResult:
        """Delegate to the wrapped ABC's ``verify_token``."""
        return self._verifier.verify_token(request.evidence, request.media_type, request.nonce)


class ReferenceCheckedVerifier:
    """Run a verifier's appraisal, then its reference-value check, as one appraisal.

    Comparing Evidence against reference values is a **Verifier** task in RFC 9334, not
    a Relying Party one, but the RA engine used to run the profile's
    :class:`~libattest.verifier.reference.VerifierReferenceHandler` itself, after the
    verdict came back — so the RA both consumed an Attestation Result and second-guessed
    it.  Composing the handler onto the verifier here keeps the behaviour identical and
    puts the check back on the verifier's side of the boundary, where a verifier that
    owns its own reference values (every remote one) already does it.

    A rejecting reference check downgrades an affirming verdict to contraindicated; a
    verdict that was not affirming is returned untouched.
    """

    def __init__(self, verifier: EvidenceVerifier, handler: Any) -> None:
        """Wrap *verifier* so *handler* appraises the Evidence behind the same port."""
        self._verifier = verifier
        self._handler = handler
        self.accepts = verifier.accepts

    def appraise(self, request: AppraisalRequest) -> VerifyResult:
        """Appraise *request*, then apply the reference-value check to an affirmation."""
        verdict = self._verifier.appraise(request)
        if not verdict.accepted:
            return verdict
        check = self._handler.handle_evidence(request.evidence, attester_id=request.statement_oid)
        if check.accepted:
            return verdict
        return VerifyResult.contraindicated(f"reference check failed: {check.reason or 'no reason given'}")


def as_evidence_verifier(verifier: Any) -> EvidenceVerifier:
    """Return *verifier* as an :class:`EvidenceVerifier`, adapting the older ABC.

    Duck-typed on ``appraise`` rather than ``isinstance`` against a runtime-checkable
    Protocol: a structural check on a data protocol would only confirm that the
    attribute names exist, which is exactly as strong as ``hasattr`` and rather more
    surprising when it fails.
    """
    if callable(getattr(verifier, "appraise", None)):
        return verifier
    return LegacyVerifierPort(verifier)


__all__ = [
    "OCTET_STREAM",
    "AppraisalRequest",
    "EvidenceVerifier",
    "LegacyVerifierPort",
    "ReferenceCheckedVerifier",
    "as_evidence_verifier",
]

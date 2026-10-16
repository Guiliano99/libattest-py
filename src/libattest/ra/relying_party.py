# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""What the RA checks before it acts on an Attestation Result (RFC 9334 Relying Party).

The RA harvests an EAR JWT out of a verifier's verdict and embeds it in a certificate.
Until now it never appraised that EAR itself: it trusted whatever the verifier object
handed back, and the only signature check lived *inside*
:class:`~libattest.ra.verifier_client.VeraisonVerifierClient`, against a key fetched
trust-on-first-use from the same endpoint that issued the EAR.  Any other verifier
implementation — in-process, third-party, or a future remote one — got a free pass, and
nothing anywhere bound the EAR to the nonce the RA had issued.  That is an evidence
router, not a Relying Party.

:class:`EarAcceptancePolicy` is the missing appraisal, and it is deliberately one
object rather than a set of flags: an RA either appraises Attestation Results or it does
not.  Once a policy is configured every EAR must satisfy all of it —

* the signature verifies against **configured** key material (never a fetched key),
* the EAR parses as a well-formed :class:`~libattest.formats.eat_ear.cwt_jwt.EARToken`,
* its ``eat_nonce`` is the nonce this RA issued for this exchange,
* its ``iat`` (and ``exp``, when present) place it inside the freshness window, and
* every submodule appraisal is ``affirming``.

The nonce check is the one that closes the replay hole: without it a captured affirming
EAR stays valid forever, because nothing ties it to the exchange it is being replayed
into.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats.eat_ear.cwt_jwt import EARToken, TrustworthinessTier, parse_ear, verify_ear_jwt
from libattest.types import VerifyResult

logger = logging.getLogger(__name__)

#: Default freshness window for an Attestation Result, in seconds.
DEFAULT_MAX_AGE_SECONDS = 300
#: Tolerance for clock disagreement between the RA and the verifier, in seconds.
DEFAULT_CLOCK_SKEW_SECONDS = 60

#: A configured EAR verification key: a key object, or PEM/DER bytes, or a PEM string.
TrustAnchor = Union[ec.EllipticCurvePublicKey, bytes, str]


def load_trust_anchor(anchor: TrustAnchor) -> ec.EllipticCurvePublicKey:
    """Normalise a configured EAR verification key to a key object.

    :raises ValueError: the material is unreadable or is not an EC public key.
    """
    if isinstance(anchor, ec.EllipticCurvePublicKey):
        return anchor
    data = anchor.encode("ascii") if isinstance(anchor, str) else bytes(anchor)
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        key = serialization.load_der_public_key(data)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("an EAR trust anchor must be an EC public key")
    return key


@dataclass(frozen=True)
class EarDecision:
    """The RA's verdict on one Attestation Result, plus the token it appraised.

    ``token`` is populated only once the EAR's signature has verified, so a caller that
    reads it is never reading unauthenticated claims.
    """

    result: VerifyResult
    token: EARToken | None = None

    @property
    def accepted(self) -> bool:
        """Return whether the RA may act on this Attestation Result."""
        return self.result.accepted


@dataclass(frozen=True)
class EarAcceptancePolicy:
    """The Relying Party checks the RA applies to every EAR it acts on.

    Attributes
    ----------
    anchors:
        Configured EAR verification key material: one anchor used for every EAR, or a
        mapping from ``ear.verifier-id.developer`` to that verifier's anchor.  ``None``
        means every appraisal must be given an explicit per-profile anchor instead.
    max_age_seconds:
        How old an EAR's ``iat`` may be before it is stale.
    clock_skew_seconds:
        Tolerance for the RA's and the verifier's clocks disagreeing.
    require_nonce:
        Whether an EAR must echo the RA-issued nonce.  Leaving this on is what makes a
        captured EAR unusable in a later exchange; turn it off only for a verifier that
        provably cannot echo one, and understand that it can then be replayed.

    """

    anchors: Mapping[str, TrustAnchor] | TrustAnchor | None = None
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS
    require_nonce: bool = True

    def appraise(
        self,
        ear_jwt: str,
        *,
        expected_nonce: bytes | None,
        anchor: TrustAnchor | None = None,
        verifier_id: str | None = None,
        now: float | None = None,
    ) -> EarDecision:
        """Appraise *ear_jwt* and return the RA's decision.

        Anchor selection, strongest first: *anchor* is the appraised profile's pinned
        key; *verifier_id* is the deployment's **configured** name for that profile's
        verifier, used as the key into an :attr:`anchors` map; and only when neither is
        configured does the map fall back to the EAR's own
        ``ear.verifier-id.developer``.  That last selector is read before the signature
        is checked, which is safe only because it can *choose among already configured
        anchors* and can never introduce one — but it lets a token nominate which of
        your anchors it would like to be checked against, which is why either of the
        configured forms is preferable.
        """
        resolved = self._resolve_anchor(ear_jwt, anchor, verifier_id)
        if resolved is None:
            return _reject("no configured EAR trust anchor for this verifier; refusing to trust its verdict")

        if not verify_ear_jwt(ear_jwt, resolved):
            return _reject("EAR signature did not verify against the configured trust anchor")

        try:
            token = parse_ear(ear_jwt)
        except ValueError as exc:
            return _reject(f"EAR did not parse as an Attestation Result: {exc}")

        reason = self._appraise_token(token, expected_nonce, now if now is not None else time.time())
        if reason is not None:
            logger.warning("RA rejected an Attestation Result: %s", reason)
            return EarDecision(VerifyResult.contraindicated(reason), token=token)

        return EarDecision(VerifyResult.affirming(ear_jwt), token=token)

    # ── the individual checks ────────────────────────────────────────────────────
    def _appraise_token(self, token: EARToken, expected_nonce: bytes | None, now: float) -> str | None:
        """Return the first failing check's reason, or ``None`` when the EAR is acceptable."""
        if self.require_nonce:
            if not expected_nonce:
                return "no RA-issued nonce to bind this Attestation Result to"
            if token.nonce is None:
                return "EAR carries no eat_nonce, so it cannot be bound to this exchange"
            if token.nonce.to_bytes() != expected_nonce:
                return "EAR eat_nonce does not match the nonce this RA issued (replayed or misrouted)"

        if token.iat > now + self.clock_skew_seconds:
            return f"EAR iat {token.iat} is in the future beyond the {self.clock_skew_seconds}s skew allowance"
        if token.iat < now - self.max_age_seconds - self.clock_skew_seconds:
            return f"EAR iat {token.iat} is older than the {self.max_age_seconds}s freshness window"
        if token.exp is not None and now > token.exp + self.clock_skew_seconds:
            return f"EAR expired at {token.exp}"

        if not token.submods:
            return "EAR carries no submodule appraisal"
        if token.ear_status is not None and token.ear_status is not TrustworthinessTier.AFFIRMING:
            return f"EAR overall status is {token.ear_status.value!r}"
        for name, appraisal in token.submods.items():
            if appraisal.status is not TrustworthinessTier.AFFIRMING:
                return f"EAR submod {name!r} status is {appraisal.status.value!r}"
        return None

    def _resolve_anchor(
        self,
        ear_jwt: str,
        anchor: TrustAnchor | None,
        verifier_id: str | None = None,
    ) -> ec.EllipticCurvePublicKey | None:
        """Return the key to verify *ear_jwt* with, or ``None`` when none is configured."""
        candidate = anchor if anchor is not None else self.anchors
        if candidate is None:
            return None
        if isinstance(candidate, Mapping):
            developer = verifier_id if verifier_id is not None else _unverified_developer(ear_jwt)
            if developer is None:
                logger.warning("EAR names no verifier-id developer; cannot select a configured anchor")
                return None
            candidate = candidate.get(developer)
            if candidate is None:
                logger.warning("no EAR trust anchor configured for verifier developer %r", developer)
                return None
        try:
            return load_trust_anchor(candidate)
        except ValueError as exc:
            logger.error("configured EAR trust anchor is unusable: %s", exc)
            return None


def _unverified_developer(ear_jwt: str) -> str | None:
    """Read ``ear.verifier-id.developer`` from an *unverified* EAR, for anchor selection only."""
    try:
        token = parse_ear(ear_jwt)
    except ValueError:
        return None
    developer = token.verifier_id.get("developer")
    return developer if isinstance(developer, str) else None


def _reject(reason: str) -> EarDecision:
    """Return a contraindicated decision carrying no token (nothing was authenticated)."""
    logger.warning("RA rejected an Attestation Result: %s", reason)
    return EarDecision(VerifyResult.contraindicated(reason))


__all__ = [
    "DEFAULT_CLOCK_SKEW_SECONDS",
    "DEFAULT_MAX_AGE_SECONDS",
    "EarAcceptancePolicy",
    "EarDecision",
    "TrustAnchor",
    "load_trust_anchor",
]

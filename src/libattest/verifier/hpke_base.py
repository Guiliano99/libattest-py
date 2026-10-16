# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Shared skeleton for the HPKE-encrypted EAR/EAT demo verifiers.

:class:`~libattest.verifier.eareat_hpke.EarEatHpkeVerifier` (JOSE-HPKE) and
:class:`~libattest.verifier.eareat_cose_hpke.CoseEatHpkeVerifier` (COSE-HPKE) differ
only in how the Evidence leg is *encoded*: a JWE over an EAT-JWS versus a
``COSE_Encrypt0`` over a nested ``COSE_Sign1``.  Everything around that — publishing
the recipient JWK and the EAR verification key, the media-type gate, the mandatory
freshness nonce, and Veraison-format EAR issuance — is identical, and used to be
maintained in two places.

That duplication was not cosmetic: the media-type gate, the "no nonce, no appraisal"
rule and the EAR trust vector are the security-bearing parts, so a fix to any of them
had to be applied twice or silently applied to one transport only.  Subclasses now
supply just :meth:`HpkeEarVerifier._appraise` and two class attributes.
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from typing import ClassVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats import eareat_hpke as evidence
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.media_types import base_media_type
from libattest.types import VerifyResult
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.ear import build_ear_jwt, ear_token_to_veraison_claims

logger = logging.getLogger(__name__)

DEFAULT_SCHEME_NAME = "ATG_PLUGIN"
DEFAULT_REFERENCE_MOCK_CLAIM = "secure"

#: Transport media type both verifiers also accept, for callers handing over opaque bytes.
OCTET_STREAM = "application/octet-stream"

_TRUST_VECTOR_KEYS = (
    "instance-identity",
    "configuration",
    "executables",
    "file-system",
    "hardware",
    "runtime-opaque",
    "storage-opaque",
    "sourced-data",
)


def load_ec_public_key(key: ec.EllipticCurvePublicKey | bytes | str) -> ec.EllipticCurvePublicKey:
    """Normalise an EC public key given as an object, PEM/DER bytes, or a PEM string.

    Normalising at construction turns "the operator configured a key this verifier can
    never use" into a startup error rather than a per-request ``contraindicated``
    verdict that reads like the attester's fault.
    """
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key
    data = key.encode("ascii") if isinstance(key, str) else bytes(key)
    try:
        pub = serialization.load_pem_public_key(data)
    except ValueError:
        pub = serialization.load_der_public_key(data)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise ValueError("attestation_public_key must be an EC public key")
    return pub


class HpkeEarVerifier(AttestationVerifier):
    """Everything an HPKE EAR/EAT demo verifier does apart from opening the envelope.

    Parameters
    ----------
    attestation_public_key:
        The attester's EAT signing key (an EC public key, or PEM/DER bytes/string).
    reference_mock_claim:
        The ``mock_claim`` value an affirming attestation must present.
    scheme_name:
        The EAR ``submods`` scheme key (defaults to ``ATG_PLUGIN``).
    verifier_developer:
        The ``ear.verifier-id.developer`` stamped into issued EARs; defaults to the
        subclass's :attr:`default_verifier_developer`, which the demos assert to prove
        which transport actually ran.
    ear_signing_key / hpke_recipient_key:
        Optional P-256 keys; fresh ones are generated when omitted.  The EAR key signs
        issued EARs (publish :meth:`ear_verification_pem`); the HPKE key is the
        recipient the attester encrypts Evidence to (publish
        :meth:`evidence_encryption_jwk`).
    hpke_info / external_aad:
        Application-context binding for the HPKE key schedule and (COSE only) the
        ``Enc_structure``.  Evidence sealed under a different context will not open, so
        both ends must be configured together; the defaults are the unbound ``b""``
        every existing peer produces — notably gencmpclient, which seals through
        OpenSSL's ``OSSL_HPKE_*`` — so binding is something a deployment turns on
        deliberately rather than something that silently breaks interop.

    """

    #: Media type this verifier's Evidence leg is carried as.  Subclasses must set it.
    media_type: ClassVar[str] = OCTET_STREAM
    #: ``ear.verifier-id.developer`` and default JWK ``kid`` for this transport.
    default_verifier_developer: ClassVar[str] = "hpke-verifier"

    def __init__(
        self,
        *,
        attestation_public_key: ec.EllipticCurvePublicKey | bytes | str,
        reference_mock_claim: str = DEFAULT_REFERENCE_MOCK_CLAIM,
        scheme_name: str = DEFAULT_SCHEME_NAME,
        verifier_developer: str | None = None,
        ear_signing_key: ec.EllipticCurvePrivateKey | None = None,
        hpke_recipient_key: ec.EllipticCurvePrivateKey | None = None,
        hpke_info: bytes = b"",
        external_aad: bytes = b"",
    ) -> None:
        """Store appraisal policy, the verifier's keys, and its encryption context."""
        self._attestation_public_key = load_ec_public_key(attestation_public_key)
        self._reference_mock_claim = reference_mock_claim
        self._scheme_name = scheme_name
        self._verifier_developer = verifier_developer or self.default_verifier_developer
        self._ear_signing_key = ear_signing_key or ec.generate_private_key(ec.SECP256R1())
        self._hpke_recipient_key = hpke_recipient_key or ec.generate_private_key(ec.SECP256R1())
        self._hpke_info = hpke_info
        self._external_aad = external_aad

    # ── published keys ───────────────────────────────────────────────────────────
    @property
    def verifier_id(self) -> str:
        """Return the ``ear.verifier-id.developer`` this instance stamps into its EARs.

        Public because it is what a Relying Party keys its EAR trust anchor on; reading
        it from the configured verifier is how an RA avoids selecting an anchor by the
        developer name carried in the (not yet verified) token.
        """
        return self._verifier_developer

    def evidence_encryption_spki_der(self) -> bytes:
        """Return the HPKE recipient public key as SubjectPublicKeyInfo DER.

        The DER form of :meth:`evidence_encryption_jwk`, for the CMP leg: it is what
        ``NonceResponse.respTypeInfo.respInfo`` carries so the attester learns which key
        to encrypt its Evidence to.
        """
        return evidence.hpke_key_to_spki_der(self._hpke_recipient_key.public_key())

    def evidence_encryption_jwk(self, *, kid: str | None = None) -> dict:
        """Return this verifier's HPKE recipient public key as a JWK for the attester.

        The recipient key is a plain EC P-256 key shared by JOSE-HPKE and COSE-HPKE
        (both use HPKE-0's DHKEM-P256 KEM), so the attester fetches it the same way;
        only the envelope it later produces (JWE vs ``COSE_Encrypt0``) differs.
        """
        jwk = cwt_jwt_utils.p256_public_to_jwk(self._hpke_recipient_key.public_key())
        jwk.update({"alg": cwt_jwt_utils.HPKE0_ALG, "use": "enc", "kid": kid or self.default_verifier_developer})
        return jwk

    def ear_verification_pem(self) -> str:
        """Return the EAR-JWT signing public key (PEM) for the MockCA to verify EARs."""
        return (
            self._ear_signing_key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii")
        )

    # ── AttestationVerifier interface ────────────────────────────────────────────
    @property
    def accepts(self) -> frozenset[str]:
        """Return the media types :meth:`verify_token` will appraise."""
        return frozenset({self.media_type, OCTET_STREAM})

    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: bytes | None = None,
    ) -> VerifyResult:
        """Appraise one CMW/HPKE statement and, on success, issue a signed EAR JWT.

        ``token_bytes`` is the ``AttestationStatement.stmt`` DER (a CMW ``UTF8String``),
        i.e. what :meth:`libattest.verifier.router.VerifierRouter.verify_bundle` passes.
        A missing nonce is ``contraindicated``, never a pass: with no RA-issued nonce
        there is nothing to bind the Evidence to and replay is unconstrained.
        """
        if base_media_type(media_type) not in self.accepts:
            return VerifyResult.unknown(f"unsupported media type {media_type!r}; expected {self.media_type!r}")
        if not nonce:
            return VerifyResult.contraindicated(f"missing freshness nonce for {self.default_verifier_developer}")
        return self._appraise(token_bytes, nonce)

    def verify_bundle_der(self, bundle_der: bytes, nonce: bytes) -> VerifyResult:
        """Appraise the first statement of an AttestationBundle DER (convenience entrypoint).

        The demo service receives the whole bundle in one POST; this unwraps it with the
        shared :mod:`libattest.formats.eareat_hpke` helpers (no hand-rolled ASN.1).
        """
        try:
            stmt_der = evidence.first_statement_der(bundle_der)
        except (ValueError, KeyError) as exc:
            logger.warning("bundle decode failed: %s", exc)
            return VerifyResult.contraindicated(f"bundle decode failed: {exc}")
        return self.verify_token(stmt_der, self.media_type, nonce)

    # ── the one transport-specific step ──────────────────────────────────────────
    @abstractmethod
    def _appraise(self, stmt_der: bytes, expected_nonce: bytes) -> VerifyResult:
        """Open the transport's envelope, verify the inner signature, and appraise."""

    # ── EAR issuance ─────────────────────────────────────────────────────────────
    def issue_ear(self, nonce: bytes, status: str = "contraindicated") -> str:
        """Sign an EAR JWT for *status* over *nonce*.

        An affirming verdict already carries its EAR as the ``VerifyResult.payload``;
        this is for callers that must also emit an EAR for a rejected verdict (e.g. a
        service that returns an EAR regardless of outcome).
        """
        return self._build_ear_jwt(cwt_jwt_utils.b64u_encode(nonce), status)

    def _build_ear_jwt(self, nonce_b64url: str, status: str) -> str:
        trust_vector = (
            {key: 0 for key in _TRUST_VECTOR_KEYS} if status == "affirming" else {key: 99 for key in _TRUST_VECTOR_KEYS}
        )
        return build_ear_jwt(
            signing_key=self._ear_signing_key,
            verifier_developer=self._verifier_developer,
            scheme_name=self._scheme_name,
            nonce=cwt_jwt_utils.b64u_decode(nonce_b64url),
            status=status,
            trust_vector=trust_vector,
        )


__all__ = [
    "DEFAULT_REFERENCE_MOCK_CLAIM",
    "DEFAULT_SCHEME_NAME",
    "OCTET_STREAM",
    "HpkeEarVerifier",
    "ear_token_to_veraison_claims",
    "load_ec_public_key",
]

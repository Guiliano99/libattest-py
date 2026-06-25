# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Privacy-preserving EAR/EAT verifier (JWT-HPKE demo).

Same RA-issued-nonce contract as the software EAR/EAT verifier, but the Evidence
arrives **encrypted for this verifier**: ``AttestationStatement.stmt`` is a CMW Record
(``["application/jose", <b64url JWE>, 4]``) carrying a JOSE-HPKE-0 JWE of the signed EAT.
Only this verifier (the HPKE recipient) can decrypt it — the MockCA and any on-path
observer see only ciphertext.

Appraisal gates (G0-G5): decode CMW -> HPKE-open -> verify inner EAT-JWS -> freshness
(inner ``eat_nonce`` AND protected-header ``eat_nonce`` == RA nonce) -> appraise
``mock_claim``.  Real decryption + verification; no stub path.

HPKE-0 via :mod:`libattest.formats.jose_hpke` and ES256 JWS via
:mod:`libattest.formats.jose_jws` — both on ``cryptography`` alone (no ``pyhpke`` /
``python-jose``).  An affirming verdict carries the signed EAR JWT as its
:attr:`~libattest.types.VerifyResult.payload`, which the RA engine harvests directly.
"""

from __future__ import annotations

import logging
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats import eareat_hpke as evidence
from libattest.formats import jose_hpke, jose_jws
from libattest.media_types import EAT_JWT, base_media_type
from libattest.types import VerifyResult
from libattest.verifier.base import AttestationVerifier

logger = logging.getLogger(__name__)

DEFAULT_SCHEME_NAME = "ATG_PLUGIN"
DEFAULT_REFERENCE_MOCK_CLAIM = "secure"
_EAT_PROFILE = "tag:github.com,2023:veraison/ear"
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


class EarEatHpkeVerifier(AttestationVerifier):
    """Verifier for JOSE-HPKE-0-encrypted EAR/EAT evidence.

    Parameters
    ----------
    attestation_public_key:
        The attester's EAT-JWS verification key (an EC public key, or PEM/DER bytes).
    reference_mock_claim:
        The ``mock_claim`` value an affirming attestation must present.
    scheme_name:
        The EAR ``submods`` scheme key (defaults to ``ATG_PLUGIN``).
    ear_signing_key / hpke_recipient_key:
        Optional P-256 keys; fresh ones are generated when omitted.  The EAR key
        signs issued EARs (publish :meth:`ear_verification_pem`); the HPKE key is the
        recipient the attester encrypts Evidence to (publish :meth:`evidence_encryption_jwk`).

    """

    media_type = EAT_JWT

    def __init__(
        self,
        *,
        attestation_public_key: ec.EllipticCurvePublicKey | bytes | str,
        reference_mock_claim: str = DEFAULT_REFERENCE_MOCK_CLAIM,
        scheme_name: str = DEFAULT_SCHEME_NAME,
        ear_signing_key: ec.EllipticCurvePrivateKey | None = None,
        hpke_recipient_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        """Store appraisal policy and the verifier's signing / recipient keys."""
        self._attestation_public_key = attestation_public_key
        self._reference_mock_claim = reference_mock_claim
        self._scheme_name = scheme_name
        self._ear_signing_key = ear_signing_key or ec.generate_private_key(ec.SECP256R1())
        self._hpke_recipient_key = hpke_recipient_key or ec.generate_private_key(ec.SECP256R1())

    # ── published keys ───────────────────────────────────────────────────────────
    def evidence_encryption_jwk(self, *, kid: str = "eareat-hpke-verifier") -> dict:
        """Return this verifier's HPKE recipient public key as a JWK for the attester."""
        jwk = jose_jws.p256_public_to_jwk(self._hpke_recipient_key.public_key())
        jwk.update({"alg": jose_hpke.ALG, "use": "enc", "kid": kid})
        return jwk

    def ear_verification_pem(self) -> str:
        """Return the EAR-JWT signing public key (PEM) for the MockCA to verify EARs."""
        return self._ear_signing_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    # ── AttestationVerifier interface ────────────────────────────────────────────
    def get_nonce(self, nonce_size: int = 32) -> bytes:
        """Return empty bytes: the RA/MockCA issues the nonce for this stateless flow."""
        return b""

    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: bytes | None = None,
    ) -> VerifyResult:
        """Appraise one CMW/JOSE-HPKE statement and, on success, issue a signed EAR JWT.

        ``token_bytes`` is the ``AttestationStatement.stmt`` DER (a CMW ``UTF8String``),
        i.e. what :meth:`libattest.verifier.router.VerifierRouter.verify_bundle` passes.
        """
        if base_media_type(media_type) not in (EAT_JWT, "application/octet-stream"):
            return VerifyResult.unknown(f"unsupported media type {media_type!r}; expected {EAT_JWT!r}")
        if not nonce:
            return VerifyResult.contraindicated("missing freshness nonce for HPKE EAR/EAT appraisal")
        return self._appraise(token_bytes, nonce)

    def nonce_response(self, nonce: bytes, *, expiry: int | None = None) -> bytes:
        """Return a ``NonceResponse`` DER handing the attester *nonce* + this verifier's HPKE key.

        Uses libattest's CMP nonce-freshness structures (``NonceResponse``); the attester
        reads ``respInfo`` to learn the recipient key to encrypt Evidence to.
        """
        return evidence.build_evidence_enc_nonce_response(
            nonce, self._hpke_recipient_key.public_key(), expiry=expiry
        )

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

    # ── gates G0-G5 ──────────────────────────────────────────────────────────────
    def _appraise(self, stmt_der: bytes, expected_nonce: bytes) -> VerifyResult:
        expected_b64u = jose_jws.b64u_encode(expected_nonce)
        try:
            jwe = evidence.extract_jwe_from_statement(stmt_der)                   # G0
            header, inner = jose_hpke.open_integrated(jwe, self._hpke_recipient_key)  # G1/G2
        except (ValueError, InvalidTag) as exc:
            logger.warning("evidence decode/decrypt failed: %s", exc)
            return VerifyResult.contraindicated(f"evidence decode/decrypt failed: {exc}")

        if header.get("eat_nonce") != expected_b64u:                             # G4a
            return VerifyResult.contraindicated("protected-header eat_nonce mismatch")

        try:                                                                     # G3
            claims = jose_jws.verify_es256(inner.decode("ascii"), self._attestation_public_key)
        except (ValueError, jose_jws.InvalidSignature) as exc:
            logger.warning("inner EAT-JWS verification failed: %s", exc)
            return VerifyResult.contraindicated(f"inner EAT-JWS verification failed: {exc}")

        if claims.get("eat_nonce") != expected_b64u:                            # G4b
            return VerifyResult.contraindicated("inner eat_nonce mismatch")

        if claims.get("mock_claim") != self._reference_mock_claim:              # G5
            return VerifyResult.contraindicated(f"mock_claim {claims.get('mock_claim')!r} does not match reference")

        logger.info("appraisal passed: mock_claim matches reference")
        return VerifyResult.affirming(self._build_ear_jwt(expected_b64u, "affirming"))

    # ── EAR issuance ─────────────────────────────────────────────────────────────
    def issue_ear(self, nonce: bytes, status: str = "contraindicated") -> str:
        """Sign an EAR JWT for *status* over *nonce*.

        An affirming verdict already carries its EAR as the ``VerifyResult.payload``;
        this is for callers that must also emit an EAR for a rejected verdict (e.g. a
        service that returns an EAR regardless of outcome).
        """
        return self._build_ear_jwt(jose_jws.b64u_encode(nonce), status)

    def _build_ear_jwt(self, nonce_b64url: str, status: str) -> str:
        trust_vector = (
            {key: 0 for key in _TRUST_VECTOR_KEYS}
            if status == "affirming"
            else {key: 99 for key in _TRUST_VECTOR_KEYS}
        )
        payload = {
            "eat_profile": _EAT_PROFILE,
            "iat": int(time.time()),
            "eat_nonce": nonce_b64url,
            "ear.verifier-id": {"build": "N/A", "developer": "eareat-hpke-verifier"},
            "submods": {
                self._scheme_name: {
                    "ear.status": status,
                    "ear.appraisal-policy-id": f"policy:{self._scheme_name}",
                    "ear.trustworthiness-vector": trust_vector,
                }
            },
        }
        return jose_jws.sign_es256(payload, self._ear_signing_key)


__all__ = ["EarEatHpkeVerifier"]

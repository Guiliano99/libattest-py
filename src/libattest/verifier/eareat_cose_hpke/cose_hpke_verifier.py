# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Privacy-preserving EAR/EAT verifier (COSE-HPKE demo, draft-ietf-cose-hpke).

COSE sibling of :class:`libattest.verifier.eareat_hpke.EarEatHpkeVerifier`.  Same
RA-issued-nonce contract, same VerifyResult/EAR-issuance shape, same Flask-facing
API (:meth:`verify_bundle_der` / :meth:`verify_token` / :meth:`evidence_encryption_jwk`
/ :meth:`ear_verification_pem`).  Only the evidence leg differs: the Evidence is a
``COSE_Encrypt0`` (integrated COSE-HPKE-0) carrying a nested ``COSE_Sign1`` over the
CWT-mapped EAT claims, rather than a JOSE-HPKE JWE over an EAT-JWS.

Appraisal gates:

* **G0** decode the CMW ``json`` record → base64url → ``COSE_Encrypt0`` bytes;
* **G1/G2** COSE-HPKE-open with the verifier's recipient key (AEAD/tamper failure → contraindicated);
* **G3** verify the nested ``COSE_Sign1`` against the attester's EAT key (done inside the same
  ``open_cose_hpke_evidence`` call via ``verify_key``);
* **G4** freshness: CWT ``eat_nonce`` claim == RA nonce;
* **G5** appraise ``mock_claim`` against the reference.

The EAR itself stays a signed JWS in Veraison wire format (the COSE change is on the
Evidence leg only), so ``_build_ear_jwt`` mirrors the JOSE verifier verbatim except for
the ``ear.verifier-id.developer`` value (``cose-hpke-verifier``), which the demo asserts
to prove the encrypted COSE route was taken.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cwt.exceptions import CWTError

from libattest.formats import eareat_hpke as evidence
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.eat_ear.cwt_jwt import EARAppraisal, EARToken, EATNonce, TrustworthinessTier
from libattest.formats.eat_ear.cwt_jwt_utils import open_cose_hpke_evidence
from libattest.media_types import EAT_CWT, base_media_type
from libattest.types import VerifyResult
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.eat_appraisal import check_nonce_and_claim

logger = logging.getLogger(__name__)

DEFAULT_SCHEME_NAME = "ATG_PLUGIN"
DEFAULT_REFERENCE_MOCK_CLAIM = "secure"
DEFAULT_VERIFIER_DEVELOPER = "cose-hpke-verifier"
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


def _load_ec_public_key(
    key: ec.EllipticCurvePublicKey | bytes | str,
) -> ec.EllipticCurvePublicKey:
    """Normalise an EC public key given as an object, PEM/DER bytes, or a PEM string.

    ``open_cose_hpke_evidence``'s COSE_Sign1 verify needs a real key object, whereas the
    demo Flask service passes the attester key as raw PEM bytes read off disk.
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


def _ear_token_to_veraison_claims(token: EARToken) -> dict[str, Any]:
    """Re-key a draft-04 EARToken into the Veraison EAR claims-set (dotted keys)."""
    submods: dict[str, Any] = {}
    for name, appr in token.submods.items():
        submod: dict[str, Any] = {
            "ear.status": appr.status.value,
            "ear.trustworthiness-vector": appr.trustworthiness_vector,
        }
        if appr.appraisal_policy_ids:
            submod["ear.appraisal-policy-id"] = appr.appraisal_policy_ids[0]
        submods[name] = submod
    claims: dict[str, Any] = {
        "eat_profile": token.eat_profile,
        "iat": token.iat,
        "ear.verifier-id": token.verifier_id,
        "submods": submods,
    }
    if token.nonce is not None:
        claims["eat_nonce"] = token.nonce.as_b64_str()
    return claims


class CoseEatHpkeVerifier(AttestationVerifier):
    """Verifier for COSE-HPKE-0-encrypted EAR/EAT evidence.

    Parameters
    ----------
    attestation_public_key:
        The attester's EAT signing key (an EC public key, or PEM/DER bytes) used to verify
        the nested ``COSE_Sign1``.
    reference_mock_claim:
        The ``mock_claim`` value an affirming attestation must present.
    scheme_name:
        The EAR ``submods`` scheme key (defaults to ``ATG_PLUGIN``).
    verifier_developer:
        The ``ear.verifier-id.developer`` stamped into issued EARs (defaults to
        ``cose-hpke-verifier``); the demo asserts it to prove the COSE route.
    ear_signing_key / hpke_recipient_key:
        Optional P-256 keys; fresh ones are generated when omitted.

    """

    media_type = EAT_CWT

    def __init__(
        self,
        *,
        attestation_public_key: ec.EllipticCurvePublicKey | bytes | str,
        reference_mock_claim: str = DEFAULT_REFERENCE_MOCK_CLAIM,
        scheme_name: str = DEFAULT_SCHEME_NAME,
        verifier_developer: str = DEFAULT_VERIFIER_DEVELOPER,
        ear_signing_key: ec.EllipticCurvePrivateKey | None = None,
        hpke_recipient_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        """Store appraisal policy and the verifier's signing / recipient keys."""
        self._attestation_public_key = _load_ec_public_key(attestation_public_key)
        self._reference_mock_claim = reference_mock_claim
        self._scheme_name = scheme_name
        self._verifier_developer = verifier_developer
        self._ear_signing_key = ear_signing_key or ec.generate_private_key(ec.SECP256R1())
        self._hpke_recipient_key = hpke_recipient_key or ec.generate_private_key(ec.SECP256R1())

    # ── published keys ───────────────────────────────────────────────────────────
    def evidence_encryption_jwk(self, *, kid: str = "cose-hpke-verifier") -> dict:
        """Return this verifier's HPKE recipient public key as a JWK for the attester.

        The recipient key is a plain EC P-256 key shared by JOSE-HPKE and COSE-HPKE (both
        use HPKE-0's DHKEM-P256 KEM), so the attester fetches it the same way; only the
        envelope it later produces (COSE_Encrypt0 vs JWE) differs.
        """
        jwk = cwt_jwt_utils.p256_public_to_jwk(self._hpke_recipient_key.public_key())
        jwk.update({"alg": cwt_jwt_utils.HPKE0_ALG, "use": "enc", "kid": kid})
        return jwk

    def ear_verification_pem(self) -> str:
        """Return the EAR-JWT signing public key (PEM) for the MockCA to verify EARs."""
        return (
            self._ear_signing_key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii")
        )

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
        """Appraise one CMW/COSE-HPKE statement and, on success, issue a signed EAR JWT.

        ``token_bytes`` is the ``AttestationStatement.stmt`` DER (a CMW ``UTF8String``).
        """
        if base_media_type(media_type) not in (EAT_CWT, "application/octet-stream"):
            return VerifyResult.unknown(f"unsupported media type {media_type!r}; expected {EAT_CWT!r}")
        if not nonce:
            return VerifyResult.contraindicated("missing freshness nonce for COSE-HPKE EAR/EAT appraisal")
        return self._appraise(token_bytes, nonce)

    def verify_bundle_der(self, bundle_der: bytes, nonce: bytes) -> VerifyResult:
        """Appraise the first statement of an AttestationBundle DER (convenience entrypoint)."""
        try:
            stmt_der = evidence.first_statement_der(bundle_der)
        except (ValueError, KeyError) as exc:
            logger.warning("bundle decode failed: %s", exc)
            return VerifyResult.contraindicated(f"bundle decode failed: {exc}")
        return self.verify_token(stmt_der, self.media_type, nonce)

    # ── gates G0-G5 ──────────────────────────────────────────────────────────────
    def _appraise(self, stmt_der: bytes, expected_nonce: bytes) -> VerifyResult:
        try:
            cose = evidence.extract_cose_from_statement(stmt_der)  # G0
            # G1/G2 COSE-HPKE-open + G3 nested COSE_Sign1 verify, in one call.
            claims = open_cose_hpke_evidence(cose, self._hpke_recipient_key, verify_key=self._attestation_public_key)
        except (ValueError, InvalidTag, CWTError) as exc:
            logger.warning("evidence decode/decrypt/verify failed: %s", exc)
            return VerifyResult.contraindicated(f"evidence decode/decrypt/verify failed: {exc}")

        if not isinstance(claims, dict):
            return VerifyResult.contraindicated("COSE payload is not a CWT claims map")

        # G4 (eat_nonce freshness) + G5 (mock_claim) — shared with the JOSE demo's appraisal tail.
        status, reason = check_nonce_and_claim(claims, expected_nonce, self._reference_mock_claim)
        if status != "affirming":
            return VerifyResult.contraindicated(reason)

        logger.info("appraisal passed: mock_claim matches reference")
        return VerifyResult.affirming(self._build_ear_jwt(cwt_jwt_utils.b64u_encode(expected_nonce), "affirming"))

    # ── EAR issuance ─────────────────────────────────────────────────────────────
    def issue_ear(self, nonce: bytes, status: str = "contraindicated") -> str:
        """Sign an EAR JWT for *status* over *nonce* (for callers that emit an EAR on rejection too)."""
        return self._build_ear_jwt(cwt_jwt_utils.b64u_encode(nonce), status)

    def _build_ear_jwt(self, nonce_b64url: str, status: str) -> str:
        trust_vector = (
            {key: 0 for key in _TRUST_VECTOR_KEYS} if status == "affirming" else {key: 99 for key in _TRUST_VECTOR_KEYS}
        )
        token = EARToken(
            eat_profile=_EAT_PROFILE,
            iat=int(time.time()),
            ear_verifier_id={"build": "N/A", "developer": self._verifier_developer},
            eat_nonce=EATNonce(cwt_jwt_utils.b64u_decode(nonce_b64url)),
            submods={
                self._scheme_name: EARAppraisal(
                    ear_status=TrustworthinessTier(status),
                    ear_trustworthiness_vector=trust_vector,
                    ear_appraisal_policy_ids=[f"policy:{self._scheme_name}"],
                )
            },
        )
        return cwt_jwt_utils.sign_es256(_ear_token_to_veraison_claims(token), self._ear_signing_key)


__all__ = ["CoseEatHpkeVerifier"]

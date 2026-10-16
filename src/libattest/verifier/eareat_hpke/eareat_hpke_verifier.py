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

Only the G0-G5 leg lives here.  Key publication, the media-type/nonce gates and EAR
issuance are shared with the COSE sibling in
:class:`~libattest.verifier.hpke_base.HpkeEarVerifier`.

HPKE-0 and ES256 JWS both come from :mod:`libattest.formats.eat_ear.cwt_jwt_utils`, on
``cryptography`` alone (no ``pyhpke`` / ``python-jose``).  An affirming verdict carries
the signed EAR JWT as its :attr:`~libattest.types.VerifyResult.payload`, which the RA
engine harvests directly.
"""

from __future__ import annotations

import logging
from typing import ClassVar

from cryptography.exceptions import InvalidTag

from libattest.formats import eareat_hpke as evidence
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.media_types import EAT_JWT
from libattest.types import VerifyResult
from libattest.verifier.eat_appraisal import check_nonce_and_claim, eat_nonce_bytes
from libattest.verifier.hpke_base import (
    DEFAULT_REFERENCE_MOCK_CLAIM,
    DEFAULT_SCHEME_NAME,
    HpkeEarVerifier,
)

logger = logging.getLogger(__name__)

DEFAULT_VERIFIER_DEVELOPER = "eareat-hpke-verifier"


class EarEatHpkeVerifier(HpkeEarVerifier):
    """Verifier for JOSE-HPKE-0-encrypted EAR/EAT evidence.

    See :class:`~libattest.verifier.hpke_base.HpkeEarVerifier` for the constructor
    parameters; this subclass supplies only the JOSE evidence leg.
    """

    media_type: ClassVar[str] = EAT_JWT
    default_verifier_developer: ClassVar[str] = DEFAULT_VERIFIER_DEVELOPER

    # ── gates G0-G5 ──────────────────────────────────────────────────────────────
    def _appraise(self, stmt_der: bytes, expected_nonce: bytes) -> VerifyResult:
        """Open the JWE, verify the inner EAT-JWS, and appraise freshness + ``mock_claim``."""
        expected_b64u = cwt_jwt_utils.b64u_encode(expected_nonce)
        try:
            jwe = evidence.extract_jwe_from_statement(stmt_der)  # G0
            header, inner = cwt_jwt_utils.open_integrated(  # G1/G2
                jwe, self._hpke_recipient_key, hpke_info=self._hpke_info
            )
        except (ValueError, InvalidTag) as exc:
            logger.warning("evidence decode/decrypt failed: %s", exc)
            return VerifyResult.contraindicated(f"evidence decode/decrypt failed: {exc}")

        if eat_nonce_bytes(header.get("eat_nonce", "")) != expected_nonce:  # G4a
            return VerifyResult.contraindicated("protected-header eat_nonce mismatch")

        try:  # G3
            claims = cwt_jwt_utils.verify_es256(inner.decode("ascii"), self._attestation_public_key)
        except (ValueError, cwt_jwt_utils.InvalidSignature) as exc:
            logger.warning("inner EAT-JWS verification failed: %s", exc)
            return VerifyResult.contraindicated(f"inner EAT-JWS verification failed: {exc}")

        # G4b (inner eat_nonce) + G5 (mock_claim) — shared with the plaintext demo
        # verifier's appraisal tail so both demos apply identical freshness/claim logic.
        status, reason = check_nonce_and_claim(claims, expected_nonce, self._reference_mock_claim)
        if status != "affirming":
            return VerifyResult.contraindicated(reason)

        logger.info("appraisal passed: mock_claim matches reference")
        return VerifyResult.affirming(self._build_ear_jwt(expected_b64u, "affirming"))


__all__ = [
    "DEFAULT_REFERENCE_MOCK_CLAIM",
    "DEFAULT_SCHEME_NAME",
    "DEFAULT_VERIFIER_DEVELOPER",
    "EarEatHpkeVerifier",
]

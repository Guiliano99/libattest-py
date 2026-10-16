# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Privacy-preserving EAR/EAT verifier (COSE-HPKE demo, draft-ietf-cose-hpke).

COSE sibling of :class:`libattest.verifier.eareat_hpke.EarEatHpkeVerifier`.  Same
RA-issued-nonce contract, same VerifyResult/EAR-issuance shape, same Flask-facing
API (:meth:`verify_bundle_der` / :meth:`verify_token` / :meth:`evidence_encryption_jwk`
/ :meth:`ear_verification_pem`) — all of it inherited from the shared
:class:`~libattest.verifier.hpke_base.HpkeEarVerifier`.  Only the evidence leg differs:
the Evidence is a ``COSE_Encrypt0`` (integrated COSE-HPKE-0) carrying a nested
``COSE_Sign1`` over the CWT-mapped EAT claims, rather than a JOSE-HPKE JWE over an
EAT-JWS.

Appraisal gates:

* **G0** decode the CMW ``json`` record → base64url → ``COSE_Encrypt0`` bytes;
* **G1/G2** COSE-HPKE-open with the verifier's recipient key (AEAD/tamper failure → contraindicated);
* **G3** verify the nested ``COSE_Sign1`` against the attester's EAT key (done inside the same
  ``open_cose_hpke_evidence`` call via ``verify_key``);
* **G4** freshness: CWT ``eat_nonce`` claim == RA nonce;
* **G5** appraise ``mock_claim`` against the reference.

The EAR itself stays a signed JWS in Veraison wire format (the COSE change is on the
Evidence leg only); the ``ear.verifier-id.developer`` value is ``cose-hpke-verifier``,
which the demo asserts to prove the encrypted COSE route was taken.
"""

from __future__ import annotations

import logging
from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cwt.exceptions import CWTError

from libattest.formats import eareat_hpke as evidence
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.eat_ear.cwt_jwt_utils import open_cose_hpke_evidence
from libattest.formats.media_types import EAT_CWT
from libattest.types import VerifyResult
from libattest.verifier.eat_appraisal import check_nonce_and_claim
from libattest.verifier.hpke_base import (
    DEFAULT_REFERENCE_MOCK_CLAIM,
    DEFAULT_SCHEME_NAME,
    HpkeEarVerifier,
)

logger = logging.getLogger(__name__)

DEFAULT_VERIFIER_DEVELOPER = "cose-hpke-verifier"


class CoseEatHpkeVerifier(HpkeEarVerifier):
    """Verifier for COSE-HPKE-0-encrypted EAR/EAT evidence.

    See :class:`~libattest.verifier.hpke_base.HpkeEarVerifier` for the constructor
    parameters; this subclass supplies only the COSE evidence leg.
    """

    media_type: ClassVar[str] = EAT_CWT
    default_verifier_developer: ClassVar[str] = DEFAULT_VERIFIER_DEVELOPER

    # ── gates G0-G5 ──────────────────────────────────────────────────────────────
    def _appraise(self, stmt_der: bytes, expected_nonce: bytes) -> VerifyResult:
        """Open the ``COSE_Encrypt0``, verify the nested ``COSE_Sign1``, and appraise."""
        try:
            cose = evidence.extract_cose_from_statement(stmt_der)  # G0
            # G1/G2 COSE-HPKE-open + G3 nested COSE_Sign1 verify, in one call.
            claims = open_cose_hpke_evidence(
                cose,
                self._hpke_recipient_key,
                verify_key=self._attestation_public_key,
                hpke_info=self._hpke_info,
                external_aad=self._external_aad,
            )
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


__all__ = [
    "DEFAULT_REFERENCE_MOCK_CLAIM",
    "DEFAULT_SCHEME_NAME",
    "DEFAULT_VERIFIER_DEVELOPER",
    "CoseEatHpkeVerifier",
]

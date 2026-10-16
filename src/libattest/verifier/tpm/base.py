# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for TPM verifier implementations."""

import logging
from typing import Any

from libattest.types import VerifyResult
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.reference import VerifierReferenceHandler

logger = logging.getLogger(__name__)


class TpmReferenceVerifier(AttestationVerifier):
    """Base verifier that delegates evidence appraisal to a reference handler."""

    media_type = "application/octet-stream"

    def __init__(
        self,
        *,
        reference_handler: VerifierReferenceHandler,
        result_payload: str = "accepted",
    ) -> None:
        """Store the reference handler and accepted verdict payload string."""
        self.reference_handler = reference_handler
        self.result_payload = result_payload

    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: bytes | None = None,
    ) -> VerifyResult:
        """Run the reference-value check; never affirm on it alone.

        This base class performs **no cryptographic appraisal**: it does not parse
        ``TPMS_ATTEST``, check the TPM generated-value magic, or verify the AK
        signature. Affirming here would mean affirming arbitrary bytes — with the
        shipped :class:`~libattest.verifier.reference.AcceptAllReferenceHandler`,
        unconditionally, and with no freshness binding at all.

        So a passing reference check yields ``unknown`` ("no claim being made"),
        which is the honest RATS verdict for an appraisal that did not happen. A
        failing one still contraindicates, so the handler keeps its power to reject.
        Subclasses that can appraise must override this — see
        :meth:`~libattest.verifier.tpm.tpm_platform_verifier.TpmPlatformVerifier.appraise_quote`.
        """
        if media_type != self.media_type:
            logger.debug("Unsupported media type %r (expected %r)", media_type, self.media_type)
            return VerifyResult.unknown(f"unsupported media type {media_type!r}; expected {self.media_type!r}")

        if not nonce:
            return VerifyResult.contraindicated("no freshness nonce supplied for TPM evidence appraisal")

        ref_result = self.reference_handler.handle_evidence(
            self._normalise_evidence(token_bytes),
            attester_id=None,
        )
        if not ref_result.accepted:
            reason = ref_result.reason or "evidence does not match reference values"
            logger.info("Evidence rejected: %s", reason)
            return VerifyResult.contraindicated(reason)

        logger.warning(
            "%s.verify_token performed no cryptographic appraisal; returning 'unknown'. "
            "Override verify_token with a real appraisal to affirm TPM evidence.",
            type(self).__name__,
        )
        return VerifyResult.unknown(
            "reference values matched, but this verifier performed no cryptographic "
            "appraisal of the TPM evidence (no TPMS_ATTEST parse, no AK signature check)"
        )

    def _normalise_evidence(self, token_bytes: bytes) -> Any:
        """Return evidence in the representation expected by the handler."""
        return token_bytes

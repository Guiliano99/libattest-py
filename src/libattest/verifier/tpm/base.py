# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for TPM verifier implementations."""

import logging
import secrets
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

    def get_nonce(self, nonce_size: int = 32) -> bytes:
        """Return a random nonce for TPM evidence freshness."""
        return secrets.token_bytes(nonce_size)

    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: bytes | None = None,
    ) -> VerifyResult:
        """Verify TPM evidence with the configured reference handler."""
        if media_type != self.media_type:
            logger.debug("Unsupported media type %r (expected %r)", media_type, self.media_type)
            return VerifyResult.unknown(f"unsupported media type {media_type!r}; expected {self.media_type!r}")

        ref_result = self.reference_handler.handle_evidence(
            self._normalise_evidence(token_bytes),
            attester_id=None,
        )
        if not ref_result.accepted:
            reason = ref_result.reason or "evidence does not match reference values"
            logger.info("Evidence rejected: %s", reason)
            return VerifyResult.contraindicated(reason)

        return VerifyResult.affirming(self.result_payload)

    def _normalise_evidence(self, token_bytes: bytes) -> Any:
        """Return evidence in the representation expected by the handler."""
        return token_bytes

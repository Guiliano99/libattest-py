# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Abstract verifier interface."""

import logging
from abc import ABC, abstractmethod

from libattest.types import VerifyResult

logger = logging.getLogger(__name__)


class AttestationVerifier(ABC):
    """Interface implemented by concrete attestation verifiers."""

    @abstractmethod
    def get_nonce(self, nonce_size: int = 32) -> bytes:
        """Return fresh nonce bytes, or empty bytes if no nonce is available."""

    @abstractmethod
    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: bytes | None = None,
    ) -> VerifyResult:
        """Verify evidence and return a typed attestation result.

        Parameters
        ----------
        token_bytes:
            Raw attestation evidence bytes.
        media_type:
            IANA media type of *token_bytes*.
        nonce:
            Freshness nonce originally issued for this session, if any.

        Returns
        -------
        VerifyResult
            Typed verdict with status, optional payload, errors, and warnings.
            Use :attr:`VerifyResult.accepted` to check the outcome.

        """

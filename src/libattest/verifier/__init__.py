# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Verifier-side abstractions and routing helpers."""

from libattest.types import BundleVerifyResult, EarStatus, VerifyResult
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.endpoints import (
    CORIM_MEDIA_TYPE,
    DEFAULT_PROVISIONING_PORT,
    DEFAULT_VERIFICATION_PORT,
    DEFAULT_VERIFIER_HOST,
    NEW_SESSION_PATH,
    PROVISIONING_BASE_PATH,
    PROVISIONING_MEDIA_TYPE,
    PROVISIONING_SESSION_PATH_TEMPLATE,
    PROVISIONING_SUBMIT_PATH,
    SESSION_MEDIA_TYPE,
    SESSION_PATH_TEMPLATE,
    VERIFICATION_BASE_PATH,
    WELL_KNOWN_VERIFICATION_PATH,
    VerifierEndpointConfig,
)
from libattest.verifier.reference import (
    ReferenceCheckResult,
    VerifierReferenceHandler,
)
from libattest.verifier.router import (
    VerifierRoute,
    VerifierRouteError,
    VerifierRouter,
    VerifierRoutingPolicy,
)

__all__ = [
    "AttestationVerifier",
    "BundleVerifyResult",
    "CORIM_MEDIA_TYPE",
    "DEFAULT_PROVISIONING_PORT",
    "DEFAULT_VERIFICATION_PORT",
    "DEFAULT_VERIFIER_HOST",
    "EarStatus",
    "NEW_SESSION_PATH",
    "PROVISIONING_BASE_PATH",
    "PROVISIONING_MEDIA_TYPE",
    "PROVISIONING_SESSION_PATH_TEMPLATE",
    "PROVISIONING_SUBMIT_PATH",
    "ReferenceCheckResult",
    "SESSION_MEDIA_TYPE",
    "SESSION_PATH_TEMPLATE",
    "VERIFICATION_BASE_PATH",
    "VerifierEndpointConfig",
    "VerifierReferenceHandler",
    "VerifierRoute",
    "VerifierRouteError",
    "VerifierRouter",
    "VerifierRoutingPolicy",
    "VerifyResult",
    "WELL_KNOWN_VERIFICATION_PATH",
]

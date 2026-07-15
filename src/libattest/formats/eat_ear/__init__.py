# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""EAT/EAR token logic: models, CWT/JWT conversion, and JOSE/COSE sign/seal.

Consolidated home for the EAT/EAR token representation (see
docs/plans/eat_ear-consolidation.hardened.md):

* :mod:`.cwt_jwt` — EAT/EAR pydantic models (``EATClaimsSet``, ``EARToken``) + the
  ``ClaimDef`` claim registry + CWT Claim Set <-> JWT-style View conversion + the EAR
  JWT signature verifier.
* :mod:`.cwt_jwt_utils` — ES256 keygen, verified JWT->CWT re-issue, ES256 JWS, and
  JOSE/COSE HPKE-0 sealing.

Only the lightweight token layer is re-exported here. The signing/sealing helpers live
in :mod:`.cwt_jwt_utils` and are imported from there directly, so importing this package
does not pull in the HPKE backend for callers that only need the models.

The unverified inspectors ``parse_ear_verdict`` and ``cose_cwt_to_jwt_view`` are
deliberately NOT re-exported at this level (they render without verifying a signature);
import them from :mod:`.cwt_jwt` explicitly when that is intended.
"""

from __future__ import annotations

from libattest.formats.eat_ear.cwt_jwt import (
    CLAIMS,
    EAR_PROFILE,
    Base64UrlBytes,
    ClaimDef,
    ClaimSet,
    DebugStatus,
    DLOAEntry,
    EARAppraisal,
    EARToken,
    EATClaimsSet,
    EATNonce,
    IntendedUse,
    JwtStyleView,
    Location,
    MeasurementResult,
    SoftwareMeasurement,
    TrustworthinessTier,
    cwt_claim_set_to_jwt_view,
    ear_is_affirming,
    jwt_claims_to_cwt_claim_set,
    jwt_style_view_to_cwt_claim_set,
    verify_ear_jwt,
)

__all__ = [
    "CLAIMS",
    "EAR_PROFILE",
    "Base64UrlBytes",
    "ClaimDef",
    "ClaimSet",
    "DLOAEntry",
    "DebugStatus",
    "EARAppraisal",
    "EARToken",
    "EATClaimsSet",
    "EATNonce",
    "IntendedUse",
    "JwtStyleView",
    "Location",
    "MeasurementResult",
    "SoftwareMeasurement",
    "TrustworthinessTier",
    "cwt_claim_set_to_jwt_view",
    "ear_is_affirming",
    "jwt_claims_to_cwt_claim_set",
    "jwt_style_view_to_cwt_claim_set",
    "verify_ear_jwt",
]

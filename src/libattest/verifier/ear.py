# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""EAR issuance shared by the in-process verifiers.

An EAR (draft-ietf-rats-ear) is built as a validated
:class:`~libattest.formats.eat_ear.cwt_jwt.EARToken` first, then emitted in the
Veraison wire format (profile ``tag:github.com,2023:veraison/ear``, dotted
``ear.*`` keys) and signed as an ES256 JWT. That is the format
:func:`libattest.formats.eat_ear.cwt_jwt.parse_ear_verdict` and the RA's
:class:`~libattest.ra.relying_party.EarAcceptancePolicy` consume.

The builder does not check the status against the trust vector: the caller owns
that mapping. The HPKE demo verifiers issue a ``warning`` EAR with an all-``99``
vector, which a guard here would refuse.
"""

from __future__ import annotations

import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.eat_ear.cwt_jwt import EARAppraisal, EARToken, EATNonce, TrustworthinessTier

_EAT_PROFILE = "tag:github.com,2023:veraison/ear"


def ear_token_to_veraison_claims(token: EARToken) -> dict[str, Any]:
    """Re-key a draft-04 :class:`EARToken` into the Veraison EAR claims-set (dotted keys).

    The EARToken is the validated, self-documenting intermediate; the wire format stays
    the Veraison one (``ear.status`` etc.) that
    :func:`libattest.formats.eat_ear.cwt_jwt.parse_ear_verdict` and the
    :class:`~libattest.ra.verifier_client.VeraisonVerifierClient` consume.
    """
    submods: dict[str, Any] = {}
    for name, appr in token.submods.items():
        submod: dict[str, Any] = {
            "ear.status": appr.status.value,
            "ear.trustworthiness-vector": appr.trustworthiness_vector,
        }
        if appr.appraisal_policy_ids:
            submod["ear.appraisal-policy-id"] = appr.appraisal_policy_ids[0]  # we set exactly one
        submods[name] = submod
    claims: dict[str, Any] = {
        "eat_profile": token.eat_profile,
        "iat": token.iat,
        "ear.verifier-id": token.verifier_id,
        "submods": submods,
    }
    if token.nonce is not None:
        claims["eat_nonce"] = token.nonce.as_b64_str()  # round-trips to the input base64url string
    return claims


def build_ear_jwt(
    *,
    signing_key: ec.EllipticCurvePrivateKey,
    verifier_developer: str,
    scheme_name: str,
    nonce: bytes,
    status: str,
    trust_vector: dict[str, int],
    policy_id: str | None = None,
) -> str:
    """Sign an EAR JWT with one ``submods`` entry and return the compact JWS.

    Parameters
    ----------
    signing_key:
        The verifier's P-256 EAR signing key (ES256).
    verifier_developer:
        ``ear.verifier-id.developer``; the RA may select its EAR trust anchor by it.
    scheme_name:
        The ``submods`` key for the appraised Attester.
    nonce:
        The RA nonce the EAR echoes as ``eat_nonce`` (8 to 64 bytes).
    status:
        ``ear.status``: ``affirming``, ``warning``, ``contraindicated`` or ``none``.
    trust_vector:
        ``ear.trustworthiness-vector``; an omitted AR4SI claim means "no claim".
    policy_id:
        ``ear.appraisal-policy-id``; defaults to ``policy:<scheme_name>``.

    Raises
    ------
    ValueError
        If *status* is not an AR4SI tier or the token does not validate
        (e.g. a nonce outside 8 to 64 bytes).

    """
    # Build a validated EARToken first (type-checks the status tier, nonce bounds, and
    # structure), then emit it in the Veraison wire format (dotted keys).
    token = EARToken(
        eat_profile=_EAT_PROFILE,  # override the draft-04 default with the Veraison profile
        iat=int(time.time()),
        ear_verifier_id={"build": "N/A", "developer": verifier_developer},
        eat_nonce=EATNonce(nonce),
        submods={
            scheme_name: EARAppraisal(
                ear_status=TrustworthinessTier(status),
                ear_trustworthiness_vector=trust_vector,
                ear_appraisal_policy_ids=[policy_id or f"policy:{scheme_name}"],
            )
        },
    )
    return cwt_jwt_utils.sign_es256(ear_token_to_veraison_claims(token), signing_key)


__all__ = ["build_ear_jwt", "ear_token_to_veraison_claims"]

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared EAR builder hoisted out of ``HpkeEarVerifier``.

The HPKE verifiers must issue the same EARs as before the hoist, apart from ``iat``.
``_pre_hoist_claims`` is the pre-hoist output: it reproduces, claim for claim, all
sixteen EARs captured from ``HpkeEarVerifier.issue_ear`` before the builder moved
(both transports, default and custom scheme/developer, all four statuses).
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.verifier.ear import build_ear_jwt, ear_token_to_veraison_claims
from libattest.verifier.eareat_cose_hpke import CoseEatHpkeVerifier
from libattest.verifier.eareat_hpke import EarEatHpkeVerifier
from libattest.verifier.hpke_base import ear_token_to_veraison_claims as reexported_claims

_NONCE = bytes(range(32))
_NONCE_B64U = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
_LEGACY_VECTOR_KEYS = (
    "configuration",
    "executables",
    "file-system",
    "hardware",
    "instance-identity",
    "runtime-opaque",
    "sourced-data",
    "storage-opaque",
)


def _pre_hoist_claims(developer: str, scheme: str, status: str) -> dict[str, Any]:
    """Return the claims (without ``iat``) the pre-hoist ``HpkeEarVerifier`` issued."""
    claim = 0 if status == "affirming" else 99
    return {
        "eat_profile": "tag:github.com,2023:veraison/ear",
        "ear.verifier-id": {"build": "N/A", "developer": developer},
        "eat_nonce": _NONCE_B64U,
        "submods": {
            scheme: {
                "ear.status": status,
                "ear.trustworthiness-vector": dict.fromkeys(_LEGACY_VECTOR_KEYS, claim),
                "ear.appraisal-policy-id": f"policy:{scheme}",
            }
        },
    }


def _claims_without_iat(ear_jwt: str, verification_key: ec.EllipticCurvePublicKey | str) -> dict[str, Any]:
    claims = cwt_jwt_utils.verify_es256(ear_jwt, verification_key)
    assert isinstance(claims.pop("iat"), int)
    return claims


@pytest.mark.parametrize("status", ["affirming", "warning", "contraindicated", "none"])
@pytest.mark.parametrize(
    ("verifier_class", "developer"),
    [(EarEatHpkeVerifier, "eareat-hpke-verifier"), (CoseEatHpkeVerifier, "cose-hpke-verifier")],
)
@pytest.mark.parametrize("custom", [False, True])
def test_hpke_ears_are_unchanged_by_the_hoist(verifier_class, developer: str, status: str, custom: bool) -> None:
    """GIVEN an HPKE verifier WHEN it issues an EAR for any status THEN the claims equal the pre-hoist ones."""
    kwargs = {"scheme_name": "S", "verifier_developer": "dev"} if custom else {}
    verifier = verifier_class(attestation_public_key=ec.generate_private_key(ec.SECP256R1()).public_key(), **kwargs)

    claims = _claims_without_iat(verifier.issue_ear(_NONCE, status), verifier.ear_verification_pem())

    expected = _pre_hoist_claims("dev", "S", status) if custom else _pre_hoist_claims(developer, "ATG_PLUGIN", status)
    assert claims == expected


def test_build_ear_jwt_carries_a_custom_vector_and_policy_id() -> None:
    """GIVEN a sparse AR4SI vector and a policy id WHEN build_ear_jwt signs THEN exactly those claims are emitted."""
    key = ec.generate_private_key(ec.SECP256R1())

    ear_jwt = build_ear_jwt(
        signing_key=key,
        verifier_developer="unit-dev",
        scheme_name="SCHEME",
        nonce=bytes(16),
        status="affirming",
        trust_vector={"instance-identity": 2},
        policy_id="policy:SCHEME/unit-root",
    )

    assert _claims_without_iat(ear_jwt, key.public_key()) == {
        "eat_profile": "tag:github.com,2023:veraison/ear",
        "ear.verifier-id": {"build": "N/A", "developer": "unit-dev"},
        "eat_nonce": cwt_jwt_utils.b64u_encode(bytes(16)),
        "submods": {
            "SCHEME": {
                "ear.status": "affirming",
                "ear.trustworthiness-vector": {"instance-identity": 2},
                "ear.appraisal-policy-id": "policy:SCHEME/unit-root",
            }
        },
    }


def test_build_ear_jwt_policy_id_defaults_to_the_scheme() -> None:
    """GIVEN no policy id WHEN build_ear_jwt signs THEN the policy id is policy:<scheme_name>."""
    key = ec.generate_private_key(ec.SECP256R1())

    ear_jwt = build_ear_jwt(
        signing_key=key,
        verifier_developer="d",
        scheme_name="X",
        nonce=bytes(8),
        status="warning",
        trust_vector={},
    )

    claims = _claims_without_iat(ear_jwt, key.public_key())
    assert claims["submods"]["X"]["ear.appraisal-policy-id"] == "policy:X"


def test_hpke_base_still_exports_the_claims_mapper() -> None:
    """GIVEN code importing ear_token_to_veraison_claims from hpke_base THEN it is the shared function."""
    assert reexported_claims is ear_token_to_veraison_claims

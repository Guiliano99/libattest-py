# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the EAR token pydantic model (libattest.formats.eat_ear.cwt_jwt).

Covers the draft-ietf-rats-ear-04 claims-set: profile default, alias <-> python-name
round-trip, extension preservation, the EARAppraisal subclass, and the two worked JSON
examples from the draft (Figure 3 contraindicated, Figure 4 composite affirming).
"""

from __future__ import annotations

from libattest.formats.eat_ear.cwt_jwt import EAR_PROFILE, EARAppraisal, EARToken, TrustworthinessTier


def _minimal_payload() -> dict:
    return {
        "iat": 1666529184,
        "ear_verifier_id": {"developer": "https://v.example", "build": "vts 0.0.1"},
        "submods": {"PSA": {"ear_status": "affirming"}},
    }


# draft-ietf-rats-ear-04 Figure 3 — single-attester contraindicated appraisal (PSA).
_FIGURE_3 = {
    "eat_profile": EAR_PROFILE,
    "iat": 1666529184,
    "ear_verifier_id": {"developer": "https://veraison-project.org", "build": "vts 0.0.1"},
    "ear_raw_evidence": ["application/vnd.evidence", "NzQ3MjY5NzM2NTYzNzQK"],
    "submods": {
        "PSA": {
            "ear_status": "contraindicated",
            "ear_trustworthiness_vector": {"instance-identity": 2, "executables": 96, "hardware": 2},
            "ear_appraisal_policy_ids": ["https://veraison.example/policy/1/60a0068d"],
        }
    },
}

# draft-ietf-rats-ear-04 Figure 4 — composite device, two affirming attesters.
_FIGURE_4 = {
    "eat_profile": EAR_PROFILE,
    "iat": 1666529300,
    "ear_verifier_id": {"developer": "https://veraison-project.org", "build": "vts 0.0.1"},
    "ear_raw_evidence": ["application/vnd.evidence", "NzQ3MjY5NzM2NTYzNzQKNzQ3MjY5NzM2NTYzNzQK"],
    "submods": {
        "CCA Platform": {
            "ear_status": "affirming",
            "ear_trustworthiness_vector": {"instance-identity": 2, "executables": 2, "hardware": 2},
            "ear_appraisal_policy_ids": ["https://veraison.example/policy/1/60a0068d"],
        },
        "CCA Realm": {
            "ear_status": "affirming",
            "ear_trustworthiness_vector": {"instance-identity": 2},
            "ear_appraisal_policy_ids": ["https://veraison.example/policy/1/60a0068d"],
        },
    },
}


def test_defaults_profile_for_producers() -> None:
    token = EARToken.model_validate(_minimal_payload())
    assert token.eat_profile == EAR_PROFILE


def test_serialises_to_underscore_wire_keys() -> None:
    token = EARToken.model_validate(
        {**_minimal_payload(), "eat_nonce": b"01234567", "ear_device_topology": {"ROOT": ["TEE"]}}
    )
    dumped = token.model_dump(by_alias=True, exclude_none=True, mode="json")
    assert "ear_verifier_id" in dumped
    assert isinstance(dumped["eat_nonce"], str)  # bytes -> base64url string
    assert dumped["ear_device_topology"] == {"ROOT": ["TEE"]}


def test_populate_by_name_allows_python_identifiers() -> None:
    token = EARToken(
        iat=1,
        verifier_id={"developer": "x", "build": "y"},
        submods={"A": {"ear_status": "affirming"}},
    )
    assert token.verifier_id["developer"] == "x"


def test_unknown_claims_are_preserved() -> None:
    token = EARToken.model_validate({**_minimal_payload(), "ear_teep_claims": {"x": 1}})
    dumped = token.model_dump(by_alias=True, exclude_none=True, mode="json")
    assert dumped["ear_teep_claims"] == {"x": 1}


def test_submods_parse_into_appraisal() -> None:
    token = EARToken.model_validate(_FIGURE_3)
    psa = token.submods["PSA"]
    assert isinstance(psa, EARAppraisal)
    assert psa.status is TrustworthinessTier.CONTRAINDICATED
    assert psa.trustworthiness_vector == {"instance-identity": 2, "executables": 96, "hardware": 2}
    assert psa.appraisal_policy_ids == ["https://veraison.example/policy/1/60a0068d"]


def test_figure3_contraindicated_roundtrips_to_wire_keys() -> None:
    token = EARToken.model_validate(_FIGURE_3)
    assert token.model_dump(by_alias=True, exclude_none=True, mode="json") == _FIGURE_3


def test_figure4_composite_affirming_roundtrips_to_wire_keys() -> None:
    token = EARToken.model_validate(_FIGURE_4)
    assert token.model_dump(by_alias=True, exclude_none=True, mode="json") == _FIGURE_4
    assert set(token.submods) == {"CCA Platform", "CCA Realm"}

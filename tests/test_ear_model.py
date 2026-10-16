# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the EAR token pydantic model (libattest.formats.eat_ear.cwt_jwt).

Covers the draft-ietf-rats-ear-04 claims-set: profile default, alias <-> python-name
round-trip, extension preservation, the EARAppraisal subclass, and the two worked JSON
examples from the draft (Figure 3 contraindicated, Figure 4 composite affirming).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats.eat_ear.cwt_jwt import (
    EAR_PROFILE,
    EARAppraisal,
    EARToken,
    TrustworthinessTier,
    parse_ear,
)
from libattest.verifier.eareat_cose_hpke import CoseEatHpkeVerifier
from libattest.verifier.eareat_hpke import EarEatHpkeVerifier


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


# ── parse_ear: the Veraison wire format becomes a validated Attestation Result ────
#
# Until parse_ear existed the RA could only read an EAR as a bag of strings, so it
# could not appraise the Attestation Result it acted on. These tests pin the inverse
# of what the shipped verifiers actually emit, not a hand-written fixture.

NONCE = b"\x09" * 32


@pytest.mark.parametrize("verifier_class", [EarEatHpkeVerifier, CoseEatHpkeVerifier])
def test_parse_ear_round_trips_an_ear_the_verifiers_actually_issue(verifier_class) -> None:
    """GIVEN an EAR issued by a shipped verifier THEN parse_ear reconstructs the model."""
    verifier = verifier_class(attestation_public_key=ec.generate_private_key(ec.SECP256R1()).public_key())

    token = parse_ear(verifier.issue_ear(NONCE, "affirming"))

    assert token.nonce is not None
    assert token.nonce.to_bytes() == NONCE, "the RA needs this to bind an EAR to its own nonce"
    assert token.verifier_id["developer"] == verifier_class.default_verifier_developer
    assert all(appraisal.status is TrustworthinessTier.AFFIRMING for appraisal in token.submods.values())


def test_parse_ear_reads_a_contraindicated_verdict() -> None:
    """GIVEN a rejected verdict THEN the tier survives parsing, not just the affirming case."""
    verifier = EarEatHpkeVerifier(attestation_public_key=ec.generate_private_key(ec.SECP256R1()).public_key())

    token = parse_ear(verifier.issue_ear(NONCE, "contraindicated"))

    assert [a.status for a in token.submods.values()] == [TrustworthinessTier.CONTRAINDICATED]


def test_parse_ear_widens_a_scalar_policy_id_to_the_modelled_list() -> None:
    """GIVEN Veraison's scalar ear.appraisal-policy-id THEN it becomes draft-04's list."""
    token = parse_ear(
        {
            "eat_profile": EAR_PROFILE,
            "iat": 1666529184,
            "ear.verifier-id": {"developer": "https://v.example", "build": "vts 0.0.1"},
            "submods": {"PSA": {"ear.status": "affirming", "ear.appraisal-policy-id": "policy:one"}},
        }
    )

    assert token.submods["PSA"].appraisal_policy_ids == ["policy:one"]


def test_parse_ear_preserves_unknown_extension_claims() -> None:
    """GIVEN EAT extension claims THEN they survive, so the model is not a lossy view."""
    token = parse_ear(
        {
            "eat_profile": EAR_PROFILE,
            "iat": 1666529184,
            "ear.verifier-id": {"developer": "https://v.example", "build": "vts 0.0.1"},
            "vendor.extra": {"k": "v"},
            "submods": {"PSA": {"ear.status": "affirming", "vendor.submod-extra": 7}},
        }
    )

    assert token.model_extra["vendor.extra"] == {"k": "v"}
    assert token.submods["PSA"].model_extra["vendor.submod-extra"] == 7


def test_parse_ear_rejects_an_ear_carrying_no_appraisal() -> None:
    """GIVEN an EAR with no submods THEN reject: there is no verdict to act on."""
    with pytest.raises(ValueError, match="no appraisal"):
        parse_ear({"eat_profile": EAR_PROFILE, "iat": 1, "ear.verifier-id": {}})


def test_parse_ear_rejects_a_malformed_jwt() -> None:
    """GIVEN something that is not a compact JWT THEN raise rather than return a shell."""
    with pytest.raises(ValueError, match="Not a JWT"):
        parse_ear("not-a-jwt")

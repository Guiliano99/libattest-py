# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Geographic Attestation Results model (libattest.formats.geographic).

Covers draft-richardson-rats-geographic-results-01's ``geographic-result-claims``:
alias <-> python-name round-trip against the draft's exact JSON keys, the non-empty
MUST, size/range bounds, extension preservation, and the self-check demo.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from libattest.formats.geographic import GeographicResultClaims


def test_roundtrip_emits_draft_json_keys() -> None:
    claims = GeographicResultClaims(
        jurisdiction_country="CH",
        jurisdiction_subdivision="ZH",
        jurisdiction_city="Zurich",
        rack_u_number=1,
        floor_number=-2,
        data_center_name="dc-alpha",
    )
    wire = claims.model_dump(by_alias=True, exclude_none=True)
    assert wire == {
        "jurisdiction-country": "CH",
        "jurisdiction-subdivision": "ZH",
        "jurisdiction-city": "Zurich",
        "rack-U-number": 1,  # capital U preserved verbatim
        "floor-number": -2,
        "data-center-name": "dc-alpha",
    }
    assert GeographicResultClaims.model_validate(wire) == claims


def test_populate_by_name_or_alias() -> None:
    by_name = GeographicResultClaims(jurisdiction_country="DE")
    by_alias = GeographicResultClaims.model_validate({"jurisdiction-country": "DE"})
    assert by_name == by_alias


def test_empty_claimset_rejected() -> None:
    with pytest.raises(ValidationError):
        GeographicResultClaims()


def test_unknown_claim_counts_toward_non_empty() -> None:
    # extra='allow': a set carrying only a future/unknown claim is still valid.
    claims = GeographicResultClaims.model_validate({"future-claim": 42})
    assert claims.model_dump(by_alias=True, exclude_none=True) == {"future-claim": 42}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"jurisdiction_subdivision": "x" * 17},  # > 16
        {"jurisdiction_subdivision": "x"},  # < 2
        {"data_center_name": "x" * 65},  # > 64
        {"room_number": "x"},  # < 2
        {"rack_u_number": 0},  # not > 0
        {"cabinet_number": 0},  # not > 0
        {"hallway_number": -1},  # not >= 0
    ],
)
def test_bounds_rejected(kwargs: dict) -> None:
    with pytest.raises(ValidationError):
        GeographicResultClaims(**kwargs)


def test_negative_floor_allowed() -> None:
    claims = GeographicResultClaims(floor_number=-3)
    assert claims.floor_number == -3


def test_demo_self_check_passes() -> None:
    from libattest.formats.geographic.structures import demo

    demo()  # asserts internally; raising would fail the test

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the configurable EAR extension OID."""

import pytest

from libattest.formats.ear_extension import EAR_EXTENSION_OID_DEFAULT
from libattest.ra.profile import jwt_profile
from libattest.testing.fakes import InMemoryVerifier


def test_jwt_profile_reads_ear_oid_when_profile_is_created(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN EAR_OID changes after import WHEN creating a profile THEN it is used for encoding."""
    monkeypatch.setenv("EAR_OID", "1.2.3.5")

    profile = jwt_profile(
        request_type_oid="request",
        statement_oid="statement",
        verifier=InMemoryVerifier(),
    )
    oid, extension_value = profile.encode_ear_extension("ear.jwt")

    assert oid == "1.2.3.5"
    assert extension_value.startswith(b"\x0c")


def test_blank_ear_oid_uses_the_format_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN a blank EAR_OID WHEN creating a profile THEN the format default is used."""
    monkeypatch.setenv("EAR_OID", "  ")

    profile = jwt_profile(
        request_type_oid="request",
        statement_oid="statement",
        verifier=InMemoryVerifier(),
    )
    oid, _extension_value = profile.encode_ear_extension("ear.jwt")

    assert oid == EAR_EXTENSION_OID_DEFAULT

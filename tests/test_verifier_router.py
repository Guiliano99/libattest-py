# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for VerifierRouter.verify_bundle's DER-bytes decode path."""

from __future__ import annotations

import pytest
from pyasn1.type import univ

from libattest.asn1_utils import encode_to_der
from libattest.formats.csrattest import (
    prepare_attestation_bundle,
    prepare_opaque_attestation_statement,
)
from libattest.testing.fakes import InMemoryVerifier
from libattest.verifier.router import VerifierRouter

OID = "2.23.133.20.1"


def _bundle_der() -> bytes:
    statement = prepare_opaque_attestation_statement(univ.ObjectIdentifier(OID), b"evidence")
    bundle = prepare_attestation_bundle([statement])
    return encode_to_der(bundle)


def test_verify_bundle_accepts_der_bytes() -> None:
    """GIVEN a bundle passed as DER bytes WHEN verified THEN it decodes and dispatches."""
    router = VerifierRouter()
    verifier = InMemoryVerifier()
    router.register("tpm", verifier, evidence_types=[OID], default=True)

    result = router.verify_bundle(_bundle_der())

    assert list(result.routes) == ["tpm"]
    assert result.per_statement[0].accepted


def test_verify_bundle_rejects_der_bytes_with_trailing_data() -> None:
    """GIVEN DER bytes with trailing garbage WHEN verified THEN a ValueError is raised."""
    router = VerifierRouter()
    router.register("tpm", InMemoryVerifier(), evidence_types=[OID], default=True)

    with pytest.raises(ValueError, match="trailing bytes"):
        router.verify_bundle(_bundle_der() + b"\x00")

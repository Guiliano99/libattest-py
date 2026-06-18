# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for AttestationBundle statement lookup helpers."""

from __future__ import annotations

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ

from libattest.formats.csrattest import (
    AttestationBundle,
    find_attestation_statements,
    prepare_attestation_bundle,
    prepare_opaque_attestation_statement,
)

QUOTE_OID = "2.23.133.20.2"
OTHER_OID = "1.3.6.1.4.1.99999.2"


def _bundle() -> AttestationBundle:
    return prepare_attestation_bundle(
        [
            prepare_opaque_attestation_statement(univ.ObjectIdentifier(QUOTE_OID), b"quote-1"),
            prepare_opaque_attestation_statement(univ.ObjectIdentifier(OTHER_OID), b"other"),
            prepare_opaque_attestation_statement(univ.ObjectIdentifier(QUOTE_OID), b"quote-2"),
        ]
    )


def test_find_returns_matches_in_bundle_order():
    statements = find_attestation_statements(_bundle(), QUOTE_OID)
    assert len(statements) == 2
    payloads = [bytes(statement["stmt"]) for statement in statements]
    assert b"quote-1" in payloads[0]
    assert b"quote-2" in payloads[1]


def test_find_accepts_oid_object_and_misses_cleanly():
    bundle = _bundle()
    assert len(find_attestation_statements(bundle, univ.ObjectIdentifier(OTHER_OID))) == 1
    assert find_attestation_statements(bundle, "1.2.3.4") == []


def test_find_works_after_der_round_trip():
    der = der_encoder.encode(_bundle())
    decoded, rest = der_decoder.decode(der, asn1Spec=AttestationBundle())
    assert not rest
    assert len(find_attestation_statements(decoded, QUOTE_OID)) == 2

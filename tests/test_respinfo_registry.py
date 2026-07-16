# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for built-in ``respInfo`` JSON codec registrations."""

from __future__ import annotations

from libattest import get_nonce_response_oid_for_name, get_oid_for_stmt_name
from libattest.formats.respinfo import DEFAULT_RESP_INFO_REGISTRY
from libattest.formats.stmt_mappings import NONCE_RESPONSE_STATEMENT_STRUCTURES


def test_default_registry_round_trips_key_attest_response() -> None:
    """GIVEN a key-attestation OID WHEN routed THEN its ``KeyAttestResp`` round-trips."""
    oid = get_nonce_response_oid_for_name("key-attest")
    payload = {
        "encSeed": "0102",
        "encSecret": "a0b1c2",
    }

    der = DEFAULT_RESP_INFO_REGISTRY.from_json(oid, payload)

    assert DEFAULT_RESP_INFO_REGISTRY.to_json(oid, der) == payload


def test_default_registry_uses_tpm_quote_response_oid() -> None:
    """GIVEN the TPM quote response OID WHEN routed THEN its ``respInfo`` codec is registered."""
    oid = get_nonce_response_oid_for_name("tpm-quote")

    assert DEFAULT_RESP_INFO_REGISTRY.is_registered(oid)
    assert oid in NONCE_RESPONSE_STATEMENT_STRUCTURES


def test_default_registry_round_trips_tpm_quote_statement_oid() -> None:
    """GIVEN a verifier-routed TcgAttestQuote WHEN converting respInfo THEN it round-trips.

    The MockCA forwards ``respInfo`` as JSON with the evidence-statement OID,
    not the CMP response-type OID, so both OIDs must select TPM20QuoteRespInfo.
    """
    oid = get_oid_for_stmt_name("tcg-attest-quote")
    payload = {"pcrSelection": [0, 1, 2, 3, 4], "hashAlgo": 11}

    der = DEFAULT_RESP_INFO_REGISTRY.from_json(oid, payload)

    assert DEFAULT_RESP_INFO_REGISTRY.to_json(oid, der) == payload
    assert oid not in NONCE_RESPONSE_STATEMENT_STRUCTURES


def test_quote_statement_alias_is_not_a_nonce_response_type() -> None:
    """GIVEN the verifier routing alias THEN it stays outside CMP wire mappings."""
    assert get_oid_for_stmt_name("tcg-attest-quote") not in NONCE_RESPONSE_STATEMENT_STRUCTURES

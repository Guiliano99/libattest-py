# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for built-in ``respInfo`` JSON codec registrations."""

from __future__ import annotations

from libattest import get_nonce_response_oid_for_name
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


def test_every_registered_resp_info_oid_has_a_response_structure() -> None:
    """GIVEN every OID with a respInfo JSON codec THEN it also has an ASN.1 decode structure.

    A respInfo cannot be converted DER<->JSON without first being able to decode
    its DER, so every :class:`RespInfoRegistry` OID must be a subset of
    ``NONCE_RESPONSE_STATEMENT_STRUCTURES``. This is the parity check a new
    statement format's registration must satisfy.
    """
    registered = set(DEFAULT_RESP_INFO_REGISTRY.registered_oids())
    structured = set(NONCE_RESPONSE_STATEMENT_STRUCTURES)

    assert registered <= structured, registered - structured

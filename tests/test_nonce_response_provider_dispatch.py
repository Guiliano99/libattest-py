# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for selecting an Evidence provider after CMP freshness."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from pyasn1.type import univ

from attest_client import AttestClient
from libattest import get_nonce_response_oid_for_name, get_oid_for_stmt_name
from libattest.attester.client import AttesterClient
from libattest.formats.csrattest import NonceResponse, NonceResponseTypeInfo
from libattest.types import AttestResult

TPM_QUOTE_EVIDENCE_OID = get_oid_for_stmt_name("tcg-attest-quote")
TPM_QUOTE_RESPONSE_OID = get_nonce_response_oid_for_name("tpm-quote")
JOSE_EVIDENCE_OID = get_oid_for_stmt_name("jose-hpke-evidence")
JOSE_RESPONSE_OID = get_nonce_response_oid_for_name("jose-hpke-evidence-params")

MISMATCHED_OID_CASES = [
    pytest.param(TPM_QUOTE_RESPONSE_OID, TPM_QUOTE_EVIDENCE_OID, id="tpm-quote"),
    pytest.param(JOSE_RESPONSE_OID, JOSE_EVIDENCE_OID, id="jose-hpke"),
]

ClientFactory = Callable[[dict[str, "RecordingProvider"]], Any]
CLIENT_CASES = [
    pytest.param(AttesterClient, "generate_evidence_from_nonce_response", id="attester-client"),
    pytest.param(
        lambda providers: AttestClient(providers=providers),
        "generate_evidence_from_cmp_nonce_response",
        id="http-client",
    ),
]


class RecordingProvider:  # pylint: disable=too-few-public-methods
    """Minimal evidence provider that records the nonce passed by a client."""

    def __init__(self, oid: str) -> None:
        """Initialize the provider with its Evidence statement OID."""
        self.oid = oid
        self.nonces: list[bytes | None] = []

    def generate_evidence(self, nonce: bytes | None = None) -> AttestResult:
        """Return Evidence for the provider's configured statement OID."""
        self.nonces.append(nonce)
        return AttestResult(self.oid, b"evidence", "application/octet-stream")


def _nonce_response(response_oid: str) -> NonceResponse:
    """Build a CMP nonce response whose type selects its response payload syntax."""
    response = NonceResponse()
    response["nonce"] = b"n" * 32
    type_info = NonceResponseTypeInfo()
    type_info["type"] = univ.ObjectIdentifier(response_oid)
    response["respTypeInfo"] = type_info
    return response


def _close(client: Any) -> None:
    """Release the HTTP session when the case uses the HTTP-capable client."""
    close = getattr(client, "close", None)
    if close is not None:
        close()


def _other_evidence_oid(evidence_oid: str) -> str:
    """Return the other OID used to make a provider registration ambiguous."""
    return JOSE_EVIDENCE_OID if evidence_oid == TPM_QUOTE_EVIDENCE_OID else TPM_QUOTE_EVIDENCE_OID


@pytest.mark.parametrize(
    ("factory", "method_name"),
    CLIENT_CASES,
)
@pytest.mark.parametrize(("response_oid", "evidence_oid"), MISMATCHED_OID_CASES)
def test_uses_the_only_registered_evidence_provider_when_response_oid_differs(
    factory: ClientFactory,
    method_name: str,
    response_oid: str,
    evidence_oid: str,
) -> None:
    """GIVEN one provider WHEN the response type differs THEN generate its Evidence."""
    provider = RecordingProvider(evidence_oid)
    client = factory({evidence_oid: provider})

    try:
        result = getattr(client, method_name)(_nonce_response(response_oid))
    finally:
        _close(client)

    assert result.oid == evidence_oid
    assert provider.nonces == [b"n" * 32]


@pytest.mark.parametrize(
    ("factory", "method_name"),
    CLIENT_CASES,
)
@pytest.mark.parametrize(("response_oid", "evidence_oid"), MISMATCHED_OID_CASES)
def test_requires_an_explicit_evidence_oid_for_multiple_providers(
    factory: ClientFactory,
    method_name: str,
    response_oid: str,
    evidence_oid: str,
) -> None:
    """GIVEN multiple providers, require the caller to select Evidence explicitly."""
    other_evidence_oid = _other_evidence_oid(evidence_oid)
    client = factory(
        {
            evidence_oid: RecordingProvider(evidence_oid),
            other_evidence_oid: RecordingProvider(other_evidence_oid),
        }
    )

    try:
        with pytest.raises(ValueError, match="evidence OID is required"):
            getattr(client, method_name)(_nonce_response(response_oid))
    finally:
        _close(client)


@pytest.mark.parametrize(
    ("factory", "method_name"),
    CLIENT_CASES,
)
@pytest.mark.parametrize(("response_oid", "evidence_oid"), MISMATCHED_OID_CASES)
def test_explicit_evidence_oid_selects_the_matching_provider(
    factory: ClientFactory,
    method_name: str,
    response_oid: str,
    evidence_oid: str,
) -> None:
    """GIVEN multiple providers, an explicit statement OID selects its provider."""
    provider = RecordingProvider(evidence_oid)
    other_evidence_oid = _other_evidence_oid(evidence_oid)
    client = factory(
        {
            evidence_oid: provider,
            other_evidence_oid: RecordingProvider(other_evidence_oid),
        }
    )

    try:
        result = getattr(client, method_name)(_nonce_response(response_oid), oid=evidence_oid)
    finally:
        _close(client)

    assert result.oid == evidence_oid
    assert provider.nonces == [b"n" * 32]

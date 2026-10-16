# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the attester's side of the exchange: what it learns, and what it tells.

Two gaps are pinned here.  An attester had no way to ask *what did the verifier
provision me* — every one read ``respTypeInfo`` itself, hardcoding the single syntax it
cared about — and it had no way to decide *what may this verifier learn*: the whole EAT
claim set went to whichever verifier the RA named, encrypted but undiminished.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from libattest import get_nonce_request_oid_for_name, get_oid_by_name
from libattest.asn1_utils import encode_to_der
from libattest.attester import (
    AttesterClient,
    ClaimReleasePolicy,
    EvidenceRequest,
    parse_verifier_info,
)
from libattest.formats.csrattest import NonceResponse
from libattest.ra import ProfileRegistry, RemoteAttestationEngine, hpke_profile, jwt_profile
from libattest.types import AttestResult
from libattest.verifier.eareat_hpke import EarEatHpkeVerifier

TX = b"\x0c" * 16
OID = "1.3.6.1.4.1.99999.1"


# ── what the verifier told the attester ──────────────────────────────────────────
def test_the_hpke_recipient_key_is_read_off_the_nonce_response() -> None:
    """GIVEN an HPKE exchange THEN the attester recovers the key to encrypt to."""
    verifier = EarEatHpkeVerifier(attestation_public_key=ec.generate_private_key(ec.SECP256R1()).public_key())
    profiles = ProfileRegistry()
    profiles.register(hpke_profile(verifier=verifier, statement_oid=get_oid_by_name("jose-hpke-evidence")))
    engine = RemoteAttestationEngine(profiles)

    response = engine.build_nonce_response(TX, get_nonce_request_oid_for_name("jose-hpke-evidence-params"))
    info = parse_verifier_info(encode_to_der(response))

    assert info.requires_freshness
    assert info.expiry == engine.nonce_store.ttl_seconds
    key = info.hpke_recipient_key()
    assert key is not None
    assert info.resp_info == verifier.evidence_encryption_spki_der()


def test_an_unrecognised_resp_info_syntax_is_not_an_error() -> None:
    """GIVEN a profile the attester was not provisioned for THEN the accessor returns None.

    An attester supporting several profiles asks each accessor in turn; a syntax it does
    not handle must read as "not this exchange", not as a decode failure.
    """
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=OID, statement_oid=OID, verifier_url="https://v.example"))
    engine = RemoteAttestationEngine(profiles)

    info = parse_verifier_info(encode_to_der(engine.build_nonce_response(TX, OID)))

    assert info.response_type_oid == OID
    assert info.hpke_recipient_key() is None


def test_a_response_without_type_info_still_parses() -> None:
    """GIVEN a bare nonce response THEN there is simply no verifier information."""
    response = NonceResponse()
    response["nonce"] = b"\x01" * 32

    info = parse_verifier_info(encode_to_der(response))

    assert info.nonce == b"\x01" * 32
    assert (info.response_type_oid, info.resp_info, info.expiry) == (None, None, None)
    assert info.hpke_recipient_key() is None


# ── what the attester tells the verifier ─────────────────────────────────────────
CLAIMS = {"eat_nonce": "n", "ueid": "device-01", "mock_claim": "secure", "firmware": "1.2.3"}


def test_the_default_policy_releases_everything() -> None:
    """GIVEN no configured limits THEN nothing is withheld (existing attesters unchanged)."""
    assert ClaimReleasePolicy.release_all().release(CLAIMS) == CLAIMS


def test_an_allow_list_withholds_everything_else() -> None:
    """GIVEN an allow-list THEN only it, plus the claims appraisal cannot do without."""
    released = ClaimReleasePolicy(allow={"mock_claim"}).release(CLAIMS)

    assert released == {"eat_nonce": "n", "mock_claim": "secure"}
    assert "ueid" not in released, "a device identifier is exactly what a policy is for"


def test_deny_beats_allow() -> None:
    """GIVEN a claim in both lists THEN the more restrictive rule wins."""
    policy = ClaimReleasePolicy(allow={"ueid", "mock_claim"}, deny={"ueid"})

    assert "ueid" not in policy.release(CLAIMS)
    assert "mock_claim" in policy.release(CLAIMS)


def test_a_single_claim_name_given_as_a_string_is_not_split_into_letters() -> None:
    """GIVEN deny="ueid" THEN one claim is denied, not the letters u, e, i and d."""
    policy = ClaimReleasePolicy(deny="ueid")

    released = policy.release({**CLAIMS, "d": 1, "u": 2})

    assert "ueid" not in released, "a privacy control that silently does nothing is worse than none"
    assert released["d"] == 1 and released["u"] == 2


def test_policies_can_differ_per_verifier() -> None:
    """GIVEN per-verifier lists THEN each verifier learns only what it needs."""
    policy = ClaimReleasePolicy(
        allow=set(),
        per_verifier={"platform": {"firmware"}, "keyattest": {"mock_claim"}},
    )

    assert set(policy.release(CLAIMS, verifier_id="platform")) == {"eat_nonce", "firmware"}
    assert set(policy.release(CLAIMS, verifier_id="keyattest")) == {"eat_nonce", "mock_claim"}
    assert set(policy.release(CLAIMS, verifier_id="unknown")) == {"eat_nonce"}


def test_essential_claims_survive_even_an_empty_allow_list() -> None:
    """GIVEN allow=set() THEN freshness and profile still go, or nothing is appraisable."""
    assert set(ClaimReleasePolicy(allow=set()).release({**CLAIMS, "eat_profile": "p"})) == {
        "eat_nonce",
        "eat_profile",
    }


def test_release_preserves_claim_order() -> None:
    """GIVEN an ordered claim set THEN the released subset keeps that order."""
    ordered = {"eat_nonce": 1, "a": 2, "b": 3, "c": 4}

    assert list(ClaimReleasePolicy(deny={"b"}).release(ordered)) == ["eat_nonce", "a", "c"]


# ── the provider receives the whole exchange ─────────────────────────────────────
class _WideProvider:
    """A provider that accepts the wider EvidenceRequest."""

    def __init__(self) -> None:
        """Start with no recorded request."""
        self.request: EvidenceRequest | None = None

    def generate_evidence_for(self, request: EvidenceRequest) -> AttestResult:
        """Record the whole request and return evidence naming what it released."""
        self.request = request
        return AttestResult(oid=OID, evidence=b"wide", media_type="application/octet-stream")


class _NarrowProvider:
    """A provider written against the original nonce-only interface."""

    def __init__(self) -> None:
        """Start with no recorded nonce."""
        self.nonce: bytes | None = None

    def generate_evidence(self, nonce: bytes | None = None) -> AttestResult:
        """Record the nonce and return evidence."""
        self.nonce = nonce
        return AttestResult(oid=OID, evidence=b"narrow", media_type="application/octet-stream")


def _nonce_response(nonce: bytes = b"\x05" * 32) -> NonceResponse:
    response = NonceResponse()
    response["nonce"] = nonce
    return response


def test_a_wide_provider_receives_the_verifier_info_and_policy() -> None:
    """GIVEN a provider that accepts EvidenceRequest THEN the whole exchange reaches it."""
    provider = _WideProvider()
    client = AttesterClient({OID: provider})
    policy = ClaimReleasePolicy(deny={"ueid"})

    client.generate_evidence_from_nonce_response(_nonce_response(), OID, verifier_id="platform", claim_policy=policy)

    assert provider.request is not None
    assert provider.request.nonce == b"\x05" * 32
    assert provider.request.verifier_id == "platform"
    assert provider.request.verifier_info is not None
    assert "ueid" not in provider.request.release(CLAIMS)


def test_a_narrow_provider_keeps_working_unchanged() -> None:
    """GIVEN the original nonce-only provider THEN it still gets its nonce and nothing breaks."""
    provider = _NarrowProvider()
    client = AttesterClient({OID: provider})

    result = client.generate_evidence_from_nonce_response(_nonce_response(), OID)

    assert result.evidence_bytes() == b"narrow"
    assert provider.nonce == b"\x05" * 32


def test_an_evidence_request_without_a_policy_releases_everything() -> None:
    """GIVEN no configured policy THEN the request withholds nothing."""
    assert EvidenceRequest(nonce=b"n").release(CLAIMS) == CLAIMS


def test_an_empty_nonce_is_reported_as_requiring_no_freshness() -> None:
    """GIVEN a zero-length nonce THEN the attester is told no freshness proof is wanted."""
    with pytest.raises(ValueError, match="empty nonce"):
        AttesterClient({OID: _NarrowProvider()}).generate_evidence_from_nonce_response(_nonce_response(b""), OID)

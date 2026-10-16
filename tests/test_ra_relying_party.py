# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the RA's Relying Party appraisal of Attestation Results.

The load-bearing test is :func:`test_a_captured_ear_cannot_be_replayed_into_another_exchange`.
Before :class:`~libattest.ra.relying_party.EarAcceptancePolicy` existed, nothing in the RA
bound an EAR to the nonce it had issued, so a captured affirming EAR stayed valid
forever. Everything else here defends a rejection that used to be an acceptance.
"""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der import encoder as der_encoder

from libattest.formats.csrattest import prepare_attestation_bundle, prepare_opaque_attestation_statement
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.ra import NonceStore, ProfileRegistry, RemoteAttestationEngine, jwt_profile
from libattest.ra.relying_party import (
    DEFAULT_MAX_AGE_SECONDS,
    EarAcceptancePolicy,
    load_trust_anchor,
)
from libattest.types import VerifyResult
from libattest.verifier.eareat_hpke import EarEatHpkeVerifier

NONCE = b"\x21" * 32
OTHER_NONCE = b"\x22" * 32
_OID = "1.3.6.1.4.1.99999.1"
_TX = b"\x07" * 16
_EAR_PROFILE = "tag:github.com,2023:veraison/ear"
_VECTOR = {"instance-identity": 0, "configuration": 0}
_ANY_KEY = ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(name="signing_key")
def _signing_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _anchor_of(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _ear(
    key: ec.EllipticCurvePrivateKey,
    *,
    nonce: bytes | None = NONCE,
    iat: int | None = None,
    exp: int | None = None,
    status: str = "affirming",
    developer: str = "test-verifier",
) -> str:
    """Sign an EAR in the Veraison wire format the shipped verifiers emit."""
    claims: dict = {
        "eat_profile": _EAR_PROFILE,
        "iat": int(iat if iat is not None else time.time()),
        "ear.verifier-id": {"build": "N/A", "developer": developer},
        "submods": {"S": {"ear.status": status, "ear.trustworthiness-vector": _VECTOR}},
    }
    if nonce is not None:
        claims["eat_nonce"] = cwt_jwt_utils.b64u_encode(nonce)
    if exp is not None:
        claims["exp"] = exp
    return cwt_jwt_utils.sign_es256(claims, key)


# ── the replay hole ──────────────────────────────────────────────────────────────
def test_a_captured_ear_cannot_be_replayed_into_another_exchange(signing_key) -> None:
    """GIVEN a valid affirming EAR WHEN presented against a different nonce THEN reject."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(signing_key))
    captured = _ear(signing_key, nonce=NONCE)

    assert policy.appraise(captured, expected_nonce=NONCE).accepted
    replayed = policy.appraise(captured, expected_nonce=OTHER_NONCE)

    assert not replayed.accepted
    assert "does not match the nonce this RA issued" in replayed.result.errors[0]


def test_an_ear_without_a_nonce_is_refused(signing_key) -> None:
    """GIVEN an EAR carrying no eat_nonce THEN reject: it binds to no exchange."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(signing_key))

    decision = policy.appraise(_ear(signing_key, nonce=None), expected_nonce=NONCE)

    assert not decision.accepted
    assert "carries no eat_nonce" in decision.result.errors[0]


def test_appraisal_without_an_ra_nonce_is_refused(signing_key) -> None:
    """GIVEN no RA-issued nonce THEN there is nothing to bind to, so refuse."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(signing_key))

    decision = policy.appraise(_ear(signing_key), expected_nonce=None)

    assert not decision.accepted
    assert "no RA-issued nonce" in decision.result.errors[0]


# ── the anchor must be configured, never fetched ─────────────────────────────────
def test_an_ear_signed_by_an_unconfigured_key_is_refused(signing_key) -> None:
    """GIVEN an EAR signed by some other key THEN the signature check fails closed."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(ec.generate_private_key(ec.SECP256R1())))

    decision = policy.appraise(_ear(signing_key), expected_nonce=NONCE)

    assert not decision.accepted
    assert "did not verify" in decision.result.errors[0]
    assert decision.token is None, "nothing authenticated, so no claims should be handed back"


def test_no_configured_anchor_means_no_trust(signing_key) -> None:
    """GIVEN a policy with no anchors THEN refuse rather than trust the verifier's word."""
    decision = EarAcceptancePolicy().appraise(_ear(signing_key), expected_nonce=NONCE)

    assert not decision.accepted
    assert "no configured EAR trust anchor" in decision.result.errors[0]


def test_anchors_can_be_selected_per_verifier_developer(signing_key) -> None:
    """GIVEN anchors keyed by developer THEN the right one is selected, others rejected."""
    other = ec.generate_private_key(ec.SECP256R1())
    policy = EarAcceptancePolicy(anchors={"vendor-a": _anchor_of(signing_key), "vendor-b": _anchor_of(other)})

    assert policy.appraise(_ear(signing_key, developer="vendor-a"), expected_nonce=NONCE).accepted
    assert not policy.appraise(_ear(signing_key, developer="vendor-b"), expected_nonce=NONCE).accepted
    assert not policy.appraise(_ear(signing_key, developer="vendor-c"), expected_nonce=NONCE).accepted


def test_a_per_profile_pin_overrides_the_policy_anchors(signing_key) -> None:
    """GIVEN an explicit anchor THEN it wins over the policy-wide configuration."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(ec.generate_private_key(ec.SECP256R1())))

    assert policy.appraise(_ear(signing_key), expected_nonce=NONCE, anchor=_anchor_of(signing_key)).accepted


# ── freshness ────────────────────────────────────────────────────────────────────
def test_a_stale_ear_is_refused(signing_key) -> None:
    """GIVEN an EAR older than the freshness window THEN reject."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(signing_key))
    stale = _ear(signing_key, iat=int(time.time()) - DEFAULT_MAX_AGE_SECONDS - 3600)

    decision = policy.appraise(stale, expected_nonce=NONCE)

    assert not decision.accepted
    assert "freshness window" in decision.result.errors[0]


def test_an_ear_dated_in_the_future_is_refused(signing_key) -> None:
    """GIVEN an iat beyond the skew allowance THEN reject rather than accept a forward-dated EAR."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(signing_key))

    decision = policy.appraise(_ear(signing_key, iat=int(time.time()) + 86400), expected_nonce=NONCE)

    assert not decision.accepted
    assert "in the future" in decision.result.errors[0]


def test_an_expired_ear_is_refused(signing_key) -> None:
    """GIVEN an exp in the past THEN honour it."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(signing_key))

    decision = policy.appraise(_ear(signing_key, exp=int(time.time()) - 3600), expected_nonce=NONCE)

    assert not decision.accepted
    assert "expired" in decision.result.errors[0]


# ── the verdict itself ───────────────────────────────────────────────────────────
def test_a_non_affirming_submodule_is_refused(signing_key) -> None:
    """GIVEN a contraindicated submod THEN the RA does not act on it."""
    policy = EarAcceptancePolicy(anchors=_anchor_of(signing_key))

    decision = policy.appraise(_ear(signing_key, status="contraindicated"), expected_nonce=NONCE)

    assert not decision.accepted
    assert "status is 'contraindicated'" in decision.result.errors[0]


def test_nonce_binding_can_be_disabled_but_is_on_by_default(signing_key) -> None:
    """GIVEN require_nonce=False THEN a nonce-less EAR passes; the default still refuses it."""
    nonce_less = _ear(signing_key, nonce=None)

    assert (
        EarAcceptancePolicy(anchors=_anchor_of(signing_key), require_nonce=False)
        .appraise(nonce_less, expected_nonce=None)
        .accepted
    )
    assert not EarAcceptancePolicy(anchors=_anchor_of(signing_key)).appraise(nonce_less, expected_nonce=None).accepted


# ── the shipped verifiers satisfy the policy ─────────────────────────────────────
def test_a_shipped_verifiers_ear_satisfies_the_policy() -> None:
    """GIVEN an EAR from EarEatHpkeVerifier THEN the RA policy accepts it as-is."""
    verifier = EarEatHpkeVerifier(attestation_public_key=ec.generate_private_key(ec.SECP256R1()).public_key())
    policy = EarAcceptancePolicy(anchors=verifier.ear_verification_pem())

    decision = policy.appraise(verifier.issue_ear(NONCE, "affirming"), expected_nonce=NONCE)

    assert decision.accepted, decision.result.errors
    assert decision.token is not None
    assert decision.token.nonce is not None and decision.token.nonce.to_bytes() == NONCE


def test_load_trust_anchor_rejects_non_ec_material() -> None:
    """GIVEN unusable anchor material THEN fail loudly at configuration time."""
    with pytest.raises(ValueError):
        load_trust_anchor(b"not a key")


# ── the engine applies the policy ────────────────────────────────────────────────
class _EarVerifier:
    """A port verifier that signs an EAR over whatever nonce it is told to."""

    accepts = frozenset({"application/octet-stream"})

    def __init__(self, key: ec.EllipticCurvePrivateKey, *, nonce: bytes | None = None, payload: bool = True) -> None:
        """Sign over *nonce* when given, else over the nonce the RA actually issued."""
        self._key = key
        self._nonce = nonce
        self._payload = payload

    def appraise(self, request) -> VerifyResult:
        """Affirm, carrying an EAR bound to the configured nonce (or none at all)."""
        if not self._payload:
            return VerifyResult.affirming(None)
        return VerifyResult.affirming(_ear(self._key, nonce=self._nonce or request.nonce))


def _engine(verifier, key: ec.EllipticCurvePrivateKey | None, **policy_kwargs) -> RemoteAttestationEngine:
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=_OID, statement_oid=_OID, verifier=verifier))
    policy = EarAcceptancePolicy(anchors=_anchor_of(key), **policy_kwargs) if key is not None else None
    return RemoteAttestationEngine(profiles, ear_policy=policy)


def _bundle() -> bytes:
    statement = prepare_opaque_attestation_statement(_OID, b"evidence")
    return bytes(der_encoder.encode(prepare_attestation_bundle([statement])))


def test_the_engine_accepts_an_ear_bound_to_the_nonce_it_issued(signing_key) -> None:
    """GIVEN a policy on the engine THEN a properly bound EAR still passes end to end."""
    engine = _engine(_EarVerifier(signing_key), signing_key)
    engine.issue_nonce(_TX, _OID)

    assert engine.verify_bundle(_bundle(), _TX).accepted


def test_the_engine_refuses_an_ear_bound_to_someone_elses_nonce(signing_key) -> None:
    """GIVEN a verifier returning a captured EAR THEN the engine rejects the statement.

    This is the replay hole at engine level: without the policy the engine embedded
    whatever EAR the verifier handed back, no matter which exchange it came from.
    """
    engine = _engine(_EarVerifier(signing_key, nonce=OTHER_NONCE), signing_key)
    engine.issue_nonce(_TX, _OID)

    outcome = engine.verify_bundle(_bundle(), _TX)

    assert not outcome.accepted
    assert outcome.first_ear is None, "a rejected EAR must not reach the certificate"
    assert "does not match the nonce this RA issued" in outcome.first_failure.errors[0]


def test_the_engine_refuses_an_affirming_verdict_that_carries_no_ear(signing_key) -> None:
    """GIVEN a policy THEN an affirmation with nothing to appraise is not acted on."""
    engine = _engine(_EarVerifier(signing_key, payload=False), signing_key)
    engine.issue_nonce(_TX, _OID)

    outcome = engine.verify_bundle(_bundle(), _TX)

    assert not outcome.accepted
    assert "without an EAR to appraise" in outcome.first_failure.errors[0]


def test_without_a_policy_the_engine_still_trusts_the_verifier(signing_key) -> None:
    """GIVEN no configured policy THEN behaviour is unchanged (in-process verifiers)."""
    engine = _engine(_EarVerifier(signing_key, nonce=OTHER_NONCE), None)
    engine.issue_nonce(_TX, _OID)

    assert engine.verify_bundle(_bundle(), _TX).accepted


def test_a_profile_pinned_anchor_is_preferred_over_the_policy_anchors(signing_key) -> None:
    """GIVEN a per-profile pin THEN the engine verifies against it, not the policy's."""
    profiles = ProfileRegistry()
    profiles.register(
        jwt_profile(
            request_type_oid=_OID,
            statement_oid=_OID,
            verifier=_EarVerifier(signing_key),
            ear_anchor=_anchor_of(signing_key),
        )
    )
    engine = RemoteAttestationEngine(
        profiles,
        ear_policy=EarAcceptancePolicy(anchors=_anchor_of(ec.generate_private_key(ec.SECP256R1()))),
    )
    engine.issue_nonce(_TX, _OID)

    assert engine.verify_bundle(_bundle(), _TX).accepted


def test_the_nonce_response_advertises_the_ttl_it_enforces() -> None:
    """GIVEN no explicit expiry THEN the RA advertises the deadline it actually holds to."""
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=_OID, statement_oid=_OID, verifier=_EarVerifier(_ANY_KEY)))
    engine = RemoteAttestationEngine(profiles, NonceStore(ttl_seconds=120))

    response = engine.build_nonce_response(_TX, _OID)

    assert int(response["expiry"]) == 120, "an absent expiry advertised no deadline while one was enforced"
    assert not engine.build_nonce_response(_TX, _OID, expiry_time=0)["expiry"].isValue

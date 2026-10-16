# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""The privacy-preserving HPKE verifiers, driven by the ordinary RA engine.

Before :func:`~libattest.ra.profile.hpke_profile` these verifiers sat outside the
engine: ``EarEatHpkeVerifier.nonce_response()`` assembled a whole ``NonceResponse``
itself, so the HPKE exchange got none of the engine's nonce lifecycle, no Relying
Party appraisal of the EAR it produced, and no route through the profile registry.
These tests pin the full round trip through the engine for **both** transports.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from libattest import get_nonce_request_oid_for_name, get_oid_by_name
from libattest.asn1_utils import encode_to_der
from libattest.formats import eareat_hpke as evidence
from libattest.formats.eareat_hpke import parse_evidence_enc_nonce_response
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.media_types import EAT_CWT, EAT_JWT
from libattest.ra import (
    EarAcceptancePolicy,
    ProfileRegistry,
    RemoteAttestationEngine,
    hpke_profile,
)
from libattest.verifier.eareat_cose_hpke import CoseEatHpkeVerifier
from libattest.verifier.eareat_hpke import EarEatHpkeVerifier
from libattest.verifier.hpke_base import DEFAULT_REFERENCE_MOCK_CLAIM

TX = b"\x0e" * 16
_TRANSPORTS = [
    pytest.param(EarEatHpkeVerifier, "jose-hpke-evidence", EAT_JWT, id="jose"),
    pytest.param(CoseEatHpkeVerifier, "cose-hpke-evidence", EAT_CWT, id="cose"),
]


def _seal(
    name: str,
    claims: dict,
    signer,
    recipient,
    *,
    nonce: bytes,
    statement_oid: str,
    hpke_info: bytes = b"",
    external_aad: bytes = b"",
) -> bytes:
    """Produce the encrypted-evidence bundle this transport expects."""
    if name.startswith("jose"):
        return evidence.sign_and_build_evidence_bundle(
            claims, signer, recipient, nonce=nonce, statement_oid=statement_oid, hpke_info=hpke_info
        )
    eat = cwt_jwt_utils.sign_es256({**claims, "eat_nonce": cwt_jwt_utils.b64u_encode(nonce)}, signer)
    return evidence.build_cose_evidence_bundle(
        eat,
        recipient,
        signer_key=signer,
        statement_oid=statement_oid,
        hpke_info=hpke_info,
        external_aad=external_aad,
    )


def _engine(verifier, statement_oid: str) -> RemoteAttestationEngine:
    profiles = ProfileRegistry()
    profiles.register(hpke_profile(verifier=verifier, statement_oid=statement_oid))
    # No anchors configured: the profile pins the verifier's own published EAR key.
    return RemoteAttestationEngine(profiles, ear_policy=EarAcceptancePolicy())


@pytest.mark.parametrize(("verifier_class", "oid_name", "media_type"), _TRANSPORTS)
def test_an_hpke_exchange_runs_end_to_end_through_the_engine(verifier_class, oid_name, media_type) -> None:
    """GIVEN an HPKE profile THEN nonce, key publication, seal, appraise and EAR all work."""
    signer = ec.generate_private_key(ec.SECP256R1())
    verifier = verifier_class(attestation_public_key=signer.public_key())
    statement_oid = get_oid_by_name(oid_name)
    engine = _engine(verifier, statement_oid)

    response = engine.build_nonce_response(TX, get_nonce_request_oid_for_name("jose-hpke-evidence-params"))
    nonce, recipient_key, _type_oid = parse_evidence_enc_nonce_response(encode_to_der(response))
    assert recipient_key is not None, "respInfo must publish the verifier's HPKE recipient key"

    bundle = _seal(
        oid_name,
        {"mock_claim": DEFAULT_REFERENCE_MOCK_CLAIM},
        signer,
        recipient_key,
        nonce=nonce,
        statement_oid=statement_oid,
    )
    outcome = engine.verify_bundle(bundle, TX)

    assert outcome.accepted, outcome.first_failure.errors if outcome.first_failure else ()
    assert len(outcome.ear_extensions) == 1
    profile = engine.profiles.by_statement(statement_oid)
    assert profile.media_type == media_type
    assert profile.verifier_id == verifier.verifier_id


@pytest.mark.parametrize(("verifier_class", "oid_name", "media_type"), _TRANSPORTS)
def test_a_cmw_statement_survives_the_profiles_unwrap(verifier_class, oid_name, media_type) -> None:
    """GIVEN a CMW statement THEN the profile does not strip it as an OCTET STRING wrapper.

    A CBOR CMW record *is* an ``OCTET STRING`` at top level, so the generic
    ``unwrap_attestation_statement`` used to eat the CMW itself and hand the verifier
    bare CBOR — the COSE transport could not survive the engine's unwrap at all.
    """
    signer = ec.generate_private_key(ec.SECP256R1())
    verifier = verifier_class(attestation_public_key=signer.public_key())
    profile = hpke_profile(verifier=verifier, statement_oid=get_oid_by_name(oid_name))

    payload = b"\x04\x03abc"  # an OCTET STRING the generic unwrap would strip
    assert profile.unwrap_statement(payload) == (payload, False)


@pytest.mark.parametrize(("verifier_class", "oid_name", "media_type"), _TRANSPORTS)
def test_evidence_sealed_to_another_exchange_is_refused(verifier_class, oid_name, media_type) -> None:
    """GIVEN evidence bound to a different nonce THEN the engine's EAR policy rejects it."""
    signer = ec.generate_private_key(ec.SECP256R1())
    verifier = verifier_class(attestation_public_key=signer.public_key())
    statement_oid = get_oid_by_name(oid_name)
    engine = _engine(verifier, statement_oid)

    response = engine.build_nonce_response(TX, get_nonce_request_oid_for_name("jose-hpke-evidence-params"))
    _nonce, recipient_key, _oid = parse_evidence_enc_nonce_response(encode_to_der(response))
    stale = _seal(
        oid_name,
        {"mock_claim": DEFAULT_REFERENCE_MOCK_CLAIM},
        signer,
        recipient_key,
        nonce=b"\x99" * 32,
        statement_oid=statement_oid,
    )

    assert not engine.verify_bundle(stale, TX).accepted


def test_hpke_profile_refuses_a_verifier_that_publishes_no_recipient_key() -> None:
    """GIVEN a verifier with no published HPKE key THEN fail at configuration time."""
    with pytest.raises(TypeError, match="evidence_encryption_spki_der"):
        hpke_profile(verifier=object(), statement_oid=get_oid_by_name("jose-hpke-evidence"))  # type: ignore[arg-type]


# ── encryption-context binding (opt-in on both ends) ─────────────────────────────
_CONTEXT = b"verifier=atg-demo;exchange=cmp"


def _bound_engine(verifier_class, oid_name, signer, **context):
    verifier = verifier_class(attestation_public_key=signer.public_key(), **context)
    statement_oid = get_oid_by_name(oid_name)
    return verifier, statement_oid, _engine(verifier, statement_oid)


@pytest.mark.parametrize(("verifier_class", "oid_name", "media_type"), _TRANSPORTS)
def test_evidence_bound_to_the_agreed_context_verifies(verifier_class, oid_name, media_type) -> None:
    """GIVEN both ends configured with the same HPKE info THEN the exchange still works."""
    signer = ec.generate_private_key(ec.SECP256R1())
    context: dict[str, bytes] = {"hpke_info": _CONTEXT}
    if not oid_name.startswith("jose"):
        context["external_aad"] = b"aad"
    _verifier, statement_oid, engine = _bound_engine(verifier_class, oid_name, signer, **context)

    response = engine.build_nonce_response(TX, get_nonce_request_oid_for_name("jose-hpke-evidence-params"))
    nonce, recipient_key, _oid = parse_evidence_enc_nonce_response(encode_to_der(response))
    bundle = _seal(
        oid_name,
        {"mock_claim": DEFAULT_REFERENCE_MOCK_CLAIM},
        signer,
        recipient_key,
        nonce=nonce,
        statement_oid=statement_oid,
        **context,
    )

    assert engine.verify_bundle(bundle, TX).accepted


@pytest.mark.parametrize(("verifier_class", "oid_name", "media_type"), _TRANSPORTS)
def test_evidence_sealed_under_another_context_does_not_open(verifier_class, oid_name, media_type) -> None:
    """GIVEN a mismatched HPKE info THEN the AEAD fails and the statement is refused.

    This is what context binding buys: a ciphertext produced for one deployment's
    verifier cannot be opened by another's, even though both hold the same published
    recipient key.
    """
    signer = ec.generate_private_key(ec.SECP256R1())
    _verifier, statement_oid, engine = _bound_engine(verifier_class, oid_name, signer, hpke_info=_CONTEXT)

    response = engine.build_nonce_response(TX, get_nonce_request_oid_for_name("jose-hpke-evidence-params"))
    nonce, recipient_key, _oid = parse_evidence_enc_nonce_response(encode_to_der(response))
    wrong = _seal(
        oid_name,
        {"mock_claim": DEFAULT_REFERENCE_MOCK_CLAIM},
        signer,
        recipient_key,
        nonce=nonce,
        statement_oid=statement_oid,
        hpke_info=b"some-other-deployment",
    )

    outcome = engine.verify_bundle(wrong, TX)

    assert not outcome.accepted
    assert outcome.first_failure is not None
    assert "decode/decrypt" in outcome.first_failure.errors[0]


def test_the_unbound_default_is_unchanged() -> None:
    """GIVEN no configured context THEN sealing and opening behave exactly as before."""
    signer = ec.generate_private_key(ec.SECP256R1())
    verifier = EarEatHpkeVerifier(attestation_public_key=signer.public_key())

    assert verifier._hpke_info == b""  # noqa: SLF001 - the interop-preserving default
    assert verifier._external_aad == b""  # noqa: SLF001


def test_two_hpke_profiles_sharing_a_request_type_warn_about_shadowing(caplog) -> None:
    """GIVEN both transports on the default request OID THEN the collision is not silent.

    The default request type means "publish your recipient key" and is shared by both
    transports, so registering both leaves only the second able to have a nonce issued
    — the first one's evidence then arrives and finds no nonce.  Silently is the wrong
    way to learn that.
    """
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    profiles = ProfileRegistry()
    profiles.register(
        hpke_profile(
            verifier=EarEatHpkeVerifier(attestation_public_key=key),
            statement_oid=get_oid_by_name("jose-hpke-evidence"),
        )
    )

    with caplog.at_level("WARNING"):
        profiles.register(
            hpke_profile(
                verifier=CoseEatHpkeVerifier(attestation_public_key=key),
                statement_oid=get_oid_by_name("cose-hpke-evidence"),
            )
        )

    assert "shadows statement" in caplog.text


def test_both_transports_coexist_on_distinct_request_types() -> None:
    """GIVEN a distinct request OID per transport THEN both are independently usable."""
    signer = ec.generate_private_key(ec.SECP256R1())
    cose_request_oid = "1.3.6.1.4.1.99999.11.2"
    profiles = ProfileRegistry()
    for verifier_class, oid_name, request_oid in (
        (EarEatHpkeVerifier, "jose-hpke-evidence", None),
        (CoseEatHpkeVerifier, "cose-hpke-evidence", cose_request_oid),
    ):
        profiles.register(
            hpke_profile(
                verifier=verifier_class(attestation_public_key=signer.public_key()),
                statement_oid=get_oid_by_name(oid_name),
                request_type_oid=request_oid,
            )
        )
    engine = RemoteAttestationEngine(profiles, ear_policy=EarAcceptancePolicy())

    for oid_name, request_oid in (
        ("jose-hpke-evidence", get_nonce_request_oid_for_name("jose-hpke-evidence-params")),
        ("cose-hpke-evidence", cose_request_oid),
    ):
        statement_oid = get_oid_by_name(oid_name)
        response = engine.build_nonce_response(TX, request_oid)
        nonce, recipient_key, _oid = parse_evidence_enc_nonce_response(encode_to_der(response))
        bundle = _seal(
            oid_name,
            {"mock_claim": DEFAULT_REFERENCE_MOCK_CLAIM},
            signer,
            recipient_key,
            nonce=nonce,
            statement_oid=statement_oid,
        )
        outcome = engine.verify_bundle(bundle, TX)
        assert outcome.accepted, (oid_name, outcome.first_failure.errors if outcome.first_failure else ())

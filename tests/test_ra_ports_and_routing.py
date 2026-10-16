# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the RA-owned verifier port and fail-closed verifier routing.

Three defects are pinned here:

* the engine used to reach the negotiated ``respInfo``, the key-attestation session id
  and the to-be-certified subject key through an ``isinstance`` check on one concrete
  client, so **no** custom verifier could ever receive them;
* :class:`~libattest.verifier.router.VerifierRouter` made the first-registered route the
  default whether or not anyone asked, so evidence of an unrecognised type was
  dispatched to an arbitrary verifier instead of being refused;
* the two HPKE verifiers each carried their own copy of the media-type and freshness
  gates, so the gates could drift apart.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import encoder as der_encoder

from libattest import get_nonce_request_oid_for_name, get_oid_by_name
from libattest.formats.csrattest import (
    pem_chain_to_cmp_certs,
    prepare_attestation_bundle,
    prepare_opaque_attestation_statement,
)
from libattest.formats.media_types import EAT_CWT, EAT_JWT
from libattest.ra import (
    AppraisalRequest,
    ProfileRegistry,
    RemoteAttestationEngine,
    as_evidence_verifier,
    jwt_profile,
    key_attest_profile,
    tpm_profile,
)
from libattest.ra.ports import ReferenceCheckedVerifier
from libattest.testing.fakes import InMemoryVerifier
from libattest.types import EarStatus, VerifyResult
from libattest.verifier.eareat_cose_hpke import CoseEatHpkeVerifier
from libattest.verifier.eareat_hpke import EarEatHpkeVerifier
from libattest.verifier.hpke_base import HpkeEarVerifier
from libattest.verifier.reference import ReferenceCheckResult, VerifierReferenceHandler
from libattest.verifier.router import VerifierRouteError, VerifierRouter

OID = "1.3.6.1.4.1.99999.1"
OTHER_OID = "1.3.6.1.4.1.99999.77"
TX = b"\x02" * 16


class RecordingPortVerifier:
    """A custom verifier that implements only the RA port — no ``AttestationVerifier``."""

    accepts = frozenset({"application/octet-stream"})

    def __init__(self) -> None:
        """Start with an empty record of the requests this verifier was handed."""
        self.requests: list[AppraisalRequest] = []

    def appraise(self, request: AppraisalRequest) -> VerifyResult:
        """Record *request* verbatim and affirm, so tests can assert what crossed the port."""
        self.requests.append(request)
        return VerifyResult.affirming("ear.from.port")


def _bundle(oid: str = OID, payload: bytes = b"jwt.evidence.sig") -> bytes:
    return bytes(der_encoder.encode(prepare_attestation_bundle([prepare_opaque_attestation_statement(oid, payload)])))


# ── the port carries what the isinstance branch used to gate ─────────────────────
def test_custom_verifier_receives_the_negotiated_resp_info() -> None:
    """GIVEN a custom port verifier THEN the negotiated respInfo reaches it as JSON."""
    from libattest.formats import tpm as tpm_formats

    verifier = RecordingPortVerifier()
    request_oid = get_nonce_request_oid_for_name("tpm-quote")
    quote_oid = get_oid_by_name("tcg-attest-quote")
    profiles = ProfileRegistry()
    profiles.register(
        tpm_profile(request_type_oid=request_oid, statement_oid=quote_oid, verifier=verifier, pcrs=[0, 1, 2])
    )
    engine = RemoteAttestationEngine(profiles)

    engine.issue_nonce(TX, request_oid, req_info=tpm_formats.encode_tpm20_quote_req_info(supported_hash_algos=[0x000B]))
    outcome = engine.verify_bundle(_bundle(oid=quote_oid), TX)

    assert outcome.accepted
    (request,) = verifier.requests
    assert request.resp_info is not None, "respInfo was reachable only by VeraisonVerifierClient before"
    assert request.resp_info == {"pcrSelection": [0, 1, 2], "hashAlgo": 11}


def test_custom_verifier_receives_the_session_id_bound_to_its_nonce() -> None:
    """GIVEN a custom port verifier THEN the statement, nonce and session id reach it."""
    verifier = RecordingPortVerifier()
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=OID, statement_oid=OID, verifier=verifier))
    engine = RemoteAttestationEngine(profiles)
    state = engine.nonce_store.issue(TX, OID, session_id="session-7")

    outcome = engine.verify_bundle(_bundle(), TX, pubkey=b"subject-spki-der")

    assert outcome.accepted
    (request,) = verifier.requests
    assert request.session_id == "session-7"
    assert request.statement_oid == OID
    assert request.nonce == state.nonce
    assert request.evidence == b"jwt.evidence.sig", "evidence is the unwrapped statement, not the container"


# ── least authority: the container and the CSR key are not handed out by default ──
def test_a_verifier_that_does_not_parse_the_container_is_not_given_it() -> None:
    """GIVEN a verifier without needs_bundle THEN it gets endorsements, not the bundle."""
    verifier = RecordingPortVerifier()
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=OID, statement_oid=OID, verifier=verifier))
    engine = RemoteAttestationEngine(profiles)
    engine.nonce_store.issue(TX, OID)

    assert engine.verify_bundle(_bundle(), TX).accepted
    (request,) = verifier.requests
    assert request.bundle is None, "the whole bundle carries every other statement in it too"
    assert request.endorsements == (), "this bundle carries no certs"


def test_a_verifier_that_declares_needs_bundle_still_gets_the_container() -> None:
    """GIVEN needs_bundle=True THEN the RA hands over the container it says it parses."""
    verifier = RecordingPortVerifier()
    verifier.needs_bundle = True  # type: ignore[attr-defined]
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=OID, statement_oid=OID, verifier=verifier))
    engine = RemoteAttestationEngine(profiles)
    engine.nonce_store.issue(TX, OID)

    bundle = _bundle()
    assert engine.verify_bundle(bundle, TX).accepted
    assert verifier.requests[0].bundle == bundle


def test_the_subject_key_reaches_only_a_profile_that_binds_it() -> None:
    """GIVEN a profile that does not bind the CSR key THEN the key is withheld from it.

    The engine used to infer "needs the CSR key" from ``build_challenge is not None``
    and then hand the key to *every* verifier regardless; the two are now separate,
    explicit properties.
    """
    plain, binding = RecordingPortVerifier(), RecordingPortVerifier()
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=OID, statement_oid=OID, verifier=plain))
    profiles.register(key_attest_profile(request_type_oid=OTHER_OID, statement_oid=OTHER_OID, verifier=binding))
    engine = RemoteAttestationEngine(profiles)
    engine.nonce_store.issue(TX, OID)
    engine.nonce_store.issue(TX, OTHER_OID)

    engine.verify_bundle(_bundle(), TX, pubkey=b"subject-spki-der", drop_transaction=False)
    engine.verify_bundle(_bundle(oid=OTHER_OID), TX, pubkey=b"subject-spki-der")

    assert plain.requests[0].subject_key is None
    assert binding.requests[0].subject_key == b"subject-spki-der"


def test_a_key_attestation_profile_still_refuses_a_missing_subject_key() -> None:
    """GIVEN binds_subject_key and no CSR key THEN refuse rather than appraise blind."""
    verifier = RecordingPortVerifier()
    profiles = ProfileRegistry()
    profiles.register(key_attest_profile(request_type_oid=OID, statement_oid=OID, verifier=verifier))
    engine = RemoteAttestationEngine(profiles)
    engine.nonce_store.issue(TX, OID)

    outcome = engine.verify_bundle(_bundle(), TX)

    assert not outcome.accepted
    assert verifier.requests == [], "nothing should have been submitted"


# ── the reference check moved behind the verifier boundary ───────────────────────
def test_a_rejecting_reference_handler_downgrades_the_verdict() -> None:
    """GIVEN a rejecting reference handler THEN an affirmation becomes contraindicated."""

    class _Rejecting(VerifierReferenceHandler):
        def handle_evidence(self, evidence, *, attester_id=None) -> ReferenceCheckResult:
            return ReferenceCheckResult(accepted=False, attester_id=attester_id, reason="pcr mismatch")

    verifier = RecordingPortVerifier()
    port = ReferenceCheckedVerifier(verifier, _Rejecting())

    result = port.appraise(
        AppraisalRequest(evidence=b"e", media_type="application/octet-stream", nonce=b"n" * 32, statement_oid=OID)
    )

    assert not result.accepted
    assert "reference check failed: pcr mismatch" in result.errors[0]
    assert port.accepts == verifier.accepts


def test_the_engine_composes_the_reference_handler_onto_the_verifier() -> None:
    """GIVEN a profile reference handler THEN the engine applies it through the port."""

    class _Rejecting(VerifierReferenceHandler):
        def handle_evidence(self, evidence, *, attester_id=None) -> ReferenceCheckResult:
            return ReferenceCheckResult(accepted=False, reason="unknown firmware")

    profiles = ProfileRegistry()
    profiles.register(
        jwt_profile(
            request_type_oid=OID,
            statement_oid=OID,
            verifier=RecordingPortVerifier(),
            reference_handler=_Rejecting(),
        )
    )
    engine = RemoteAttestationEngine(profiles)
    engine.nonce_store.issue(TX, OID)

    outcome = engine.verify_bundle(_bundle(), TX)

    assert not outcome.accepted
    assert "unknown firmware" in outcome.first_failure.errors[0]


# ── the older ABC keeps working, through one visible adapter ─────────────────────
def test_legacy_verify_token_verifier_is_adapted() -> None:
    """GIVEN a verify_token-only verifier THEN the adapter delegates and derives accepts."""
    legacy = InMemoryVerifier(result=VerifyResult.affirming("legacy.ear"))
    legacy.media_type = EAT_JWT
    port = as_evidence_verifier(legacy)

    result = port.appraise(
        AppraisalRequest(evidence=b"e", media_type=EAT_JWT, nonce=b"n" * 32, statement_oid=OID, session_id="ignored")
    )

    assert result.payload == "legacy.ear"
    assert legacy.verify_calls == [(b"e", EAT_JWT, b"n" * 32)]
    assert port.accepts == frozenset({EAT_JWT})


def test_native_port_verifier_is_not_wrapped() -> None:
    """GIVEN a verifier that already implements appraise THEN it is returned unchanged."""
    verifier = RecordingPortVerifier()
    assert as_evidence_verifier(verifier) is verifier


# ── routing fails closed ─────────────────────────────────────────────────────────
def test_unmatched_evidence_gets_no_route_without_an_explicit_default() -> None:
    """GIVEN a route registered without default=True THEN unknown evidence is refused."""
    verifier = InMemoryVerifier()
    router = VerifierRouter()
    router.register("tpm", verifier, evidence_types=[OID])

    result = router.verify_bundle(_bundle(oid=OTHER_OID))

    assert result.per_statement[0].status == EarStatus.unknown
    assert list(result.routes) == [""]
    assert verifier.verify_calls == [], "fail-open dispatch would have appraised it anyway"


def test_explicit_default_route_still_catches_unmatched_evidence() -> None:
    """GIVEN default=True THEN the fallback route is used, as an operator asked for."""
    router = VerifierRouter()
    router.register("catch-all", InMemoryVerifier(), evidence_types=[OID], default=True)

    result = router.verify_bundle(_bundle(oid=OTHER_OID))

    assert list(result.routes) == ["catch-all"]
    assert result.per_statement[0].accepted


def test_route_refuses_a_media_type_its_verifier_does_not_accept() -> None:
    """GIVEN a wire media type outside the route's accepts THEN resolution fails."""
    router = VerifierRouter()
    router.register("jose", InMemoryVerifier(), evidence_types=[OID], accepts={EAT_JWT}, default=True)

    with pytest.raises(VerifierRouteError, match="does not accept media type"):
        router.verify_token(b"evidence", EAT_CWT, evidence_type=OID)


def test_media_type_parameters_do_not_defeat_route_matching() -> None:
    """GIVEN an eat_profile parameter THEN the route still accepts (RFC 9782 §2)."""
    router = VerifierRouter()
    router.register("jose", InMemoryVerifier(), evidence_types=[OID], accepts={EAT_JWT}, default=True)

    assert router.verify_token(b"evidence", f'{EAT_JWT}; eat_profile="1.2.3.4"', evidence_type=OID).accepted


def test_route_accepts_are_taken_from_the_verifier_when_not_declared() -> None:
    """GIVEN a verifier that declares accepts THEN the route inherits them."""
    verifier = EarEatHpkeVerifier(attestation_public_key=ec.generate_private_key(ec.SECP256R1()).public_key())
    router = VerifierRouter()
    router.register("hpke", verifier, evidence_types=[OID])

    assert router.routes["hpke"].accepts == verifier.accepts
    assert EAT_JWT in router.routes["hpke"].accepts


# ── the two HPKE verifiers share one gate ────────────────────────────────────────
@pytest.mark.parametrize("verifier_class", [EarEatHpkeVerifier, CoseEatHpkeVerifier])
def test_hpke_verifiers_share_one_gate_implementation(verifier_class) -> None:
    """GIVEN either HPKE transport THEN the media-type and freshness gates are the same code."""
    verifier = verifier_class(attestation_public_key=ec.generate_private_key(ec.SECP256R1()).public_key())

    assert isinstance(verifier, HpkeEarVerifier)
    # The shared shell is inherited, not re-implemented: only _appraise is overridden.
    assert verifier_class.verify_token is HpkeEarVerifier.verify_token
    assert verifier_class.issue_ear is HpkeEarVerifier.issue_ear
    assert verifier_class._appraise is not HpkeEarVerifier._appraise  # noqa: SLF001

    assert verifier.verify_token(b"stmt", verifier.media_type, None).status == EarStatus.contraindicated
    assert verifier.verify_token(b"stmt", "application/pkcs7-mime", b"n" * 32).status == EarStatus.unknown


def test_hpke_verifiers_stamp_distinct_verifier_ids() -> None:
    """GIVEN the collapse THEN each transport still identifies itself in the issued EAR."""
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    jose = EarEatHpkeVerifier(attestation_public_key=key)
    cose = CoseEatHpkeVerifier(attestation_public_key=key)

    assert jose.evidence_encryption_jwk()["kid"] == "eareat-hpke-verifier"
    assert cose.evidence_encryption_jwk()["kid"] == "cose-hpke-verifier"
    assert jose.issue_ear(b"\x05" * 32) != cose.issue_ear(b"\x05" * 32)


def test_a_single_media_type_declared_as_a_string_is_not_split_into_characters() -> None:
    """GIVEN accepts as a bare str THEN it is one media type, not seventeen letters."""
    router = VerifierRouter()
    router.register("jose", InMemoryVerifier(), evidence_types=[OID], accepts=EAT_JWT, default=True)

    assert router.routes["jose"].accepts == frozenset({EAT_JWT})
    assert router.verify_token(b"evidence", EAT_JWT, evidence_type=OID).accepted


def test_a_verifier_declaring_one_media_type_as_a_string_is_read_the_same_way() -> None:
    """GIVEN a verifier whose accepts is a str THEN both the route and the port coerce it."""
    verifier = InMemoryVerifier()
    verifier.accepts = EAT_JWT  # type: ignore[assignment]
    router = VerifierRouter()
    router.register("jose", verifier, evidence_types=[OID])

    assert router.routes["jose"].accepts == frozenset({EAT_JWT})
    assert as_evidence_verifier(verifier).accepts == frozenset({EAT_JWT})


def test_bundle_endorsements_are_extracted_once_and_handed_to_every_statement() -> None:
    """GIVEN a bundle carrying certs THEN each verifier gets them as DER endorsements."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ak-endorser")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )
    bundle = prepare_attestation_bundle(
        [prepare_opaque_attestation_statement(OID, b"jwt.evidence.sig")],
        certs=pem_chain_to_cmp_certs(cert.public_bytes(serialization.Encoding.PEM).decode()),
    )

    verifier = RecordingPortVerifier()
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=OID, statement_oid=OID, verifier=verifier))
    engine = RemoteAttestationEngine(profiles)
    engine.nonce_store.issue(TX, OID)

    assert engine.verify_bundle(bytes(der_encoder.encode(bundle)), TX).accepted
    (request,) = verifier.requests
    assert request.endorsements == (cert.public_bytes(serialization.Encoding.DER),)
    assert request.bundle is None, "the endorsements arrive without the rest of the container"


# ── every affirming statement yields its extension, not just the first ───────────
def test_every_affirming_statement_yields_its_own_ear_extension() -> None:
    """GIVEN two attested statements THEN both extensions are reachable.

    Only ``first_ear_extension`` existed before, so a second attestation in the same
    bundle was verified and then silently dropped on the way into the certificate.
    """
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=OID, statement_oid=OID, verifier=RecordingPortVerifier()))
    profiles.register(
        jwt_profile(request_type_oid=OTHER_OID, statement_oid=OTHER_OID, verifier=RecordingPortVerifier())
    )
    engine = RemoteAttestationEngine(profiles)
    engine.nonce_store.issue(TX, OID)
    engine.nonce_store.issue(TX, OTHER_OID)

    bundle = prepare_attestation_bundle(
        [
            prepare_opaque_attestation_statement(OID, b"first.evidence"),
            prepare_opaque_attestation_statement(OTHER_OID, b"second.evidence"),
        ]
    )
    outcome = engine.verify_bundle(bytes(der_encoder.encode(bundle)), TX)

    assert outcome.accepted
    assert [oid for oid, _ear in outcome.affirming_ears] == [OID, OTHER_OID]
    assert len(outcome.ear_extensions) == 2
    assert outcome.first_ear_extension == outcome.ear_extensions[0]

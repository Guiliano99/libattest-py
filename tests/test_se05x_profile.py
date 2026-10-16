# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""The SE05x profile, driven end to end by the ordinary RA engine.

Nonce issue, Evidence, bundle, verifier appraisal and Relying Party EAR appraisal all
run in-process through :class:`~libattest.ra.RemoteAttestationEngine` with
:func:`~libattest.ra.se05x_profile`. The Evidence comes from a minimal in-test
"software SE" built like the simulator's answer (field TLVs in the ``82 hh ll`` form,
signature over ``SHA-256(command) || body``); the per-check negatives live in
``tests/test_se05x_verifier.py``.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pyasn1.type import univ

from libattest import get_nonce_request_oid_for_name, get_nonce_response_oid_for_name, get_oid_for_stmt_name
from libattest.asn1_utils import encode_to_der
from libattest.formats.csrattest import (
    pem_chain_to_cmp_certs,
    prepare_asn1_attestation_statement,
    prepare_attestation_bundle,
)
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.media_types import SE05X_ATTESTATION_MEDIA_TYPE
from libattest.formats.se05x import apdu
from libattest.formats.se05x.structures import encode_se05x_attest_evidence
from libattest.ra import (
    EarAcceptancePolicy,
    NonceStore,
    ProfileRegistry,
    RemoteAttestationEngine,
    se05x_profile,
)
from libattest.ra.engine import BundleVerifyOutcome
from libattest.ra.profile import AttestationProfile
from libattest.verifier.reference import ReferenceCheckResult, VerifierReferenceHandler
from libattest.verifier.se05x import Se05xAttestVerifier

TX = b"\x05" * 16
_REQUEST_OID = get_nonce_request_oid_for_name("se05x-attest-request")
_RESPONSE_OID = get_nonce_response_oid_for_name("se05x-attest-response")
_STATEMENT_OID = get_oid_for_stmt_name("se05x-attest")
_POLICY_ID = "policy:SE05X/demo-sim-root"
_OBJECT_ID = 0x10AA0002
_TEST_EAR_OID = "1.2.3.4.5.6.7"  # test-private
_NOW = datetime.datetime.now(datetime.UTC)


def _cert(subject: str, public_key, issuer_key, issuer: str, *, ca: bool) -> x509.Certificate:
    def name(common_name: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    return (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def _spki(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


# The software SE: a demo root, the attestation key with its certificate, the SE-generated key.
_ROOT_NAME = "libattest demo SE05x attestation root (not NXP)"
_ROOT_KEY = ec.generate_private_key(ec.SECP256R1())
_ROOT = _cert(_ROOT_NAME, _ROOT_KEY.public_key(), _ROOT_KEY, _ROOT_NAME, ca=True)
_ATTEST_KEY = ec.generate_private_key(ec.SECP256R1())
_LEAF = _cert("SE05x attestation key 0xF0000012", _ATTEST_KEY.public_key(), _ROOT_KEY, _ROOT_NAME, ca=False)
_SUBJECT_KEY = ec.generate_private_key(ec.SECP256R1()).public_key()


def _tlv82(tag: int, value: bytes) -> bytes:
    return bytes((tag, 0x82)) + len(value).to_bytes(2, "big") + value


def _evidence(nonce: bytes) -> bytes:
    """Return a DER ``Se05xAttestEvidence``: the SE's attested read of ``_SUBJECT_KEY`` under *nonce*."""
    command = apdu.recorded_command(apdu.build_attested_read(_OBJECT_ID, nonce))
    policy = apdu.POLICY_ALLOW_READ | apdu.POLICY_ALLOW_SIGN | apdu.POLICY_ALLOW_ATTESTATION
    attributes = (
        _OBJECT_ID.to_bytes(4, "big")
        + bytes((apdu.TYPE_EC_KEY_PAIR_NIST_P256, 0x01))  # type, set indicator NOT_SET
        + bytes(8)  # minimum AEAD tag length, owner, RFU
        + bytes((8,))
        + bytes(4)
        + policy.to_bytes(4, "big")  # one policy: len || authObjId || AR header
        + bytes((apdu.ORIGIN_INTERNAL,))
        + bytes(4)  # object version
    )
    point = _SUBJECT_KEY.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    body = (
        _tlv82(0x41, point)
        + _tlv82(0x42, bytes(18))  # chip id
        + _tlv82(0x43, attributes)
        + _tlv82(0x44, apdu.P256_KEY_SIZE.to_bytes(2, "big"))
        + _tlv82(0x4F, bytes(12))  # timestamp
    )
    signature = _ATTEST_KEY.sign(hashlib.sha256(command).digest() + body, ec.ECDSA(hashes.SHA256()))
    return encode_se05x_attest_evidence(command, body + bytes((0x52, len(signature))) + signature)


def _bundle(nonce: bytes) -> bytes:
    """Pack the Evidence as the Attester does: an ASN.1 statement plus the attestation certificate."""
    statement = prepare_asn1_attestation_statement(univ.ObjectIdentifier(_STATEMENT_OID), _evidence(nonce))
    certs = pem_chain_to_cmp_certs(_LEAF.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    return encode_to_der(prepare_attestation_bundle([statement], certs=certs))


def _verifier() -> Se05xAttestVerifier:
    return Se05xAttestVerifier(roots=[_ROOT], policy_id=_POLICY_ID)


def _engine(profile: AttestationProfile) -> RemoteAttestationEngine:
    profiles = ProfileRegistry()
    profiles.register(profile)
    # No anchors configured: the profile pins the verifier's own EAR key.
    return RemoteAttestationEngine(profiles, NonceStore(nonce_bytes=16), ear_policy=EarAcceptancePolicy())


def _issue_nonce(engine: RemoteAttestationEngine) -> bytes:
    return bytes(engine.build_nonce_response(TX, _REQUEST_OID)["nonce"])


def _reason(outcome: BundleVerifyOutcome) -> str:
    failure = outcome.first_failure
    assert failure is not None
    return " ".join(failure.errors)


def test_the_se05x_oids_round_trip_through_the_profile_registry() -> None:
    """GIVEN a registered SE05x profile THEN both lookups find it and it reads its wiring off the verifier."""
    verifier = _verifier()
    profiles = ProfileRegistry()
    profile = profiles.register(se05x_profile(verifier=verifier))

    assert profiles.by_request_type(_REQUEST_OID) is profile
    assert profiles.by_statement(_STATEMENT_OID) is profile
    assert profile.response_type_oid == _RESPONSE_OID
    assert profile.binds_subject_key
    assert profile.media_type == SE05X_ATTESTATION_MEDIA_TYPE
    assert profile.verifier_id == verifier.verifier_id
    assert profile.ear_anchor == verifier.ear_verification_pem()
    assert profile.build_verifier_info(None).resp_info is None


def test_an_se05x_exchange_runs_end_to_end_through_the_engine() -> None:
    """GIVEN the SE05x profile WHEN nonce, Evidence and bundle round-trip THEN the verifier's EAR is accepted."""
    verifier = _verifier()
    engine = _engine(se05x_profile(verifier=verifier))

    response = engine.build_nonce_response(TX, _REQUEST_OID)
    nonce = bytes(response["nonce"])
    assert len(nonce) == 16
    assert str(response["respTypeInfo"]["type"]) == _RESPONSE_OID
    assert not response["respTypeInfo"]["respInfo"].isValue, "SE05x negotiates nothing"

    outcome = engine.verify_bundle(_bundle(nonce), TX, pubkey=_spki(_SUBJECT_KEY))

    assert outcome.accepted, _reason(outcome)
    assert outcome.first_ear is not None
    claims = cwt_jwt_utils.verify_es256(outcome.first_ear, verifier.ear_verification_pem())
    assert cwt_jwt_utils.b64u_decode(claims["eat_nonce"]) == nonce
    assert claims["submods"] == {
        "SE05X": {
            "ear.status": "affirming",
            "ear.trustworthiness-vector": {"instance-identity": 2},
            "ear.appraisal-policy-id": _POLICY_ID,
        }
    }
    assert outcome.first_ear_extension is not None, "the EAR reaches the certificate-extension encoder"


def test_a_bundle_without_the_subject_key_is_refused() -> None:
    """GIVEN a subject-binding profile WHEN verify_bundle gets no pubkey THEN the engine refuses the statement."""
    engine = _engine(se05x_profile(verifier=_verifier()))

    outcome = engine.verify_bundle(_bundle(_issue_nonce(engine)), TX)

    assert not outcome.accepted
    assert "key attestation requires the to-be-certified SubjectPublicKeyInfo" in _reason(outcome)


def test_a_bundle_for_another_subject_key_is_refused() -> None:
    """GIVEN Evidence for one key WHEN the CSR carries another THEN the verifier refuses the binding."""
    engine = _engine(se05x_profile(verifier=_verifier()))
    other = ec.generate_private_key(ec.SECP256R1()).public_key()

    outcome = engine.verify_bundle(_bundle(_issue_nonce(engine)), TX, pubkey=_spki(other))

    assert not outcome.accepted
    assert "subject key does not match the attested key" in _reason(outcome)


def test_a_replayed_bundle_is_refused() -> None:
    """GIVEN an accepted bundle WHEN it is sent again under a fresh nonce of the same tx THEN it is refused."""
    engine = _engine(se05x_profile(verifier=_verifier()))
    bundle = _bundle(_issue_nonce(engine))
    assert engine.verify_bundle(bundle, TX, pubkey=_spki(_SUBJECT_KEY)).accepted

    _issue_nonce(engine)
    replay = engine.verify_bundle(bundle, TX, pubkey=_spki(_SUBJECT_KEY))

    assert not replay.accepted
    assert "does not match the RA nonce" in _reason(replay)


def test_an_ear_signed_by_another_key_is_refused_by_the_policy() -> None:
    """GIVEN an RA that pins another verifier's EAR key THEN the affirming EAR fails the Relying Party check."""
    profile = dataclasses.replace(se05x_profile(verifier=_verifier()), ear_anchor=_verifier().ear_verification_pem())
    engine = _engine(profile)

    outcome = engine.verify_bundle(_bundle(_issue_nonce(engine)), TX, pubkey=_spki(_SUBJECT_KEY))

    assert not outcome.accepted
    assert "EAR signature did not verify against the configured trust anchor" in _reason(outcome)


def test_the_ear_goes_under_the_configured_extension_oid() -> None:
    """GIVEN se05x_profile(ear_oid=...) WHEN the bundle is accepted THEN the EAR extension carries that OID."""
    engine = _engine(se05x_profile(verifier=_verifier(), ear_oid=_TEST_EAR_OID))

    outcome = engine.verify_bundle(_bundle(_issue_nonce(engine)), TX, pubkey=_spki(_SUBJECT_KEY))

    assert outcome.accepted, _reason(outcome)
    assert outcome.first_ear_extension is not None
    assert outcome.first_ear_extension[0] == _TEST_EAR_OID


def test_a_rejecting_reference_handler_refuses_valid_evidence() -> None:
    """GIVEN se05x_profile(reference_handler=<rejecting>) WHEN valid Evidence arrives THEN the engine refuses it."""

    class _Rejecting(VerifierReferenceHandler):
        def handle_evidence(self, evidence, *, attester_id=None) -> ReferenceCheckResult:
            return ReferenceCheckResult(accepted=False, reason="unknown chip id")

    engine = _engine(se05x_profile(verifier=_verifier(), reference_handler=_Rejecting()))

    outcome = engine.verify_bundle(_bundle(_issue_nonce(engine)), TX, pubkey=_spki(_SUBJECT_KEY))

    assert not outcome.accepted
    assert "reference check failed: unknown chip id" in _reason(outcome)

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the SE05x verifier (:class:`~libattest.verifier.se05x.Se05xAttestVerifier`).

The Evidence comes from a small in-test "software SE": a P-256 attestation key with a
certificate under a demo root, a response body built by hand exactly as the patched
simulator builds it (every TLV in the ``82 hh ll`` form, the signature TLV in short
form) and signed with ECDSA/SHA-256 over ``SHA-256(command) || body``. The signed
message is computed here without :func:`libattest.formats.se05x.apdu.signed_message`,
so the test cross-checks the codec rather than reusing it. The cross-check against the
real simulator is the golden vector in ``tests/test_se05x_golden.py``.
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from libattest import get_oid_for_stmt_name
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.media_types import SE05X_ATTESTATION_MEDIA_TYPE
from libattest.formats.se05x import apdu
from libattest.formats.se05x.structures import encode_se05x_attest_evidence
from libattest.ra import AppraisalRequest, EarAcceptancePolicy
from libattest.types import EarStatus
from libattest.verifier.se05x import Se05xAttestVerifier

_POLICY_ID = "policy:SE05X/demo-sim-root"
_NONCE = bytes.fromhex("00112233445566778899aabbccddeeff")
_OBJECT_ID = 0x10AA0002
_CHIP_ID = bytes.fromhex("8a938c757fa75ad5a711a20a04b9a0d78e84")
_TIMESTAMP = bytes.fromhex("6ab382d60000000000000003")
_KEY_POLICY = apdu.POLICY_ALLOW_READ | apdu.POLICY_ALLOW_SIGN | apdu.POLICY_ALLOW_ATTESTATION
_NOW = datetime.datetime.now(datetime.UTC)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _root(common_name: str, *, path_length: int | None = 0) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _leaf(
    public_key: ec.EllipticCurvePublicKey,
    issuer: tuple[ec.EllipticCurvePrivateKey, x509.Certificate],
    *,
    not_after: datetime.datetime = _NOW + datetime.timedelta(days=365),
    subject: str = "SE05x attestation key 0xF0000012",
    ca: bool = False,
    key_usage: x509.KeyUsage | None = None,
) -> x509.Certificate:
    """Issue a certificate for *public_key* under *issuer*: an end entity unless *ca* (then pathLen 0)."""
    issuer_key, issuer_cert = issuer
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - datetime.timedelta(days=400))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


def _key_usage(*, digital_signature: bool = False, key_encipherment: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(digital_signature, False, key_encipherment, False, False, False, False, False, False)


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _spki(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _point(key: ec.EllipticCurvePublicKey, fmt=serialization.PublicFormat.UncompressedPoint) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, fmt)


def _compressed_spki(key: ec.EllipticCurvePublicKey) -> bytes:
    """Return the P-256 SPKI of *key* with a compressed point, an encoding RFC 5480 permits."""
    header = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")
    return header + _point(key, serialization.PublicFormat.CompressedPoint)


# The software SE: a demo root, the attestation key and its certificate, the attested key.
_ROOT = _root("libattest demo SE05x attestation root (not NXP)")
_ATTEST_KEY = ec.generate_private_key(ec.SECP256R1())
_LEAF = _leaf(_ATTEST_KEY.public_key(), _ROOT)
_SUBJECT_KEY = ec.generate_private_key(ec.SECP256R1()).public_key()


def _attributes(object_id: int = _OBJECT_ID, *, type_code: int = 0x29, origin: int = 0x02) -> bytes:
    """Return a TAG_3 attribute block as the simulator encodes it (one policy entry)."""
    return (
        object_id.to_bytes(4, "big")
        + bytes((type_code, 0x01))  # type, kSE05x_SetIndicator_NOT_SET
        + b"\x00\x00"  # minimum AEAD tag length
        + b"\x00" * 4  # owner
        + b"\x00\x00"  # RFU
        + bytes((8,))
        + (0).to_bytes(4, "big")
        + _KEY_POLICY.to_bytes(4, "big")  # policy: len || authObjId || AR header
        + bytes((origin,))
        + b"\x00" * 4  # object version (PR #19)
    )


@dataclasses.dataclass(frozen=True)
class _Read:
    """One attested read as the software SE answers it; a test overrides single fields."""

    freshness: bytes = _NONCE
    attest_key_id: int = apdu.ATTEST_KEY_ID
    algo: int = apdu.ALGO_ECDSA_SHA256
    value: bytes | None = _point(_SUBJECT_KEY)
    attributes: bytes = _attributes()
    object_size: int = 0x0020
    signer: ec.EllipticCurvePrivateKey = _ATTEST_KEY


def _tlv82(tag: int, value: bytes) -> bytes:
    return bytes((tag, 0x82)) + len(value).to_bytes(2, "big") + value


def _tlv_short(tag: int, value: bytes) -> bytes:
    return bytes((tag, len(value))) + value


def _command_and_body(read: _Read = _Read(), *, wire_tlv=_tlv82) -> tuple[bytes, bytes]:
    """Return ``(recorded command, response body)`` for *read*, signed as the simulator signs.

    The SE signs the field TLVs in the ``82 hh ll`` form whatever form it sends them in;
    *wire_tlv* picks the form on the wire.
    """
    command = apdu.recorded_command(
        apdu.build_attested_read(_OBJECT_ID, read.freshness, attest_key_id=read.attest_key_id, algo=read.algo)
    )
    fields = [
        *([] if read.value is None else [(0x41, read.value)]),
        (0x42, _CHIP_ID),
        (0x43, read.attributes),
        (0x44, read.object_size.to_bytes(2, "big")),
        (0x4F, _TIMESTAMP),
    ]
    signed = hashlib.sha256(command).digest() + b"".join(_tlv82(tag, value) for tag, value in fields)
    signature = read.signer.sign(signed, ec.ECDSA(hashes.SHA256()))
    body = b"".join(wire_tlv(tag, value) for tag, value in fields)
    return command, body + bytes((0x52, len(signature))) + signature


def _evidence(read: _Read = _Read()) -> bytes:
    return encode_se05x_attest_evidence(*_command_and_body(read))


def _request(
    evidence: bytes,
    *,
    nonce: bytes = _NONCE,
    media_type: str = SE05X_ATTESTATION_MEDIA_TYPE,
    chain: tuple[x509.Certificate, ...] = (_LEAF,),
    subject_key: bytes | None = _spki(_SUBJECT_KEY),
) -> AppraisalRequest:
    return AppraisalRequest(
        evidence=evidence,
        media_type=media_type,
        nonce=nonce,
        statement_oid=get_oid_for_stmt_name("se05x-attest"),
        endorsements=tuple(_der(cert) for cert in chain),
        subject_key=subject_key,
    )


def _verifier() -> Se05xAttestVerifier:
    return Se05xAttestVerifier(roots=[_ROOT[1]], policy_id=_POLICY_ID)


# ── affirming path ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "subject_key",
    [_spki(_SUBJECT_KEY), _compressed_spki(_SUBJECT_KEY), None],
    ids=["subject-bound", "compressed-subject-spki", "no-subject-key"],
)
def test_a_valid_attested_read_is_affirmed_with_the_ar4si_ear(subject_key: bytes | None) -> None:
    """GIVEN a fresh, correctly signed attested read WHEN appraised THEN the EAR claims instance-identity 2 only."""
    verifier = _verifier()

    verdict = verifier.appraise(_request(_evidence(), subject_key=subject_key))

    assert verdict.status == EarStatus.affirming, verdict.errors
    assert isinstance(verdict.payload, str)
    claims = cwt_jwt_utils.verify_es256(verdict.payload, verifier.ear_verification_pem())
    assert claims["submods"] == {
        "SE05X": {
            "ear.status": "affirming",
            "ear.trustworthiness-vector": {"instance-identity": 2},
            "ear.appraisal-policy-id": _POLICY_ID,
        }
    }
    assert cwt_jwt_utils.b64u_decode(claims["eat_nonce"]) == _NONCE
    assert claims["ear.verifier-id"]["developer"] == verifier.verifier_id


def test_the_ra_accepts_the_ear_with_the_pinned_key_and_its_nonce() -> None:
    """GIVEN an affirming SE05x EAR WHEN the RA appraises it with the verifier's pinned key THEN it is accepted."""
    verifier = _verifier()
    ear = verifier.appraise(_request(_evidence())).payload
    assert isinstance(ear, str)

    decision = EarAcceptancePolicy().appraise(
        ear, expected_nonce=_NONCE, anchor=verifier.ear_verification_pem(), verifier_id=verifier.verifier_id
    )

    assert decision.accepted, decision.result.errors
    assert (
        not EarAcceptancePolicy()
        .appraise(ear, expected_nonce=bytes(16), anchor=verifier.ear_verification_pem())
        .accepted
    ), "the EAR is bound to the RA nonce"


def test_the_verifier_declares_the_se05x_media_type() -> None:
    """GIVEN the verifier THEN it declares and accepts only the SE05x media type."""
    assert Se05xAttestVerifier.media_type == SE05X_ATTESTATION_MEDIA_TYPE
    assert _verifier().accepts == frozenset({SE05X_ATTESTATION_MEDIA_TYPE})


def test_the_configured_ear_key_and_developer_are_used() -> None:
    """GIVEN an EAR signing key and a developer WHEN an EAR is issued THEN that key signs it and it names them."""
    ear_key = ec.generate_private_key(ec.SECP256R1())
    verifier = Se05xAttestVerifier(
        roots=[_ROOT[1]], policy_id=_POLICY_ID, ear_signing_key=ear_key, verifier_developer="custom-dev"
    )

    ear = verifier.appraise(_request(_evidence())).payload

    assert isinstance(ear, str)
    assert serialization.load_pem_public_key(verifier.ear_verification_pem().encode()) == ear_key.public_key()
    assert cwt_jwt_utils.verify_es256(ear, ear_key.public_key())["ear.verifier-id"]["developer"] == "custom-dev"


def test_the_policy_id_and_roots_are_required() -> None:
    """GIVEN no policy id or no roots WHEN the verifier is built THEN construction fails."""
    with pytest.raises(TypeError):
        Se05xAttestVerifier(roots=[_ROOT[1]])  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="policy_id"):
        Se05xAttestVerifier(roots=[_ROOT[1]], policy_id="")
    with pytest.raises(ValueError, match="root"):
        Se05xAttestVerifier(roots=[], policy_id=_POLICY_ID)


# ── one negative per check ───────────────────────────────────────────────────────
def _legacy_layout() -> bytes:
    """Return an applet-3.x response body: value, attributes, timestamp, freshness, chip id, signature."""
    body = (
        _tlv82(0x41, _point(_SUBJECT_KEY))
        + _tlv82(0x42, _attributes())
        + _tlv82(0x43, _TIMESTAMP)
        + _tlv82(0x44, _NONCE)
        + _tlv82(0x45, _CHIP_ID)
    )
    signature = _ATTEST_KEY.sign(body, ec.ECDSA(hashes.SHA256()))
    command, _ = _command_and_body()
    return encode_se05x_attest_evidence(command, body + bytes((0x46, len(signature))) + signature)


def _with_body(transform) -> bytes:
    command, body = _command_and_body()
    return encode_se05x_attest_evidence(command, transform(body))


def _wire_command() -> bytes:
    _, body = _command_and_body()
    return encode_se05x_attest_evidence(apdu.build_attested_read(_OBJECT_ID, _NONCE), body)


_P384_KEY = ec.generate_private_key(ec.SECP384R1())
_OTHER_ROOT = _root("untrusted root")
_OTHER_KEY = ec.generate_private_key(ec.SECP256R1())
# An NXP-shaped chain: a root without pathLenConstraint, an intermediate CA, the leaf.
_OPEN_ROOT = _root("attestation root without pathLenConstraint", path_length=None)
_INTERMEDIATE_KEY = ec.generate_private_key(ec.SECP256R1())
_INTERMEDIATE = _leaf(_INTERMEDIATE_KEY.public_key(), _OPEN_ROOT, subject="attestation intermediate CA", ca=True)
_CHAINED_LEAF = _leaf(_ATTEST_KEY.public_key(), (_INTERMEDIATE_KEY, _INTERMEDIATE))
# DER of OIDs, to corrupt an endorsement the way an Attester could.
_ECDSA_WITH_SHA256 = bytes.fromhex("06082a8648ce3d040302")  # 1.2.840.10045.4.3.2
_UNKNOWN_SIGNATURE_ALGORITHM = bytes.fromhex("06082a8648ce3d040309")  # 1.2.840.10045.4.3.9
_KEY_USAGE_OID = bytes.fromhex("0603551d0f")  # 2.5.29.15
_BASIC_CONSTRAINTS_OID = bytes.fromhex("0603551d13")  # 2.5.29.19
_SIGNING_LEAF = _leaf(_ATTEST_KEY.public_key(), _ROOT, key_usage=_key_usage(digital_signature=True))


def _with_endorsement(der: bytes) -> AppraisalRequest:
    return dataclasses.replace(_request(_evidence()), endorsements=(der,))


_NEGATIVE_CASES = [
    pytest.param(
        lambda: _request(_evidence(), media_type="application/octet-stream"),
        "unsupported media type",
        id="wrong-media-type",
    ),
    pytest.param(lambda: _request(_evidence(), nonce=_NONCE[:15]), "16-byte RA nonce", id="nonce-15"),
    pytest.param(lambda: _request(_evidence(), nonce=_NONCE + b"\x00"), "16-byte RA nonce", id="nonce-17"),
    pytest.param(lambda: _request(_evidence(), nonce=_NONCE * 2), "16-byte RA nonce", id="nonce-32"),
    pytest.param(lambda: _request(_evidence() + b"\x00"), "not a DER Se05xAttestEvidence", id="trailing-bytes"),
    pytest.param(lambda: _request(_wire_command()), "command APDU rejected", id="command-with-le"),
    pytest.param(
        lambda: _request(_evidence(_Read(freshness=bytes(16)))),
        "does not match the RA nonce",
        id="tag7-mismatch",
    ),
    pytest.param(
        lambda: _request(_evidence(_Read(attest_key_id=0xF0000099))),
        "attestation key id 0xf0000099",
        id="other-attestation-key-id",
    ),
    pytest.param(lambda: _request(_evidence(_Read(algo=0x22))), "algorithm 0x22", id="algo-0x22"),
    pytest.param(lambda: _request(_legacy_layout()), "response body rejected", id="legacy-layout"),
    pytest.param(
        lambda: _request(_with_body(lambda body: body + b"\x90\x00")),
        "response body rejected",
        id="trailing-status-word",
    ),
    pytest.param(lambda: _request(_evidence(_Read(value=None))), "no TAG_1", id="no-tag1"),
    pytest.param(
        lambda: _request(_evidence(_Read(value=_point(_SUBJECT_KEY, serialization.PublicFormat.CompressedPoint)))),
        "65-byte uncompressed",
        id="compressed-point",
    ),
    pytest.param(
        lambda: _request(_evidence(_Read(value=b"\x02" + _point(_SUBJECT_KEY)[1:]))),
        "65-byte uncompressed",
        id="65-bytes-without-04",
    ),
    pytest.param(
        lambda: _request(_evidence(_Read(value=b"\x04" + b"\x01" * 64))),
        "not a point on P-256",
        id="point-off-curve",
    ),
    pytest.param(
        lambda: _request(_evidence(_Read(attributes=_attributes()[:14]))),
        "object attributes rejected",
        id="attributes-truncated",
    ),
    pytest.param(
        lambda: _request(_evidence(_Read(attributes=_attributes(0x10AA0003)))),
        "attribute object id 0x10aa0003",
        id="attribute-id-mismatch",
    ),
    pytest.param(
        lambda: _request(_evidence(_Read(attributes=_attributes(type_code=0x21)))),
        "object type 0x21",
        id="wrong-type",
    ),
    pytest.param(
        lambda: _request(_evidence(_Read(attributes=_attributes(origin=0x01)))),
        "key origin 0x01",
        id="origin-imported",
    ),
    pytest.param(lambda: _request(_evidence(_Read(object_size=0x0030))), "object size 0x0030", id="wrong-size"),
    pytest.param(
        lambda: _request(_evidence(), chain=(_leaf(_ATTEST_KEY.public_key(), _OTHER_ROOT),)),
        "does not terminate at a trusted root",
        id="untrusted-root",
    ),
    pytest.param(
        lambda: _request(
            _evidence(), chain=(_leaf(_ATTEST_KEY.public_key(), _ROOT, not_after=_NOW - datetime.timedelta(days=1)),)
        ),
        "certificate not valid at",
        id="expired-certificate",
    ),
    pytest.param(lambda: _request(_evidence(), chain=()), "empty certificate chain", id="no-chain"),
    pytest.param(
        lambda: _request(_evidence(), chain=(_INTERMEDIATE, _CHAINED_LEAF)),
        "certificate issuer does not match",
        id="chain-root-first",
    ),
    pytest.param(
        lambda: _request(_evidence(), chain=(_leaf(_ATTEST_KEY.public_key(), _OPEN_ROOT, ca=True),)),
        "not an end-entity signing certificate",
        id="ca-leaf",
    ),
    pytest.param(
        lambda: _request(
            _evidence(), chain=(_leaf(_ATTEST_KEY.public_key(), _ROOT, key_usage=_key_usage(key_encipherment=True)),)
        ),
        "not an end-entity signing certificate",
        id="leaf-without-digital-signature",
    ),
    pytest.param(
        lambda: _with_endorsement(_der(_LEAF).replace(_ECDSA_WITH_SHA256, _UNKNOWN_SIGNATURE_ALGORITHM)),
        "attestation certificate chain rejected",
        id="unknown-signature-algorithm",
    ),
    pytest.param(
        lambda: _with_endorsement(_der(_SIGNING_LEAF).replace(_KEY_USAGE_OID, _BASIC_CONSTRAINTS_OID)),
        "attestation certificate chain rejected",
        id="duplicate-extension",
    ),
    pytest.param(
        lambda: _request(_evidence(), chain=(_leaf(_P384_KEY.public_key(), _ROOT),)),
        "not a P-256 key",
        id="p384-attestation-key",
    ),
    pytest.param(
        lambda: _request(_evidence(_Read(signer=_OTHER_KEY))),
        "signature does not verify",
        id="signed-by-another-key",
    ),
    pytest.param(
        lambda: _request(_with_body(lambda body: body.replace(_CHIP_ID, b"\xff" + _CHIP_ID[1:], 1))),
        "signature does not verify",
        id="tampered-chip-id",
    ),
    pytest.param(
        lambda: _request(_evidence(), subject_key=_spki(_OTHER_KEY.public_key())),
        "subject key does not match",
        id="subject-key-mismatch",
    ),
    pytest.param(
        lambda: _request(_evidence(), subject_key=b"\x30\x00"),
        "not a DER SubjectPublicKeyInfo",
        id="subject-key-not-spki",
    ),
]


@pytest.mark.parametrize(("make_request", "reason"), _NEGATIVE_CASES)
def test_a_failed_check_is_contraindicated_without_an_ear(make_request, reason: str) -> None:
    """GIVEN Evidence failing exactly one check WHEN appraised THEN it is contraindicated, with no EAR."""
    # Two roots: the demo-shaped one (pathLen 0) and one without pathLen, so a CA leaf reaches the leaf check.
    verdict = Se05xAttestVerifier(roots=[_ROOT[1], _OPEN_ROOT[1]], policy_id=_POLICY_ID).appraise(make_request())

    assert verdict.status == EarStatus.contraindicated
    assert verdict.payload is None, "no EAR is issued on failure"
    assert len(verdict.errors) == 1
    assert reason in verdict.errors[0]


# ── other valid shapes ───────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("roots", "make_request"),
    [
        pytest.param(
            [_OPEN_ROOT[1]],
            lambda: _request(_evidence(), chain=(_CHAINED_LEAF, _INTERMEDIATE)),
            id="leaf-intermediate-root",
        ),
        pytest.param([_OTHER_ROOT[1], _ROOT[1]], lambda: _request(_evidence()), id="second-of-two-roots"),
        pytest.param(
            [_ROOT[1]], lambda: _request(_evidence(), chain=(_SIGNING_LEAF,)), id="leaf-with-digital-signature"
        ),
        pytest.param(
            [_ROOT[1]],
            lambda: _request(encode_se05x_attest_evidence(*_command_and_body(wire_tlv=_tlv_short))),
            id="short-form-wire-tlvs",
        ),
        pytest.param(
            [_ROOT[1]],
            lambda: _request(_evidence(), media_type=f"{SE05X_ATTESTATION_MEDIA_TYPE}; v=1"),
            id="media-type-parameter",
        ),
    ],
)
def test_other_valid_evidence_shapes_are_affirmed(roots: list[x509.Certificate], make_request) -> None:
    """GIVEN a valid attested read in another permitted shape WHEN appraised THEN it is affirmed.

    The verifier signs over the ``82 hh ll`` re-encoding, never the wire bytes (AN12413
    §4.1.3.2 lets the SE send either length form); it takes the signing key from the
    first certificate and tries every root.
    """
    verdict = Se05xAttestVerifier(roots=roots, policy_id=_POLICY_ID).appraise(make_request())

    assert verdict.status == EarStatus.affirming, verdict.errors

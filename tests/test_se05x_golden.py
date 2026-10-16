# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""The SE05x verifier against Evidence produced by the patched SE050 simulator.

``tests/data/se05x/golden_vector.json`` holds one attested read of a P-256 key pair
generated inside the simulator (random attestation key), captured with
``Se05xClient.attested_read`` under a random 16-byte RA nonce. The bytes come from the
Rust simulator and are parsed by the Python codec, so this is the non-circular check
beside the in-test "software SE" of ``tests/test_se05x_verifier.py``. The simulator
has no certificate of its own: the test mints a demo root and a certificate over the
captured attestation public key at test time, so the vector never expires.

Recapture it with a running simulator (``docker/se05x-demo/README.md``) whenever the
simulator's attestation patch changes; the vector records the patch's SHA-256, and a
test fails when the patch no longer matches it.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from libattest import get_oid_for_stmt_name
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.media_types import SE05X_ATTESTATION_MEDIA_TYPE
from libattest.formats.se05x.structures import encode_se05x_attest_evidence
from libattest.ra.ports import AppraisalRequest
from libattest.types import EarStatus, VerifyResult
from libattest.verifier.se05x import Se05xAttestVerifier

_VECTOR = json.loads((Path(__file__).parent / "data" / "se05x" / "golden_vector.json").read_text())
_NONCE = bytes.fromhex(_VECTOR["nonce"])
_COMMAND = bytes.fromhex(_VECTOR["recorded_command"])
_BODY = bytes.fromhex(_VECTOR["response_body"])
_SUBJECT_SPKI = bytes.fromhex(_VECTOR["subject_public_key_spki"])
_POLICY_ID = "policy:SE05X/demo-sim-root"
_SIM_PATCH = Path(__file__).parents[1] / "docker" / "se05x-demo" / "sim" / "0003-se05x-attestation.patch"
# The body starts with TAG_1 (41 82 00 41 | 65-byte point); the chip id TLV (42 82 00 12) follows.
_CHIP_ID_OFFSET = 4 + 65 + 4


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _root_and_leaf() -> tuple[x509.Certificate, x509.Certificate]:
    """Mint a demo root and, under it, a certificate for the captured attestation key."""
    attest_key = serialization.load_der_public_key(bytes.fromhex(_VECTOR["attestation_public_key_spki"]))
    assert isinstance(attest_key, ec.EllipticCurvePublicKey)
    root_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)

    def cert(subject: str, public_key: ec.EllipticCurvePublicKey, *, ca: bool) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(_name(subject))
            .issuer_name(_name("libattest demo SE05x attestation root (not NXP)"))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
            .sign(root_key, hashes.SHA256())
        )

    root = cert("libattest demo SE05x attestation root (not NXP)", root_key.public_key(), ca=True)
    return root, cert("SE05x attestation key", attest_key, ca=False)


def _appraise(*, body: bytes = _BODY, nonce: bytes = _NONCE) -> tuple[Se05xAttestVerifier, VerifyResult]:
    root, leaf = _root_and_leaf()
    verifier = Se05xAttestVerifier(roots=[root], policy_id=_POLICY_ID)
    request = AppraisalRequest(
        evidence=encode_se05x_attest_evidence(_COMMAND, body),
        media_type=SE05X_ATTESTATION_MEDIA_TYPE,
        nonce=nonce,
        statement_oid=get_oid_for_stmt_name("se05x-attest"),
        endorsements=(leaf.public_bytes(serialization.Encoding.DER),),
        subject_key=_SUBJECT_SPKI,
    )
    return verifier, verifier.appraise(request)


def test_the_vector_was_captured_with_the_current_simulator_patch() -> None:
    """GIVEN the vector's recorded patch hash THEN it equals the SHA-256 of today's attestation patch."""
    assert hashlib.sha256(_SIM_PATCH.read_bytes()).hexdigest() == _VECTOR["sim_patch_0003_sha256"], (
        "simulator patch changed: recapture the golden vector"
    )


def test_the_captured_evidence_is_affirmed_with_the_exact_ear() -> None:
    """GIVEN the simulator's Evidence and a root over its attestation key THEN an affirming EAR, exact submods."""
    verifier, result = _appraise()

    assert result.status == EarStatus.affirming, result.errors
    assert isinstance(result.payload, str)
    claims = cwt_jwt_utils.verify_es256(result.payload, verifier.ear_verification_pem())
    assert cwt_jwt_utils.b64u_decode(claims["eat_nonce"]) == _NONCE
    assert claims["submods"] == {
        "SE05X": {
            "ear.status": "affirming",
            "ear.trustworthiness-vector": {"instance-identity": 2},
            "ear.appraisal-policy-id": _POLICY_ID,
        }
    }


def test_one_flipped_byte_of_the_response_is_contraindicated() -> None:
    """GIVEN the captured response with one chip-id byte flipped THEN the SE's signature no longer verifies."""
    assert _BODY[_CHIP_ID_OFFSET - 4 : _CHIP_ID_OFFSET] == bytes.fromhex("42820012"), "vector layout changed"
    body = bytearray(_BODY)
    body[_CHIP_ID_OFFSET] ^= 0x01

    _, result = _appraise(body=bytes(body))

    assert result.status == EarStatus.contraindicated
    assert result.payload is None
    assert result.errors == ("Evidence signature does not verify with the attestation certificate key",)


@pytest.mark.parametrize("nonce", [bytes(16), _NONCE[:-1] + bytes((_NONCE[-1] ^ 0x01,))], ids=["zero", "last-bit"])
def test_another_nonce_is_contraindicated(nonce: bytes) -> None:
    """GIVEN the captured Evidence WHEN appraised under another RA nonce THEN TAG_7 does not match."""
    _, result = _appraise(nonce=nonce)

    assert result.status == EarStatus.contraindicated
    assert result.payload is None
    assert result.errors == ("freshness TAG_7 of the signed command does not match the RA nonce",)

# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for EarEatHpkeVerifier — the full HPKE-0 EAR/EAT appraisal pipeline.

Builds a real AttestationBundle (a CMW Record carrying a JOSE-HPKE-0 JWE of a signed
EAT-JWS) using the library's own bundle helpers, then drives the verifier end-to-end:
CMW extraction -> HPKE-open -> inner EAT-JWS verify -> freshness (inner + protected-header
eat_nonce) -> mock_claim appraisal -> signed EAR.  Negatives exercise each gate: tampered
ciphertext, wrong mock_claim, replayed nonce, bad inner signature, missing nonce, wrong
media type.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ

from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.cmw import encode_cmw_json_record
from libattest.formats.csrattest import (
    decode_attestation_bundle,
    prepare_attestation_bundle,
    prepare_attestation_statement,
)
from libattest.types import EarStatus
from libattest.verifier.eareat_hpke import EarEatHpkeVerifier

EVIDENCE_OID = "1.3.6.1.4.1.99999.10"
NONCE = b"\x01" * 32


def _attester_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def _make_verifier(attester: ec.EllipticCurvePrivateKey, mock_claim: str = "secure") -> EarEatHpkeVerifier:
    return EarEatHpkeVerifier(
        attestation_public_key=_attester_pem(attester),
        reference_mock_claim=mock_claim,
    )


# This helper mirrors every independent evidence variation used by the negative tests.
# pylint: disable=too-many-arguments
def _bundle_der(
    verifier: EarEatHpkeVerifier,
    attester: ec.EllipticCurvePrivateKey,
    *,
    nonce: bytes = NONCE,
    mock_claim: str = "secure",
    tamper: bool = False,
    oid: str = EVIDENCE_OID,
    inner_signer: ec.EllipticCurvePrivateKey | None = None,
) -> bytes:
    """Build an AttestationBundle DER mirroring what the gencmpclient attester emits."""
    inner = cwt_jwt_utils.sign_es256(
        {"eat_nonce": cwt_jwt_utils.b64u_encode(nonce), "mock_claim": mock_claim, "iat": 0},
        inner_signer or attester,
    )
    jwe = cwt_jwt_utils.seal_integrated(
        inner.encode(),
        {"kid": "eareat-hpke-verifier", "eat_nonce": cwt_jwt_utils.b64u_encode(nonce)},
        verifier.evidence_encryption_jwk(),
    )
    if tamper:
        parts = jwe.split(".")
        parts[3] = ("B" if parts[3][0] != "B" else "C") + parts[3][1:]
        jwe = ".".join(parts)
    cmw_der = encode_cmw_json_record("application/jose", cwt_jwt_utils.b64u_encode(jwe.encode("ascii")), 4)
    statement = prepare_attestation_statement(univ.ObjectIdentifier(oid), cmw_der)
    return der_encoder.encode(prepare_attestation_bundle([statement]))


# pylint: enable=too-many-arguments
def test_positive_affirming_and_ear_verifies() -> None:
    """Verify that a valid JOSE-HPKE bundle produces a signed affirming EAR."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    result = verifier.verify_bundle_der(_bundle_der(verifier, attester), NONCE)

    assert result.accepted
    # The MockCA verifies the EAR against the published key — do the same here.
    claims = cwt_jwt_utils.verify_es256(result.payload, verifier.ear_verification_pem())
    assert claims["submods"]["ATG_PLUGIN"]["ear.status"] == "affirming"
    assert claims["eat_nonce"] == cwt_jwt_utils.b64u_encode(NONCE)


def test_issue_ear_contraindicated_keeps_veraison_wire_format() -> None:
    """Preserve the expected Veraison wire claims for contraindicated EARs."""
    # The EAR is now built via a validated EARToken, but must still emit the Veraison
    # claims-set (dotted keys, veraison profile, 99 trust vector) the consumers expect.
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    claims = cwt_jwt_utils.verify_es256(verifier.issue_ear(NONCE, "contraindicated"), verifier.ear_verification_pem())
    assert claims["eat_profile"] == "tag:github.com,2023:veraison/ear"
    assert claims["ear.verifier-id"] == {"build": "N/A", "developer": "eareat-hpke-verifier"}
    assert claims["eat_nonce"] == cwt_jwt_utils.b64u_encode(NONCE)
    submod = claims["submods"]["ATG_PLUGIN"]
    assert submod["ear.status"] == "contraindicated"
    assert submod["ear.appraisal-policy-id"] == "policy:ATG_PLUGIN"
    assert set(submod["ear.trustworthiness-vector"].values()) == {99}


def test_cmw_stmt_is_utf8string() -> None:
    """Encode JOSE evidence in the CMW UTF8String alternative."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    bundle = decode_attestation_bundle(_bundle_der(verifier, attester))
    stmt_der = bytes(bundle["attestations"][0]["stmt"])
    assert stmt_der[0] == 0x0C  # UTF8String


def test_negative_tampered_ciphertext() -> None:
    """Reject an evidence bundle after modifying its ciphertext."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    result = verifier.verify_bundle_der(_bundle_der(verifier, attester, tamper=True), NONCE)
    assert not result.accepted


def test_negative_wrong_mock_claim() -> None:
    """Reject evidence whose mock claim does not meet the appraisal policy."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    result = verifier.verify_bundle_der(_bundle_der(verifier, attester, mock_claim="insecure"), NONCE)
    assert not result.accepted


def test_negative_replayed_nonce() -> None:
    """Reject evidence reused with a different freshness nonce."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    # Evidence bound to NONCE, but appraised against a different expected nonce.
    result = verifier.verify_bundle_der(_bundle_der(verifier, attester), b"\x02" * 32)
    assert not result.accepted


def test_negative_bad_inner_signature() -> None:
    """Reject evidence whose inner EAT is signed by an untrusted key."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    rogue = ec.generate_private_key(ec.SECP256R1())  # signs the inner EAT but is not trusted
    result = verifier.verify_bundle_der(_bundle_der(verifier, attester, inner_signer=rogue), NONCE)
    assert not result.accepted


def test_verify_token_missing_nonce_rejected() -> None:
    """Reject token verification when no expected freshness nonce is supplied."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    result = verifier.verify_token(b"\x0c\x00", verifier.media_type, None)
    assert not result.accepted


def test_verify_token_wrong_media_type_unknown() -> None:
    """Return an unknown result for a token with an unsupported media type."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _make_verifier(attester)
    result = verifier.verify_token(b"\x0c\x00", "application/cbor", NONCE)
    assert result.status == EarStatus.unknown


def test_evidence_encryption_jwk_shape() -> None:
    """Expose only the public P-256 HPKE recipient-key parameters."""
    verifier = _make_verifier(ec.generate_private_key(ec.SECP256R1()))
    jwk = verifier.evidence_encryption_jwk()
    assert (jwk["kty"], jwk["crv"], jwk["alg"], jwk["use"]) == ("EC", "P-256", "HPKE-0", "enc")
    assert "d" not in jwk

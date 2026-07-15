# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""End-to-end JWT-HPKE flow over the reusable libattest.formats.eareat_hpke helpers.

Exercises the full privacy-preserving EAR/EAT chain as the demo runs it, using ONLY
libattest structures (no hand-rolled ASN.1):

  1. CMP nonce-freshness exchange — verifier publishes its HPKE key in a ``NonceResponse``
     (libattest ``NonceResponse``); the attester parses it.
  2. Attester builds the encrypted evidence ``AttestationBundle`` (libattest CSR
     attestation-statement structures + jose_hpke + CMW record).
  3. Verifier decodes the bundle, HPKE-opens, verifies the inner EAT-JWS, appraises, and
     issues a signed EAR.

Plus codec round-trips (CMW record, NonceRequest/NonceResponse) and a tamper negative.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der import decoder, encoder

from libattest import get_nonce_request_oid_for_name, get_nonce_response_oid_for_name
from libattest.formats import eareat_hpke as evidence
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.csrattest import NonceRequest, NonceResponse
from libattest.verifier.eareat_hpke import EarEatHpkeVerifier
from libattest.x509 import decode_cmw_json_record, encode_cmw_json_record

NONCE = b"\x07" * 32


def _verifier(attester: ec.EllipticCurvePrivateKey) -> EarEatHpkeVerifier:
    pem = attester.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return EarEatHpkeVerifier(attestation_public_key=pem)


def test_full_chain_affirming() -> None:
    """Verify the nonce exchange, JOSE-HPKE evidence, and affirming appraisal chain."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _verifier(attester)

    # 1. CMP nonce exchange: verifier hands the attester the nonce + its HPKE key.
    nonce_resp_der = verifier.nonce_response(NONCE, expiry=300)
    nonce, hpke_key, type_oid = evidence.parse_evidence_enc_nonce_response(nonce_resp_der)
    assert nonce == NONCE
    assert type_oid == get_nonce_response_oid_for_name("jose-hpke-evidence-params")
    assert isinstance(hpke_key, ec.EllipticCurvePublicKey)

    # 2. Attester builds the HPKE-encrypted evidence bundle (libattest CSR structures).
    bundle_der = evidence.sign_and_build_evidence_bundle(
        {"mock_claim": "secure", "iat": 0},
        attester,
        hpke_key,
        nonce=nonce,
    )

    # 3. Verifier appraises and issues an EAR that verifies under the published key.
    result = verifier.verify_bundle_der(bundle_der, nonce)
    assert result.accepted
    claims = cwt_jwt_utils.verify_es256(result.payload, verifier.ear_verification_pem())
    assert claims["submods"]["ATG_PLUGIN"]["ear.status"] == "affirming"


def test_full_chain_wrong_claim_contraindicated() -> None:
    """Reject evidence whose mock claim does not satisfy the verifier policy."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _verifier(attester)
    _, hpke_key, _ = evidence.parse_evidence_enc_nonce_response(verifier.nonce_response(NONCE))
    assert isinstance(hpke_key, ec.EllipticCurvePublicKey)
    bundle_der = evidence.sign_and_build_evidence_bundle(
        {"mock_claim": "insecure"},
        attester,
        hpke_key,
        nonce=NONCE,
    )
    assert not verifier.verify_bundle_der(bundle_der, NONCE).accepted


def test_full_chain_tampered_bundle_contraindicated() -> None:
    """Reject a JOSE-HPKE evidence bundle after ciphertext tampering."""
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _verifier(attester)
    _, hpke_key, _ = evidence.parse_evidence_enc_nonce_response(verifier.nonce_response(NONCE))
    assert isinstance(hpke_key, ec.EllipticCurvePublicKey)
    bundle_der = bytearray(
        evidence.sign_and_build_evidence_bundle({"mock_claim": "secure"}, attester, hpke_key, nonce=NONCE)
    )
    bundle_der[-1] ^= 0x01  # flip a ciphertext byte near the end
    assert not verifier.verify_bundle_der(bytes(bundle_der), NONCE).accepted


def test_cmw_record_roundtrip() -> None:
    """Round-trip JOSE CMW records with and without the optional type indicator."""
    compact_jwe = "a.b..c."
    encoded_jwe = cwt_jwt_utils.b64u_encode(compact_jwe.encode("ascii"))
    der = encode_cmw_json_record(evidence.CMW_MEDIA_JOSE, encoded_jwe, evidence.CMW_TYPE_JOSE)
    assert decode_cmw_json_record(der) == (evidence.CMW_MEDIA_JOSE, encoded_jwe, evidence.CMW_TYPE_JOSE)
    # two-element record (no cmw_type)
    der2 = encode_cmw_json_record("application/eat+jwt", "xyz")
    assert decode_cmw_json_record(der2) == ("application/eat+jwt", "xyz", None)


def test_nonce_request_roundtrip() -> None:
    """Round-trip a nonce request carrying the evidence-encryption type OID."""
    req_der = evidence.build_nonce_request(length=32)
    req, _ = decoder.decode(req_der, asn1Spec=NonceRequest())
    assert int(req["len"]) == 32
    assert str(req["reqTypeInfo"]["type"]) == get_nonce_request_oid_for_name("jose-hpke-evidence-params")


def test_nonce_response_without_respinfo() -> None:
    """Preserve a nonce response that does not advertise an HPKE key."""
    # A zero-length nonce / no respInfo means "no key advertised".
    resp = NonceResponse()
    resp["nonce"] = NONCE
    der = encoder.encode(resp)
    nonce, hpke_key, type_oid = evidence.parse_evidence_enc_nonce_response(der)
    assert nonce == NONCE and hpke_key is None and type_oid is None


def test_extract_jwe_rejects_non_jose_record() -> None:
    """Reject CMW records with a media type other than the JOSE evidence type."""
    der = encode_cmw_json_record("application/eat+jwt", "not-a-jwe")
    with pytest.raises(ValueError, match="media type"):
        evidence.extract_jwe_from_statement(der)


def test_jose_evidence_statement_carries_a_base64url_compact_jwe() -> None:
    """GIVEN a JOSE evidence statement WHEN encoded THEN its CMW record holds base64url text."""
    signer = ec.generate_private_key(ec.SECP256R1())
    recipient = ec.generate_private_key(ec.SECP256R1())
    eat_jws = cwt_jwt_utils.sign_es256({"eat_nonce": cwt_jwt_utils.b64u_encode(NONCE)}, signer)

    statement = evidence.build_evidence_statement(eat_jws, recipient.public_key(), nonce=NONCE)
    media_type, encoded_jwe, cmw_type = decode_cmw_json_record(bytes(statement["stmt"]))

    assert media_type == evidence.CMW_MEDIA_JOSE
    assert cmw_type == evidence.CMW_TYPE_JOSE
    assert encoded_jwe == cwt_jwt_utils.b64u_encode(evidence.extract_jwe_from_statement(bytes(statement["stmt"])).encode())

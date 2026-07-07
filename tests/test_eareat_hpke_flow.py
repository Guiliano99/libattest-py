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

from libattest.formats import eareat_hpke as evidence
from libattest.formats import jose_jws
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
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _verifier(attester)

    # 1. CMP nonce exchange: verifier hands the attester the nonce + its HPKE key.
    nonce_resp_der = verifier.nonce_response(NONCE, expiry=300)
    nonce, hpke_key, type_oid = evidence.parse_evidence_enc_nonce_response(nonce_resp_der)
    assert nonce == NONCE
    assert type_oid == evidence.EVIDENCE_ENC_PARAMS_OID
    assert isinstance(hpke_key, ec.EllipticCurvePublicKey)

    # 2. Attester builds the HPKE-encrypted evidence bundle (libattest CSR structures).
    bundle_der = evidence.sign_and_build_evidence_bundle(
        {"mock_claim": "secure", "iat": 0}, attester, hpke_key, nonce=nonce,
    )

    # 3. Verifier appraises and issues an EAR that verifies under the published key.
    result = verifier.verify_bundle_der(bundle_der, nonce)
    assert result.accepted
    claims = jose_jws.verify_es256(result.payload, verifier.ear_verification_pem())
    assert claims["submods"]["ATG_PLUGIN"]["ear.status"] == "affirming"


def test_full_chain_wrong_claim_contraindicated() -> None:
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _verifier(attester)
    _, hpke_key, _ = evidence.parse_evidence_enc_nonce_response(verifier.nonce_response(NONCE))
    bundle_der = evidence.sign_and_build_evidence_bundle(
        {"mock_claim": "insecure"}, attester, hpke_key, nonce=NONCE,
    )
    assert not verifier.verify_bundle_der(bundle_der, NONCE).accepted


def test_full_chain_tampered_bundle_contraindicated() -> None:
    attester = ec.generate_private_key(ec.SECP256R1())
    verifier = _verifier(attester)
    _, hpke_key, _ = evidence.parse_evidence_enc_nonce_response(verifier.nonce_response(NONCE))
    bundle_der = bytearray(
        evidence.sign_and_build_evidence_bundle({"mock_claim": "secure"}, attester, hpke_key, nonce=NONCE)
    )
    bundle_der[-1] ^= 0x01  # flip a ciphertext byte near the end
    assert not verifier.verify_bundle_der(bytes(bundle_der), NONCE).accepted


def test_cmw_record_roundtrip() -> None:
    der = encode_cmw_json_record(evidence.CMW_MEDIA_JOSE, "a.b..c.", evidence.CMW_TYPE_JOSE)
    assert decode_cmw_json_record(der) == (evidence.CMW_MEDIA_JOSE, "a.b..c.", evidence.CMW_TYPE_JOSE)
    # two-element record (no cmw_type)
    der2 = encode_cmw_json_record("application/eat+jwt", "xyz")
    assert decode_cmw_json_record(der2) == ("application/eat+jwt", "xyz", None)


def test_nonce_request_roundtrip() -> None:
    req_der = evidence.build_nonce_request(length=32)
    req, _ = decoder.decode(req_der, asn1Spec=NonceRequest())
    assert int(req["len"]) == 32
    assert str(req["reqTypeInfo"]["type"]) == evidence.EVIDENCE_ENC_PARAMS_OID


def test_nonce_response_without_respinfo() -> None:
    # A zero-length nonce / no respInfo means "no key advertised".
    resp = NonceResponse()
    resp["nonce"] = NONCE
    der = encoder.encode(resp)
    nonce, hpke_key, type_oid = evidence.parse_evidence_enc_nonce_response(der)
    assert nonce == NONCE and hpke_key is None and type_oid is None


def test_extract_jwe_rejects_non_jose_record() -> None:
    der = encode_cmw_json_record("application/eat+jwt", "not-a-jwe")
    with pytest.raises(ValueError, match="media type"):
        evidence.extract_jwe_from_statement(der)

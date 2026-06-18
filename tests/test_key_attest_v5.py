import json

from pyasn1.codec.der import decoder, encoder

from libattest.formats.key_attest_pop import (
    KeyAttestChall,
    VerifierMakeCredentialRequest,
    decode_key_attest_resp,
    encode_to_der,
    key_attest_chall_ak_name,
    key_attest_chall_ek_cert_chain,
    key_attest_chall_json_value,
    key_attest_resp_enc_secret,
    key_attest_resp_enc_seed,
    prepare_key_attest_chall,
    prepare_key_attest_resp,
    resolve_key_attest_chall_oid,
    resolve_key_attest_resp_oid,
    verifier_make_credential_request_to_json,
    verifier_make_credential_result_from_json,
    verifier_make_credential_result_to_json,
)


def test_key_attest_chall_is_oid_and_utf8_json():
    chall = prepare_key_attest_chall(ak_name=b"ak-name", ek_cert_chain=[b"cert-a", b"cert-b"])

    assert chall.componentType[0].name == "type"
    assert chall.componentType[1].name == "value"
    assert key_attest_chall_ak_name(chall) == b"ak-name"

    decoded, rest = decoder.decode(encoder.encode(chall), asn1Spec=KeyAttestChall())
    assert rest == b""
    assert str(decoded["type"]) == resolve_key_attest_chall_oid()
    assert key_attest_chall_ek_cert_chain(decoded) == [b"cert-a", b"cert-b"]
    assert json.loads(str(decoded["value"])) == {
        "akName": "616b2d6e616d65",
        "ekCertChain": ["636572742d61", "636572742d62"],
    }


def test_key_attest_resp_is_oid_and_utf8_json_without_seed():
    resp = prepare_key_attest_resp(enc_seed=b"credential-blob", enc_secret=b"encrypted-secret")

    assert resp.componentType[0].name == "type"
    assert resp.componentType[1].name == "value"
    assert key_attest_resp_enc_seed(resp) == b"credential-blob"
    assert key_attest_resp_enc_secret(resp) == b"encrypted-secret"

    decoded = decode_key_attest_resp(encode_to_der(resp))
    assert str(decoded["type"]) == resolve_key_attest_resp_oid()
    value = json.loads(str(decoded["value"]))
    assert value == {
        "encSeed": "63726564656e7469616c2d626c6f62",
        "encSecret": "656e637279707465642d736563726574",
    }
    assert "seed" not in value


def test_key_attest_chall_json_helper_returns_application_payload():
    chall = prepare_key_attest_chall(ak_name=b"ak-name", ek_cert_chain=[])

    assert key_attest_chall_json_value(chall) == {
        "akName": "616b2d6e616d65",
        "ekCertChain": [],
    }


def test_verifier_make_credential_request_json_forwards_ak_name_and_ek_chain():
    req = VerifierMakeCredentialRequest(
        transaction_id="tx-1",
        ak_name=b"ak-name",
        ek_cert_chain=[b"cert-a", b"cert-b"],
        policy={"profile": "demo"},
    )

    assert verifier_make_credential_request_to_json(req) == {
        "transactionID": "tx-1",
        "akName": "616b2d6e616d65",
        "ekCertChain": ["636572742d61", "636572742d62"],
        "policy": {"profile": "demo"},
    }


def test_verifier_make_credential_result_json_keeps_seed_out_of_asn1_response():
    result = verifier_make_credential_result_from_json(
        {
            "seed": "73656564",
            "encSeed": "63726564656e7469616c",
            "encSecret": "736563726574",
        }
    )

    assert result.seed == b"seed"
    assert result.enc_seed == b"credential"
    assert result.enc_secret == b"secret"

    as_json = verifier_make_credential_result_to_json(result)
    assert as_json == {
        "seed": "73656564",
        "encSeed": "63726564656e7469616c",
        "encSecret": "736563726574",
    }

    resp = prepare_key_attest_resp(
        enc_seed=result.enc_seed,
        enc_secret=result.enc_secret,
    )
    encoded = encode_to_der(resp)
    assert b"seed" not in encoded
    assert "seed" not in str(decode_key_attest_resp(encoded)["value"])

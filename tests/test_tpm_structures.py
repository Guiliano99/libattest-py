# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""DER round-trip tests for the consolidated ``formats.tpm.structures`` module.

Covers the six v6 key-attestation structures (with the trailing-optional
``pcrValues`` present / absent / trailing-garbage-rejected hazard) and confirms the
moved quote + TCG structures still round-trip unchanged after consolidation.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from libattest.asn1_utils import encode_to_der
from libattest.formats.csrattest import pem_chain_to_cmp_certs
from libattest.formats.tpm import structures as s


def _self_signed_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ek-test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ── OID defaults ────────────────────────────────────────────────────────────────


def test_v6_oid_defaults():
    assert str(s.id_tpm_iak_key_attest_request) == "1.3.6.1.4.1.99999.5.1"
    assert str(s.id_tpm_iak_key_attest_response) == "1.3.6.1.4.1.99999.5.2"
    assert str(s.id_tpm_iak_key_attest_statement) == "1.3.6.1.4.1.99999.5.3"
    assert str(s.id_tpm_ldevid_key_attest_request) == "1.3.6.1.4.1.99999.6.1"
    assert str(s.id_tpm_ldevid_key_attest_response) == "1.3.6.1.4.1.99999.6.2"
    assert str(s.id_tpm_ldevid_key_attest_statement) == "1.3.6.1.4.1.99999.6.3"


# ── Profile B (IAK) round-trips ──────────────────────────────────────────────────


def test_iak_req_info_roundtrip_and_makecred_json():
    ek_pem = _self_signed_pem()
    req = s.prepare_iak_key_attest_req_info(
        ak_public=b"AK-2B-PUBLIC",
        supported_hash_algos=[0x000B],
        ek_cert_chain_pem=ek_pem,
        ek_public=b"EK-2B-PUBLIC",
    )
    decoded = s.decode_iak_key_attest_req_info(encode_to_der(req))
    assert bytes(decoded["akPublic"]) == b"AK-2B-PUBLIC"
    assert bytes(decoded["ekPublic"]) == b"EK-2B-PUBLIC"
    assert [int(x) for x in decoded["supportedHashAlgo"]] == [0x000B]
    assert len(decoded["ekCertChain"]) == 1

    # /makeCredential JSON carries akPublic (NOT akName — M4 computes the name).
    j = s.iak_key_attest_req_info_to_json(encode_to_der(req))
    assert j == {
        "akPublic": b"AK-2B-PUBLIC".hex(),
        "ekPublic": b"EK-2B-PUBLIC".hex(),
        "ekCertChain": j["ekCertChain"],
    }
    assert "akName" not in j
    assert len(pem_chain_to_cmp_certs(j["ekCertChain"])) == 1


def test_iak_resp_info_roundtrip_carries_pcr_selection():
    resp = s.prepare_iak_key_attest_resp_info(
        enc_seed=b"encrypted-seed", enc_secret=b"credential-blob", pcr_selection=[4, 0, 1], hash_algo=0x000B
    )
    decoded = s.decode_iak_key_attest_resp_info(encode_to_der(resp))
    assert bytes(decoded["encSeed"]) == b"encrypted-seed"
    assert bytes(decoded["encSecret"]) == b"credential-blob"
    assert [int(x) for x in decoded["pcrSelection"]] == [0, 1, 4]  # deduped, ascending
    assert int(decoded["hashAlgo"]) == 0x000B


def test_iak_evidence_roundtrip_with_pcr_values():
    ev = s.prepare_iak_key_attest_evidence(b"attest", b"quote-sig", b"activation-sig", pcr_values=b"pcrs")
    decoded = s.decode_iak_key_attest_evidence(encode_to_der(ev))
    assert bytes(decoded["tpmsAttest"]) == b"attest"
    assert bytes(decoded["quoteSignature"]) == b"quote-sig"
    assert bytes(decoded["activationSignature"]) == b"activation-sig"
    assert bytes(decoded["pcrValues"]) == b"pcrs"


def test_iak_evidence_roundtrip_without_pcr_values():
    # The trailing OPTIONAL must decode unambiguously when absent.
    ev = s.prepare_iak_key_attest_evidence(b"attest", b"quote-sig", b"activation-sig")
    der = encode_to_der(ev)
    decoded = s.decode_iak_key_attest_evidence(der)
    assert bytes(decoded["activationSignature"]) == b"activation-sig"
    assert not decoded["pcrValues"].isValue


def test_iak_evidence_rejects_trailing_bytes():
    der = encode_to_der(s.prepare_iak_key_attest_evidence(b"a", b"q", b"x"))
    with pytest.raises(ValueError):
        s.decode_iak_key_attest_evidence(der + b"\x00")


# ── Profile C (LDevID) round-trips ───────────────────────────────────────────────


def test_ldevid_req_info_roundtrip():
    req = s.prepare_ldevid_key_attest_req_info(b"LDEVID-2B-PUBLIC", ["ak-1", "ak-2"])
    decoded = s.decode_ldevid_key_attest_req_info(encode_to_der(req))
    assert bytes(decoded["ldevidPublic"]) == b"LDEVID-2B-PUBLIC"
    assert [str(x) for x in decoded["certificateName"]] == ["ak-1", "ak-2"]


def test_ldevid_resp_info_roundtrip():
    resp = s.prepare_ldevid_key_attest_resp_info("ak-1")
    decoded = s.decode_ldevid_key_attest_resp_info(encode_to_der(resp))
    assert str(decoded["certificateName"]) == "ak-1"


def test_ldevid_evidence_roundtrip_tpmtpublic_mandatory():
    ev = s.prepare_ldevid_key_attest_evidence(b"certify-attest", b"iak-sig", b"bare-tpmt-public")
    decoded = s.decode_ldevid_key_attest_evidence(encode_to_der(ev))
    assert bytes(decoded["tpmsAttest"]) == b"certify-attest"
    assert bytes(decoded["tpmtSignature"]) == b"iak-sig"
    assert bytes(decoded["tpmTPublic"]) == b"bare-tpmt-public"


def test_ldevid_evidence_rejects_trailing_bytes():
    der = encode_to_der(s.prepare_ldevid_key_attest_evidence(b"a", b"s", b"p"))
    with pytest.raises(ValueError):
        s.decode_ldevid_key_attest_evidence(der + b"\x00")


# ── moved quote + TCG structures still round-trip after consolidation ────────────


def test_quote_req_info_still_roundtrips():
    der = s.encode_tpm20_quote_req_info(certificate_names=["ak-1"], supported_hash_algos=[0x000B])
    names, algos = s.decode_tpm20_quote_req_info(der)
    assert names == ["ak-1"]
    assert algos == [0x000B]


def test_quote_resp_info_still_roundtrips():
    der = s.encode_tpm20_quote_resp_info(pcr_selection=[0, 1, 2], hash_algo=0x000B, certificate_name="ak-1")
    name, pcrs, hash_algo = s.decode_tpm20_quote_resp_info(der)
    assert name == "ak-1"
    assert pcrs == [0, 1, 2]
    assert hash_algo == 0x000B


def test_tcg_attest_certify_still_roundtrips():
    val = s.prepare_tcg_attest_certify(b"attest", b"sig", b"tpub")
    decoded = s.decode_tcg_attest_certify(encode_to_der(val))
    assert bytes(decoded["tpmSAttest"]) == b"attest"
    assert bytes(decoded["signature"]) == b"sig"
    assert bytes(decoded["tpmTPublic"]) == b"tpub"

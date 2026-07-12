# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""v5 TPM key-attestation: typed ASN.1 codecs, JSON adapters, and verify() gates.

The full make_credential<->activate + certify + PoP round-trip needs a live TPM
and is exercised by ``docker/tpm-demo`` and the remote-attest-e2e docker stack;
these tests cover the TPM-free layers: DER round-trips, the RA<->verifier JSON
adapters, and the verifier's early appraisal gates (decode / magic / freshness).
"""

from __future__ import annotations

import datetime
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from libattest.formats.csrattest import pem_chain_to_cmp_certs
from libattest.formats.key_attest_pop import (
    DEFAULT_KEY_ATTEST_EVIDENCE_OID,
    decode_key_attest_chall,
    decode_key_attest_evidence,
    decode_key_attest_resp,
    encode_to_der,
    key_attest_chall_to_json,
    key_attest_resp_from_json,
    prepare_key_attest_chall,
    prepare_key_attest_evidence,
    prepare_key_attest_resp,
    resolve_key_attest_evidence_oid,
)
from libattest.verifier.verify_bridge import verify_key_attest


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


def _certify_attest(nonce: bytes, *, magic: int = 0xFF544347, atype: int = 0x8017) -> bytes:
    """Hand-build a minimal certify ``TPMS_ATTEST`` (type 0x8017)."""
    def tpm2b(b: bytes) -> bytes:
        return struct.pack(">H", len(b)) + b

    name34 = b"\x00\x0b" + b"\x11" * 32
    return b"".join(
        [
            struct.pack(">I", magic),
            struct.pack(">H", atype),
            tpm2b(name34),  # qualifiedSigner
            tpm2b(nonce),  # extraData
            b"\x00" * 17,  # clockInfo
            b"\x00" * 8,  # firmwareVersion
            tpm2b(name34),  # TPMS_CERTIFY_INFO.name
            tpm2b(b""),  # qualifiedName
        ]
    )


# ── typed ASN.1 round-trips ────────────────────────────────────────────────────


def test_key_attest_chall_roundtrip_and_adapter():
    ek_pem = _self_signed_pem()
    chall = prepare_key_attest_chall(ak_name=b"\xab" * 34, ek_public=b"EK-PUB", ek_cert_chain_pem=ek_pem)

    decoded = decode_key_attest_chall(encode_to_der(chall))
    assert bytes(decoded["akName"]) == b"\xab" * 34
    assert bytes(decoded["ekPublic"]) == b"EK-PUB"
    assert len(decoded["ekCertChain"]) == 1

    # adapter: KeyAttestChall DER -> {akName hex, ekPublic hex, ekCertChain PEM}
    j = key_attest_chall_to_json(encode_to_der(chall))
    assert j["akName"] == (b"\xab" * 34).hex()
    assert j["ekPublic"] == b"EK-PUB".hex()
    assert "BEGIN CERTIFICATE" in j["ekCertChain"]
    # the emitted PEM re-parses back to exactly one cert
    assert len(pem_chain_to_cmp_certs(j["ekCertChain"])) == 1


def test_key_attest_resp_roundtrip_and_adapter():
    resp = prepare_key_attest_resp(enc_seed=b"credential-blob", enc_secret=b"encrypted-secret")
    decoded = decode_key_attest_resp(encode_to_der(resp))
    assert bytes(decoded["encSeed"]) == b"credential-blob"
    assert bytes(decoded["encSecret"]) == b"encrypted-secret"

    # adapter: {encSeed hex, encSecret hex} -> KeyAttestResp DER == direct build
    from_json = key_attest_resp_from_json(
        {"encSeed": b"credential-blob".hex(), "encSecret": b"encrypted-secret".hex()}
    )
    assert from_json == encode_to_der(resp)


def test_key_attest_resp_carries_no_seed():
    # The verifier-retained seed must never appear in KeyAttestResp.
    resp_der = key_attest_resp_from_json({"encSeed": b"blob".hex(), "encSecret": b"secret".hex()})
    decoded = decode_key_attest_resp(resp_der)
    assert set(decoded.keys()) == {"encSeed", "encSecret"}


def test_key_attest_evidence_roundtrip():
    ev = prepare_key_attest_evidence(b"tcg", b"tpmsig", b"tpub", b"popsig")
    decoded = decode_key_attest_evidence(encode_to_der(ev))
    assert bytes(decoded["tcgCertifyInfo"]) == b"tcg"
    assert bytes(decoded["tpmSignature"]) == b"tpmsig"
    assert bytes(decoded["tpmTPublic"]) == b"tpub"
    assert bytes(decoded["keyAttestSignature"]) == b"popsig"


def test_resolve_evidence_oid_default_and_env(monkeypatch):
    assert resolve_key_attest_evidence_oid() == DEFAULT_KEY_ATTEST_EVIDENCE_OID == "1.3.6.1.4.1.99999.2"
    monkeypatch.setenv("KEY_ATTEST_EVIDENCE_OID", "1.2.3.4")
    assert resolve_key_attest_evidence_oid() == "1.2.3.4"


# ── verify() early gates (TPM-free) ────────────────────────────────────────────


def _evidence(nonce: bytes, *, magic: int = 0xFF544347) -> bytes:
    return encode_to_der(
        prepare_key_attest_evidence(_certify_attest(nonce, magic=magic), b"sig", b"pub", b"pop")
    )


def _verify(evidence_der: bytes, *, nonce: bytes = b"NONCE1"):
    return verify_key_attest(
        evidence_der,
        seed=b"seed",
        nonce=nonce,
        pubkey_pem=b"",
        ak_chain_pem="",
        trust_anchor="",
    )


def test_verify_rejects_malformed_evidence():
    result = _verify(b"\x00\x01not-der")
    assert not result.accepted
    assert "decode" in result.errors[0]


def test_verify_rejects_bad_magic():
    # A forged TPM_GENERATED_VALUE is rejected at the TPMS_ATTEST unmarshal step.
    result = _verify(_evidence(b"NONCE1", magic=0xDEADBEEF))
    assert not result.accepted


def test_verify_rejects_nonce_mismatch():
    result = _verify(_evidence(b"OTHER"), nonce=b"NONCE1")
    assert not result.accepted
    assert "nonce mismatch" in result.errors[0]


def test_verify_fresh_nonce_reaches_ak_chain_gate():
    # Correct magic/type/nonce -> proceeds to the AK-chain check, which fails on
    # an empty chain (proving the freshness gate passed).
    result = _verify(_evidence(b"NONCE1"), nonce=b"NONCE1")
    assert not result.accepted
    assert "AK" in result.errors[0] or "chain" in result.errors[0]

"""NXP ELE dev-attest codec: hermetic round-trip + signature-convention tests.

Everything is generated in-process (P-384 key, 280-byte statement) — no
simulator, no fixtures on disk.  The integration path against a *simulator*
statement is covered by the ``imx93-ele-sim-attest`` 4/4 gate loop.

Sign/verify here go through ``keyutils_py`` (see GUIDELINES.md §1), so these
tests also pin the keyutils routing: a regression that reverts to raw
cryptography calls would still pass the *positive* checks, but the
single-vs-double-hash test (``test_double_hash_convention_fails``) fails on
any convention drift.
"""
from __future__ import annotations

import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from keyutils_py import sign_data

from libattest.formats.csrattest.csr_attest_structures import (
    prepare_attestation_bundle,
    prepare_opaque_attestation_statement,
)
from pyasn1.codec.der import encoder
from pyasn1.type import univ

from libattest.formats.nxp import (
    ELE_DEV_ATTEST_OID_DEFAULT,
    EleDevAttestError,
    canonical_signed_bytes,
    decode_ele_dev_attest,
    log_statement_debug,
    pretty_print_ele_dev_attest,
    pretty_print_statement,
    pretty_print_stmt_bundle,
    verify_ele_dev_attest_signature,
)

SOC_ID = 0x9300  # i.MX93
LMDA = 0x0002


def _build_statement(device_key: ec.EllipticCurvePrivateKey, nonce16: bytes, double_hash: bool = False) -> bytes:
    """Assemble a structurally valid 280-byte dev-attest statement (sim layout)."""
    import hashlib
    from cryptography.hazmat.primitives import hashes

    dev_info = struct.pack(
        "<BBHHHHBB", 0xDB, 2, 92, SOC_ID, 0x0001, LMDA, 2, 0
    ) + b"\x10" * 16 + b"\x11" * 32 + b"\x12" * 32  # uid, rom_sha, fw_sha
    addn_info = b"\x13" * 64 + struct.pack("<BBBB", 1, 1, 1, 0)
    assert len(dev_info) == 92 and len(addn_info) == 68
    canonical = dev_info + addn_info + nonce16
    assert len(canonical) == 176
    if double_hash:
        sig_der = device_key.sign(hashlib.sha384(canonical).digest(), ec.ECDSA(hashes.SHA384()))
    else:
        sig_der = sign_data(canonical, device_key, hash_alg="sha384")
    r, s = ec_utils.decode_dss_signature(sig_der)
    sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    hdr = struct.pack("<BBBB", 0x06, 0x46, 0xDB, 0xE1) + struct.pack("<I", 0)
    raw = hdr + canonical + sig
    assert len(raw) == 280
    return raw


@pytest.fixture(scope="module")
def stmt_env():
    key = ec.generate_private_key(ec.SECP384R1())
    nonce16 = b"\xaa" * 16
    raw = _build_statement(key, nonce16)
    return key.public_key(), raw, nonce16


def test_decode_fields_byte_exact(stmt_env):
    pub, raw, nonce16 = stmt_env
    stmt = decode_ele_dev_attest(raw)
    assert stmt.soc_id == SOC_ID and stmt.lmda_val == LMDA
    assert stmt.uid == raw[20:36]
    assert stmt.sha_rom_patch == raw[36:68] and stmt.sha_fw == raw[68:100]
    assert stmt.oem_srkh == raw[100:164]
    assert stmt.nounce == nonce16 and len(stmt.nounce) == 16
    assert stmt.signature == raw[184:280]


def test_signature_verifies_via_keyutils(stmt_env):
    pub, raw, _ = stmt_env
    assert verify_ele_dev_attest_signature(raw, pub) is True
    assert decode_ele_dev_attest(raw).verify_signature(pub) is True


def test_canonical_rederives_from_object(stmt_env):
    _, raw, _ = stmt_env
    stmt = decode_ele_dev_attest(raw)
    assert canonical_signed_bytes(stmt) == canonical_signed_bytes(raw) == raw[8:184]


def test_tamper_rejected(stmt_env):
    pub, raw, _ = stmt_env
    bad = bytearray(raw)
    bad[50] ^= 0xFF  # inside the signed region
    assert verify_ele_dev_attest_signature(bytes(bad), pub) is False


def test_wrong_length_rejected(stmt_env):
    _, raw, _ = stmt_env
    with pytest.raises(EleDevAttestError):
        decode_ele_dev_attest(raw[:200])


def test_double_hash_convention_fails(stmt_env):
    """The NXP attester hashes the canonical buffer exactly ONCE.

    If either side pre-hashed the digest, verification would fail — this pins
    the single-hash convention empirically (the double-hash trap).
    """
    pub, _, nonce16 = stmt_env
    key = ec.generate_private_key(ec.SECP384R1())
    double = _build_statement(key, nonce16, double_hash=True)
    assert verify_ele_dev_attest_signature(double, key.public_key()) is False


def test_pretty_print_per_format(stmt_env):
    _, raw, _ = stmt_env
    out = pretty_print_ele_dev_attest(decode_ele_dev_attest(raw))
    assert "0x9300" in out and "lmda_val" in out and "nounce (16 B)" in out


def _stmt(stmt_bytes: bytes, oid: str = ELE_DEV_ATTEST_OID_DEFAULT):
    """One decoded AttestationStatement wrapping *stmt_bytes* as an OCTET STRING."""
    return prepare_opaque_attestation_statement(univ.ObjectIdentifier(oid), stmt_bytes)


def test_pretty_print_statement_does_oid_and_asn1_parsing(stmt_env):
    """The 3-function API takes wire DER (or decoded) and parses it itself."""
    from libattest.formats.csrattest.csr_attest_structures import decode_attestation_statement

    _, raw, _ = stmt_env
    der = encoder.encode(_stmt(raw))
    out = pretty_print_statement(der)
    assert "ELE dev-attest statement" in out
    # decoded form gives the same result
    assert out == pretty_print_statement(decode_attestation_statement(der))


def test_pretty_print_stmt_bundle_renders_all_statements(stmt_env):
    _, raw, _ = stmt_env
    from libattest.formats.nxp.tlv import encode_tlv

    ka = encode_tlv(0x0A, b"\xaa" * 16)  # auth_challenge TLV (key-attest family)
    bundle = prepare_attestation_bundle([
        _stmt(raw),
        _stmt(ka, "1.3.6.1.4.1.99999.31"),
    ])
    out = pretty_print_stmt_bundle(encoder.encode(bundle))
    assert "ELE dev-attest statement" in out
    assert "ELE key-attest certificate" in out
    # statement order is preserved
    assert out.index("dev-attest") < out.index("key-attest")


def test_log_statement_debug(caplog, stmt_env):
    import logging

    _, raw, _ = stmt_env
    der = encoder.encode(_stmt(raw))
    with caplog.at_level(logging.DEBUG, logger="libattest.formats.nxp"):
        log_statement_debug(der, extra="gate=G2")
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "ELE dev-attest statement" in joined
    assert "gate=G2" in joined


def test_unknown_oid_graceful():
    der = encoder.encode(_stmt(b"\x01\x05abc", oid="1.3.6.1.4.1.99999.21"))
    assert "no NXP codec registered" in pretty_print_statement(der)

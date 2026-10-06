#!/usr/bin/env python3
"""Self-test: decode + verify a real SimELE 280-byte statement with the new codec."""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate
from libattest.formats.nxp.ele_dev_attest import (
    decode_ele_dev_attest, verify_ele_dev_attest_signature, canonical_signed_bytes,
    pretty_print_ele_dev_attest, EleDevAttestError,
)
import hashlib

d = open("/tmp/nxptest_dir.txt").read().strip()
raw = open(os.path.join(d, "stmt.bin"), "rb").read()
assert len(raw) == 280, len(raw)

# load device attestation public key from the anchor (device cert -> pubkey)
anchor = json.load(open(os.path.join(d, "anchor.json")))
cert = load_pem_x509_certificate(open(os.path.join(d, "device_attest.pem"), "rb").read())
pub = cert.public_key()

stmt = decode_ele_dev_attest(raw)
print("== decoded ==")
print(pretty_print_ele_dev_attest(stmt))

# 1. signature verifies against the attester device-attest key
ok = verify_ele_dev_attest_signature(stmt, pub)
print("\n[1] signature verifies:", ok)
assert ok

# 2. canonical bytes re-derive identically from raw vs object
assert canonical_signed_bytes(stmt) == raw[8:184], "canonical mismatch"
print("[2] canonical_signed_bytes(raw) == canonical_signed_bytes(obj):", True)

# 3. round-trip: fields re-derive byte-exact from the raw buffer
assert stmt.uid == raw[20:36] and stmt.sha_rom_patch == raw[36:68] and stmt.sha_fw == raw[68:100]
assert stmt.oem_srkh == raw[100:164] and stmt.nounce == raw[168:184]
print("[3] field offsets byte-exact:", True)

# 4. tamper detection: flip one byte in the signed region -> must fail
bad = bytearray(raw); bad[50] ^= 0xFF
assert verify_ele_dev_attest_signature(bytes(bad), pub) is False
print("[4] tamper detected (verify returned False):", True)

# 5. wrong length -> EleDevAttestError
try:
    decode_ele_dev_attest(raw[:200]); print("[5] FAIL: short accepted"); raise SystemExit(1)
except EleDevAttestError:
    print("[5] wrong length rejected:", True)

# 6. prettyPrint present + non-empty, contains the soc_id
pp = pretty_print_ele_dev_attest(stmt)
assert "0x9300" in pp and "lmda_val" in pp
print("[6] prettyPrint present:", True)

print("\nALL DEV-ATTEST CODEC CHECKS PASS")

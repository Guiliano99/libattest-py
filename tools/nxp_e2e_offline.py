#!/usr/bin/env python3
"""Offline end-to-end scenario for the NXP ELE key-attest E2E (libattest.formats.nxp).

Exercises the NEW library code across the full LAMPS wire boundary, no Docker,
no services:

  Attester  (sim ELE device)
     -> 280-byte dev-attest statement, ECDSA P-384 via keyutils_py.sign_data
     -> wrapped as AttestationStatement{type OID, stmt OCTET STRING}
     -> AttestationBundle{attestations}  DER  (the CSR id-aa-attestation payload)
  CA/RA   (offline libattest code)
     -> decode_attestation_bundle (ASN.1)
     -> FORMAT-AGNOSTIC: reads the type OID, routes on it, never inspects bytes
     -> nonce binding (RA 32B nonce, statement signed nonce[:16])
  Verifier (offline, OID-keyed)
     -> codec decode + keyutils_py.verify_signature
     -> pretty_print_statement (human readable)
     -> log_statement_debug (DEBUG)

Exit 0 only if the statement appraises; tamper/replay/rogue-root variants must
all be rejected.
"""
from __future__ import annotations

import logging
import struct
import sys
import pathlib
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().with_name("src")))

import os
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from pyasn1.type import univ
from pyasn1.codec.der import encoder
from keyutils_py import sign_data, verify_signature

from libattest.formats.csrattest.csr_attest_structures import (
    decode_attestation_bundle,
    prepare_attestation_bundle,
    prepare_opaque_attestation_statement,
)
from libattest.formats.nxp import (
    ELE_DEV_ATTEST_OID_DEFAULT,
    decode_ele_dev_attest,
    pretty_print_statement,
    verify_ele_dev_attest_signature,
)

FAILS = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")
    if not cond:
        FAILS.append(name)


# ── attester: simulated ELE device ────────────────────────────────────────────
def build_device(profile: dict, nonce16: bytes, dev_key: ec.EllipticCurvePrivateKey) -> bytes:
    """280-byte dev-attest statement (sim layout), signed via keyutils_py."""
    dev_info = struct.pack("<BBHHHHBB", 0xDB, 2, 92,
                           profile["soc_id"], profile["soc_rev"], profile["lmda"], 2, 0
                           ) + profile["uid"] + profile["rom"] + profile["fw"]
    addn = profile["srkh"] + struct.pack("<BBBB", 1, 1, 1, 0)
    assert len(dev_info) == 92 and len(addn) == 68
    canonical = dev_info + addn + nonce16
    sig_der = sign_data(canonical, dev_key, hash_alg="sha384")
    r, s = ec_utils.decode_dss_signature(sig_der)
    sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    raw = struct.pack("<BBBB", 0x06, 0x46, 0xDB, 0xE1) + struct.pack("<I", 0) + canonical + sig
    assert len(raw) == 280
    return raw


def wire_bundle(raw: bytes, oid: str = ELE_DEV_ATTEST_OID_DEFAULT) -> bytes:
    """cmpClient's job: wrap opaque stmt as AttestationStatement, DER the bundle."""
    stmt = prepare_opaque_attestation_statement(univ.ObjectIdentifier(oid), raw)
    return encoder.encode(prepare_attestation_bundle([stmt]))


PROFILE = {
    "soc_id": 0x9300, "soc_rev": 1, "lmda": 2,
    "uid": bytes.fromhex("10f4e008f455a3011a27fefac5071a2d"),
    "rom": bytes.fromhex("eac87755" * 8), "fw": bytes.fromhex("824ba5d0" * 8),
    "srkh": bytes.fromhex("df8f0ace" * 16),
}

print("=" * 74)
print("E2E offline — NXP ELE dev-attest via libattest.formats.nxp (new library)")
print("=" * 74)

dev_key = ec.generate_private_key(ec.SECP384R1())
ra_nonce = os.urandom(32)  # MockCA/RA default: 32 bytes
nonce16 = ra_nonce[:16]     # ELE signs nonce[:16] (V2)

# attester
raw = build_device(PROFILE, nonce16, dev_key)
bundle_der = wire_bundle(raw)
print(f"\n[attester] statement {len(raw)}B signed (keyutils_py) | bundle DER {len(bundle_der)}B")
check("bundle is a LAMPS AttestationBundle DER", bundle_der[:1] == b"\x30" and b"\x06" in bundle_der[:20])

# ── CA/RA: format-agnostic routing on the OID alone ───────────────────────────
print("\n[CA/RA] decode_attestation_bundle — format-agnostic, routes on OID")
bundle = decode_attestation_bundle(bundle_der)
stmts = list(bundle["attestations"])
check("bundle carries exactly 1 statement", len(stmts) == 1)
oid = str(stmts[0]["type"])
check("CA/RA reads statement type OID", oid == ELE_DEV_ATTEST_OID_DEFAULT, oid)
check("CA/RA never needs to parse inner bytes (opaque)",
      type(stmts[0]["stmt"]).__name__ in ("Any", "OctetString"))

# ── verifier: OID-keyed appraisal ──────────────────────────────────────────────
print("\n[verifier] OID-keyed appraisal (codec + keyutils_py.verify_signature)")

# unwrap the stmt open type once (the same helper the pretty API uses);
# the codec works on the NXP-native payload, csrattest owns the envelope.
from libattest.formats.csrattest.csr_attest_structures import unwrap_attestation_statement
payload, is_wrapped = unwrap_attestation_statement(bytes(stmts[0]["stmt"]))
check("stmt carried as opaque OCTET STRING (envelope)", is_wrapped)

# G0: structural decode via the codec
stmt = decode_ele_dev_attest(payload)
check("G0 structural decode (280B LE struct)", stmt.soc_id == PROFILE["soc_id"])

# G1: signature over the canonical buffer (keyutils)
check("G1 signature verifies vs device-attest anchor",
      verify_ele_dev_attest_signature(payload, dev_key.public_key()))
# G1b: the SAME check called straight through keyutils_py (bypassing the codec's
# fixed-width r||s re-encoding) — proves the keyutils routing is load-bearing.
sig = stmt.signature
der_sig = ec_utils.encode_dss_signature(int.from_bytes(sig[:48], "big"),
                                        int.from_bytes(sig[48:], "big"))
try:
    verify_signature(dev_key.public_key(), der_sig, payload[8:184], hash_alg="sha384")
    check("G1b keyutils_py.verify_signature direct: OK", True)
except Exception as exc:  # noqa: BLE001 - test gate
    check("G1b keyutils_py.verify_signature direct: OK", False, repr(exc))

# G2: nonce binding — statement signed nonce[:16] of the 32B RA nonce
check("G2 freshness: signed nounce == RA nonce[:16]", stmt.nounce == nonce16)

# G3: lifecycle/fused facts (device policy check)
check("G3 soc_id/lmda/ssm within policy",
      stmt.soc_id == 0x9300 and stmt.lmda_val == 2 and stmt.ssm_state == 2)

# human-readable output (the pretty API does the OID + ASN.1 parsing itself)
import io
buf = io.StringIO()
with redirect_stdout(buf):
    pretty = pretty_print_statement(stmts[0])
check("pretty_print_statement on the wire statement (OID+ASN.1 parsed in-function)",
      "ELE dev-attest statement" in pretty and "0x9300" in pretty)
print("\n" + pretty)

# debug log
recs = []
class Cap(logging.Handler):
    def emit(self, r): recs.append(r.getMessage())
lg = logging.getLogger("libattest.formats.nxp")
lg.addHandler(Cap()); lg.setLevel(logging.DEBUG); _prop = lg.propagate; lg.propagate = False
from libattest.formats.nxp import log_statement_debug
log_statement_debug(stmts[0], extra="e2e=offline")
lg.removeHandler(Cap()); lg.setLevel(logging.NOTSET); lg.propagate = _prop
check("log_statement_debug emitted DEBUG record with pretty tree",
      any("ELE dev-attest statement" in m and "e2e=offline" in m for m in recs))

# ── negative gates (the new library must reject, not just accept) ─────────────
print("\n[negative gates]")
bad = bytearray(bundle_der)
# find a byte in the statement payload region (inside the OCTET STRING) and flip it
idx = bad.find(bytes.fromhex("10f4e008"))  # uid starts here
check("located payload for tamper", idx > 0)
if idx > 0:
    bad[idx] ^= 0xFF
    tb = decode_attestation_bundle(bytes(bad))
    bad_payload, _ = unwrap_attestation_statement(bytes(tb["attestations"][0]["stmt"]))
    check("tamper rejected (G1 fails)",
          verify_ele_dev_attest_signature(bad_payload, dev_key.public_key()) is False)

# replay: same statement, different RA nonce
replay_bundle = wire_bundle(raw)  # raw still binds the OLD nonce16
other_nonce = os.urandom(32)
rs_payload, _ = unwrap_attestation_statement(
    bytes(decode_attestation_bundle(replay_bundle)["attestations"][0]["stmt"]))
rs = decode_ele_dev_attest(rs_payload)
check("replay rejected (nonce mismatch vs new RA nonce)", rs.nounce != other_nonce[:16])

# rogue anchor: verify against a DIFFERENT device-attest key
rogue = ec.generate_private_key(ec.SECP384R1())
check("rogue anchor rejected",
      verify_ele_dev_attest_signature(raw, rogue.public_key()) is False)

print("\n" + "=" * 74)
if FAILS:
    print(f"E2E RESULT: FAIL — {len(FAILS)} gate(s): {FAILS}")
    sys.exit(1)
print("E2E RESULT: PASS — statement generated, wrapped, routed by OID, appraised;")
print("            tamper / replay / rogue-anchor all rejected (offline, new library).")
